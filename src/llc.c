/* Copied from tbf.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <stdio.h>

#include <osmocom/core/msgb.h>

#include "bts.h"
#include "gprs_ms.h"
#include "pcu_utils.h"
#include "llc.h"

void llc_init(struct gprs_llc *llc)
{
	llc_reset(llc);
}

/* reset LLC frame */
void llc_reset(struct gprs_llc *llc)
{
	llc->index = 0;
	llc->length = 0;
	llc->prio = 0;
	llc->meta_info = (struct MetaInfo){0};

	memset(llc->frame, 0x42, sizeof(llc->frame));
}

void llc_reset_frame_space(struct gprs_llc *llc)
{
	llc->index = 0;
}

/* Put an Unconfirmed Information (UI) Dummy command, see GSM 44.064, 6.4.2.2 */
void llc_put_dummy_frame(struct gprs_llc *llc, size_t req_len)
{
	/* The shortest dummy command (the spec requests at least 6 octets) */
	static const uint8_t llc_dummy_command[] = {
		0x43, 0xc0, 0x01, 0x2b, 0x2b, 0x2b
	};
	static const size_t max_dummy_command_len = 79;

	llc_put_frame(llc, llc_dummy_command, sizeof(llc_dummy_command));

	if (req_len > max_dummy_command_len)
		req_len = max_dummy_command_len;

	/* Add further stuffing, if the requested length exceeds the minimum
	 * dummy command length */
	if (llc->length < req_len) {
		memset(&llc->frame[llc->length], 0x2b, req_len - llc->length);
		llc->length = req_len;
	}
}

void llc_put_frame(struct gprs_llc *llc, const uint8_t *data, size_t len)
{
	/* only put frames when we are empty */
	OSMO_ASSERT(llc->index == 0 && llc->length == 0);
	llc_append_frame(llc, data, len);
}

void llc_append_frame(struct gprs_llc *llc, const uint8_t *data, size_t len)
{
	/* TODO: bounds check */
	memcpy(llc->frame + llc->length, data, len);
	llc->length += len;
}

static bool llc_pdu_can_be_discarded(const uint8_t *data, size_t len)
{
	const unsigned keep_small_thresh = 60;

	/* Is the frame small, perhaps only a TCP ACK? */
	if (len <= keep_small_thresh)
		return false;

	if ((data[0] & 0x0f) == 1 /* GPRS_SAPI_GMM */)
		return false;

	if ((data[0] & 0xe0) != 0xc0 /* LLC UI */)
		/* It is not an LLC UI frame, see TS 44.064, 6.3 */
		return false;

	return true;
}

void llc_queue_init(struct gprs_llc_queue *q, struct GprsMs *ms)
{
	unsigned int i;

	q->ms = ms;
	q->queue_size = 0;
	q->queue_octets = 0;
	q->avg_queue_delay = 0;
	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		INIT_LLIST_HEAD(&q->pq[i].queue);
		gprs_codel_init(&q->pq[i].codel_state);
	}
}

/* interval=0 -> don't use codel in the LLC queue */
void llc_queue_set_codel_interval(struct gprs_llc_queue *q, unsigned int interval)
{
	unsigned int i;
	if (interval == LLC_CODEL_DISABLE) {
		q->use_codel = false;
		return;
	}
	q->use_codel = true;
	for (i = 0; i < ARRAY_SIZE(q->pq); i++)
		gprs_codel_set_interval(&q->pq[i].codel_state, interval);
}

static enum gprs_llc_queue_prio llc_sapi2prio(uint8_t sapi)
{
	switch (sapi) {
	case 1:
		return LLC_QUEUE_PRIO_GMM;
	case 2:
	case 7:
	case 8:
		return LLC_QUEUE_PRIO_TOM_SMS;
	default:
		return LLC_QUEUE_PRIO_OTHER;
	}
}

void llc_queue_enqueue(struct gprs_llc_queue *q, struct msgb *llc_msg, const struct timespec *expire_time)
{
	struct MetaInfo *meta_storage;
	struct gprs_llc_hdr *llc_hdr = (struct gprs_llc_hdr *)msgb_data(llc_msg);
	enum gprs_llc_queue_prio prio;

	osmo_static_assert(sizeof(*meta_storage) <= sizeof(llc_msg->cb), info_does_not_fit);

	prio = llc_sapi2prio(llc_hdr->sapi);

	q->queue_size += 1;
	q->queue_octets += msgb_length(llc_msg);

	meta_storage = (struct MetaInfo *)&llc_msg->cb[0];
	osmo_clock_gettime(CLOCK_MONOTONIC, &meta_storage->recv_time);
	meta_storage->expire_time = *expire_time;

	msgb_enqueue(&q->pq[prio].queue, llc_msg);
}

void llc_queue_clear(struct gprs_llc_queue *q, struct gprs_rlcmac_bts *bts)
{
	struct msgb *msg;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		while ((msg = msgb_dequeue(&q->pq[i].queue))) {
			if (bts)
				bts_do_rate_ctr_inc(bts, CTR_LLC_FRAME_DROPPED);
			msgb_free(msg);
		}
	}

	q->queue_size = 0;
	q->queue_octets = 0;
}

void llc_queue_move_and_merge(struct gprs_llc_queue *q, struct gprs_llc_queue *o)
{
	struct msgb *msg, *msg1 = NULL, *msg2 = NULL;
	struct llist_head new_queue;
	unsigned int i;
	size_t queue_size = 0;
	size_t queue_octets = 0;
	INIT_LLIST_HEAD(&new_queue);

	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		while (1) {
			if (msg1 == NULL)
				msg1 = msgb_dequeue(&q->pq[i].queue);

			if (msg2 == NULL)
				msg2 = msgb_dequeue(&o->pq[i].queue);

			if (msg1 == NULL && msg2 == NULL)
				break;

			if (msg1 == NULL) {
				msg = msg2;
				msg2 = NULL;
			} else if (msg2 == NULL) {
				msg = msg1;
				msg1 = NULL;
			} else {
				const struct MetaInfo *mi1 = (struct MetaInfo *)&msg1->cb[0];
				const struct MetaInfo *mi2 = (struct MetaInfo *)&msg2->cb[0];

				if (timespeccmp(&mi2->recv_time, &mi1->recv_time, >)) {
					msg = msg1;
					msg1 = NULL;
				} else {
					msg = msg2;
					msg2 = NULL;
				}
			}

			msgb_enqueue(&new_queue, msg);
			queue_size += 1;
			queue_octets += msgb_length(msg);
		}

		OSMO_ASSERT(llist_empty(&q->pq[i].queue));
		OSMO_ASSERT(llist_empty(&o->pq[i].queue));
		llist_splice_init(&new_queue, &q->pq[i].queue);
	}

	o->queue_size = 0;
	o->queue_octets = 0;
	q->queue_size = queue_size;
	q->queue_octets = queue_octets;
}

/* Prepend / Put back a previously dequeued LLC frame (llc_queue_dequeue()) */
void llc_queue_merge_prepend(struct gprs_llc_queue *q, const struct gprs_llc *llc)
{
	struct MetaInfo *meta_storage;
	unsigned int len = llc_frame_length(llc);
	struct msgb *llc_msg = msgb_alloc(len, "llc_pdu_queue");

	OSMO_ASSERT(llc_msg);
	memcpy(msgb_put(llc_msg, len), llc->frame, len);

	q->queue_size += 1;
	q->queue_octets += msgb_length(llc_msg);

	meta_storage = (struct MetaInfo *)&llc_msg->cb[0];
	memcpy(meta_storage, &llc->meta_info, sizeof(struct MetaInfo));

	/* Prepend: */
	llist_add(&llc_msg->list, &q->pq[llc->prio].queue);
}

#define ALPHA 0.5f

static struct msgb *llc_queue_pick_msg(struct gprs_llc_queue *q, enum gprs_llc_queue_prio *prio)
{
	struct msgb *msg;
	struct timespec tv_now, tv_result;
	uint32_t lifetime;
	unsigned int i;
	const struct MetaInfo *meta_storage;

	for (i = 0; i < ARRAY_SIZE(q->pq); i++) {
		if ((msg = msgb_dequeue(&q->pq[i].queue))) {
			*prio = (enum gprs_llc_queue_prio)i;
			break;
		}
	}
	if (!msg)
		return NULL;

	meta_storage = (struct MetaInfo *)&msg->cb[0];

	q->queue_size -= 1;
	q->queue_octets -= msgb_length(msg);

	/* take the second time */
	osmo_clock_gettime(CLOCK_MONOTONIC, &tv_now);
	timespecsub(&tv_now, &meta_storage->recv_time, &tv_result);

	lifetime = tv_result.tv_sec*1000 + tv_result.tv_nsec/1000000;
	q->avg_queue_delay = q->avg_queue_delay * ALPHA + lifetime * (1-ALPHA);

	return msg;
}

struct msgb *llc_queue_dequeue(struct gprs_llc_queue *q, enum gprs_llc_queue_prio *out_prio, struct MetaInfo *out_info)
{
	struct msgb *msg;
	struct timespec tv_now, tv_now2;
	uint32_t octets = 0, frames = 0;
	struct gprs_rlcmac_bts *bts = q->ms->bts;
	struct gprs_pcu *pcu = bts->pcu;
	struct timespec hyst_delta = {0, 0};
	enum gprs_llc_queue_prio prio;
	const struct MetaInfo *info = NULL;

	if (pcu->vty.llc_discard_csec)
		csecs_to_timespec(pcu->vty.llc_discard_csec, &hyst_delta);

	osmo_clock_gettime(CLOCK_MONOTONIC, &tv_now);
	timespecadd(&tv_now, &hyst_delta, &tv_now2);

	while ((msg = llc_queue_pick_msg(q, &prio))) {
		info = (const struct MetaInfo *)&msg->cb[0];
		const struct timespec *tv_disc = &info->expire_time;
		const struct timespec *tv_recv = &info->recv_time;

		gprs_bssgp_update_queue_delay(tv_recv, &tv_now);

		if (q->use_codel) {
			int bytes = llc_queue_octets(q);
			if (gprs_codel_control(&q->pq[prio].codel_state, tv_recv, &tv_now, bytes))
				goto drop_frame;
		}

		/* Is the age below the low water mark? */
		if (!llc_queue_is_frame_expired(&tv_now2, tv_disc))
			break;

		/* Is the age below the high water mark */
		if (!llc_queue_is_frame_expired(&tv_now, tv_disc)) {
			/* Has the previous message not been dropped? */
			if (frames == 0)
				break;

			/* Hysteresis mode, try to discard LLC messages until
			 * the low water mark has been reached */

			/* Check whether to abort the hysteresis mode:
			 * Can the PDU be discarded according to its type? */
			if (!llc_pdu_can_be_discarded(msg->data, msg->len))
				break;
		}

		bts_do_rate_ctr_inc(bts, CTR_LLC_FRAME_TIMEDOUT);
drop_frame:
		frames++;
		octets += msg->len;
		msgb_free(msg);
		bts_do_rate_ctr_inc(bts, CTR_LLC_FRAME_DROPPED);
		continue;
	}

	if (frames) {
		LOGPMS(q->ms, DTBFDL, LOGL_NOTICE, "Discarding LLC PDU "
			"because lifetime limit reached, "
			"count=%u new_queue_size=%zu\n",
			  frames, llc_queue_size(q));
		if (frames > 0xff)
			frames = 0xff;
		if (octets > 0xffffff)
			octets = 0xffffff;
		if (pcu->bssgp.bctx)
			bssgp_tx_llc_discarded(pcu->bssgp.bctx, ms_tlli(q->ms), frames, octets);
	}

	if (!msg)
		return NULL;

	if (out_prio)
		*out_prio = prio;

	if (out_info) {
		OSMO_ASSERT(info);
		*out_info = *info;
	}

	return msg;
}

void llc_queue_calc_pdu_lifetime(struct gprs_rlcmac_bts *bts, const uint16_t pdu_delay_csec, struct timespec *tv)
{
	uint16_t delay_csec;
	if (bts->pcu->vty.force_llc_lifetime)
		delay_csec = bts->pcu->vty.force_llc_lifetime;
	else
		delay_csec = pdu_delay_csec;

	/* keep timestamp at 0 for infinite delay */
	if (delay_csec == 0xffff) {
		memset(tv, 0, sizeof(*tv));
		return;
	}

	/* calculate timestamp of timeout */
	struct timespec now, csec;
	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	csecs_to_timespec(delay_csec, &csec);

	timespecadd(&now, &csec, tv);
}

bool llc_queue_is_frame_expired(const struct timespec *tv_now, const struct timespec *tv)
{
	/* Timeout is infinite */
	if (tv->tv_sec == 0 && tv->tv_nsec == 0)
		return false;

	return timespeccmp(tv_now, tv, >);
}
