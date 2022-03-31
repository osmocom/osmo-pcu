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

bool llc_is_user_data_frame(const uint8_t *data, size_t len)
{
	if (len < 2)
		return false;

	if ((data[0] & 0x0f) == 1 /* GPRS_SAPI_GMM */)
		return false;

	if ((data[0] & 0xe0) != 0xc0 /* LLC UI */)
		/* It is not an LLC UI frame, see TS 44.064, 6.3 */
		return false;

	return true;
}

void llc_queue_init(struct gprs_llc_queue *q)
{
	INIT_LLIST_HEAD(&q->queue);
	q->queue_size = 0;
	q->queue_octets = 0;
	q->avg_queue_delay = 0;
}


void llc_queue_enqueue(struct gprs_llc_queue *q, struct msgb *llc_msg, const struct timespec *expire_time)
{
	struct MetaInfo *meta_storage;

	osmo_static_assert(sizeof(*meta_storage) <= sizeof(llc_msg->cb), info_does_not_fit);

	q->queue_size += 1;
	q->queue_octets += msgb_length(llc_msg);

	meta_storage = (struct MetaInfo *)&llc_msg->cb[0];
	osmo_clock_gettime(CLOCK_MONOTONIC, &meta_storage->recv_time);
	meta_storage->expire_time = *expire_time;

	msgb_enqueue(&q->queue, llc_msg);
}

void llc_queue_clear(struct gprs_llc_queue *q, struct gprs_rlcmac_bts *bts)
{
	struct msgb *msg;

	while ((msg = msgb_dequeue(&q->queue))) {
		if (bts)
			bts_do_rate_ctr_inc(bts, CTR_LLC_FRAME_DROPPED);
		msgb_free(msg);
	}

	q->queue_size = 0;
	q->queue_octets = 0;
}

void llc_queue_move_and_merge(struct gprs_llc_queue *q, struct gprs_llc_queue *o)
{
	struct msgb *msg, *msg1 = NULL, *msg2 = NULL;
	struct llist_head new_queue;
	size_t queue_size = 0;
	size_t queue_octets = 0;
	INIT_LLIST_HEAD(&new_queue);

	while (1) {
		if (msg1 == NULL)
			msg1 = msgb_dequeue(&q->queue);

		if (msg2 == NULL)
			msg2 = msgb_dequeue(&o->queue);

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

	OSMO_ASSERT(llist_empty(&q->queue));
	OSMO_ASSERT(llist_empty(&o->queue));

	o->queue_size = 0;
	o->queue_octets = 0;

	llist_splice_init(&new_queue, &q->queue);
	q->queue_size = queue_size;
	q->queue_octets = queue_octets;
}

#define ALPHA 0.5f

struct msgb *llc_queue_dequeue(struct gprs_llc_queue *q, const struct MetaInfo **info)
{
	struct msgb *msg;
	struct timespec *tv, tv_now, tv_result;
	uint32_t lifetime;
	const struct MetaInfo *meta_storage;

	msg = msgb_dequeue(&q->queue);
	if (!msg)
		return NULL;

	meta_storage = (struct MetaInfo *)&msg->cb[0];

	if (info)
		*info = meta_storage;

	q->queue_size -= 1;
	q->queue_octets -= msgb_length(msg);

	/* take the second time */
	osmo_clock_gettime(CLOCK_MONOTONIC, &tv_now);
	tv = (struct timespec *)&msg->data[sizeof(*tv)];
	timespecsub(&tv_now, &meta_storage->recv_time, &tv_result);

	lifetime = tv_result.tv_sec*1000 + tv_result.tv_nsec/1000000;
	q->avg_queue_delay = q->avg_queue_delay * ALPHA + lifetime * (1-ALPHA);

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
