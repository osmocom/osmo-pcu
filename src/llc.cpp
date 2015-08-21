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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <tbf.h>
#include <bts.h>

#include <stdio.h>

extern "C" {
#include <osmocom/core/msgb.h>
}

/* reset LLC frame */
void gprs_llc::reset()
{
	m_index = 0;
	m_length = 0;

	memset(frame, 0x42, sizeof(frame));
}

void gprs_llc::reset_frame_space()
{
	m_index = 0;
}

/* Put an Unconfirmed Information (UI) Dummy command, see GSM 44.064, 6.4.2.2 */
void gprs_llc::put_dummy_frame(size_t req_len)
{
	/* The shortest dummy command (the spec requests at least 6 octets) */
	static const uint8_t llc_dummy_command[] = {
		0x43, 0xc0, 0x01, 0x2b, 0x2b, 0x2b
	};
	static const size_t max_dummy_command_len = 79;

	put_frame(llc_dummy_command, sizeof(llc_dummy_command));

	if (req_len > max_dummy_command_len)
		req_len = max_dummy_command_len;

	/* Add further stuffing, if the requested length exceeds the minimum
	 * dummy command length */
	while (m_length < req_len)
		frame[m_length++] = 0x2b;
}

void gprs_llc::put_frame(const uint8_t *data, size_t len)
{
	/* only put frames when we are empty */
	OSMO_ASSERT(m_index == 0 && m_length == 0);
	append_frame(data, len);
}

void gprs_llc::append_frame(const uint8_t *data, size_t len)
{
	/* TODO: bounds check */
	memcpy(frame + m_length, data, len);
	m_length += len;
}

void gprs_llc::init()
{
	reset();
}

bool gprs_llc::is_user_data_frame(uint8_t *data, size_t len)
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

void gprs_llc_queue::init()
{
	INIT_LLIST_HEAD(&m_queue);
	m_queue_size = 0;
	m_queue_octets = 0;
	m_avg_queue_delay = 0;
}

void gprs_llc_queue::enqueue(struct msgb *llc_msg, const MetaInfo *info)
{
	static const MetaInfo def_meta = {{0}};
	MetaInfo *meta_storage;

	osmo_static_assert(sizeof(*info) <= sizeof(llc_msg->cb), info_does_not_fit);

	m_queue_size += 1;
	m_queue_octets += msgb_length(llc_msg);

	meta_storage = (MetaInfo *)&llc_msg->cb[0];
	*meta_storage = info ? *info : def_meta;

	msgb_enqueue(&m_queue, llc_msg);
}

void gprs_llc_queue::clear(BTS *bts)
{
	struct msgb *msg;

	while ((msg = msgb_dequeue(&m_queue))) {
		if (bts)
			bts->llc_dropped_frame();
		msgb_free(msg);
	}

	m_queue_size = 0;
	m_queue_octets = 0;
}

void gprs_llc_queue::move_and_merge(gprs_llc_queue *o)
{
	struct msgb *msg, *msg1 = NULL, *msg2 = NULL;
	struct llist_head new_queue;
	size_t queue_size = 0;
	size_t queue_octets = 0;
	INIT_LLIST_HEAD(&new_queue);

	while (1) {
		if (msg1 == NULL)
			msg1 = msgb_dequeue(&m_queue);

		if (msg2 == NULL)
			msg2 = msgb_dequeue(&o->m_queue);

		if (msg1 == NULL && msg2 == NULL)
			break;

		if (msg1 == NULL) {
			msg = msg2;
			msg2 = NULL;
		} else if (msg2 == NULL) {
			msg = msg1;
			msg1 = NULL;
		} else {
			const MetaInfo *mi1 = (MetaInfo *)&msg1->cb[0];
			const MetaInfo *mi2 = (MetaInfo *)&msg2->cb[0];

			if (timercmp(&mi2->recv_time, &mi1->recv_time, >)) {
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

	OSMO_ASSERT(llist_empty(&m_queue));
	OSMO_ASSERT(llist_empty(&o->m_queue));

	o->m_queue_size = 0;
	o->m_queue_octets = 0;

	llist_splice_init(&new_queue, &m_queue);
	m_queue_size = queue_size;
	m_queue_octets = queue_octets;
}

#define ALPHA 0.5f

struct msgb *gprs_llc_queue::dequeue(const MetaInfo **info)
{
	struct msgb *msg;
	struct timeval *tv, tv_now, tv_result;
	uint32_t lifetime;
	const MetaInfo *meta_storage;

	msg = msgb_dequeue(&m_queue);
	if (!msg)
		return NULL;

	meta_storage = (MetaInfo *)&msg->cb[0];

	if (info)
		*info = meta_storage;

	m_queue_size -= 1;
	m_queue_octets -= msgb_length(msg);

	/* take the second time */
	gettimeofday(&tv_now, NULL);
	tv = (struct timeval *)&msg->data[sizeof(*tv)];
	timersub(&tv_now, &meta_storage->recv_time, &tv_result);

	lifetime = tv_result.tv_sec*1000 + tv_result.tv_usec/1000;
	m_avg_queue_delay = m_avg_queue_delay * ALPHA + lifetime * (1-ALPHA);

	return msg;
}

void gprs_llc_queue::calc_pdu_lifetime(BTS *bts, const uint16_t pdu_delay_csec, struct timeval *tv)
{
	uint16_t delay_csec;
	if (bts->bts_data()->force_llc_lifetime)
		delay_csec = bts->bts_data()->force_llc_lifetime;
	else
		delay_csec = pdu_delay_csec;

	/* keep timestamp at 0 for infinite delay */
	if (delay_csec == 0xffff) {
		memset(tv, 0, sizeof(*tv));
		return;
	}

	/* calculate timestamp of timeout */
	struct timeval now, csec;
	gettimeofday(&now, NULL);
	csec.tv_usec = (delay_csec % 100) * 10000;
	csec.tv_sec = delay_csec / 100;

	timeradd(&now, &csec, tv);
}

bool gprs_llc_queue::is_frame_expired(const struct timeval *tv_now,
	const struct timeval *tv)
{
	/* Timeout is infinite */
	if (tv->tv_sec == 0 && tv->tv_usec == 0)
		return false;

	return timercmp(tv_now, tv, >);
}
