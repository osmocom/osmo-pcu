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
	static const int max_dummy_command_len = 79;

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

	if ((data[0] & 0x0e) != 0xc0 /* LLC UI */)
		/* It is not an LLC UI frame */
		return false;

	return true;
}

void gprs_llc_queue::init()
{
	INIT_LLIST_HEAD(&m_queue);
	m_queue_size = 0;
	m_avg_queue_delay = 0;
}

void gprs_llc_queue::enqueue(struct msgb *llc_msg)
{
	m_queue_size += 1;
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
}

#define ALPHA 0.5f

struct msgb *gprs_llc_queue::dequeue()
{
	struct msgb *msg;
	struct timeval *tv, tv_now, tv_result;
	uint32_t lifetime;


	msg = msgb_dequeue(&m_queue);
	if (!msg)
		return NULL;

	m_queue_size -= 1;

	/* take the second time */
	gettimeofday(&tv_now, NULL);
	tv = (struct timeval *)&msg->data[sizeof(*tv)];
	timersub(&tv_now, tv, &tv_result);

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

bool gprs_llc_queue::is_frame_expired(struct timeval *tv_now, struct timeval *tv)
{
	/* Timeout is infinite */
	if (tv->tv_sec == 0 && tv->tv_usec == 0)
		return false;

	return timercmp(tv_now, tv, >);
}
