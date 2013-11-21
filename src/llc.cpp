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
}

void gprs_llc::reset_frame_space()
{
	m_index = 0;
}

void gprs_llc::enqueue(struct msgb *llc_msg)
{
	msgb_enqueue(&queue, llc_msg);
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

void gprs_llc::clear(BTS *bts)
{
	struct msgb *msg;

	while ((msg = msgb_dequeue(&queue))) {
		bts->llc_dropped_frame();
		msgb_free(msg);
	}
}

void gprs_llc::init()
{
	INIT_LLIST_HEAD(&queue);
	reset();
}

struct msgb *gprs_llc::dequeue()
{
	return msgb_dequeue(&queue);
}


void gprs_llc::calc_pdu_lifetime(BTS *bts, const uint16_t pdu_delay_csec, struct timeval *tv)
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

bool gprs_llc::is_frame_expired(struct timeval *tv_now, struct timeval *tv)
{
	/* Timeout is infinite */
	if (tv->tv_sec == 0 && tv->tv_usec == 0)
		return false;

	return timercmp(tv_now, tv, >);
}
