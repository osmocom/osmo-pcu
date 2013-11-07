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

extern "C" {
#include <osmocom/core/msgb.h>
}

/* reset LLC frame */
void gprs_llc::reset()
{
	index = 0;
	length = 0;
}

void gprs_llc::reset_frame_space()
{
	index = 0;
}

void gprs_llc::enqueue(struct msgb *llc_msg)
{
	msgb_enqueue(&queue, llc_msg);
}

void gprs_llc::put_frame(const uint8_t *data, size_t len)
{
	memcpy(frame, data, len);
	length = len;
}

void gprs_llc::clear(BTS *bts)
{
	struct msgb *msg;

	while ((msg = msgb_dequeue(&queue))) {
		bts->dropped_frame();
		msgb_free(msg);
	}
}

void gprs_llc::init()
{
	INIT_LLIST_HEAD(&queue);
}

struct msgb *gprs_llc::dequeue()
{
	return msgb_dequeue(&queue);
}

void gprs_llc::update_frame(struct msgb *msg)
{
	/* TODO: assert that index is 0 now */
	/* TODO: bounds check */
	memcpy(frame, msg->data, msg->len);
	length = msg->len;
}
