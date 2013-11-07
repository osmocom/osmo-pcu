/*
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

#pragma once

#include <stdint.h>

#define LLC_MAX_LEN 1543

/**
 * I represent the LLC data to a MS
 */
struct gprs_llc {
	void init();
	void reset();
	void reset_frame_space();

	void enqueue(struct msgb *llc_msg);
	struct msgb *dequeue();

	void update_frame(struct msgb *msg);
	void put_frame(const uint8_t *data, size_t len);
	void clear(BTS *bts);

	uint8_t frame[LLC_MAX_LEN]; /* current DL or UL frame */
	uint16_t index; /* current write/read position of frame */
	uint16_t length; /* len of current DL LLC_frame, 0 == no frame */
	struct llist_head queue; /* queued LLC DL data */
};

