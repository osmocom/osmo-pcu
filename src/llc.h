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
#include <string.h>

#define LLC_MAX_LEN 1543

/**
 * I represent the LLC data to a MS
 */
struct gprs_llc {
	static void calc_pdu_lifetime(BTS *bts, const uint16_t pdu_delay_csec, struct timeval *tv);
	static bool is_frame_expired(struct timeval *now, struct timeval *tv);

	void init();
	void reset();
	void reset_frame_space();

	void enqueue(struct msgb *llc_msg);
	struct msgb *dequeue();

	void put_frame(const uint8_t *data, size_t len);
	void append_frame(const uint8_t *data, size_t len);

	void consume(size_t len);
	void consume(uint8_t *data, size_t len);
	void clear(BTS *bts);

	uint16_t chunk_size() const;
	uint16_t remaining_space() const;
	uint16_t frame_length() const;

	bool fits_in_current_frame(uint8_t size) const;

	uint8_t frame[LLC_MAX_LEN]; /* current DL or UL frame */
	uint16_t m_index; /* current write/read position of frame */
	uint16_t m_length; /* len of current DL LLC_frame, 0 == no frame */
	struct llist_head queue; /* queued LLC DL data */

	size_t m_queue_size;
};

inline uint16_t gprs_llc::chunk_size() const
{
	return m_length - m_index;
}

inline uint16_t gprs_llc::remaining_space() const
{
	return LLC_MAX_LEN - m_length;
}

inline uint16_t gprs_llc::frame_length() const
{
	return m_length;
}

inline void gprs_llc::consume(size_t len)
{
	m_index += len;
}

inline void gprs_llc::consume(uint8_t *data, size_t len)
{
	/* copy and increment index */
	memcpy(data, frame + m_index, len);
	consume(len);
}

inline bool gprs_llc::fits_in_current_frame(uint8_t chunk_size) const
{
	return m_length + chunk_size <= LLC_MAX_LEN;
}
