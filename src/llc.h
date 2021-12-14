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
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
	#include <osmocom/core/linuxlist.h>
#ifdef __cplusplus
}
#endif

#include <stdint.h>
#include <string.h>
#include <time.h>

#define LLC_MAX_LEN 1543

struct gprs_rlcmac_bts;

/**
 * I represent the LLC data to a MS
 */
struct gprs_llc {

#ifdef __cplusplus
	static bool is_user_data_frame(uint8_t *data, size_t len);

	void init();
	void reset();
	void reset_frame_space();

	void put_frame(const uint8_t *data, size_t len);
	void put_dummy_frame(size_t req_len);
	void append_frame(const uint8_t *data, size_t len);
#endif

	uint8_t frame[LLC_MAX_LEN]; /* current DL or UL frame */
	uint16_t m_index; /* current write/read position of frame */
	uint16_t m_length; /* len of current DL LLC_frame, 0 == no frame */
};

struct MetaInfo {
	struct timespec recv_time;
	struct timespec expire_time;
};
/**
 * I store the LLC frames that come from the SGSN.
 */
struct gprs_llc_queue {
#ifdef __cplusplus
	static void calc_pdu_lifetime(struct gprs_rlcmac_bts *bts, const uint16_t pdu_delay_csec,
		struct timespec *tv);
	static bool is_frame_expired(const struct timespec *now,
		const struct timespec *tv);
	static bool is_user_data_frame(uint8_t *data, size_t len);

	void enqueue(struct msgb *llc_msg, const struct timespec *expire_time);
	struct msgb *dequeue(const MetaInfo **info = 0);
#endif
	uint32_t m_avg_queue_delay; /* Average delay of data going through the queue */
	size_t m_queue_size;
	size_t m_queue_octets;
	struct llist_head m_queue; /* queued LLC DL data */
};

#ifdef __cplusplus
extern "C" {
#endif
void llc_queue_init(struct gprs_llc_queue *q);
void llc_queue_clear(struct gprs_llc_queue *q, struct gprs_rlcmac_bts *bts);
void llc_queue_move_and_merge(struct gprs_llc_queue *q, struct gprs_llc_queue *o);

static inline uint16_t llc_chunk_size(const struct gprs_llc *llc)
{
	return llc->m_length - llc->m_index;
}

static inline uint16_t llc_remaining_space(const struct gprs_llc *llc)
{
	return LLC_MAX_LEN - llc->m_length;
}

static inline uint16_t llc_frame_length(const struct gprs_llc *llc)
{
	return llc->m_length;
}

static inline void llc_consume(struct gprs_llc *llc, size_t len)
{
	llc->m_index += len;
}

static inline void llc_consume_data(struct gprs_llc *llc, uint8_t *data, size_t len)
{
	/* copy and increment index */
	memcpy(data, llc->frame + llc->m_index, len);
	llc_consume(llc, len);
}

static inline bool llc_fits_in_current_frame(const struct gprs_llc *llc, uint8_t chunk_size)
{
	return llc->m_length + chunk_size <= LLC_MAX_LEN;
}

static inline size_t llc_queue_size(const struct gprs_llc_queue *q)
{
	return q->m_queue_size;
}

static inline size_t llc_queue_octets(const struct gprs_llc_queue *q)
{
	return q->m_queue_octets;
}

#ifdef __cplusplus
}
#endif
