/* 3GPP TS 44.064
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2022 by by Sysmocom s.f.m.c. GmbH
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

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <osmocom/core/endian.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/endian.h>

#include "gprs_codel.h"

#define LLC_MAX_LEN 1543

struct gprs_rlcmac_bts;
struct GprsMs;

struct gprs_llc_hdr {
#if OSMO_IS_LITTLE_ENDIAN
	union { /* 5.2, 6.2.0 */
		uint8_t address;
		uint8_t sapi:4, unused:2, c_r:1, pd:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	union {
		uint8_t address;
		uint8_t pd:1, c_r:1, unused:2, sapi:4;
#endif
	};
	uint8_t control[0];
} __attribute__ ((packed));

struct MetaInfo {
	struct timespec recv_time;
	struct timespec expire_time;
};
enum gprs_llc_queue_prio { /* lowest value has highest prio */
	LLC_QUEUE_PRIO_GMM = 0, /* SAPI 1 */
	LLC_QUEUE_PRIO_TOM_SMS, /* SAPI 2,7,8 */
	LLC_QUEUE_PRIO_OTHER, /* Other SAPIs */
	_LLC_QUEUE_PRIO_SIZE /* used to calculate size of enum */
};

/**
 * I represent the LLC data to a MS
 */
struct gprs_llc {
	uint8_t frame[LLC_MAX_LEN]; /* current DL or UL frame */
	uint16_t index; /* current write/read position of frame */
	uint16_t length; /* len of current DL LLC_frame, 0 == no frame */

	/* Saved when dequeue from llc_queue; allows re-enqueing in the queue if Tx fails */
	enum gprs_llc_queue_prio prio;
	struct MetaInfo meta_info;
};

void llc_init(struct gprs_llc *llc);
void llc_reset(struct gprs_llc *llc);
void llc_reset_frame_space(struct gprs_llc *llc);

void llc_put_frame(struct gprs_llc *llc, const uint8_t *data, size_t len);
void llc_put_dummy_frame(struct gprs_llc *llc, size_t req_len);
void llc_append_frame(struct gprs_llc *llc, const uint8_t *data, size_t len);

static inline uint16_t llc_chunk_size(const struct gprs_llc *llc)
{
	return llc->length - llc->index;
}

static inline uint16_t llc_remaining_space(const struct gprs_llc *llc)
{
	return LLC_MAX_LEN - llc->length;
}

static inline uint16_t llc_frame_length(const struct gprs_llc *llc)
{
	return llc->length;
}

static inline void llc_consume(struct gprs_llc *llc, size_t len)
{
	llc->index += len;
}

static inline void llc_consume_data(struct gprs_llc *llc, uint8_t *data, size_t len)
{
	/* copy and increment index */
	memcpy(data, llc->frame + llc->index, len);
	llc_consume(llc, len);
}

static inline bool llc_fits_in_current_frame(const struct gprs_llc *llc, uint8_t chunk_size)
{
	return llc->length + chunk_size <= LLC_MAX_LEN;
}

/**
 * I store the LLC frames that come from the SGSN.
 */
struct gprs_llc_prio_queue {
	struct gprs_codel codel_state;
	struct llist_head queue; /* queued LLC DL data. See enum gprs_llc_queue_prio. */
};
struct gprs_llc_queue {
	struct GprsMs *ms; /* backpointer */
	uint32_t avg_queue_delay; /* Average delay of data going through the queue */
	size_t queue_size;
	size_t queue_octets;
	bool use_codel;
	struct gprs_llc_prio_queue pq[_LLC_QUEUE_PRIO_SIZE]; /* queued LLC DL data. See enum gprs_llc_queue_prio. */
};

void llc_queue_calc_pdu_lifetime(struct gprs_rlcmac_bts *bts, const uint16_t pdu_delay_csec,
		struct timespec *tv);
bool llc_queue_is_frame_expired(const struct timespec *tv_now, const struct timespec *tv);

void llc_queue_init(struct gprs_llc_queue *q, struct GprsMs *ms);
void llc_queue_clear(struct gprs_llc_queue *q, struct gprs_rlcmac_bts *bts);
void llc_queue_set_codel_interval(struct gprs_llc_queue *q, unsigned int interval);
void llc_queue_move_and_merge(struct gprs_llc_queue *q, struct gprs_llc_queue *o);
void llc_queue_merge_prepend(struct gprs_llc_queue *q, struct gprs_llc *llc);
void llc_queue_enqueue(struct gprs_llc_queue *q, struct msgb *llc_msg, const struct timespec *expire_time);
struct msgb *llc_queue_dequeue(struct gprs_llc_queue *q, enum gprs_llc_queue_prio *out_prio, struct MetaInfo *out_info);

static inline size_t llc_queue_size(const struct gprs_llc_queue *q)
{
	return q->queue_size;
}

static inline size_t llc_queue_octets(const struct gprs_llc_queue *q)
{
	return q->queue_octets;
}

#ifdef __cplusplus
}
#endif
