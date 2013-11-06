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

#include "gprs_rlcmac.h"

#include <stdint.h>

struct bssgp_bvc_ctx;
struct rlc_ul_header;

/*
 * TBF instance
 */

#define LLC_MAX_LEN 1543
#define RLC_MAX_SNS 128 /* GPRS, must be power of 2 */
#define RLC_MAX_WS  64 /* max window size */
#define RLC_MAX_LEN 54 /* CS-4 including spare bits */

#define Tassign_agch 0,200000	/* waiting after IMM.ASS confirm */
#define Tassign_pacch 2,0	/* timeout for pacch assigment */

enum gprs_rlcmac_tbf_state {
	GPRS_RLCMAC_NULL = 0,	/* new created TBF */
	GPRS_RLCMAC_ASSIGN,	/* wait for downlink assignment */
	GPRS_RLCMAC_FLOW,	/* RLC/MAC flow, resource needed */
	GPRS_RLCMAC_FINISHED,	/* flow finished, wait for release */
	GPRS_RLCMAC_WAIT_RELEASE,/* wait for release or restart of DL TBF */
	GPRS_RLCMAC_RELEASING,	/* releasing, wait to free TBI/USF */
};

enum gprs_rlcmac_tbf_poll_state {
	GPRS_RLCMAC_POLL_NONE = 0,
	GPRS_RLCMAC_POLL_SCHED, /* a polling was scheduled */
};

enum gprs_rlcmac_tbf_dl_ass_state {
	GPRS_RLCMAC_DL_ASS_NONE = 0,
	GPRS_RLCMAC_DL_ASS_SEND_ASS, /* send downlink assignment on next RTS */
	GPRS_RLCMAC_DL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_ul_ass_state {
	GPRS_RLCMAC_UL_ASS_NONE = 0,
	GPRS_RLCMAC_UL_ASS_SEND_ASS, /* send uplink assignment on next RTS */
	GPRS_RLCMAC_UL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_ul_ack_state {
	GPRS_RLCMAC_UL_ACK_NONE = 0,
	GPRS_RLCMAC_UL_ACK_SEND_ACK, /* send acknowledge on next RTS */
	GPRS_RLCMAC_UL_ACK_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_direction {
	GPRS_RLCMAC_DL_TBF,
	GPRS_RLCMAC_UL_TBF
};

#define GPRS_RLCMAC_FLAG_CCCH		0 /* assignment on CCCH */
#define GPRS_RLCMAC_FLAG_PACCH		1 /* assignment on PACCH */
#define GPRS_RLCMAC_FLAG_UL_DATA	2 /* uplink data received */
#define GPRS_RLCMAC_FLAG_DL_ACK		3 /* downlink acknowledge received  */
#define GPRS_RLCMAC_FLAG_TO_UL_ACK	4
#define GPRS_RLCMAC_FLAG_TO_DL_ACK	5
#define GPRS_RLCMAC_FLAG_TO_UL_ASS	6
#define GPRS_RLCMAC_FLAG_TO_DL_ASS	7
#define GPRS_RLCMAC_FLAG_TO_MASK	0xf0 /* timeout bits */

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

struct gprs_rlcmac_tbf {

	static void free_all(struct gprs_rlcmac_trx *trx);
	static void free_all(struct gprs_rlcmac_pdch *pdch);

	bool state_is(enum gprs_rlcmac_tbf_state rhs) const;
	bool state_is_not(enum gprs_rlcmac_tbf_state rhs) const;
	void set_state(enum gprs_rlcmac_tbf_state new_state);

	/* TODO: add the gettimeofday as parameter */
	struct msgb *llc_dequeue(bssgp_bvc_ctx *bctx);

	/* TODO: extract LLC class? */
	int assemble_forward_llc(uint8_t *data, uint8_t len);

	struct msgb *create_dl_acked_block(uint32_t fn, uint8_t ts);
	struct msgb *create_dl_ass(uint32_t fn);
	struct msgb *create_ul_ass(uint32_t fn);
	struct msgb *create_ul_ack(uint32_t fn);
	int snd_dl_ack(uint8_t final, uint8_t ssn, uint8_t *rbb);
	int snd_ul_ud();

	/* blocks were acked */
	int rcv_data_block_acknowledged(const uint8_t *data, size_t len, int8_t rssi);

	int rlcmac_diag();

	int update();
	void handle_timeout();
	void stop_timer();
	void stop_t3191();

	void poll_timeout();

	/** tlli handling */
	void update_tlli(uint32_t tlli);
	uint32_t tlli() const;
	bool is_tlli_valid() const;
	void tlli_mark_valid();

	uint8_t tfi() const;

	const char *imsi() const;
	void assign_imsi(const char *imsi);

	struct llist_head list;
	uint32_t state_flags;
	enum gprs_rlcmac_tbf_direction direction;
	struct gprs_rlcmac_trx *trx;
	uint8_t tsc;
	uint8_t first_ts; /* first TS used by TBF */
	uint8_t first_common_ts; /* first TS that the phone can send and
		reveive simultaniously */
	uint8_t control_ts; /* timeslot control messages and polling */
	uint8_t ms_class;
	struct gprs_rlcmac_pdch *pdch[8]; /* list of PDCHs allocated to TBF */
	uint16_t ta;

	gprs_llc m_llc;

	enum gprs_rlcmac_tbf_dl_ass_state dl_ass_state;
	enum gprs_rlcmac_tbf_ul_ass_state ul_ass_state;
	enum gprs_rlcmac_tbf_ul_ack_state ul_ack_state;

	enum gprs_rlcmac_tbf_poll_state poll_state;
	uint32_t poll_fn; /* frame number to poll */

	uint16_t ws;	/* window size */
	uint16_t sns;	/* sequence number space */

	/* Please note that all variables here will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	union {
		struct {
			uint16_t bsn;	/* block sequence number */
			uint16_t v_s;	/* send state */
			uint16_t v_a;	/* ack state */
			char v_b[RLC_MAX_SNS/2]; /* acknowledge state array */
			int32_t tx_counter; /* count all transmitted blocks */
			uint8_t wait_confirm; /* wait for CCCH IMM.ASS cnf */
		} dl;
		struct {
			uint16_t bsn;	/* block sequence number */
			uint16_t v_r;	/* receive state */
			uint16_t v_q;	/* receive window state */
			char v_n[RLC_MAX_SNS/2]; /* receive state array */
			int32_t rx_counter; /* count all received blocks */
			uint8_t n3103;	/* N3103 counter */
			uint8_t usf[8];	/* list USFs per PDCH (timeslot) */
			uint8_t contention_resolution_done; /* set after done */
			uint8_t final_ack_sent; /* set if we sent final ack */
		} ul;
	} dir;
	uint8_t rlc_block[RLC_MAX_SNS/2][RLC_MAX_LEN]; /* block history */
	uint8_t rlc_block_len[RLC_MAX_SNS/2]; /* block len  of history */
	
	uint8_t n3105;	/* N3105 counter */

	struct osmo_timer_list	timer;
	unsigned int T; /* Txxxx number */
	unsigned int num_T_exp; /* number of consecutive T expirations */
	
	struct osmo_gsm_timer_list	gsm_timer;
	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */

	struct {
		struct timeval dl_bw_tv; /* timestamp for dl bw calculation */
		uint32_t dl_bw_octets; /* number of octets since bw_tv */

		struct timeval rssi_tv; /* timestamp for rssi calculation */
		int32_t rssi_sum; /* sum of rssi values */
		int rssi_num; /* number of rssi values added since rssi_tv */

		struct timeval dl_loss_tv; /* timestamp for loss calculation */
		uint16_t dl_loss_lost; /* sum of lost packets */
		uint16_t dl_loss_received; /* sum of received packets */

	} meas;

	uint8_t cs; /* current coding scheme */

#ifdef DEBUG_DIAGRAM
	int diag; /* number where TBF is presented in diagram */
	int diag_new; /* used to format output of new TBF */
#endif

	/* these should become protected but only after gprs_rlcmac_data.c
	 * stops to iterate over all tbf in its current form */
	enum gprs_rlcmac_tbf_state state;

	/* store the BTS this TBF belongs to */
	BTS *bts;

	/*
	 * private fields. We can't make it private as it is breaking the
	 * llist macros.
	 */
	uint32_t m_tlli;
	uint8_t m_tlli_valid;
	uint8_t m_tfi;

	/* store IMSI for look-up and PCH retransmission */
	char m_imsi[16];

protected:
	gprs_rlcmac_bts *bts_data() const;

};


/* dispatch Unitdata.DL messages */
int tbf_handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const char *imsi, const uint8_t ms_class,
		const uint16_t delay_csec, const uint8_t *data, const uint16_t len);

struct gprs_rlcmac_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts,
	int8_t use_trx, uint8_t ms_class,
	uint32_t tlli, uint8_t ta, struct gprs_rlcmac_tbf *dl_tbf);

struct gprs_rlcmac_tbf *tbf_alloc(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *old_tbf,
	enum gprs_rlcmac_tbf_direction dir, uint8_t tfi, uint8_t trx,
	uint8_t ms_class, uint8_t single_slot);

void tbf_free(struct gprs_rlcmac_tbf *tbf);

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf);

void tbf_new_state(struct gprs_rlcmac_tbf *tbf,
        enum gprs_rlcmac_tbf_state state);

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
                        unsigned int seconds, unsigned int microseconds);

inline bool gprs_rlcmac_tbf::state_is(enum gprs_rlcmac_tbf_state rhs) const
{
	return state == rhs;
}

inline bool gprs_rlcmac_tbf::state_is_not(enum gprs_rlcmac_tbf_state rhs) const
{
	return state != rhs;
}

inline void gprs_rlcmac_tbf::set_state(enum gprs_rlcmac_tbf_state new_state)
{
	state = new_state;
}

inline uint32_t gprs_rlcmac_tbf::tlli() const
{
	return m_tlli;
}

inline bool gprs_rlcmac_tbf::is_tlli_valid() const
{
	return m_tlli_valid;
}

inline uint8_t gprs_rlcmac_tbf::tfi() const
{
	return m_tfi;
}

inline const char *gprs_rlcmac_tbf::imsi() const
{
	return m_imsi;
}

const char *tbf_name(gprs_rlcmac_tbf *tbf);
