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

struct gprs_rlcmac_tbf {
	struct llist_head list;
	enum gprs_rlcmac_tbf_state state;
	uint32_t state_flags;
	enum gprs_rlcmac_tbf_direction direction;
	uint8_t tfi;
	uint32_t tlli;
	uint8_t tlli_valid;
	uint8_t trx;
	uint16_t arfcn;
	uint8_t tsc;
	uint8_t first_ts; /* first TS used by TBF */
	uint8_t first_common_ts; /* first TS that the phone can send and
		reveive simultaniously */
	uint8_t control_ts; /* timeslot control messages and polling */
	uint8_t ms_class;
	struct gprs_rlcmac_pdch *pdch[8]; /* list of PDCHs allocated to TBF */
	uint16_t ta;
	uint8_t llc_frame[LLC_MAX_LEN]; /* current DL or UL frame */
	uint16_t llc_index; /* current write/read position of frame */
	uint16_t llc_length; /* len of current DL LLC_frame, 0 == no frame */
	struct llist_head llc_queue; /* queued LLC DL data */

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
			char imsi[16]; /* store IMSI for PCH retransmission */
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
		char imsi[16];

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
};


/* dispatch Unitdata.DL messages */
int tbf_handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const char *imsi, const uint8_t ms_class,
		const uint16_t delay_csec, const uint8_t *data, const uint16_t len);

struct gprs_rlcmac_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts,
	int8_t use_trx, uint8_t ms_class,
	uint32_t tlli, uint8_t ta, struct gprs_rlcmac_tbf *dl_tbf);
