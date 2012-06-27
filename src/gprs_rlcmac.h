/* gprs_rlcmac.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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
 
#ifndef GPRS_RLCMAC_H
#define GPRS_RLCMAC_H

#include <bitvector.h>
#include <gsm_rlcmac.h>
#include <gsm_timer.h>

extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
}

/*
 * PDCH instanc
 */

struct gprs_rlcmac_tbf;

struct gprs_rlcmac_pdch {
	uint8_t enable; /* TS is enabled */
	uint8_t tsc; /* TSC of this slot */
	uint8_t next_ul_tfi; /* next uplink TBF/TFI to schedule (0..31) */
	uint8_t next_dl_tfi; /* next downlink TBF/TFI to schedule (0..31) */
	struct gprs_rlcmac_tbf *tbf[32]; /* array of TBF pointers, by TFI */
};

struct gprs_rlcmac_trx {
	uint16_t arfcn;
	struct gprs_rlcmac_pdch pdch[8];
};

struct gprs_rlcmac_bts {
	struct gprs_rlcmac_trx trx[8];
};

extern struct gprs_rlcmac_bts *gprs_rlcmac_bts;

/*
 * TBF instance
 */

#define LLC_MAX_LEN 1543
#define RLC_MAX_SNS 128 /* GPRS, must be power of 2 */
#define RLC_MAX_WS  64 /* max window size */
#define RLC_MAX_LEN 52 /* CS-4 */
#define UL_RLC_DATA_BLOCK_LEN 23

#define T3169 6		/* 5 seconds + one second, because we don't use
			 * counters before starting timer. */
#define N3103_MAX 4	/* how many tries to poll PACKET CONTROL ACK */

enum gprs_rlcmac_tbf_state {
	GPRS_RLCMAC_FLOW,	/* RLC/MAC flow, ressource needed */
	GPRS_RLCMAC_FINISHED,	/* flow finished, wait for release */
	GPRS_RLCMAC_RELEASING,	/* releasing, wait to free TBI/USF */
};

enum gprs_rlcmac_tbf_poll_state {
	GPRS_RLCMAC_POLL_NONE = 0,
	GPRS_RLCMAC_POLL_SCHED, /* a polling was scheduled */
};

enum gprs_rlcmac_tbf_ul_substate {
	GPRS_RLCMAC_UL_NONE = 0,
	GPRS_RLCMAC_UL_SEND_ACK, /* send acknowledge on next RTS */
	GPRS_RLCMAC_UL_WAIT_POLL, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_direction {
	GPRS_RLCMAC_DL_TBF,
	GPRS_RLCMAC_UL_TBF
};

struct gprs_rlcmac_tbf {
	struct llist_head list;
	enum gprs_rlcmac_tbf_state state;
	enum gprs_rlcmac_tbf_direction direction;
	uint8_t tfi;
	uint32_t tlli;
	uint8_t tlli_valid;
	uint8_t trx, ts, tsc;
	uint16_t arfcn, ta;
	uint8_t llc_frame[LLC_MAX_LEN];
	uint16_t llc_index;

	enum gprs_rlcmac_tbf_poll_state poll_state;
	uint32_t poll_fn;

	uint16_t bsn;	/* block sequence number */
	uint16_t ws;	/* window size */
	uint16_t sns;	/* sequence number space */
	union {
		struct {
			uint16_t v_s;	/* send state */
			uint16_t v_a;	/* ack state */
			char v_b[RLC_MAX_SNS/2]; /* acknowledge state array */
		} dl;
		struct {
			uint16_t v_r;	/* receive state */
			uint16_t v_q;	/* receive window state */
			char v_n[RLC_MAX_SNS/2]; /* receive state array */
			int32_t rx_counter; /* count all received blocks */
			enum gprs_rlcmac_tbf_ul_substate substate;
			uint8_t usf;	/* USF */
			uint8_t n3103;	/* N3103 counter */
		} ul;
	} dir;
	uint8_t rlc_block[RLC_MAX_SNS/2][RLC_MAX_LEN]; /* block history */
	uint8_t rlc_block_len[RLC_MAX_SNS/2]; /* block len  of history */
	
	struct osmo_timer_list	timer;
	unsigned int T; /* Txxxx number */
	unsigned int num_T_exp; /* number of consecutive T expirations */
	
	struct osmo_gsm_timer_list	gsm_timer;
	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */
};

extern struct llist_head gprs_rlcmac_tbfs;

int tfi_alloc(uint8_t *_trx, uint8_t *_ts);

struct gprs_rlcmac_tbf *tbf_alloc(uint8_t tfi, uint8_t trx, uint8_t ts);

struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi);

struct gprs_rlcmac_tbf *tbf_by_tlli(uint8_t tlli);

void tbf_free(struct gprs_rlcmac_tbf *tbf);

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
                                unsigned int seconds);

void tbf_timer_stop(struct gprs_rlcmac_tbf *tbf);

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1, 
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

void gprs_rlcmac_tx_ul_ack(uint8_t tfi, uint32_t tlli, RlcMacUplinkDataBlock_t * ul_data_block);

void gprs_rlcmac_data_block_parse(gprs_rlcmac_tbf* tbf, RlcMacUplinkDataBlock_t * ul_data_block);

int gprs_rlcmac_rcv_data_block(bitvec *rlc_block);

int gprs_rlcmac_rcv_control_block(bitvec *rlc_block);

int gprs_rlcmac_rcv_block(uint8_t *data, uint8_t len, uint32_t fn);

int gprs_rlcmac_rcv_rts_block(uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta);

void gprs_rlcmac_tx_dl_data_block(uint32_t tlli, uint8_t tfi, uint8_t *pdu, int start_index, int end_index, uint8_t bsn, uint8_t fbi);

int gprs_rlcmac_segment_llc_pdu(struct gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_downlink_assignment(gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_packet_downlink_assignment(gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_enqueue_block(bitvec *block, int len);

int gprs_rlcmac_rcv_data_block_acknowledged(uint8_t *data, uint8_t len);

struct msgb *gprs_rlcmac_send_uplink_ack(struct gprs_rlcmac_tbf *tbf,
        uint32_t fn);

#endif // GPRS_RLCMAC_H
