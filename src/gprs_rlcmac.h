/* gprs_rlcmac.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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
 
#ifndef GPRS_RLCMAC_H
#define GPRS_RLCMAC_H

#ifdef __cplusplus
#include <bitvector.h>
#include <gsm_rlcmac.h>
#include <gsm_timer.h>

extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
}
#endif

/* generate a diagram for debugging timing issues */
//#define DEBUG_DIAGRAM

/* This special feature will delay assignment of downlink TBF by one second,
 * in case there is already a TBF.
 * This is usefull to debug downlink establishment during packet idle mode.
 */
//#define DEBUG_DL_ASS_IDLE

/*
 * PDCH instanc
 */

struct gprs_rlcmac_tbf;

struct gprs_rlcmac_pdch {
	uint8_t enable; /* TS is enabled */
	uint8_t tsc; /* TSC of this slot */
	uint8_t next_ul_tfi; /* next uplink TBF/TFI to schedule (0..31) */
	uint8_t next_dl_tfi; /* next downlink TBF/TFI to schedule (0..31) */
	struct gprs_rlcmac_tbf *ul_tbf[32]; /* array of UL TBF, by UL TFI */
	struct gprs_rlcmac_tbf *dl_tbf[32]; /* array of DL TBF, by DL TFI */
	struct llist_head paging_list; /* list of paging messages */
	uint32_t last_rts_fn; /* store last frame number of RTS */
};

struct gprs_rlcmac_trx {
	void *fl1h;
	uint16_t arfcn;
	struct gprs_rlcmac_pdch pdch[8];
	struct gprs_rlcmac_tbf *ul_tbf[32]; /* array of UL TBF, by UL TFI */
	struct gprs_rlcmac_tbf *dl_tbf[32]; /* array of DL TBF, by DL TFI */
};

struct gprs_rlcmac_bts {
	uint8_t bsic;
	uint8_t fc_interval;
	uint8_t cs1;
	uint8_t cs2;
	uint8_t cs3;
	uint8_t cs4;
	uint8_t initial_cs_dl, initial_cs_ul;
	uint8_t force_cs;	/* 0=use from BTS 1=use from VTY */
	uint16_t force_llc_lifetime; /* overrides lifetime from SGSN */
	uint8_t t3142;
	uint8_t t3169;
	uint8_t t3191;
	uint16_t t3193_msec;
	uint8_t t3195;
	uint8_t n3101;
	uint8_t n3103;
	uint8_t n3105;
	struct gprs_rlcmac_trx trx[8];
	int (*alloc_algorithm)(struct gprs_rlcmac_bts *bts,
		struct gprs_rlcmac_tbf *old_tbf,
		struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);
	uint32_t alloc_algorithm_curst; /* options to customize algorithm */
	uint8_t force_two_phase;
	uint8_t alpha, gamma;
};

extern struct gprs_rlcmac_bts *gprs_rlcmac_bts;

#ifdef __cplusplus
/*
 * paging entry
 */
struct gprs_rlcmac_paging {
	struct llist_head list;
	uint8_t chan_needed;
	uint8_t identity_lv[9];
};

/*
 * single block allocation entry
 */
struct gprs_rlcmac_sba {
	struct llist_head list;
	uint8_t trx;
	uint8_t ts;
	uint32_t fn;
	uint8_t ta;
};

/*
 * coding scheme info
 */
struct gprs_rlcmac_cs {
	uint8_t	block_length;
	uint8_t block_data;
	uint8_t block_payload;
};

extern struct gprs_rlcmac_cs gprs_rlcmac_cs[];

#ifdef DEBUG_DIAGRAM
void debug_diagram(int diag, const char *format, ...);
#else
#define debug_diagram(a, b, args...) ;
#endif

int gprs_rlcmac_received_lost(struct gprs_rlcmac_tbf *tbf, uint16_t received,
	uint16_t lost);

int gprs_rlcmac_lost_rep(struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_meas_rep(Packet_Measurement_Report_t *pmr);

int gprs_rlcmac_rssi(struct gprs_rlcmac_tbf *tbf, int8_t rssi);

int gprs_rlcmac_rssi_rep(struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_dl_bw(struct gprs_rlcmac_tbf *tbf, uint16_t octets);

int sba_alloc(struct gprs_rlcmac_bts *bts, uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta);

struct gprs_rlcmac_sba *sba_find(uint8_t trx, uint8_t ts, uint32_t fn);

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1, 
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

int gprs_rlcmac_rcv_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts, uint8_t *data, uint8_t len,
	uint32_t fn, int8_t rssi);

int write_immediate_assignment(
	struct gprs_rlcmac_bts *bts,
	bitvec * dest, uint8_t downlink, uint8_t ra, 
        uint32_t ref_fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, 
        uint8_t tfi, uint8_t usf, uint32_t tlli, uint8_t polling,
	uint32_t fn, uint8_t single_block, uint8_t alpha, uint8_t gamma,
	int8_t ta_idx);

void write_packet_uplink_assignment(
	struct gprs_rlcmac_bts *bts,
	bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli, 
	struct gprs_rlcmac_tbf *tbf, uint8_t poll, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx);

void write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t old_tfi,
	uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx, uint8_t ta_ts);



void write_packet_uplink_ack(struct gprs_rlcmac_bts *bts, RlcMacDownlink_t * block, struct gprs_rlcmac_tbf *tbf,
        uint8_t final);

int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_poll_timeout(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_sba_timeout(struct gprs_rlcmac_sba *sba);

int gprs_rlcmac_rcv_rach(struct gprs_rlcmac_bts *bts, uint8_t ra, uint32_t Fn, int16_t qta);

int gprs_rlcmac_rcv_control_block(struct gprs_rlcmac_bts *bts,
	bitvec *rlc_block, uint8_t trx, uint8_t ts,
	uint32_t fn);

struct msgb *gprs_rlcmac_send_packet_uplink_assignment(
	struct gprs_rlcmac_bts *bts,
        struct gprs_rlcmac_tbf *tbf, uint32_t fn);

struct msgb *gprs_rlcmac_send_packet_downlink_assignment(
	struct gprs_rlcmac_bts *bts,
        struct gprs_rlcmac_tbf *tbf, uint32_t fn);

void gprs_rlcmac_trigger_downlink_assignment(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *tbf,
        struct gprs_rlcmac_tbf *old_tbf, const char *imsi);

int gprs_rlcmac_downlink_ack(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *tbf, uint8_t final,
        uint8_t ssn, uint8_t *rbb);

int gprs_rlcmac_paging_request(uint8_t *ptmsi, uint16_t ptmsi_len,
	const char *imsi);

unsigned write_packet_paging_request(bitvec * dest);

unsigned write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
	uint8_t *identity, uint8_t chan_needed);

int gprs_rlcmac_rcv_data_block_acknowledged(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts,
	uint8_t *data, uint8_t len, int8_t rssi);

struct msgb *gprs_rlcmac_send_data_block_acknowledged(
	struct gprs_rlcmac_bts *bts,
        struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts);

struct msgb *gprs_rlcmac_send_uplink_ack(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *tbf,
        uint32_t fn);

int gprs_rlcmac_rcv_rts_block(uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);

int gprs_rlcmac_imm_ass_cnf(uint8_t *data, uint32_t fn);

int gprs_rlcmac_add_paging(uint8_t chan_needed, uint8_t *identity_lv);

struct gprs_rlcmac_paging *gprs_rlcmac_dequeue_paging(
	struct gprs_rlcmac_pdch *pdch);

struct msgb *gprs_rlcmac_send_packet_paging_request(
	struct gprs_rlcmac_pdch *pdch);

int remember_timing_advance(uint32_t tlli, uint8_t ta);

int recall_timing_advance(uint32_t tlli);

int flush_timing_advance(void);

extern "C" {
#endif
int alloc_algorithm_a(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);

int alloc_algorithm_b(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);
#ifdef __cplusplus
}
#endif

#endif // GPRS_RLCMAC_H
