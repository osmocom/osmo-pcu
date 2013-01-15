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
	int (*alloc_algorithm)(struct gprs_rlcmac_tbf *old_tbf,
		struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);
	uint32_t alloc_algorithm_curst; /* options to customize algorithm */
	uint8_t force_two_phase;
	uint8_t alpha, gamma;
};

extern struct gprs_rlcmac_bts *gprs_rlcmac_bts;

#ifdef __cplusplus
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

	struct timeval bw_tv; /* timestamp for bandwidth calculation */
	uint32_t bw_octets; /* number of octets transmitted since bw_tv */

	uint8_t cs; /* current coding scheme */

#ifdef DEBUG_DIAGRAM
	int diag; /* number where TBF is presented in diagram */
	int diag_new; /* used to format output of new TBF */
#endif
};

extern struct llist_head gprs_rlcmac_ul_tbfs; /* list of uplink TBFs */
extern struct llist_head gprs_rlcmac_dl_tbfs; /* list of downlink TBFs */
extern struct llist_head gprs_rlcmac_sbas; /* list of single block allocs */

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

int sba_alloc(uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta);

struct gprs_rlcmac_sba *sba_find(uint8_t trx, uint8_t ts, uint32_t fn);

int tfi_alloc(enum gprs_rlcmac_tbf_direction dir, uint8_t *_trx,
	int8_t use_trx);

struct gprs_rlcmac_tbf *tbf_alloc(struct gprs_rlcmac_tbf *old_tbf,
	enum gprs_rlcmac_tbf_direction dir, uint8_t tfi, uint8_t trx,
	uint8_t ms_class, uint8_t single_slot);

struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi, uint8_t trx,
        enum gprs_rlcmac_tbf_direction dir);

struct gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli,
	enum gprs_rlcmac_tbf_direction dir);

struct gprs_rlcmac_tbf *tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts);

void tbf_free(struct gprs_rlcmac_tbf *tbf);

int tbf_update(struct gprs_rlcmac_tbf *tbf);

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf);

void tbf_new_state(struct gprs_rlcmac_tbf *tbf,
        enum gprs_rlcmac_tbf_state state);

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
                        unsigned int seconds, unsigned int microseconds);

void tbf_timer_stop(struct gprs_rlcmac_tbf *tbf);

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1, 
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

int gprs_rlcmac_rcv_block(uint8_t trx, uint8_t ts, uint8_t *data, uint8_t len,
	uint32_t fn);

int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra, 
        uint32_t ref_fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, 
        uint8_t tfi, uint8_t usf, uint32_t tlli, uint8_t polling,
	uint32_t fn, uint8_t single_block, uint8_t alpha, uint8_t gamma,
	int8_t ta_idx);

void write_packet_uplink_assignment(bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli, 
	struct gprs_rlcmac_tbf *tbf, uint8_t poll, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx);

void write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t old_tfi,
	uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx, uint8_t ta_ts);



void write_packet_uplink_ack(RlcMacDownlink_t * block, struct gprs_rlcmac_tbf *tbf,
        uint8_t final);

int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

void tbf_timer_cb(void *_tbf);

int gprs_rlcmac_poll_timeout(struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta);

int gprs_rlcmac_rcv_control_block(bitvec *rlc_block, uint8_t trx, uint8_t ts,
	uint32_t fn);

struct msgb *gprs_rlcmac_send_packet_uplink_assignment(
        struct gprs_rlcmac_tbf *tbf, uint32_t fn);

struct msgb *gprs_rlcmac_send_packet_downlink_assignment(
        struct gprs_rlcmac_tbf *tbf, uint32_t fn);

void gprs_rlcmac_trigger_downlink_assignment(struct gprs_rlcmac_tbf *tbf,
        struct gprs_rlcmac_tbf *old_tbf, char *imsi);

int gprs_rlcmac_downlink_ack(struct gprs_rlcmac_tbf *tbf, uint8_t final,
        uint8_t ssn, uint8_t *rbb);

int gprs_rlcmac_paging_request(uint8_t *ptmsi, uint16_t ptmsi_len,
	const char *imsi);

unsigned write_packet_paging_request(bitvec * dest);

unsigned write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
	uint8_t *identity, uint8_t chan_needed);

int gprs_rlcmac_rcv_data_block_acknowledged(uint8_t trx, uint8_t ts,
	uint8_t *data, uint8_t len);

struct msgb *gprs_rlcmac_send_data_block_acknowledged(
        struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts);

struct msgb *gprs_rlcmac_send_uplink_ack(struct gprs_rlcmac_tbf *tbf,
        uint32_t fn);

int gprs_rlcmac_rcv_rts_block(uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);

int gprs_rlcmac_imm_ass_cnf(uint8_t *data, uint32_t fn);

int gprs_rlcmac_add_paging(uint8_t chan_needed, uint8_t *identity_lv);

struct gprs_rlcmac_paging *gprs_rlcmac_dequeue_paging(
	struct gprs_rlcmac_pdch *pdch);

struct msgb *gprs_rlcmac_send_packet_paging_request(
	struct gprs_rlcmac_pdch *pdch);

extern "C" {
#endif
int alloc_algorithm_a(struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);

int alloc_algorithm_b(struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);
#ifdef __cplusplus
}
#endif

#endif // GPRS_RLCMAC_H
