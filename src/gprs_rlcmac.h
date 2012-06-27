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

#define LLC_MAX_LEN 1543
#define UL_RLC_DATA_BLOCK_LEN 23

enum gprs_rlcmac_tbf_stage {
	TBF_ESTABLISH,
	TBF_DATA_TRANSFER,
	TBF_RELEASE
};

enum gprs_rlcmac_tbf_state {
	WAIT_ESTABLISH,
	CCCH_ESTABLISH,
	PACCH_ESTABLISH,
	FINISH_ESTABLISH,
	WAIT_DATA_TRANSFER,
	DATA_TRANSFER,
	FINISH_DATA_TRANSFER,
	RELEASE
};

enum gprs_rlcmac_tbf_direction {
	GPRS_RLCMAC_DL_TBF,
	GPRS_RLCMAC_UL_TBF
};

struct tbf_llc_pdu {
	struct llist_head list;
	uint8_t num;
	uint8_t data[LLC_MAX_LEN];
	uint16_t len;
};

struct gprs_rlcmac_tbf {
	struct llist_head list;
	enum gprs_rlcmac_tbf_state state;
	enum gprs_rlcmac_tbf_stage stage;
	enum gprs_rlcmac_tbf_direction direction;
	struct gprs_rlcmac_tbf *next_tbf;
	uint8_t tfi;
	uint32_t tlli;
	
	struct llist_head llc_pdus;
	struct tbf_llc_pdu llc_pdu;
	uint8_t llc_pdu_list_len;
	uint8_t rlc_data[LLC_MAX_LEN];
	uint16_t data_index;
	uint8_t bsn;
	uint8_t trx, ts, tsc;
	uint16_t arfcn, ta;
	
	struct osmo_timer_list	timer;
	unsigned int T; /* Txxxx number */
	unsigned int num_T_exp; /* number of consecutive T expirations */
	
	struct osmo_gsm_timer_list	gsm_timer;
	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */
};

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1, 
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

extern struct llist_head gprs_rlcmac_tbfs;

int select_pdch(uint8_t *_trx, uint8_t *_ts);

int tfi_alloc();

static struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi, gprs_rlcmac_tbf_direction dir);

static struct gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli, gprs_rlcmac_tbf_direction dir);

static void tbf_free(struct gprs_rlcmac_tbf *tbf);

static struct tbf_llc_pdu *tbf_llc_pdu_by_num(struct llist_head llc_pdus, uint8_t num);

int tbf_add_llc_pdu(struct gprs_rlcmac_tbf *tbf, uint8_t *data, uint16_t llc_pdu_len);

struct gprs_rlcmac_tbf *tbf_alloc(gprs_rlcmac_tbf_direction dir, uint32_t tlli = 0);

int tbf_ul_establish(struct gprs_rlcmac_tbf *tbf, uint8_t ra, uint32_t Fn, uint16_t qta);

int tbf_dl_establish(struct gprs_rlcmac_tbf *tbf, uint8_t *imsi = NULL);

int tbf_ul_data_transfer(struct gprs_rlcmac_tbf *tbf, RlcMacUplinkDataBlock_t * ul_data_block);

int tbf_dl_data_transfer(struct gprs_rlcmac_tbf *tbf, uint8_t *llc_pdu = NULL, uint16_t llc_pdu_len = 0);

int tbf_ul_release(struct gprs_rlcmac_tbf *tbf);

int tbf_dl_release(struct gprs_rlcmac_tbf *tbf);

static void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T, unsigned int seconds);

static void tbf_gsm_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int fT, int frames);

int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra, uint32_t fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, uint8_t tfi, uint32_t tlli = 0);

void gprs_rlcmac_tx_ul_ack(uint8_t tfi, uint32_t tlli, uint8_t ti, uint8_t bsn);

void gprs_rlcmac_data_block_parse(gprs_rlcmac_tbf* tbf, RlcMacUplinkDataBlock_t * ul_data_block);

int gprs_rlcmac_rcv_data_block(bitvec *rlc_block);

int gprs_rlcmac_rcv_control_block(bitvec *rlc_block);

void gprs_rlcmac_rcv_block(bitvec *rlc_block);

void gprs_rlcmac_rcv_rts_block(uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta);

int gprs_rlcmac_tx_llc_pdus(struct gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_downlink_assignment(gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_packet_downlink_assignment(gprs_rlcmac_tbf *tbf);

#endif // GPRS_RLCMAC_H
