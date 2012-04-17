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

#include <BitVector.h>
#include <gsm_rlcmac.h>
#include <gsm_timer.h>

extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
}

enum gprs_rlcmac_tbf_state {
	GPRS_RLCMAC_WAIT_DATA_SEQ_START,
	GPRS_RLCMAC_WAIT_NEXT_DATA_BLOCK,
	GPRS_RLCMAC_WAIT_NEXT_DATA_SEQ
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
	uint8_t rlc_data[60];
	uint16_t data_index;
	uint8_t bsn;
	
	struct osmo_timer_list	timer;
	unsigned int T; /* Txxxx number */
	unsigned int num_T_exp; /* number of consecutive T expirations */
	
	struct osmo_gsm_timer_list	gsm_timer;
	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */
};

extern struct llist_head gprs_rlcmac_tbfs;

int tfi_alloc();

struct gprs_rlcmac_tbf *tbf_alloc(uint8_t tfi);

static struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi);

static struct gprs_rlcmac_tbf *tbf_by_tlli(uint8_t tlli);

static void tbf_free(struct gprs_rlcmac_tbf *tbf);

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1, 
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

void gprs_rlcmac_tx_ul_ack(uint8_t tfi, uint32_t tlli, RlcMacUplinkDataBlock_t * ul_data_block);

void gprs_rlcmac_data_block_parse(gprs_rlcmac_tbf* tbf, RlcMacUplinkDataBlock_t * ul_data_block);

int gprs_rlcmac_rcv_data_block(BitVector *rlc_block);

int gprs_rlcmac_rcv_control_block(BitVector *rlc_block);

void gprs_rlcmac_rcv_block(BitVector *rlc_block);

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, uint16_t ta);

void gprs_rlcmac_tx_dl_data_block(uint32_t tlli, uint8_t tfi, uint8_t *pdu, int start_index, int end_index, uint8_t bsn, uint8_t fbi);

int gprs_rlcmac_segment_llc_pdu(struct gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

void gprs_rlcmac_downlink_assignment(gprs_rlcmac_tbf *tbf);

#endif // GPRS_RLCMAC_H
