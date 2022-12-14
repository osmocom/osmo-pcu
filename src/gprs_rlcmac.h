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
 */

#ifndef GPRS_RLCMAC_H
#define GPRS_RLCMAC_H

#include <stdbool.h>
#include <stdint.h>

#include <pcu_l1_if.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/pcu/pcuif_proto.h>
#include "gsm_rlcmac.h"
#ifdef __cplusplus
}
#endif

/* This special feature will delay assignment of downlink TBF by one second,
 * in case there is already a TBF.
 * This is usefull to debug downlink establishment during packet idle mode.
 */
//#define DEBUG_DL_ASS_IDLE

#define DUMMY_VEC "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"

struct gprs_rlcmac_tbf;
struct gprs_rlcmac_bts;
struct GprsMs;

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
 * coding scheme info
 */
struct gprs_rlcmac_cs {
	uint8_t	block_length;
	uint8_t block_data;
	uint8_t block_payload;
};

/* TS allocation internal functions */
int find_multi_slots(struct gprs_rlcmac_trx *trx, uint8_t mslot_class, uint8_t *ul_slots, uint8_t *dl_slots);

int gprs_rlcmac_received_lost(struct gprs_rlcmac_dl_tbf *tbf, uint16_t received,
	uint16_t lost);

int gprs_rlcmac_lost_rep(struct gprs_rlcmac_dl_tbf *tbf);

int gprs_rlcmac_meas_rep(GprsMs *ms, Packet_Measurement_Report_t *pmr);

int gprs_rlcmac_rssi(struct gprs_rlcmac_tbf *tbf, int8_t rssi);

int gprs_rlcmac_rssi_rep(struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_dl_bw(struct gprs_rlcmac_dl_tbf *tbf, uint16_t octets);

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1,
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

struct msgb *gprs_rlcmac_app_info_msg(const struct gsm_pcu_if_app_info_req *req);

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts,
        uint32_t fn, uint8_t block_nr);

extern "C" {
#endif
int gprs_rlcmac_paging_request(struct gprs_rlcmac_bts *bts, const struct osmo_mobile_identity *mi, uint16_t pgroup);
#ifdef __cplusplus
}
#endif


#endif // GPRS_RLCMAC_H
