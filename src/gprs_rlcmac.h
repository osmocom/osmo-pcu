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


struct gprs_rlcmac_tbf;
struct gprs_rlcmac_bts;
struct BTS;

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

#ifdef DEBUG_DIAGRAM
void debug_diagram(BTS *bts, int diag, const char *format, ...);
#else
#define debug_diagram(a, b, c, args...) ;
#endif

int gprs_rlcmac_received_lost(struct gprs_rlcmac_tbf *tbf, uint16_t received,
	uint16_t lost);

int gprs_rlcmac_lost_rep(struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_meas_rep(Packet_Measurement_Report_t *pmr);

int gprs_rlcmac_rssi(struct gprs_rlcmac_tbf *tbf, int8_t rssi);

int gprs_rlcmac_rssi_rep(struct gprs_rlcmac_tbf *tbf);

int gprs_rlcmac_dl_bw(struct gprs_rlcmac_tbf *tbf, uint16_t octets);

/* TS 44.060 Section 10.4.7 Table 10.4.7.1: Payload Type field */
enum gprs_rlcmac_block_type {
	GPRS_RLCMAC_DATA_BLOCK = 0x0,
	GPRS_RLCMAC_CONTROL_BLOCK = 0x1, 
	GPRS_RLCMAC_CONTROL_BLOCK_OPT = 0x2,
	GPRS_RLCMAC_RESERVED = 0x3
};

int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf);

struct msgb *gprs_rlcmac_send_packet_uplink_assignment(
        struct gprs_rlcmac_tbf *tbf, uint32_t fn);

int gprs_rlcmac_downlink_ack(
	struct gprs_rlcmac_tbf *tbf, uint8_t final,
        uint8_t ssn, uint8_t *rbb);

int gprs_rlcmac_paging_request(uint8_t *ptmsi, uint16_t ptmsi_len,
	const char *imsi);

struct msgb *gprs_rlcmac_send_data_block_acknowledged(
        struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts);

struct msgb *gprs_rlcmac_send_uplink_ack(
	struct gprs_rlcmac_tbf *tbf,
        uint32_t fn);

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);

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
