/* pcu_l1_if.h
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
 */

#ifndef PCU_L1_IF_H
#define PCU_L1_IF_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/core/write_queue.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/pcu/pcuif_proto.h>
#ifdef __cplusplus
}
#endif

#include "pdch.h"

static inline uint8_t qta2ta(int16_t qta)
{
	if (qta < 0)
		return 0;
	if (qta > 252)
		qta = 252;
	return qta >> 2;
}

static inline int8_t sign_qta2ta(int16_t qta)
{
	int8_t ta_adj = 0;

	if (qta < -252)
		qta = -252;

	if (qta > 252)
		qta = 252;

	/* 1-bit TA adjustment  if TA error reported by L1 is outside +/- 2 qbits */
	if (qta > 2)
		ta_adj = 1;
	if (qta < -2)
		ta_adj = -1;

	return (qta >> 2) + ta_adj;
}

static inline uint8_t ta_limit(int16_t ta)
{
	if (ta < 0)
		ta = 0;
	if (ta > 63)
		ta = 63;
	return ta;
}

/*
 * L1 Measurement values
 */

struct pcu_l1_meas_ts {
	unsigned have_ms_i_level:1;

	int16_t ms_i_level; /* I_LEVEL in dB */
};

static inline void pcu_l1_meas_ts_set_ms_i_level(struct pcu_l1_meas_ts* ts, int16_t v) {
	ts->ms_i_level = v;
	ts->have_ms_i_level = 1;
}

struct pcu_l1_meas {
	unsigned have_rssi:1;
	unsigned have_ber:1;
	unsigned have_bto:1;
	unsigned have_link_qual:1;
	unsigned have_ms_rx_qual:1;
	unsigned have_ms_c_value:1;
	unsigned have_ms_sign_var:1;
	unsigned have_ms_i_level:1;

	int8_t rssi; /* RSSI in dBm */
	uint8_t ber; /* Bit error rate in % */
	int16_t bto; /* Burst timing offset in quarter bits */
	int16_t link_qual; /* Link quality in dB */
	int16_t ms_rx_qual; /* MS RXQUAL value in % */
	int16_t ms_c_value; /* C value in dB */
	int16_t ms_sign_var; /* SIGN_VAR in dB */

	struct pcu_l1_meas_ts ts[8];
};

static inline void pcu_l1_meas_set_rssi(struct pcu_l1_meas *m, int8_t v) {
	m->rssi = v;
	m->have_rssi = 1;
}
static inline void pcu_l1_meas_set_ber(struct pcu_l1_meas *m, uint8_t v) {
	m->ber = v;
	m->have_ber = 1;
}
static inline void pcu_l1_meas_set_bto(struct pcu_l1_meas *m, int16_t v) {
	m->bto = v;
	m->have_bto = 1;
}
static inline void pcu_l1_meas_set_link_qual(struct pcu_l1_meas *m, int16_t v) {
	m->link_qual = v;
	m->have_link_qual = 1;
}
static inline void pcu_l1_meas_set_ms_rx_qual(struct pcu_l1_meas *m, int16_t v) {
	m->ms_rx_qual = v;
	m->have_ms_rx_qual = 1;
}
static inline void pcu_l1_meas_set_ms_c_value(struct pcu_l1_meas *m, int16_t v) {
	m->ms_c_value = v;
	m->have_ms_c_value = 1;
}
static inline void pcu_l1_meas_set_ms_sign_var(struct pcu_l1_meas *m, int16_t v) {
	m->ms_sign_var = v;
	m->have_ms_sign_var = 1;
}
static inline void pcu_l1_meas_set_ms_i_level(struct pcu_l1_meas *m, size_t idx, int16_t v) {
	pcu_l1_meas_ts_set_ms_i_level(&m->ts[idx], v);
	m->have_ms_i_level = 1;
}

#ifdef __cplusplus
struct gprs_rlcmac_bts;
void pcu_l1if_tx_pdtch(msgb *msg, struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
		       uint16_t arfcn, uint32_t fn, uint8_t block_nr);
void pcu_l1if_tx_ptcch(struct gprs_rlcmac_bts *bts,
		       uint8_t trx, uint8_t ts, uint16_t arfcn,
		       uint32_t fn, uint8_t block_nr,
		       uint8_t *data, size_t data_len);
void pcu_l1if_tx_agch(struct gprs_rlcmac_bts *bts, bitvec *block, int len);
#endif

#ifdef __cplusplus
extern "C" {
#endif
struct gprs_rlcmac_bts;

int pcu_tx_neigh_addr_res_req(struct gprs_rlcmac_bts *bts, const struct neigh_cache_entry_key *neigh_key);
void pcu_l1if_tx_pch(struct gprs_rlcmac_bts *bts, struct bitvec *block, int plen, const char *imsi);
void pcu_l1if_tx_pch2(struct gprs_rlcmac_bts *bts, struct bitvec *block, int plen, const char *imsi, uint32_t msg_id);

int pcu_rx(struct gsm_pcu_if *pcu_prim, size_t pcu_prim_length);
int pcu_l1if_open(void);
void pcu_l1if_close(void);
int pcu_sock_send(struct msgb *msg);

int pcu_tx_txt_ind(enum gsm_pcu_if_text_type t, const char *fmt, ...);

int pcu_rx_rts_req_pdtch(struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr);
int pcu_rx_rts_req_ptcch(struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr);

int pcu_rx_rach_ind_ptcch(struct gprs_rlcmac_bts *bts, uint8_t trx_nr, uint8_t ts_nr, uint32_t fn, int16_t qta);
int pcu_rx_data_ind_pdtch(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_pdch *pdch, uint8_t *data,
	uint8_t len, uint32_t fn, struct pcu_l1_meas *meas);

void pcu_rx_block_time(struct gprs_rlcmac_bts *bts, uint16_t arfcn, uint32_t fn, uint8_t ts_no);

struct e1_conn_pars {
	/* Number of E1 line */
	uint8_t e1_nr;
	/* Number of E1 timeslot */
	uint8_t e1_ts;
	/* Number of I.460 subslot inside E1 timeslot */
	uint8_t e1_ts_ss;
};

int pcu_l1if_get_e1_ccu_conn_pars(struct e1_conn_pars **e1_conn_pars, uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr);

#define PCUIF_HDR_SIZE ( sizeof(struct gsm_pcu_if) - sizeof(((struct gsm_pcu_if *)0)->u) )

#ifdef __cplusplus
}
#endif
#endif // PCU_L1_IF_H
