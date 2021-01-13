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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
void pcu_l1if_tx_pdtch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn,
        uint32_t fn, uint8_t block_nr);
void pcu_l1if_tx_ptcch(struct gprs_rlcmac_bts *bts,
		       uint8_t trx, uint8_t ts, uint16_t arfcn,
		       uint32_t fn, uint8_t block_nr,
		       uint8_t *data, size_t data_len);
void pcu_l1if_tx_agch(bitvec * block, int len);

void pcu_l1if_tx_pch(bitvec * block, int plen, uint16_t pgroup);

int pcu_tx_txt_ind(enum gsm_pcu_if_text_type t, const char *fmt, ...);

int pcu_l1if_open(void);
void pcu_l1if_close(void);

int pcu_rx(uint8_t msg_type, struct gsm_pcu_if *pcu_prim);
int pcu_sock_send(struct msgb *msg);
#endif

#ifdef __cplusplus
extern "C" {
#endif
int pcu_rx_rts_req_pdtch(uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr);
int pcu_rx_rts_req_ptcch(uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr);

int pcu_rx_rach_ind_ptcch(uint8_t trx_nr, uint8_t ts_nr, uint32_t fn, int16_t qta);
int pcu_rx_data_ind_pdtch(uint8_t trx, uint8_t ts, uint8_t *data,
	uint8_t len, uint32_t fn, struct pcu_l1_meas *meas);

void pcu_rx_block_time(uint16_t arfcn, uint32_t fn, uint8_t ts_no);
void pcu_rx_ra_time(uint16_t arfcn, uint32_t fn, uint8_t ts_no);
uint16_t imsi2paging_group(const char* imsi);
#ifdef __cplusplus
}
#endif
#endif // PCU_L1_IF_H
