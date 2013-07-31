/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef OPENBSC_CLONE_H
#define OPENBSC_CLONE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <stdint.h>

enum gprs_llc_cmd {
	GPRS_LLC_NULL,
	GPRS_LLC_RR,
	GPRS_LLC_ACK,
	GPRS_LLC_RNR,
	GPRS_LLC_SACK,
	GPRS_LLC_DM,
	GPRS_LLC_DISC,
	GPRS_LLC_UA,
	GPRS_LLC_SABM,
	GPRS_LLC_FRMR,
	GPRS_LLC_XID,
	GPRS_LLC_UI,
};

struct gprs_llc_hdr_parsed {
	uint8_t sapi;
	uint8_t is_cmd:1,
		 ack_req:1,
		 is_encrypted:1;
	uint32_t seq_rx;
	uint32_t seq_tx;
	uint32_t fcs;
	uint32_t fcs_calc;
	const uint8_t *data;
	uint16_t data_len;
	uint16_t crc_length;
	enum gprs_llc_cmd cmd;
};

int gprs_llc_hdr_parse(struct gprs_llc_hdr_parsed *ghp, const uint8_t *llc_hdr, int len);

/* Table 10.4 / 10.4a, GPRS Mobility Management (GMM) */
#define GSM48_MT_GMM_ATTACH_ACK		0x02

/* Chapter 9.4.2 / Table 9.4.2 */
struct gsm48_attach_ack {
	uint8_t att_result:4,	/* 10.5.5.7 */
		 force_stby:4;	/* 10.5.5.1 */
	uint8_t ra_upd_timer;	/* 10.5.7.3 */
	uint8_t radio_prio;	/* 10.5.7.2 */
	struct gsm48_ra_id ra_id; /* 10.5.5.15 */
	uint8_t data[0];
} __attribute__((packed));

enum gsm48_gprs_ie_mm {
	GSM48_IE_GMM_CIPH_CKSN		= 0x08, /* 10.5.1.2 */
	GSM48_IE_GMM_TIMER_READY	= 0x17,	/* 10.5.7.3 */
	GSM48_IE_GMM_ALLOC_PTMSI	= 0x18,	/* 10.5.1.4 */
	GSM48_IE_GMM_PTMSI_SIG		= 0x19,	/* 10.5.5.8 */
	GSM48_IE_GMM_AUTH_RAND		= 0x21,	/* 10.5.3.1 */
	GSM48_IE_GMM_AUTH_SRES		= 0x22,	/* 10.5.3.2 */
	GSM48_IE_GMM_IMEISV		= 0x23,	/* 10.5.1.4 */
	GSM48_IE_GMM_DRX_PARAM		= 0x27,	/* 10.5.5.6 */
	GSM48_IE_GMM_MS_NET_CAPA	= 0x31,	/* 10.5.5.12 */
	GSM48_IE_GMM_PDP_CTX_STATUS	= 0x32,	/* 10.5.7.1 */
	GSM48_IE_GMM_PS_LCS_CAPA	= 0x33,	/* 10.5.5.22 */
	GSM48_IE_GMM_GMM_MBMS_CTX_ST	= 0x35,	/* 10.5.7.6 */
};

extern const struct tlv_definition gsm48_gmm_att_tlvdef;

#ifdef __cplusplus
}
#endif

#endif
