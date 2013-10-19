/* gprs_rlcmac.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
 
#include <gprs_bssgp_pcu.h>
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <bts.h>
#include <encoding.h>
#include <tbf.h>


struct gprs_rlcmac_cs gprs_rlcmac_cs[] = {
/*	frame length	data block	max payload */
	{ 0,		0,		0  },
	{ 23,		23,		20 }, /* CS-1 */
	{ 34,		33,		30 }, /* CS-2 */
	{ 40,		39,		36 }, /* CS-3 */
	{ 54,		53,		50 }, /* CS-4 */
};

LLIST_HEAD(gprs_rlcmac_ul_tbfs);
LLIST_HEAD(gprs_rlcmac_dl_tbfs);
extern void *tall_pcu_ctx;

#ifdef DEBUG_DIAGRAM
struct timeval diagram_time = {0,0};
struct timeval diagram_last_tv = {0,0};

void debug_diagram(int diag, const char *format, ...)
{
	va_list ap;
	char debug[128];
	char line[1024];
	struct gprs_rlcmac_tbf *tbf, *tbf_a[16];
	int max_diag = -1, i;
	uint64_t diff = 0;

	va_start(ap, format);
	vsnprintf(debug, sizeof(debug) - 1, format, ap);
	debug[19] = ' ';
	debug[20] = '\0';
	va_end(ap);

	memset(tbf_a, 0, sizeof(tbf_a));
	llist_for_each_entry(tbf, &gprs_rlcmac_ul_tbfs, list) {
		if (tbf->diag < 16) {
			if (tbf->diag > max_diag)
				max_diag = tbf->diag;
			tbf_a[tbf->diag] = tbf;
		}
	}
	llist_for_each_entry(tbf, &gprs_rlcmac_dl_tbfs, list) {
		if (tbf->diag < 16) {
			if (tbf->diag > max_diag)
				max_diag = tbf->diag;
			tbf_a[tbf->diag] = tbf;
		}
	}

	if (diagram_last_tv.tv_sec) {
		diff = (uint64_t)(diagram_time.tv_sec -
					diagram_last_tv.tv_sec) * 1000;
		diff += diagram_time.tv_usec / 1000;
		diff -= diagram_last_tv.tv_usec / 1000;
	}
	memcpy(&diagram_last_tv, &diagram_time, sizeof(struct timeval));

	if (diff > 0) {
		if (diff > 99999)
			strcpy(line, "  ...  : ");
		else
			sprintf(line, "%3d.%03d: ", (int)(diff / 1000),
				(int)(diff % 1000));
		for (i = 0; i <= max_diag; i++) {
			if (tbf_a[i] == NULL) {
				strcat(line, "                    ");
				continue;
			}
			if (tbf_a[i]->diag_new) {
				strcat(line, "         |          ");
				continue;
			}
			strcat(line, "                    ");
		}
		puts(line);
	}
	strcpy(line, "       : ");
	for (i = 0; i <= max_diag; i++) {
		if (tbf_a[i] == NULL) {
			strcat(line, "                    ");
			continue;
		}
		if (tbf_a[i]->diag != diag) {
			strcat(line, "         |          ");
			continue;
		}
		if (strlen(debug) < 19) {
			strcat(line, "                    ");
			memcpy(line + strlen(line) - 11 - strlen(debug) / 2,
				debug, strlen(debug));
		} else
			strcat(line, debug);
		tbf_a[i]->diag_new = 1;
	}
	puts(line);
}
#endif

/* FIXME: spread resources over multiple TRX. Also add option to use same
 * TRX in case of existing TBF for TLLI in the other direction. */
/* search for free TFI and return TFI, TRX */
int tfi_find_free(struct gprs_rlcmac_bts *bts, enum gprs_rlcmac_tbf_direction dir,
		uint8_t *_trx, int8_t use_trx)
{
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf **tbfp;
	uint8_t trx_from, trx_to, trx, ts, tfi;

	if (use_trx >= 0 && use_trx < 8)
		trx_from = trx_to = use_trx;
	else {
		trx_from = 0;
		trx_to = 7;
	}

	/* on TRX find first enabled TS */
	for (trx = trx_from; trx <= trx_to; trx++) {
		for (ts = 0; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->is_enabled())
				continue;
			break;
		}
		if (ts < 8)
			break;
	}
	if (trx > trx_to) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		return -EINVAL;
	}


	LOGP(DRLCMAC, LOGL_DEBUG, "Searching for first unallocated TFI: "
		"TRX=%d first TS=%d\n", trx, ts);
	if (dir == GPRS_RLCMAC_UL_TBF)
		tbfp = bts->trx[trx].ul_tbf;
	else
		tbfp = bts->trx[trx].dl_tbf;
	for (tfi = 0; tfi < 32; tfi++) {
		if (!tbfp[tfi])
			break;
	}
	
	if (tfi < 32) {
		LOGP(DRLCMAC, LOGL_DEBUG, " Found TFI=%d.\n", tfi);
		*_trx = trx;
		return tfi;
	}
	LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available.\n");

	return -1;
}

/* received RLC/MAC block from L1 */
int gprs_rlcmac_rcv_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts, uint8_t *data, uint8_t len,
	uint32_t fn, int8_t rssi)
{
	unsigned payload = data[0] >> 6;
	bitvec *block;
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = gprs_rlcmac_rcv_data_block_acknowledged(bts, trx, ts, data,
			len, rssi);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		block = bitvec_alloc(len);
		if (!block)
			return -ENOMEM;
		bitvec_unpack(block, data);
		rc = gprs_rlcmac_rcv_control_block(bts, block, trx, ts, fn);
		bitvec_free(block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload(%u).\n", payload);
		rc = -EINVAL;
	}

	return rc;
}

/* Send Uplink unit-data to SGSN. */
int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf)
{
	uint8_t qos_profile[3];
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + tbf->llc_index;
	struct bssgp_bvc_ctx *bctx = gprs_bssgp_pcu_current_bctx();

	LOGP(DBSSGP, LOGL_INFO, "LLC [PCU -> SGSN] TFI: %u TLLI: 0x%08x len=%d\n", tbf->tfi, tbf->tlli, tbf->llc_index);
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	
	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	uint8_t *buf = msgb_push(llc_pdu, TL16V_GROSS_LEN(sizeof(uint8_t)*tbf->llc_index));
	tl16v_put(buf, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*tbf->llc_index, tbf->llc_frame);
	qos_profile[0] = QOS_PROFILE >> 16;
	qos_profile[1] = QOS_PROFILE >> 8;
	qos_profile[2] = QOS_PROFILE;
	bssgp_tx_ul_ud(bctx, tbf->tlli, qos_profile, llc_pdu);

	return 0;
}

int gprs_rlcmac_paging_request(uint8_t *ptmsi, uint16_t ptmsi_len,
	const char *imsi)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] Paging Request (CCCH)\n");
	bitvec *paging_request = bitvec_alloc(23);
	bitvec_unhex(paging_request, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	int plen = Encoding::write_paging_request(paging_request, ptmsi, ptmsi_len);
	pcu_l1if_tx_pch(paging_request, plen, (char *)imsi);
	bitvec_free(paging_request);

	return 0;
}


