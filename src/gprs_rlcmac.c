/* gprs_rlcmac.c
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/gsm48.h>

#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <bts.h>
#include <encoding.h>
#include <tbf.h>
#include <gprs_debug.h>

extern void *tall_pcu_ctx;

int gprs_rlcmac_paging_request(struct gprs_rlcmac_bts *bts, const struct osmo_mobile_identity *mi,
			       const char *imsi)
{
	if (log_check_level(DRLCMAC, LOGL_NOTICE)) {
		char str[64];
		osmo_mobile_identity_to_str_buf(str, sizeof(str), mi);
		LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] Paging Request (CCCH) MI=%s\n", str);
	}
	struct bitvec *paging_request = bitvec_alloc(22, tall_pcu_ctx);
	bitvec_unhex(paging_request, DUMMY_VEC);
	int plen = write_paging_request(paging_request, mi);
	if (plen <= 0) {
		LOGP(DRLCMAC, LOGL_ERROR, "TX: [PCU -> BTS] Failed to encode Paging Request\n");
		return -1;
	}
	bts_do_rate_ctr_inc(bts, CTR_PCH_REQUESTS);

	pcu_l1if_tx_pch2(bts, paging_request, plen, false, imsi, GSM_RESERVED_TMSI);
	bitvec_free(paging_request);

	return 0;
}

/* Encode Application Information Request to Packet Application Information (3GPP TS 44.060 11.2.47) */
struct msgb *gprs_rlcmac_app_info_msg(const struct gsm_pcu_if_app_info_req *req) {
	struct msgb *msg;
	uint16_t msgb_len = req->len + 1;
	struct bitvec bv = {0, msgb_len, NULL};
	const enum bit_value page_mode[] = {ZERO, ZERO}; /* Normal Paging (3GPP TS 44.060 12.20) */

	if (!req->len) {
		LOGP(DRLCMAC, LOGL_ERROR, "Application Information Request with zero length received!\n");
		return NULL;
	}

	msg = msgb_alloc(msgb_len, "app_info_msg");
	if (!msg)
		return NULL;

	bv.data = msgb_put(msg, msgb_len);
	bitvec_set_bits(&bv, page_mode, 2);
	bitvec_set_uint(&bv, req->application_type, 4);
	bitvec_set_bytes(&bv, req->data, req->len);
	return msg;
}
