/* pcu_l1_if.cpp
 *
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <ctype.h>

extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gsm/l1sap.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_rest_octets.h>
#include <osmocom/gsm/sysinfo.h>
#include <osmocom/gsm/gsm0502.h>

#include <nacc_fsm.h>
#include <pcu_l1_if_phy.h>
}

#include <gprs_rlcmac.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <osmocom/pcu/pcuif_proto.h>
#include <bts.h>
#include <pdch.h>
#include <tbf_ul.h>
#include <tbf_dl.h>
#include <gprs_ms.h>

extern void *tall_pcu_ctx;

struct e1_ccu_conn_pars {
	struct llist_head entry;

	/* Related air interface */
	uint8_t bts_nr;
	uint8_t trx_nr;
	uint8_t ts_nr;

	/* E1 communication parameter */
	struct e1_conn_pars e1_conn_pars;
};

/* List storage to collect E1 connection information that we receive through the pcu_sock. The collected data serves as
 * a lookup table so that we can lookup the E1 connection information for each PDCH (trx number and timeslot number)
 * when it is needed. */
static LLIST_HEAD(e1_ccu_table);

/*
 * PCU messages
 */

/* Can be used to allocate message with non-variable size */
struct msgb *pcu_msgb_alloc(uint8_t msg_type, uint8_t bts_nr)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;

	msg = msgb_alloc(sizeof(struct gsm_pcu_if), "pcu_sock_tx");
	if (!msg)
		return NULL;
	msgb_put(msg, sizeof(struct gsm_pcu_if));
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	pcu_prim->msg_type = msg_type;
	pcu_prim->bts_nr = bts_nr;

	return msg;
}

/* Allocate message with extra size, only reserve pcuif msg hdr */
static struct msgb *pcu_msgb_alloc_ext_size(uint8_t msg_type, uint8_t bts_nr, size_t extra_size)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	msg = msgb_alloc(sizeof(struct gsm_pcu_if) + extra_size, "pcu_sock_tx");
	/* Only header is filled, caller is responible for reserving + filling
	 * message type specific contents: */
	msgb_put(msg, PCUIF_HDR_SIZE);
	pcu_prim = (struct gsm_pcu_if *) msgb_data(msg);
	pcu_prim->msg_type = msg_type;
	pcu_prim->bts_nr = bts_nr;
	return msg;
}

const struct value_string gsm_pcu_if_text_type_names[] = {
	OSMO_VALUE_STRING(PCU_VERSION),
	OSMO_VALUE_STRING(PCU_OML_ALERT),
	{ 0, NULL }
};

int pcu_tx_txt_ind(enum gsm_pcu_if_text_type t, const char *fmt, ...)
{
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_txt_ind *txt;
	va_list ap;
	char *rep;
	struct msgb *msg = pcu_msgb_alloc(PCU_IF_MSG_TXT_IND, 0);
	if (!msg)
		return -ENOMEM;

	pcu_prim = (struct gsm_pcu_if *) msg->data;
	txt = &pcu_prim->u.txt_ind;
	txt->type = t;

	va_start(ap, fmt);
	rep = talloc_vasprintf(tall_pcu_ctx, fmt, ap);
	va_end(ap);

	if (!rep)
		return -ENOMEM;

	osmo_strlcpy(txt->text, rep, TXT_MAX_LEN);
	talloc_free(rep);

	LOGP(DL1IF, LOGL_INFO, "Sending %s TXT as %s to BTS\n", txt->text,
	     get_value_string(gsm_pcu_if_text_type_names, t));

	return pcu_sock_send(msg);
}

static int pcu_tx_act_req(struct gprs_rlcmac_bts *bts, const struct gprs_rlcmac_pdch *pdch,
			  uint8_t activate)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_act_req *act_req;

	LOGPDCH(pdch, DL1IF, LOGL_INFO, "Sending %s request\n",
		(activate) ? "activate" : "deactivate");

	msg = pcu_msgb_alloc(PCU_IF_MSG_ACT_REQ, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	act_req = &pcu_prim->u.act_req;
	act_req->activate = activate;
	act_req->trx_nr = pdch->trx_no();
	act_req->ts_nr = pdch->ts_no;

	return pcu_sock_send(msg);
}

static int pcu_tx_data_req(struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts, uint8_t sapi,
	uint16_t arfcn, uint32_t fn, uint8_t block_nr, uint8_t *data,
	uint8_t len)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_data *data_req;
	int current_fn = bts_current_frame_number(bts);

	LOGP(DL1IF, LOGL_DEBUG, "(bts=%u,trx=%u,ts=%u) FN=%u Sending data request: sapi=%d "
	     "arfcn=%d cur_fn=%d block=%d data=%s\n", bts->nr, trx, ts, fn, sapi,
	     arfcn, current_fn, block_nr, osmo_hexdump(data, len));

	msg = pcu_msgb_alloc(PCU_IF_MSG_DATA_REQ, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	data_req = &pcu_prim->u.data_req;

	data_req->sapi = sapi;
	data_req->fn = fn;
	data_req->arfcn = arfcn;
	data_req->trx_nr = trx;
	data_req->ts_nr = ts;
	data_req->block_nr = block_nr;
	if (len)
		memcpy(data_req->data, data, len);
	data_req->len = len;

	return pcu_sock_send(msg);
}

void pcu_l1if_tx_pdtch(msgb *msg, struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
#ifdef ENABLE_DIRECT_PHY
	if (bts->trx[trx].fl1h) {
		if (!msg) /* Simply skip sending idle frames to L1 */
			return;
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 0, fn, arfcn, block_nr,
			msg->data, msg->len);
		msgb_free(msg);
		return;
	}
#endif
	if (!msg) {
		pcu_tx_data_req(bts, trx, ts, PCU_IF_SAPI_PDTCH, arfcn, fn, block_nr,
				NULL, 0);
		return;
	}

	pcu_tx_data_req(bts, trx, ts, PCU_IF_SAPI_PDTCH, arfcn, fn, block_nr,
			msg->data, msg->len);
	msgb_free(msg);
}

void pcu_l1if_tx_ptcch(struct gprs_rlcmac_bts *bts,
		       uint8_t trx, uint8_t ts, uint16_t arfcn,
		       uint32_t fn, uint8_t block_nr,
		       uint8_t *data, size_t data_len)
{
	if (data_len && the_pcu->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_PTCCH))
		gsmtap_send(the_pcu->gsmtap, arfcn, ts, GSMTAP_CHANNEL_PTCCH, 0, fn, 0, 0, data, data_len);
#ifdef ENABLE_DIRECT_PHY
	if (bts->trx[trx].fl1h) {
		if (!data_len) /* Simply skip sending idle frames to L1 */
			return;
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 1, fn, arfcn, block_nr, data, data_len);
		return;
	}
#endif
	if (!data_len) {
		pcu_tx_data_req(bts, trx, ts, PCU_IF_SAPI_PTCCH, arfcn, fn, block_nr, NULL, 0);
		return;
	}

	pcu_tx_data_req(bts, trx, ts, PCU_IF_SAPI_PTCCH, arfcn, fn, block_nr, data, data_len);
}

void pcu_l1if_tx_agch(struct gprs_rlcmac_bts *bts, bitvec *block, int plen)
{
	uint8_t data[GSM_MACBLOCK_LEN]; /* prefix PLEN */

	/* FIXME: why does OpenBTS has no PLEN and no fill in message? */
	bitvec_pack(block, data + 1);
	data[0] = (plen << 2) | 0x01;

	if (the_pcu->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_AGCH))
		gsmtap_send(the_pcu->gsmtap, 0, 0, GSMTAP_CHANNEL_AGCH, 0, 0, 0, 0, data, GSM_MACBLOCK_LEN);

	pcu_tx_data_req(bts, 0, 0, PCU_IF_SAPI_AGCH, 0, 0, 0, data, sizeof(data));
}

#define IMSI_DIGITS_FOR_PAGING 3
/* Send a MAC block via the paging channel. (See also comment below) */
void pcu_l1if_tx_pch(struct gprs_rlcmac_bts *bts, bitvec *block, int plen, const char *imsi)
{
	uint8_t data[IMSI_DIGITS_FOR_PAGING + GSM_MACBLOCK_LEN];

	/* prepend last three IMSI digits (if present) from which BTS/BSC will calculate the paging group */
	if (imsi && strlen(imsi) >= IMSI_DIGITS_FOR_PAGING)
		memcpy(data, imsi + strlen(imsi) - IMSI_DIGITS_FOR_PAGING, IMSI_DIGITS_FOR_PAGING);
	else
		memset(data, '0', IMSI_DIGITS_FOR_PAGING);

	/* block provided by upper layer comes without first byte (plen), prepend it manually: */
	OSMO_ASSERT(sizeof(data) >= IMSI_DIGITS_FOR_PAGING + 1 + block->data_len);
	data[IMSI_DIGITS_FOR_PAGING] = (plen << 2) | 0x01;
	bitvec_pack(block, data + IMSI_DIGITS_FOR_PAGING + 1);

	if (the_pcu->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_PCH))
		gsmtap_send(the_pcu->gsmtap, 0, 0, GSMTAP_CHANNEL_PCH, 0, 0, 0, 0,
			    data + IMSI_DIGITS_FOR_PAGING, GSM_MACBLOCK_LEN);

	pcu_tx_data_req(bts, 0, 0, PCU_IF_SAPI_PCH, 0, 0, 0, data, sizeof(data));
}

/* Send a MAC block via the paging channel. This will (obviously) only work for MAC blocks that contain an
 * IMMEDIATE ASSIGNMENT or a PAGING COMMAND message. In case the MAC block contains an IMMEDIATE ASSIGNMENT
 * message, the receiving end is required to confirm when the IMMEDIATE ASSIGNMENT has been sent. */
void pcu_l1if_tx_pch_dt(struct gprs_rlcmac_bts *bts, struct bitvec *block, int plen, const char *imsi, uint32_t tlli)
{
	struct gsm_pcu_if_pch_dt pch_dt = { 0 };

	pch_dt.tlli = tlli;
	if (imsi)
		OSMO_STRLCPY_ARRAY(pch_dt.imsi, imsi);

	pch_dt.data[0] = (plen << 2) | 0x01;
	bitvec_pack(block, pch_dt.data + 1);

	pcu_tx_data_req(bts, 0, 0, PCU_IF_SAPI_PCH_DT, 0, 0, 0, (uint8_t*)&pch_dt, sizeof(pch_dt));
}

int pcu_tx_neigh_addr_res_req(struct gprs_rlcmac_bts *bts, const struct neigh_cache_entry_key *neigh_key)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_neigh_addr_req *naddr_req;

	LOGP(DL1IF, LOGL_DEBUG, "(bts=%u) Tx Neighbor Address Resolution Request: " NEIGH_CACHE_ENTRY_KEY_FMT "\n",
	     bts->nr, NEIGH_CACHE_ENTRY_KEY_ARGS(neigh_key));

	msg = pcu_msgb_alloc_ext_size(PCU_IF_MSG_CONTAINER, bts->nr, sizeof(struct gsm_pcu_if_neigh_addr_req));
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msgb_data(msg);
	naddr_req = (struct gsm_pcu_if_neigh_addr_req *)&pcu_prim->u.container.data[0];

	msgb_put(msg, sizeof(pcu_prim->u.container) + sizeof(struct gsm_pcu_if_neigh_addr_req));
	pcu_prim->u.container.msg_type = PCU_IF_MSG_NEIGH_ADDR_REQ;
	osmo_store16be(sizeof(struct gsm_pcu_if_neigh_addr_req), &pcu_prim->u.container.length);

	osmo_store16be(neigh_key->local_lac, &naddr_req->local_lac);
	osmo_store16be(neigh_key->local_ci, &naddr_req->local_ci);
	osmo_store16be(neigh_key->tgt_arfcn, &naddr_req->tgt_arfcn);
	naddr_req->tgt_bsic = neigh_key->tgt_bsic;

	return pcu_sock_send(msg);
}

void pcu_rx_block_time(struct gprs_rlcmac_bts *bts, uint16_t arfcn, uint32_t fn, uint8_t ts_no)
{
	bts_set_current_block_frame_number(bts, fn);
}

int pcu_rx_data_ind_pdtch(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_pdch *pdch, uint8_t *data,
	uint8_t len, uint32_t fn, struct pcu_l1_meas *meas)
{
	int rc;

	if (!pdch->is_enabled()) {
		LOGPDCH(pdch, DL1IF, LOGL_INFO, "Received DATA.ind (PDTCH) on disabled TS\n");
		return -EINVAL;
	}

	rc = pdch->rcv_block(data, len, fn, meas);
	pdch_ulc_expire_fn(pdch->ulc, fn);
	return rc;
}

static int list_arfcn(const struct gprs_rlcmac_bts *bts, const struct gsm_sysinfo_freq *freq, const char *text)
{
	int n = 0, i;
	for (i = 0; i < 1024; i++) {
		if (freq[i].mask) {
			if (!n)
				LOGP(DL1IF, LOGL_INFO, "BTS%d: %s", bts->nr, text);
			LOGPC(DL1IF, LOGL_INFO, " %d", i);
			n++;
		}
	}
	if (n)
		LOGPC(DL1IF, LOGL_INFO, "\n");

	return n;
}

static int pcu_rx_data_ind_bcch(struct gprs_rlcmac_bts *bts, uint8_t *data, uint8_t len)
{
	struct gsm48_system_information_type_2 *si2;
	const uint8_t *si_ro;

	switch (len) {
	case 0:
		/* Due to historical reasons also accept a completely empty message as
		 * revoke command for SI13. */
		LOGP(DL1IF, LOGL_ERROR,
		     "Received PCU data indication that contains no data -- Revoked SI13.\n");
		bts->si13_is_set = false;

		return 0;
	case 1:
		/* Revoke SI, type is identified by a single byte which is coded after
		 * enum osmo_sysinfo_type. */
		switch (data[0]) {
		case SYSINFO_TYPE_1:
			bts->si1_is_set = false;
			break;
		case SYSINFO_TYPE_2:
			bts->si2_is_set = false;
			break;
		case SYSINFO_TYPE_3:
			bts->si3_is_set = false;
			break;
		case SYSINFO_TYPE_13:
			bts->si13_is_set = false;
			break;
		default:
			LOGP(DL1IF, LOGL_ERROR,
			     "Received PCU data indication that contains an unsupported system information identifier (%02x,OSMO) -- ignored.\n", data[0]);
			return -EINVAL;
		}
		LOGP(DPCU, LOGL_DEBUG,
		     "Received PCU data indication: Revoked SI%s\n",
		     get_value_string(osmo_sitype_strs, data[0]));
		return 0;
	case GSM_MACBLOCK_LEN:
		/* Update SI, type is identified by the RR sysinfo type, which is the
		 * 3rd byte in the buffer. */
		switch (data[2]) {
		case GSM48_MT_RR_SYSINFO_1:
			memcpy(bts->si1, data, GSM_MACBLOCK_LEN);
			bts->si1_is_set = true;
			break;
		case GSM48_MT_RR_SYSINFO_2:
			memcpy(bts->si2, data, GSM_MACBLOCK_LEN);
			bts->si2_is_set = true;
			si2 = (struct gsm48_system_information_type_2 *)bts->si2;
			gsm48_decode_freq_list(bts->si2_bcch_cell_list, si2->bcch_frequency_list,
					       sizeof(si2->bcch_frequency_list), 0xce, 1);
			list_arfcn(bts, bts->si2_bcch_cell_list, "SI2 Neighbour cells in same band:");
			break;
		case GSM48_MT_RR_SYSINFO_3:
			memcpy(bts->si3, data, GSM_MACBLOCK_LEN);
			bts->si3_is_set = true;
			break;
		case GSM48_MT_RR_SYSINFO_13:
			memcpy(bts->si13, data, GSM_MACBLOCK_LEN);
			bts->si13_is_set = true;
			si_ro = ((struct gsm48_system_information_type_13*)data)->rest_octets;
			if (osmo_gsm48_rest_octets_si13_decode(&bts->si13_ro_decoded, si_ro) < 0)
				LOGP(DPCU, LOGL_ERROR, "Error decoding SI13\n");
			break;
		default:
			LOGP(DL1IF, LOGL_ERROR,
			     "Received PCU data indication that contains an unsupported system information identifier (%02x,RR) -- ignored.\n", data[2]);
			return -EINVAL;
		}
		LOGP(DPCU, LOGL_DEBUG,
		     "Received PCU data indication: Updated %s: %s\n",
		     gsm48_pdisc_msgtype_name(data[1], data[2]),
		     osmo_hexdump_nospc(data + 1, GSM_MACBLOCK_LEN));
		return 0;
	default:
		LOGP(DL1IF, LOGL_ERROR,
		     "Received PCU data indication with unexpected data length: %u -- ignored.\n",
		     len);
		return -EINVAL;
	}
}

static int pcu_rx_data_ind(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_data *data_ind)
{
	int rc;
	int current_fn = bts_current_frame_number(bts);
	struct pcu_l1_meas meas = {0};
	struct gprs_rlcmac_pdch *pdch;
	uint8_t gsmtap_chantype;

	LOGP(DL1IF, LOGL_DEBUG, "(bts=%" PRIu8 ",trx=%" PRIu8 ",ts=%" PRIu8 ") FN=%u "
		"Rx DATA.ind: sapi=%d arfcn=%d cur_fn=%d "
		"block=%d data=%s\n", bts->nr, data_ind->trx_nr, data_ind->ts_nr,
		data_ind->fn, data_ind->sapi, data_ind->arfcn, current_fn,
		data_ind->block_nr, osmo_hexdump(data_ind->data, data_ind->len));

	switch (data_ind->sapi) {
	case PCU_IF_SAPI_PDTCH:
		pdch = &bts->trx[data_ind->trx_nr].pdch[data_ind->ts_nr];
		pcu_l1_meas_set_rssi(&meas, data_ind->rssi);
		/* convert BER to % value */
		pcu_l1_meas_set_ber(&meas, data_ind->ber10k / 100);
		pcu_l1_meas_set_bto(&meas, data_ind->ta_offs_qbits);
		pcu_l1_meas_set_link_qual(&meas, data_ind->lqual_cb / 10);

		LOGPDCH(pdch, DL1IF, LOGL_DEBUG, "FN=%u Rx DATA.ind PDTCH: "
			"BER10k = %d, BTO = %d, Q = %d\n", data_ind->fn,
			data_ind->ber10k, data_ind->ta_offs_qbits, data_ind->lqual_cb);

		rc = pcu_rx_data_ind_pdtch(bts, pdch, data_ind->data, data_ind->len,
					   data_ind->fn, &meas);
		gsmtap_chantype = GSMTAP_CHANNEL_PDTCH;
		break;
	case PCU_IF_SAPI_BCCH:
		rc = pcu_rx_data_ind_bcch(bts, data_ind->data, data_ind->len);
		gsmtap_chantype = GSMTAP_CHANNEL_BCCH;
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "(bts=%" PRIu8 ",trx=%" PRIu8 ",ts=%" PRIu8 ") "
		     "FN=%u Rx DATA.ind with unsupported sapi %d\n",
		     bts->nr, data_ind->trx_nr, data_ind->ts_nr, data_ind->fn, data_ind->sapi);
		rc = -EINVAL;
		gsmtap_chantype = GSMTAP_CHANNEL_UNKNOWN;
	}

	if (rc < 0 && (the_pcu->gsmtap_categ_mask & (1 <<PCU_GSMTAP_C_UL_UNKNOWN))) {
		gsmtap_send(the_pcu->gsmtap, data_ind->arfcn | GSMTAP_ARFCN_F_UPLINK, data_ind->ts_nr,
			    gsmtap_chantype, 0, data_ind->fn, meas.rssi, meas.link_qual, data_ind->data, data_ind->len);
	}

	return rc;
}

static int pcu_rx_data_cnf(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_data *data_cnf)
{
	int rc = 0;
	int current_fn = bts_current_frame_number(bts);

	LOGP(DL1IF, LOGL_DEBUG, "Data confirm received: sapi=%d fn=%d cur_fn=%d\n",
		data_cnf->sapi, data_cnf->fn, current_fn);

	switch (data_cnf->sapi) {
	case PCU_IF_SAPI_PCH:
		if (data_cnf->data[2] == GSM48_MT_RR_IMM_ASS)
			bts_rcv_imm_ass_cnf(bts, data_cnf->data, GSM_RESERVED_TMSI, data_cnf->fn);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data confirm with "
			"unsupported sapi %d\n", data_cnf->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_rx_data_cnf_dt(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_data_cnf_dt *data_cnf_dt)
{
	int rc = 0;
	int current_fn = bts_current_frame_number(bts);

	LOGP(DL1IF, LOGL_DEBUG, "Data confirm received: sapi=%d fn=%d cur_fn=%d\n",
	     data_cnf_dt->sapi, data_cnf_dt->fn, current_fn);

	switch (data_cnf_dt->sapi) {
	case PCU_IF_SAPI_PCH:
		bts_rcv_imm_ass_cnf(bts, NULL, data_cnf_dt->tlli, data_cnf_dt->fn);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data confirm with unsupported sapi %d\n", data_cnf_dt->sapi);
		rc = -EINVAL;
	}

	return rc;
}

// FIXME: remove this, when changed from c++ to c.
int pcu_rx_rts_req_pdtch(struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr)
{
	return gprs_rlcmac_rcv_rts_block(bts,
					trx, ts, fn, block_nr);
}
int pcu_rx_rts_req_ptcch(struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr)
{
	struct gprs_rlcmac_pdch *pdch;

	/* Prevent buffer overflow */
	if (trx >= ARRAY_SIZE(bts->trx) || ts >= 8)
		return -EINVAL;

	/* Make sure PDCH time-slot is enabled */
	pdch = &bts->trx[trx].pdch[ts];
	if (!pdch_is_enabled(pdch))
		return -EAGAIN;

	/* If there's no TBF attached to this PDCH, we can skip Tx of PTCCH
	 * since there's nothing worthy of being transmitted. This way BTS can
	 * identify idle blocks and send nothing or dumy blocks with reduced
	 * energy for the sake of energy saving.
	 */
	const unsigned num_tbfs = pdch->num_tbfs(GPRS_RLCMAC_DL_TBF)
				+ pdch->num_tbfs(GPRS_RLCMAC_UL_TBF);
	bool skip_idle = (num_tbfs == 0);
#ifdef ENABLE_DIRECT_PHY
		/* In DIRECT_PHY mode we want to always submit something to L1 in
		 * TRX0, since BTS is not preparing dummy bursts on idle TS for us: */
		skip_idle = skip_idle && trx != 0;
#endif
	if (skip_idle) {
		pcu_l1if_tx_ptcch(bts, trx, ts, bts->trx[trx].arfcn, fn, block_nr,
				  NULL, 0);
		return 0;
	}

	pcu_l1if_tx_ptcch(bts, trx, ts, bts->trx[trx].arfcn, fn, block_nr,
			  pdch->ptcch_msg, GSM_MACBLOCK_LEN);
	return 0;
}

static int pcu_rx_rts_req(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_rts_req *rts_req)
{
	int rc = 0;
	int current_fn = bts_current_frame_number(bts);
	const struct gprs_rlcmac_pdch *pdch;
	pdch = &bts->trx[rts_req->trx_nr].pdch[rts_req->ts_nr];

	LOGPDCH(pdch, DL1IF, LOGL_DEBUG, "FN=%u RX RTS.req: sapi=%d "
		"arfcn=%d cur_fn=%d block=%d\n", rts_req->fn,
		rts_req->sapi, rts_req->arfcn, current_fn, rts_req->block_nr);

	switch (rts_req->sapi) {
	case PCU_IF_SAPI_PDTCH:
		pcu_rx_rts_req_pdtch(bts, rts_req->trx_nr, rts_req->ts_nr,
			rts_req->fn, rts_req->block_nr);
		break;
	case PCU_IF_SAPI_PTCCH:
		pcu_rx_rts_req_ptcch(bts, rts_req->trx_nr, rts_req->ts_nr,
			rts_req->fn, rts_req->block_nr);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "(bts=%u,trx=%u,ts=%u) FN=%u RX RTS.req with "
		     "unsupported sapi %d\n", bts->nr, rts_req->trx_nr, rts_req->ts_nr,
		     rts_req->fn, rts_req->sapi);
		rc = -EINVAL;
	}

	return rc;
}

/* C -> C++ adapter for direct PHY access code (e.g. osmo-bts-sysmo) */
extern "C" int pcu_rx_rach_ind_ptcch(struct gprs_rlcmac_bts *bts, uint8_t trx_nr, uint8_t ts_nr, uint32_t fn, int16_t qta)
{
	struct rach_ind_params rip = {
		/* The content of RA is not of interest on PTCCH/U */
		.burst_type = GSM_L1_BURST_TYPE_ACCESS_0,
		.is_11bit = false,
		.ra = 0x00,
		.trx_nr = trx_nr,
		.ts_nr = ts_nr,
		.rfn = fn,
		.qta = qta,
	};

	return bts_rcv_ptcch_rach(bts, &rip);
}

static int pcu_rx_rach_ind(struct gprs_rlcmac_bts *bts, const struct gsm_pcu_if_rach_ind *rach_ind)
{
	int rc = 0;
	int current_fn = bts_current_frame_number(bts);

	LOGP(DL1IF, LOGL_INFO, "RACH request received: sapi=%d "
		"qta=%d, ra=0x%02x, fn=%u, cur_fn=%d, is_11bit=%d\n", rach_ind->sapi, rach_ind->qta,
		rach_ind->ra, rach_ind->fn, current_fn, rach_ind->is_11bit);

	if (OSMO_UNLIKELY(rach_ind->fn > GSM_TDMA_HYPERFRAME - 1)) {
		LOGP(DL1IF, LOGL_ERROR, "RACH request contains fn=%u that exceeds valid limits (0-%u) -- ignored!\n",
		     rach_ind->fn,  GSM_TDMA_HYPERFRAME - 1);
			return -EINVAL;
	}

	struct rach_ind_params rip = {
		.burst_type = (enum ph_burst_type) rach_ind->burst_type,
		.is_11bit = rach_ind->is_11bit > 0,
		.ra = rach_ind->ra,
		.trx_nr = rach_ind->trx_nr,
		.ts_nr = rach_ind->ts_nr,
		.rfn = rach_ind->fn,
		.qta = rach_ind->qta,
	};

	switch (rach_ind->sapi) {
	case PCU_IF_SAPI_RACH:
		rc = bts_rcv_rach(bts, &rip);
		break;
	case PCU_IF_SAPI_PTCCH:
		rc = bts_rcv_ptcch_rach(bts, &rip);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU rach request with "
			"unsupported sapi %d\n", rach_ind->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_info_ind_ns(struct gprs_rlcmac_bts *bts,
			   const struct gsm_pcu_if_info_ind *info_ind)
{
	struct osmo_sockaddr remote[PCU_IF_NUM_NSVC] = { };
	struct osmo_sockaddr local[PCU_IF_NUM_NSVC] = { };
	uint16_t nsvci[PCU_IF_NUM_NSVC] = { };
	uint16_t valid = 0;

	for (unsigned int i = 0; i < PCU_IF_NUM_NSVC; i++) {
		struct osmo_sockaddr_str sockstr;

		switch (info_ind->address_type[i]) {
		case PCU_IF_ADDR_TYPE_IPV4:
			local[i].u.sin.sin_family = AF_INET;
			local[i].u.sin.sin_addr.s_addr = INADDR_ANY;
			local[i].u.sin.sin_port = htons(info_ind->local_port[i]);

			remote[i].u.sin.sin_family = AF_INET;
			memcpy(&remote[i].u.sin.sin_addr, &info_ind->remote_ip[i].v4,
			       sizeof(struct in_addr));
			remote[i].u.sin.sin_port = htons(info_ind->remote_port[i]);
			break;
		case PCU_IF_ADDR_TYPE_IPV6:
			local[i].u.sin6.sin6_family = AF_INET6;
			local[i].u.sin6.sin6_addr = in6addr_any;
			local[i].u.sin6.sin6_port = htons(info_ind->local_port[i]);

			remote[i].u.sin6.sin6_family = AF_INET6;
			memcpy(&remote[i].u.sin6.sin6_addr,
			       &info_ind->remote_ip[i].v6,
			       sizeof(struct in6_addr));
			remote[i].u.sin6.sin6_port = htons(info_ind->remote_port[i]);
			break;
		default:
			continue;
		}
		nsvci[i] = info_ind->nsvci[i];

		LOGP(DL1IF, LOGL_DEBUG, " NS%u nsvci=%u\n", i, nsvci[i]);
		if (osmo_sockaddr_str_from_sockaddr(&sockstr, &remote[i].u.sas))
			strcpy(sockstr.ip, "invalid");

		LOGP(DL1IF, LOGL_DEBUG, " NS%u address: r=%s:%u<->l=NULL:%u\n",
		     i, sockstr.ip, sockstr.port, info_ind->local_port[i]);

		valid |= 1 << i;
	}

	if (valid == 0) {
		LOGP(DL1IF, LOGL_ERROR, "No NSVC available to connect to the SGSN!\n");
		return -EINVAL;
	}

	return gprs_ns_update_config(bts, info_ind->nsei, local, remote, nsvci, valid);
}

static int pcu_rx_info_ind(struct gprs_rlcmac_bts *bts, const struct gsm_pcu_if_info_ind *info_ind)
{
	struct gprs_bssgp_pcu *pcu;
	int rc = 0;
	unsigned int trx_nr, ts_nr;
	unsigned int i;

	if (llist_count(&the_pcu->bts_list) > 1)
		LOGP(DL1IF, LOGL_ERROR, "more than one BTS regsitered at this PCU. This PCU has only been tested with one BTS! OS#5930\n");

	LOGP(DL1IF, LOGL_DEBUG, "Info indication received:\n");

	/* NOTE: The classic way to confirm an IMMEDIATE assignment is to send the whole MAC block payload back to the
	 * PCU. So it is the MAC block itsself that serves a reference for the confirmation. This method has certain
	 * disadvantages so it was replaced with a method that uses the TLLI as a reference ("Direct TLLI"). This new
	 * method will replace the old one. The code that handles the old method will be removed in the foreseeable
	 * future. (see also OS#5927) */
	if (info_ind->version == 0x0a) {
		LOGP(DL1IF, LOGL_NOTICE, "PCUIF version 10 is deprecated. OS#5927\n");
	} else if (info_ind->version != PCU_IF_VERSION) {
		fprintf(stderr, "PCU interface version number of BTS/BSC (%u) is different (%u).\nPlease use a BTS/BSC with a compatble interface!\n",
			info_ind->version, PCU_IF_VERSION);
		exit(-1);
	}

	the_pcu->pcu_if_version = info_ind->version;

	if (!(info_ind->flags & PCU_IF_FLAG_ACTIVE)) {
		LOGP(DL1IF, LOGL_NOTICE, "BTS not available\n");
		if (!bts->active)
			return -EAGAIN;
bssgp_failed:
		bts->active = false;
		/* free all TBF */
		for (trx_nr = 0; trx_nr < ARRAY_SIZE(bts->trx); trx_nr++) {
			bts->trx[trx_nr].arfcn = info_ind->trx[trx_nr].arfcn;
			for (ts_nr = 0; ts_nr < ARRAY_SIZE(bts->trx[0].pdch); ts_nr++)
				if (bts->trx[trx_nr].pdch[ts_nr].is_enabled())
					bts->trx[trx_nr].pdch[ts_nr].disable();
		}
		gprs_bssgp_destroy(bts);
		exit(0);
	}
	LOGP(DL1IF, LOGL_INFO, "BTS available\n");
	LOGP(DL1IF, LOGL_DEBUG, " mcc=%03u\n", info_ind->mcc);
	LOGP(DL1IF, LOGL_DEBUG, " mnc=%0*u\n", info_ind->mnc_3_digits, info_ind->mnc);
	LOGP(DL1IF, LOGL_DEBUG, " lac=%d\n", info_ind->lac);
	LOGP(DL1IF, LOGL_DEBUG, " rac=%d\n", info_ind->rac);
	LOGP(DL1IF, LOGL_DEBUG, " cell_id=%d\n", info_ind->cell_id);
	LOGP(DL1IF, LOGL_DEBUG, " bsic=%d\n", info_ind->bsic);
	LOGP(DL1IF, LOGL_DEBUG, " nsei=%d\n", info_ind->nsei);
	LOGP(DL1IF, LOGL_DEBUG, " nse_timer=%d %d %d %d %d %d %d\n",
		info_ind->nse_timer[0], info_ind->nse_timer[1],
		info_ind->nse_timer[2], info_ind->nse_timer[3],
		info_ind->nse_timer[4], info_ind->nse_timer[5],
		info_ind->nse_timer[6]);
	LOGP(DL1IF, LOGL_DEBUG, " cell_timer=%d %d %d %d %d %d %d %d %d %d "
		"%d\n",
		info_ind->cell_timer[0], info_ind->cell_timer[1],
		info_ind->cell_timer[2], info_ind->cell_timer[3],
		info_ind->cell_timer[4], info_ind->cell_timer[5],
		info_ind->cell_timer[6], info_ind->cell_timer[7],
		info_ind->cell_timer[8], info_ind->cell_timer[9],
		info_ind->cell_timer[10]);
	LOGP(DL1IF, LOGL_DEBUG, " repeat_time=%d\n", info_ind->repeat_time);
	LOGP(DL1IF, LOGL_DEBUG, " repeat_count=%d\n", info_ind->repeat_count);
	LOGP(DL1IF, LOGL_DEBUG, " bvci=%d\n", info_ind->bvci);
	LOGP(DL1IF, LOGL_DEBUG, " t3142=%d\n", info_ind->t3142);
	LOGP(DL1IF, LOGL_DEBUG, " t3169=%d\n", info_ind->t3169);
	LOGP(DL1IF, LOGL_DEBUG, " t3191=%d\n", info_ind->t3191);
	LOGP(DL1IF, LOGL_DEBUG, " t3193=%d (ms)\n", info_ind->t3193_10ms * 10);
	LOGP(DL1IF, LOGL_DEBUG, " t3195=%d\n", info_ind->t3195);
	LOGP(DL1IF, LOGL_DEBUG, " n3101=%d\n", info_ind->n3101);
	LOGP(DL1IF, LOGL_DEBUG, " n3103=%d\n", info_ind->n3103);
	LOGP(DL1IF, LOGL_DEBUG, " n3105=%d\n", info_ind->n3105);
	LOGP(DL1IF, LOGL_DEBUG, " cv_countdown=%d\n", info_ind->cv_countdown);
	LOGP(DL1IF, LOGL_DEBUG, " dl_tbf_ext=%d\n", info_ind->dl_tbf_ext);
	LOGP(DL1IF, LOGL_DEBUG, " ul_tbf_ext=%d\n", info_ind->ul_tbf_ext);
	bts->cgi_ps.rai.lac.plmn.mcc = info_ind->mcc;
	bts->cgi_ps.rai.lac.plmn.mnc = info_ind->mnc;
	bts->cgi_ps.rai.lac.plmn.mnc_3_digits = info_ind->mnc_3_digits;
	bts->cgi_ps.rai.lac.lac = info_ind->lac;
	bts->cgi_ps.rai.rac = info_ind->rac;
	bts->cgi_ps.cell_identity = info_ind->cell_id;
	bts->bsic = info_ind->bsic;

	bts->cs_mask = 1 << 0; /* We need at least 1 CS, let's enable CS1 */
	for (i = 0; i < 4; i++) {
		uint8_t allowed = !!(info_ind->flags & (PCU_IF_FLAG_CS1 << i));
		bts->cs_mask |= allowed << i;
		if (allowed)
			LOGP(DL1IF, LOGL_DEBUG, " Use CS%d\n",  i + 1);
	}
	bts_recalc_max_cs(bts);

	bts->mcs_mask = 0;
	for (i = 0; i < 9; i++) {
		uint8_t allowed = !!(info_ind->flags & (PCU_IF_FLAG_MCS1 << i));
		bts->mcs_mask |= allowed << i;
		if (allowed)
			LOGP(DL1IF, LOGL_DEBUG, " Use MCS%d\n", i + 1);

	}
	bts_recalc_max_mcs(bts);

	LOGP(DL1IF, LOGL_DEBUG, " initial_cs=%u%s\n", info_ind->initial_cs,
	     the_pcu->vty.force_initial_cs ? " (VTY forced, ignoring)" : "");
	bts->pcuif_info_ind.initial_cs = info_ind->initial_cs;
	bts_recalc_initial_cs(bts);

	LOGP(DL1IF, LOGL_DEBUG, " initial_mcs=%u%s\n", info_ind->initial_mcs,
	     the_pcu->vty.force_initial_mcs ? " (VTY forced, ignoring)" : "");
	bts->pcuif_info_ind.initial_mcs = info_ind->initial_mcs;
	bts_recalc_initial_mcs(bts);

	pcu = gprs_bssgp_init(
			bts,
			info_ind->nsei, info_ind->bvci,
			info_ind->mcc, info_ind->mnc, info_ind->mnc_3_digits,
			info_ind->lac, info_ind->rac, info_ind->cell_id);
	if (!pcu) {
		LOGP(DL1IF, LOGL_ERROR, "Failed to init BSSGP\n");
		goto bssgp_failed;
	}

	rc = pcu_info_ind_ns(pcu->bts, info_ind);
	if (rc < 0) {
		LOGP(DL1IF, LOGL_ERROR, "No NSVC available to connect to the SGSN!\n");
		goto bssgp_failed;
	}

	if (info_ind->t3142) { /* if timer values are set */
		osmo_tdef_set(bts->T_defs_bts, 3142, info_ind->t3142, OSMO_TDEF_S);
		osmo_tdef_set(bts->T_defs_bts, 3169, info_ind->t3169, OSMO_TDEF_S);
		osmo_tdef_set(bts->T_defs_bts, 3191, info_ind->t3191, OSMO_TDEF_S);
		osmo_tdef_set(bts->T_defs_bts, 3193, info_ind->t3193_10ms * 10, OSMO_TDEF_MS);
		osmo_tdef_set(bts->T_defs_bts, 3195, info_ind->t3195, OSMO_TDEF_S);
		bts->n3101 = info_ind->n3101;
		bts->n3103 = info_ind->n3103;
		bts->n3105 = info_ind->n3105;
	}

	for (trx_nr = 0; trx_nr < ARRAY_SIZE(bts->trx); trx_nr++) {
		bts->trx[trx_nr].arfcn = info_ind->trx[trx_nr].arfcn;
		if ((info_ind->flags & PCU_IF_FLAG_SYSMO)
		 && info_ind->trx[trx_nr].hlayer1) {
#ifdef ENABLE_DIRECT_PHY
			LOGP(DL1IF, LOGL_DEBUG, " TRX %d hlayer1=%x\n", trx_nr,
				info_ind->trx[trx_nr].hlayer1);
				if (!bts->trx[trx_nr].fl1h)
					bts->trx[trx_nr].fl1h = l1if_open_trx(
						bts->nr, trx_nr,
						info_ind->trx[trx_nr].hlayer1,
						the_pcu->gsmtap);
			if (!bts->trx[trx_nr].fl1h) {
				LOGP(DL1IF, LOGL_FATAL, "Failed to open direct "
					"PHY access for PDCH.\n");
				exit(0);
			}
#else
			LOGP(DL1IF, LOGL_FATAL, "Compiled without direct PHY "
					"access for PDCH, but enabled at "
					"BTS. Please deactivate it!\n");
			exit(0);
#endif
		}

		for (ts_nr = 0; ts_nr < ARRAY_SIZE(bts->trx[0].pdch); ts_nr++) {
			const struct gsm_pcu_if_info_trx_ts *its = &info_ind->trx[trx_nr].ts[ts_nr];
			struct gprs_rlcmac_pdch *pdch = &bts->trx[trx_nr].pdch[ts_nr];
			if ((info_ind->trx[trx_nr].pdch_mask & (1 << ts_nr))) {
				/* FIXME: activate dynamically at RLCMAC */
				if (!pdch->is_enabled()) {
#ifdef ENABLE_DIRECT_PHY
					if ((info_ind->flags &
							PCU_IF_FLAG_SYSMO))
						l1if_connect_pdch(
							bts->trx[trx_nr].fl1h, ts_nr);
#endif
					pcu_tx_act_req(bts, pdch, 1);
					pdch->enable();
				}

				pdch->tsc = its->tsc;

				/* (Optional) frequency hopping parameters */
				if (its->hopping) {
					pdch->fh.enabled = true;
					pdch->fh.maio    = its->maio;
					pdch->fh.hsn     = its->hsn;

					OSMO_ASSERT(its->ma_bit_len <= sizeof(pdch->fh.ma) * 8);
					pdch->fh.ma_oct_len = OSMO_BYTES_FOR_BITS(its->ma_bit_len);
					pdch->fh.ma_bit_len = its->ma_bit_len;

					/* Mobile Allocation + padding (byte/bit order as on the wire):
					 * | 00 00 00 00 00 cc bb aa | -> | cc bb aa 00 00 00 00 00 | */
					unsigned int offset = sizeof(pdch->fh.ma) - pdch->fh.ma_oct_len;
					memcpy(pdch->fh.ma, its->ma + offset, pdch->fh.ma_oct_len);
				}

				LOGP(DL1IF, LOGL_INFO, "PDCH (trx=%u, ts=%u): tsc=%u, hopping=%s\n",
				     trx_nr, ts_nr, pdch->tsc, pdch->fh.enabled ? "yes" : "no");
			} else {
				if (pdch->is_enabled()) {
#ifdef ENABLE_DIRECT_PHY
					if ((info_ind->flags & PCU_IF_FLAG_SYSMO))
						l1if_disconnect_pdch(bts->trx[trx_nr].fl1h, ts_nr);
#endif
					pcu_tx_act_req(bts, pdch, 0);
					pdch->disable();
				}
			}
		}
	}

	bts->active = true;
	return rc;
}

/* Query E1 CCU connection parameters by TS and TRX number */
int pcu_l1if_get_e1_ccu_conn_pars(struct e1_conn_pars **e1_conn_pars, uint8_t bts_nr, uint8_t trx_nr, uint8_t ts_nr)
{
	struct e1_ccu_conn_pars *e1_ccu_conn_pars;

	llist_for_each_entry(e1_ccu_conn_pars, &e1_ccu_table, entry) {
		if (e1_ccu_conn_pars->bts_nr == bts_nr && e1_ccu_conn_pars->trx_nr == trx_nr
		    && e1_ccu_conn_pars->ts_nr == ts_nr) {
			*e1_conn_pars = &e1_ccu_conn_pars->e1_conn_pars;
			return 0;
		}
	}

	return -EINVAL;
}

/* Allocate a new connection parameter struct and store connection parameters */
static void new_e1_ccu_conn_pars(const struct gsm_pcu_if_e1_ccu_ind *e1_ccu_ind, uint8_t bts_nr)
{
	struct e1_ccu_conn_pars *e1_ccu_conn_pars;

	e1_ccu_conn_pars = talloc_zero(tall_pcu_ctx, struct e1_ccu_conn_pars);
	OSMO_ASSERT(e1_ccu_conn_pars);
	e1_ccu_conn_pars->bts_nr = bts_nr;
	e1_ccu_conn_pars->trx_nr = e1_ccu_ind->trx_nr;
	e1_ccu_conn_pars->ts_nr = e1_ccu_ind->ts_nr;
	e1_ccu_conn_pars->e1_conn_pars.e1_nr = e1_ccu_ind->e1_nr;
	e1_ccu_conn_pars->e1_conn_pars.e1_ts = e1_ccu_ind->e1_ts;
	e1_ccu_conn_pars->e1_conn_pars.e1_ts_ss = e1_ccu_ind->e1_ts_ss;
	llist_add(&e1_ccu_conn_pars->entry, &e1_ccu_table);
}

static int pcu_rx_e1_ccu_ind(struct gprs_rlcmac_bts *bts, const struct gsm_pcu_if_e1_ccu_ind *e1_ccu_ind)
{
	struct e1_conn_pars *e1_conn_pars;
	uint8_t rate;
	uint8_t subslot_nr;
	int rc;

	/* only used with log statement below, no technical relevance otherwise. */
	if (e1_ccu_ind->e1_ts_ss > 3) {
		rate = 64;
		subslot_nr = 0;
	} else {
		rate = 16;
		subslot_nr = e1_ccu_ind->e1_ts_ss;
	}

	LOGP(DL1IF, LOGL_NOTICE,
	     "(ts=%u,trx=%u) new E1 CCU communication parameters for CCU (E1-line:%u, E1-TS:%u, E1-SS:%u, rate:%ukbps)\n",
	     e1_ccu_ind->ts_nr, e1_ccu_ind->trx_nr, e1_ccu_ind->e1_nr, e1_ccu_ind->e1_ts,
	     subslot_nr, rate);

	/* Search for an existing entry, when found, update it. */
	rc = pcu_l1if_get_e1_ccu_conn_pars(&e1_conn_pars, bts->nr, e1_ccu_ind->trx_nr, e1_ccu_ind->ts_nr);
	if (rc == 0) {
		e1_conn_pars->e1_nr = e1_ccu_ind->e1_nr;
		e1_conn_pars->e1_ts = e1_ccu_ind->e1_ts;
		e1_conn_pars->e1_ts_ss = e1_ccu_ind->e1_ts_ss;
		return 0;
	}

	/* Create new connection parameter entry */
	new_e1_ccu_conn_pars(e1_ccu_ind, bts->nr);
	return 0;
}

static int pcu_rx_time_ind(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_time_ind *time_ind)
{
	uint8_t fn13 = time_ind->fn % 13;

	/* omit frame numbers not starting at a MAC block */
	if (fn13 != 0 && fn13 != 4 && fn13 != 8)
		return 0;

	LOGP(DL1IF, LOGL_DEBUG, "Time indication received: %d\n", time_ind->fn % 52);

	/* Ignore TIME.ind completely, we nowadays relay on DATA.ind always
	 * providing all block FNs. */
	return 0;
}

static int pcu_rx_pag_req(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_pag_req *pag_req)
{
	struct osmo_mobile_identity mi;
	struct GprsMs *ms = NULL;
	struct paging_req_cs req = { .chan_needed = pag_req->chan_needed,
				     .tlli = GSM_RESERVED_TMSI };
	int rc;

	LOGP(DL1IF, LOGL_DEBUG, "Paging request received: chan_needed=%d "
		"length=%d\n", pag_req->chan_needed, pag_req->identity_lv[0]);

	/* check if identity does not fit: length > sizeof(lv) - 1 */
	if (pag_req->identity_lv[0] >= sizeof(pag_req->identity_lv)) {
		LOGP(DL1IF, LOGL_ERROR, "Paging identity too large (%" PRIu8 ")\n",
			pag_req->identity_lv[0]);
		return -EINVAL;
	}

	rc = osmo_mobile_identity_decode(&mi, &pag_req->identity_lv[1], pag_req->identity_lv[0], true);
	if (rc < 0) {
		LOGP(DL1IF, LOGL_ERROR, "Failed to decode Mobile Identity in Paging Request (rc=%d)\n", rc);
		return -EINVAL;
	}

	switch (mi.type) {
	case GSM_MI_TYPE_TMSI:
		req.mi_tmsi = mi;
		req.mi_tmsi_present = true;
		/* TODO: look up MS by TMSI? Derive TLLI? */
		break;
	case GSM_MI_TYPE_IMSI:
		req.mi_imsi = mi;
		req.mi_imsi_present = true;
		ms = bts_get_ms_by_imsi(bts, req.mi_imsi.imsi);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Unexpected MI type %u\n", mi.type);
		return -EINVAL;
	}

	return bts_add_paging(bts, &req, ms);
}

static int pcu_rx_susp_req(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_susp_req *susp_req)
{
	struct bssgp_bvc_ctx *bctx = the_pcu->bssgp.bctx;
	GprsMs *ms;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_ra_id ra_id;

	gsm48_parse_ra(&ra_id, susp_req->ra_id);

	LOGP(DL1IF, LOGL_INFO, "GPRS Suspend request received: TLLI=0x%08x RAI=%s\n",
		susp_req->tlli, osmo_rai_name(&ra_id));

	if ((ms = bts_get_ms_by_tlli(bts, susp_req->tlli, GSM_RESERVED_TMSI))) {
		/* We need to catch both pointers here since MS may become freed
		   after first tbf_free(dl_tbf) if only DL TBF was available */
		dl_tbf = ms_dl_tbf(ms);
		ul_tbf = ms_ul_tbf(ms);
		if (dl_tbf)
			tbf_free(dl_tbf);
		if (ul_tbf)
			tbf_free(ul_tbf);
	}

	if (!bctx)
		return -1;

	return bssgp_tx_suspend(bctx->nsei, susp_req->tlli, &ra_id);
}

static int pcu_rx_app_info_req(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_app_info_req *app_info_req)
{
	struct llist_head *tmp;

	LOGP(DL1IF, LOGL_DEBUG, "Application Information Request received: type=0x%08x len=%i\n",
	     app_info_req->application_type, app_info_req->len);

	bts->app_info_pending = 0;
	llist_for_each(tmp, &bts->ms_list) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		if (!ms_dl_tbf(ms))
			continue;
		bts->app_info_pending++;
		ms->app_info_pending = true;
	}

	if (!bts->app_info_pending) {
		LOGP(DL1IF, LOGL_NOTICE, "Packet Application Information will not be sent, no subscribers with active"
		     " TBF\n");
		return -1;
	}

	if (bts->app_info) {
		LOGP(DL1IF, LOGL_NOTICE, "Previous Packet Application Information was not sent to all subscribers,"
		     " overwriting with new one\n");
		msgb_free(bts->app_info);
	}

	LOGP(DL1IF, LOGL_INFO, "Sending Packet Application Information to %i subscribers with active TBF\n",
	     bts->app_info_pending);
	bts->app_info = gprs_rlcmac_app_info_msg(app_info_req);
	return 0;
}

static int pcu_rx_neigh_addr_cnf(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_neigh_addr_cnf *naddr_cnf)
{
	struct llist_head *tmp;
	struct osmo_cell_global_id_ps cgi_ps;
	struct osmo_cell_global_id_ps *cgi_ps_ptr = &cgi_ps;

	struct neigh_cache_entry_key neigh_key = {
		.local_lac = osmo_load16be(&naddr_cnf->orig_req.local_lac),
		.local_ci = osmo_load16be(&naddr_cnf->orig_req.local_ci),
		.tgt_arfcn = osmo_load16be(&naddr_cnf->orig_req.tgt_arfcn),
		.tgt_bsic = naddr_cnf->orig_req.tgt_bsic,
	};

	if (naddr_cnf->err_code == 0) {
		cgi_ps.rai.lac.plmn.mcc = osmo_load16be(&naddr_cnf->cgi_ps.mcc);
		cgi_ps.rai.lac.plmn.mnc = osmo_load16be(&naddr_cnf->cgi_ps.mnc);
		cgi_ps.rai.lac.plmn.mnc_3_digits = naddr_cnf->cgi_ps.mnc_3_digits;
		cgi_ps.rai.lac.lac = osmo_load16be(&naddr_cnf->cgi_ps.lac);
		cgi_ps.rai.rac = naddr_cnf->cgi_ps.rac;
		cgi_ps.cell_identity = osmo_load16be(&naddr_cnf->cgi_ps.cell_identity);

		LOGP(DL1IF, LOGL_INFO, "Rx Neighbor Address Resolution Confirmation for " NEIGH_CACHE_ENTRY_KEY_FMT ": %s\n",
		     NEIGH_CACHE_ENTRY_KEY_ARGS(&neigh_key), osmo_cgi_ps_name(&cgi_ps));

		/* Cache the cgi_ps so we can avoid requesting again same resolution for a while */
		neigh_cache_add(bts->pcu->neigh_cache, &neigh_key, &cgi_ps);
	} else {
		cgi_ps_ptr = NULL;
		LOGP(DL1IF, LOGL_INFO, "Rx Neighbor Address Resolution Confirmation for " NEIGH_CACHE_ENTRY_KEY_FMT ": failed with err_code=%u\n",
		     NEIGH_CACHE_ENTRY_KEY_ARGS(&neigh_key), naddr_cnf->err_code);
	}

	llist_for_each(tmp, &bts->ms_list) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		if (ms->nacc && nacc_fsm_is_waiting_addr_resolution(ms->nacc, &neigh_key))
			osmo_fsm_inst_dispatch(ms->nacc->fi, NACC_EV_RX_RAC_CI, cgi_ps_ptr);
	}
	return 0;
}

static int pcu_rx_container(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_container *container)
{
	int rc;
	uint16_t data_length = osmo_load16be(&container->length);

	switch (container->msg_type) {
	case PCU_IF_MSG_NEIGH_ADDR_CNF:
		if (data_length < sizeof(struct gsm_pcu_if_neigh_addr_cnf)) {
			LOGP(DL1IF, LOGL_ERROR, "Rx container(NEIGH_ADDR_CNF) message too short: %u vs exp %zu\n",
			     data_length, sizeof(struct gsm_pcu_if_neigh_addr_cnf));
			return -EINVAL;
		}
		rc = pcu_rx_neigh_addr_cnf(bts, (struct gsm_pcu_if_neigh_addr_cnf*)&container->data);
		break;
	default:
		LOGP(DL1IF, LOGL_NOTICE, "(bts=%d) Rx unexpected msg type (%u) inside container!\n",
		     bts->nr, container->msg_type);
		rc = -1;
	}
	return rc;
}

#define CHECK_IF_MSG_SIZE(prim_len, prim_msg) \
	do { \
		size_t _len = PCUIF_HDR_SIZE + sizeof(prim_msg); \
		if (prim_len < _len) { \
			LOGP(DL1IF, LOGL_ERROR, "Received %zu bytes on PCU Socket, but primitive %s " \
			     "size is %zu, discarding\n", prim_len, #prim_msg, _len); \
			return -EINVAL; \
		} \
	} while(0);
int pcu_rx(struct gsm_pcu_if *pcu_prim, size_t pcu_prim_length)
{
	int rc = 0;
	size_t exp_len;
	struct gprs_rlcmac_bts *bts = gprs_pcu_get_bts_by_nr(the_pcu, pcu_prim->bts_nr);
	if (!bts) {
		LOGP(DL1IF, LOGL_NOTICE, "Received message for new BTS%d\n", pcu_prim->bts_nr);
		bts = bts_alloc(the_pcu, pcu_prim->bts_nr);
		if (!bts) {
			LOGP(DL1IF, LOGL_ERROR, "Failed to create object for BTS%d!\n", pcu_prim->bts_nr);
			return -EAGAIN;
		}
	}

	switch (pcu_prim->msg_type) {
	case PCU_IF_MSG_DATA_IND:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.data_ind);
		rc = pcu_rx_data_ind(bts, &pcu_prim->u.data_ind);
		break;
	case PCU_IF_MSG_DATA_CNF:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.data_cnf);
		rc = pcu_rx_data_cnf(bts, &pcu_prim->u.data_cnf);
		break;
	case PCU_IF_MSG_DATA_CNF_DT:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.data_cnf_dt);
		rc = pcu_rx_data_cnf_dt(bts, &pcu_prim->u.data_cnf_dt);
		break;
	case PCU_IF_MSG_RTS_REQ:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.rts_req);
		rc = pcu_rx_rts_req(bts, &pcu_prim->u.rts_req);
		break;
	case PCU_IF_MSG_RACH_IND:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.rach_ind);
		rc = pcu_rx_rach_ind(bts, &pcu_prim->u.rach_ind);
		break;
	case PCU_IF_MSG_INFO_IND:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.info_ind);
		rc = pcu_rx_info_ind(bts, &pcu_prim->u.info_ind);
		break;
	case PCU_IF_MSG_E1_CCU_IND:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.e1_ccu_ind);
		rc = pcu_rx_e1_ccu_ind(bts, &pcu_prim->u.e1_ccu_ind);
		break;
	case PCU_IF_MSG_TIME_IND:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.time_ind);
		rc = pcu_rx_time_ind(bts, &pcu_prim->u.time_ind);
		break;
	case PCU_IF_MSG_PAG_REQ:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.pag_req);
		rc = pcu_rx_pag_req(bts, &pcu_prim->u.pag_req);
		break;
	case PCU_IF_MSG_SUSP_REQ:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.susp_req);
		rc = pcu_rx_susp_req(bts, &pcu_prim->u.susp_req);
		break;
	case PCU_IF_MSG_APP_INFO_REQ:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.app_info_req);
		rc = pcu_rx_app_info_req(bts, &pcu_prim->u.app_info_req);
		break;
	case PCU_IF_MSG_INTERF_IND:
		/* TODO: handle interference reports */
		break;
	case PCU_IF_MSG_CONTAINER:
		CHECK_IF_MSG_SIZE(pcu_prim_length, pcu_prim->u.container);
		/* ^ check if we can access container fields, v check with container data length */
		exp_len = PCUIF_HDR_SIZE + sizeof(pcu_prim->u.container) + osmo_load16be(&pcu_prim->u.container.length);
		if (pcu_prim_length < exp_len) {
			LOGP(DL1IF, LOGL_ERROR, "Received %zu bytes on PCU Socket, but primitive container size" \
			     "is %zu, discarding\n", pcu_prim_length, exp_len);
			rc = -EINVAL;
			break;
		}
		rc = pcu_rx_container(bts, &pcu_prim->u.container);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received unknown PCU msg type %d\n",
			pcu_prim->msg_type);
		rc = -EINVAL;
	}

	return rc;
}
