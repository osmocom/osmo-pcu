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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include <osmocom/gsm/sysinfo.h>
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
#include <gprs_ms_storage.h>

// FIXME: move this, when changed from c++ to c.
extern "C" {
void *l1if_open_pdch(uint8_t trx_no, uint32_t hlayer1,
		     struct gsmtap_inst *gsmtap);
int l1if_connect_pdch(void *obj, uint8_t ts);
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn,
        uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len);
}

extern void *tall_pcu_ctx;

#define PAGING_GROUP_LEN 3

/* returns [0,999] on success, > 999 on error */
uint16_t imsi2paging_group(const char* imsi)
{
	uint16_t pgroup = 0;
	size_t len;

	len = (imsi != NULL) ? strlen(imsi) : 0;
	if (len < PAGING_GROUP_LEN)
		return 0xFFFF;
	imsi += len - PAGING_GROUP_LEN;

	while (*imsi != '\0') {
		if (!isdigit(*imsi))
			return 0xFFFF;
		pgroup *= 10;
		pgroup += *imsi - '0';
		imsi++;
	}
	return pgroup;
}

/*
 * PCU messages
 */

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

static int pcu_tx_act_req(struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts, uint8_t activate)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_act_req *act_req;

	LOGP(DL1IF, LOGL_INFO, "Sending %s request: trx=%d ts=%d\n",
		(activate) ? "activate" : "deactivate", trx, ts);

	msg = pcu_msgb_alloc(PCU_IF_MSG_ACT_REQ, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	act_req = &pcu_prim->u.act_req;
	act_req->activate = activate;
	act_req->trx_nr = trx;
	act_req->ts_nr = ts;

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

	LOGP(DL1IF, LOGL_DEBUG, "Sending data request: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d cur_fn=%d block=%d data=%s\n", trx, ts, sapi, arfcn, fn, current_fn,
		block_nr, osmo_hexdump(data, len));

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
	memcpy(data_req->data, data, len);
	data_req->len = len;

	return pcu_sock_send(msg);
}

void pcu_l1if_tx_pdtch(msgb *msg, struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
#ifdef ENABLE_DIRECT_PHY
	if (bts->trx[trx].fl1h) {
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 0, fn, arfcn, block_nr,
			msg->data, msg->len);
		msgb_free(msg);
		return;
	}
#endif
	pcu_tx_data_req(bts, trx, ts, PCU_IF_SAPI_PDTCH, arfcn, fn, block_nr,
			msg->data, msg->len);
	msgb_free(msg);
}

void pcu_l1if_tx_ptcch(struct gprs_rlcmac_bts *bts,
		       uint8_t trx, uint8_t ts, uint16_t arfcn,
		       uint32_t fn, uint8_t block_nr,
		       uint8_t *data, size_t data_len)
{
	if (the_pcu->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_PTCCH))
		gsmtap_send(the_pcu->gsmtap, arfcn, ts, GSMTAP_CHANNEL_PTCCH, 0, fn, 0, 0, data, data_len);
#ifdef ENABLE_DIRECT_PHY
	if (bts->trx[trx].fl1h) {
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 1, fn, arfcn, block_nr, data, data_len);
		return;
	}
#endif
	pcu_tx_data_req(bts, trx, ts, PCU_IF_SAPI_PTCCH, arfcn, fn, block_nr, data, data_len);
}

void pcu_l1if_tx_agch(struct gprs_rlcmac_bts *bts, bitvec * block, int plen)
{
	uint8_t data[GSM_MACBLOCK_LEN]; /* prefix PLEN */

	/* FIXME: why does OpenBTS has no PLEN and no fill in message? */
	bitvec_pack(block, data + 1);
	data[0] = (plen << 2) | 0x01;

	if (the_pcu->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_AGCH))
		gsmtap_send(the_pcu->gsmtap, 0, 0, GSMTAP_CHANNEL_AGCH, 0, 0, 0, 0, data, GSM_MACBLOCK_LEN);

	pcu_tx_data_req(bts, 0, 0, PCU_IF_SAPI_AGCH, 0, 0, 0, data, GSM_MACBLOCK_LEN);
}

void pcu_l1if_tx_pch(struct gprs_rlcmac_bts *bts, bitvec * block, int plen, uint16_t pgroup)
{
	uint8_t data[PAGING_GROUP_LEN + GSM_MACBLOCK_LEN];
	int i;

	/* prepend paging group */
	for (i = 0; i < PAGING_GROUP_LEN; i++) {
		data[PAGING_GROUP_LEN - 1 - i] = '0' + (char)(pgroup % 10);
		pgroup = pgroup / 10;
	}
	OSMO_ASSERT(pgroup == 0);

	/* block provided by upper layer comes without first byte (plen),
	 * prepend it manually:
	 */
	OSMO_ASSERT(sizeof(data) >= PAGING_GROUP_LEN + 1 + block->data_len);
	data[3] = (plen << 2) | 0x01;
	bitvec_pack(block, data + PAGING_GROUP_LEN + 1);

	if (the_pcu->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_PCH))
		gsmtap_send(the_pcu->gsmtap, 0, 0, GSMTAP_CHANNEL_PCH, 0, 0, 0, 0, data + 3, GSM_MACBLOCK_LEN);

	pcu_tx_data_req(bts, 0, 0, PCU_IF_SAPI_PCH, 0, 0, 0, data, PAGING_GROUP_LEN + GSM_MACBLOCK_LEN);
}

void pcu_rx_block_time(struct gprs_rlcmac_bts *bts, uint16_t arfcn, uint32_t fn, uint8_t ts_no)
{
	bts_set_current_block_frame_number(bts, fn, 0);
}

void pcu_rx_ra_time(struct gprs_rlcmac_bts *bts, uint16_t arfcn, uint32_t fn, uint8_t ts_no)
{
	/* access bursts may arrive some bursts earlier */
	bts_set_current_block_frame_number(bts, fn, 5);
}

int pcu_rx_data_ind_pdtch(struct gprs_rlcmac_bts *bts, uint8_t trx_no, uint8_t ts_no, uint8_t *data,
	uint8_t len, uint32_t fn, struct pcu_l1_meas *meas)
{
	struct gprs_rlcmac_pdch *pdch;

	pdch = &bts->trx[trx_no].pdch[ts_no];
	return pdch->rcv_block(data, len, fn, meas);
}

static int pcu_rx_data_ind_bcch(struct gprs_rlcmac_bts *bts, uint8_t *data, uint8_t len)
{
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
		case GSM48_MT_RR_SYSINFO_3:
			memcpy(bts->si3, data, GSM_MACBLOCK_LEN);
			bts->si3_is_set = true;
			break;
		case GSM48_MT_RR_SYSINFO_13:
			memcpy(bts->si13, data, GSM_MACBLOCK_LEN);
			bts->si13_is_set = true;
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
	uint8_t gsmtap_chantype;

	LOGP(DL1IF, LOGL_DEBUG, "Data indication received: sapi=%d arfcn=%d "
		"fn=%d cur_fn=%d block=%d data=%s\n", data_ind->sapi,
		data_ind->arfcn, data_ind->fn, current_fn, data_ind->block_nr,
		osmo_hexdump(data_ind->data, data_ind->len));

	switch (data_ind->sapi) {
	case PCU_IF_SAPI_PDTCH:
		pcu_l1_meas_set_rssi(&meas, data_ind->rssi);
		/* convert BER to % value */
		pcu_l1_meas_set_ber(&meas, data_ind->ber10k / 100);
		pcu_l1_meas_set_bto(&meas, data_ind->ta_offs_qbits);
		pcu_l1_meas_set_link_qual(&meas, data_ind->lqual_cb / 10);

		LOGP(DL1IF, LOGL_DEBUG, "Data indication with raw measurements received: BER10k = %d, BTO = %d, Q = %d\n",
		     data_ind->ber10k, data_ind->ta_offs_qbits, data_ind->lqual_cb);

		rc = pcu_rx_data_ind_pdtch(bts, data_ind->trx_nr, data_ind->ts_nr,
			data_ind->data, data_ind->len, data_ind->fn,
			&meas);
		gsmtap_chantype = GSMTAP_CHANNEL_PDTCH;
		break;
	case PCU_IF_SAPI_BCCH:
		rc = pcu_rx_data_ind_bcch(bts, data_ind->data, data_ind->len);
		gsmtap_chantype = GSMTAP_CHANNEL_BCCH;
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data indication with "
			"unsupported sapi %d\n", data_ind->sapi);
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
		if (data_cnf->data[2] == 0x3f)
			bts_rcv_imm_ass_cnf(bts, data_cnf->data, data_cnf->fn);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data confirm with "
			"unsupported sapi %d\n", data_cnf->sapi);
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
	if (!pdch->m_is_enabled)
		return -EAGAIN;

	pcu_l1if_tx_ptcch(bts, trx, ts, bts->trx[trx].arfcn, fn, block_nr,
			  pdch->ptcch_msg, GSM_MACBLOCK_LEN);
	return 0;
}

static int pcu_rx_rts_req(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_rts_req *rts_req)
{
	int rc = 0;
	int current_fn = bts_current_frame_number(bts);

	LOGP(DL1IF, LOGL_DEBUG, "RTS request received: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d cur_fn=%d block=%d\n", rts_req->trx_nr, rts_req->ts_nr,
		rts_req->sapi, rts_req->arfcn, rts_req->fn, current_fn, rts_req->block_nr);

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
		LOGP(DL1IF, LOGL_ERROR, "Received PCU RTS request with "
			"unsupported sapi %d\n", rts_req->sapi);
		rc = -EINVAL;
	}

	return rc;
}

/* C -> C++ adapter for direct DSP access code (e.g. osmo-bts-sysmo) */
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

	if (info_ind->version != PCU_IF_VERSION) {
		fprintf(stderr, "PCU interface version number of BTS (%u) is "
			"different (%u).\nPlease re-compile!\n",
			info_ind->version, PCU_IF_VERSION);
		exit(-1);
	}

	LOGP(DL1IF, LOGL_DEBUG, "Info indication received:\n");

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
				bts->trx[trx_nr].pdch[ts_nr].free_resources();
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
					bts->trx[trx_nr].fl1h = l1if_open_pdch(
						trx_nr,
						info_ind->trx[trx_nr].hlayer1,
						the_pcu->gsmtap);
			if (!bts->trx[trx_nr].fl1h) {
				LOGP(DL1IF, LOGL_FATAL, "Failed to open direct "
					"DSP access for PDCH.\n");
				exit(0);
			}
#else
			LOGP(DL1IF, LOGL_FATAL, "Compiled without direct DSP "
					"access for PDCH, but enabled at "
					"BTS. Please deactivate it!\n");
			exit(0);
#endif
		}

		for (ts_nr = 0; ts_nr < ARRAY_SIZE(bts->trx[0].pdch); ts_nr++) {
			const struct gsm_pcu_if_info_ts *its = &info_ind->trx[trx_nr].ts[ts_nr];
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
					pcu_tx_act_req(bts, trx_nr, ts_nr, 1);
					pdch->enable();
				}

				pdch->tsc = its->tsc;

				/* (Optional) frequency hopping parameters */
				if (its->h) {
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
					pcu_tx_act_req(bts, trx_nr, ts_nr, 0);
					pdch->free_resources();
					pdch->disable();
				}
			}
		}
	}

	bts->active = true;
	return rc;
}

static int pcu_rx_time_ind(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_time_ind *time_ind)
{
	uint8_t fn13 = time_ind->fn % 13;

	/* omit frame numbers not starting at a MAC block */
	if (fn13 != 0 && fn13 != 4 && fn13 != 8)
		return 0;

	LOGP(DL1IF, LOGL_DEBUG, "Time indication received: %d\n", time_ind->fn % 52);

	bts_set_current_frame_number(bts, time_ind->fn);
	return 0;
}

static int pcu_rx_pag_req(struct gprs_rlcmac_bts *bts, struct gsm_pcu_if_pag_req *pag_req)
{
	struct osmo_mobile_identity mi;
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

	return bts_add_paging(bts, pag_req->chan_needed, &mi);
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

	if ((ms = bts_ms_store(bts)->get_ms(susp_req->tlli))) {
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
	llist_for_each(tmp, bts_ms_store(bts)->ms_list()) {
		GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
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

int pcu_rx(uint8_t msg_type, struct gsm_pcu_if *pcu_prim)
{
	int rc = 0;
	struct gprs_rlcmac_bts *bts = gprs_pcu_get_bts_by_nr(the_pcu, pcu_prim->bts_nr);
	if (!bts) {
		LOGP(DL1IF, LOGL_NOTICE, "Received message for new BTS%d\n", pcu_prim->bts_nr);
		bts = bts_alloc(the_pcu, pcu_prim->bts_nr);
		if (!bts) {
			LOGP(DL1IF, LOGL_ERROR, "Failed to create object for BTS%d!\n", pcu_prim->bts_nr);
			return -EAGAIN;
		}
	}

	switch (msg_type) {
	case PCU_IF_MSG_DATA_IND:
		rc = pcu_rx_data_ind(bts, &pcu_prim->u.data_ind);
		break;
	case PCU_IF_MSG_DATA_CNF:
		rc = pcu_rx_data_cnf(bts, &pcu_prim->u.data_cnf);
		break;
	case PCU_IF_MSG_RTS_REQ:
		rc = pcu_rx_rts_req(bts, &pcu_prim->u.rts_req);
		break;
	case PCU_IF_MSG_RACH_IND:
		rc = pcu_rx_rach_ind(bts, &pcu_prim->u.rach_ind);
		break;
	case PCU_IF_MSG_INFO_IND:
		rc = pcu_rx_info_ind(bts, &pcu_prim->u.info_ind);
		break;
	case PCU_IF_MSG_TIME_IND:
		rc = pcu_rx_time_ind(bts, &pcu_prim->u.time_ind);
		break;
	case PCU_IF_MSG_PAG_REQ:
		rc = pcu_rx_pag_req(bts, &pcu_prim->u.pag_req);
		break;
	case PCU_IF_MSG_SUSP_REQ:
		rc = pcu_rx_susp_req(bts, &pcu_prim->u.susp_req);
		break;
	case PCU_IF_MSG_APP_INFO_REQ:
		rc = pcu_rx_app_info_req(bts, &pcu_prim->u.app_info_req);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received unknown PCU msg type %d\n",
			msg_type);
		rc = -EINVAL;
	}

	return rc;
}
