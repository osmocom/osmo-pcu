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
#include <osmocom/gsm/l1sap.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
}

#include <gprs_rlcmac.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <osmocom/pcu/pcuif_proto.h>
#include <bts.h>
#include <pdch.h>

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

static int pcu_tx_act_req(uint8_t trx, uint8_t ts, uint8_t activate)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_act_req *act_req;

	LOGP(DL1IF, LOGL_INFO, "Sending %s request: trx=%d ts=%d\n",
		(activate) ? "activate" : "deactivate", trx, ts);

	msg = pcu_msgb_alloc(PCU_IF_MSG_ACT_REQ, 0);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	act_req = &pcu_prim->u.act_req;
	act_req->activate = activate;
	act_req->trx_nr = trx;
	act_req->ts_nr = ts;

	return pcu_sock_send(msg);
}

static int pcu_tx_data_req(uint8_t trx, uint8_t ts, uint8_t sapi,
	uint16_t arfcn, uint32_t fn, uint8_t block_nr, uint8_t *data,
	uint8_t len)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_data *data_req;
	int current_fn = get_current_fn();

	LOGP(DL1IF, LOGL_DEBUG, "Sending data request: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d cur_fn=%d block=%d data=%s\n", trx, ts, sapi, arfcn, fn, current_fn,
		block_nr, osmo_hexdump(data, len));

	msg = pcu_msgb_alloc(PCU_IF_MSG_DATA_REQ, 0);
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

void pcu_l1if_tx_pdtch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
#ifdef ENABLE_DIRECT_PHY
	struct gprs_rlcmac_bts *bts = bts_main_data();

	if (bts->trx[trx].fl1h) {
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 0, fn, arfcn, block_nr,
			msg->data, msg->len);
		msgb_free(msg);
		return;
	}
#endif
	pcu_tx_data_req(trx, ts, PCU_IF_SAPI_PDTCH, arfcn, fn, block_nr,
			msg->data, msg->len);
	msgb_free(msg);
}

void pcu_l1if_tx_ptcch(uint8_t trx, uint8_t ts, uint16_t arfcn,
		       uint32_t fn, uint8_t block_nr,
		       uint8_t *data, size_t data_len)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	if (bts->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_PTCCH))
		gsmtap_send(bts->gsmtap, arfcn, ts, GSMTAP_CHANNEL_PTCCH, 0, fn, 0, 0, data, data_len);
#ifdef ENABLE_DIRECT_PHY
	if (bts->trx[trx].fl1h) {
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 1, fn, arfcn, block_nr, data, data_len);
		return;
	}
#endif
	pcu_tx_data_req(trx, ts, PCU_IF_SAPI_PTCCH, arfcn, fn, block_nr, data, data_len);
}

void pcu_l1if_tx_agch(bitvec * block, int plen)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint8_t data[GSM_MACBLOCK_LEN]; /* prefix PLEN */

	/* FIXME: why does OpenBTS has no PLEN and no fill in message? */
	bitvec_pack(block, data + 1);
	data[0] = (plen << 2) | 0x01;

	if (bts->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_AGCH))
		gsmtap_send(bts->gsmtap, 0, 0, GSMTAP_CHANNEL_AGCH, 0, 0, 0, 0, data, GSM_MACBLOCK_LEN);

	pcu_tx_data_req(0, 0, PCU_IF_SAPI_AGCH, 0, 0, 0, data, GSM_MACBLOCK_LEN);
}

void pcu_l1if_tx_pch(bitvec * block, int plen, uint16_t pgroup)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
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

	if (bts->gsmtap_categ_mask & (1 << PCU_GSMTAP_C_DL_PCH))
		gsmtap_send(bts->gsmtap, 0, 0, GSMTAP_CHANNEL_PCH, 0, 0, 0, 0, data + 3, GSM_MACBLOCK_LEN);

	pcu_tx_data_req(0, 0, PCU_IF_SAPI_PCH, 0, 0, 0, data, PAGING_GROUP_LEN + GSM_MACBLOCK_LEN);
}

extern "C" void pcu_rx_block_time(uint16_t arfcn, uint32_t fn, uint8_t ts_no)
{
	BTS::main_bts()->set_current_block_frame_number(fn, 0);
}

extern "C" void pcu_rx_ra_time(uint16_t arfcn, uint32_t fn, uint8_t ts_no)
{
	/* access bursts may arrive some bursts earlier */
	BTS::main_bts()->set_current_block_frame_number(fn, 5);
}

extern "C" int pcu_rx_data_ind_pdtch(uint8_t trx_no, uint8_t ts_no, uint8_t *data,
	uint8_t len, uint32_t fn, struct pcu_l1_meas *meas)
{
	struct gprs_rlcmac_pdch *pdch;

	pdch = &bts_main_data()->trx[trx_no].pdch[ts_no];
	return pdch->rcv_block(data, len, fn, meas);
}

static int pcu_rx_data_ind_bcch(uint8_t *data, uint8_t len)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	if (len == 0) {
		bts->si13_is_set = false;
		LOGP(DL1IF, LOGL_INFO, "Received PCU data indication with empty SI13: cache cleaned\n");
		return 0;
	}

	if (len != GSM_MACBLOCK_LEN) {
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data indication with SI13 with unexpected length %u\n", len);
		return -EINVAL;
	}

	memcpy(bts->si13, data, GSM_MACBLOCK_LEN);
	bts->si13_is_set = true;

	return 0;
}

static int pcu_rx_data_ind(struct gsm_pcu_if_data *data_ind)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	int rc;
	int current_fn = get_current_fn();
	pcu_l1_meas meas;
	uint8_t gsmtap_chantype;

	LOGP(DL1IF, LOGL_DEBUG, "Data indication received: sapi=%d arfcn=%d "
		"fn=%d cur_fn=%d block=%d data=%s\n", data_ind->sapi,
		data_ind->arfcn, data_ind->fn, current_fn, data_ind->block_nr,
		osmo_hexdump(data_ind->data, data_ind->len));

	switch (data_ind->sapi) {
	case PCU_IF_SAPI_PDTCH:
		meas.set_rssi(data_ind->rssi);
		/* convert BER to % value */
		meas.set_ber(data_ind->ber10k / 100);
		meas.set_bto(data_ind->ta_offs_qbits);
		meas.set_link_qual(data_ind->lqual_cb / 10);

		LOGP(DL1IF, LOGL_DEBUG, "Data indication with raw measurements received: BER10k = %d, BTO = %d, Q = %d\n",
		     data_ind->ber10k, data_ind->ta_offs_qbits, data_ind->lqual_cb);

		rc = pcu_rx_data_ind_pdtch(data_ind->trx_nr, data_ind->ts_nr,
			data_ind->data, data_ind->len, data_ind->fn,
			&meas);
		gsmtap_chantype = GSMTAP_CHANNEL_PDTCH;
		break;
	case PCU_IF_SAPI_BCCH:
		rc = pcu_rx_data_ind_bcch(data_ind->data, data_ind->len);
		gsmtap_chantype = GSMTAP_CHANNEL_BCCH;
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data indication with "
			"unsupported sapi %d\n", data_ind->sapi);
		rc = -EINVAL;
		gsmtap_chantype = GSMTAP_CHANNEL_UNKNOWN;
	}

	if (rc < 0 && (bts->gsmtap_categ_mask & (1 <<PCU_GSMTAP_C_UL_UNKNOWN))) {
		gsmtap_send(bts->gsmtap, data_ind->arfcn | GSMTAP_ARFCN_F_UPLINK, data_ind->ts_nr,
			    gsmtap_chantype, 0, data_ind->fn, meas.rssi, meas.link_qual, data_ind->data, data_ind->len);
	}

	return rc;
}

static int pcu_rx_data_cnf(struct gsm_pcu_if_data *data_cnf)
{
	int rc = 0;
	int current_fn = get_current_fn();

	LOGP(DL1IF, LOGL_DEBUG, "Data confirm received: sapi=%d fn=%d cur_fn=%d\n",
		data_cnf->sapi, data_cnf->fn, current_fn);

	switch (data_cnf->sapi) {
	case PCU_IF_SAPI_PCH:
		if (data_cnf->data[2] == 0x3f)
			BTS::main_bts()->rcv_imm_ass_cnf(data_cnf->data, data_cnf->fn);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data confirm with "
			"unsupported sapi %d\n", data_cnf->sapi);
		rc = -EINVAL;
	}

	return rc;
}

// FIXME: remove this, when changed from c++ to c.
extern "C" int pcu_rx_rts_req_pdtch(uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr)
{
	return gprs_rlcmac_rcv_rts_block(bts_main_data(),
					trx, ts, fn, block_nr);
}
extern "C" int pcu_rx_rts_req_ptcch(uint8_t trx, uint8_t ts,
	uint32_t fn, uint8_t block_nr)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	struct gprs_rlcmac_pdch *pdch;

	/* Prevent buffer overflow */
	if (trx >= ARRAY_SIZE(bts->trx) || ts >= 8)
		return -EINVAL;

	/* Make sure PDCH time-slot is enabled */
	pdch = &bts->trx[trx].pdch[ts];
	if (!pdch->m_is_enabled)
		return -EAGAIN;

	pcu_l1if_tx_ptcch(trx, ts, bts->trx[trx].arfcn, fn, block_nr,
			  pdch->ptcch_msg, GSM_MACBLOCK_LEN);
	return 0;
}

static int pcu_rx_rts_req(struct gsm_pcu_if_rts_req *rts_req)
{
	int rc = 0;
	int current_fn = get_current_fn();

	LOGP(DL1IF, LOGL_DEBUG, "RTS request received: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d cur_fn=%d block=%d\n", rts_req->trx_nr, rts_req->ts_nr,
		rts_req->sapi, rts_req->arfcn, rts_req->fn, current_fn, rts_req->block_nr);

	switch (rts_req->sapi) {
	case PCU_IF_SAPI_PDTCH:
		pcu_rx_rts_req_pdtch(rts_req->trx_nr, rts_req->ts_nr,
			rts_req->fn, rts_req->block_nr);
		break;
	case PCU_IF_SAPI_PTCCH:
		pcu_rx_rts_req_ptcch(rts_req->trx_nr, rts_req->ts_nr,
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
extern "C" int pcu_rx_rach_ind_ptcch(uint8_t trx_nr, uint8_t ts_nr, uint32_t fn, int16_t qta)
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

	return BTS::main_bts()->rcv_ptcch_rach(&rip);
}

static int pcu_rx_rach_ind(const struct gsm_pcu_if_rach_ind *rach_ind)
{
	int rc = 0;
	int current_fn = get_current_fn();

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
		rc = BTS::main_bts()->rcv_rach(&rip);
		break;
	case PCU_IF_SAPI_PTCCH:
		rc = BTS::main_bts()->rcv_ptcch_rach(&rip);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU rach request with "
			"unsupported sapi %d\n", rach_ind->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_rx_info_ind(struct gsm_pcu_if_info_ind *info_ind)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	struct gprs_bssgp_pcu *pcu;
	struct gprs_rlcmac_pdch *pdch;
	struct osmo_sockaddr local_sockaddr, remote_sockaddr;
	struct osmo_sockaddr_str local;
	struct in_addr ia;
	int rc = 0;
	int good_nsvc = 0;
	unsigned int trx, ts;
	int i;

	if (info_ind->version != PCU_IF_VERSION) {
		fprintf(stderr, "PCU interface version number of BTS (%d) is "
			"different (%d).\nPlease re-compile!\n",
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
		for (trx = 0; trx < ARRAY_SIZE(bts->trx); trx++) {
			bts->trx[trx].arfcn = info_ind->trx[trx].arfcn;
			for (ts = 0; ts < ARRAY_SIZE(bts->trx[0].pdch); ts++)
				bts->trx[trx].pdch[ts].free_resources();
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
	bts->bsic = info_ind->bsic;
	for (i = 0; i < 4; i++) {
		if ((info_ind->flags & (PCU_IF_FLAG_CS1 << i)))
			LOGP(DL1IF, LOGL_DEBUG, " Use CS%d\n", i+1);
	}
	for (i = 0; i < 9; i++) {
		if ((info_ind->flags & (PCU_IF_FLAG_MCS1 << i)))
			LOGP(DL1IF, LOGL_DEBUG, " Use MCS%d\n", i+1);
	}
	LOGP(DL1IF, LOGL_DEBUG, " initial_cs=%d\n", info_ind->initial_cs);
	LOGP(DL1IF, LOGL_DEBUG, " initial_mcs=%d\n", info_ind->initial_mcs);

	pcu = gprs_bssgp_init(
			bts,
			info_ind->nsei, info_ind->bvci,
			info_ind->mcc, info_ind->mnc, info_ind->mnc_3_digits,
			info_ind->lac, info_ind->rac, info_ind->cell_id);
	if (!pcu) {
		LOGP(DL1IF, LOGL_NOTICE, "Failed to init BSSGP\n");
		goto bssgp_failed;
	}

	for (int i=0; i<2; i++) {
		struct osmo_sockaddr_str sockstr;

		switch (info_ind->remote_proto[i]) {
		case IPPROTO_IPIP:
			local_sockaddr.u.sin.sin_family = AF_INET;
			local_sockaddr.u.sin.sin_addr.s_addr = INADDR_ANY;
			local_sockaddr.u.sin.sin_port = htons(info_ind->local_port[i]);

			remote_sockaddr.u.sin.sin_family = AF_INET;
			remote_sockaddr.u.sin.sin_addr = info_ind->remote_ip[i].ipv4;
			remote_sockaddr.u.sin.sin_port = htons(info_ind->remote_port[i]);
			break;
		case IPPROTO_IPV6:
			local_sockaddr.u.sin6.sin6_family = AF_INET6;
			local_sockaddr.u.sin6.sin6_addr = in6addr_any;
			local_sockaddr.u.sin6.sin6_port = htons(info_ind->local_port[i]);

			remote_sockaddr.u.sin6.sin6_family = AF_INET6;
			remote_sockaddr.u.sin6.sin6_addr = info_ind->remote_ip[i].ipv6;
			remote_sockaddr.u.sin6.sin6_port = htons(info_ind->remote_port[i]);
			break;
		default:
			continue;
		}

		LOGP(DL1IF, LOGL_DEBUG, " NS%d nsvci=%d\n", i, info_ind->nsvci[i]);
		LOGP(DL1IF, LOGL_DEBUG, " NS%d local_port=%d\n", i, info_ind->local_port[i]);
		LOGP(DL1IF, LOGL_DEBUG, " NS%d remote_port=%d\n", i, info_ind->remote_port[i]);

		if (osmo_sockaddr_str_from_sockaddr(&sockstr, &remote_sockaddr.u.sas))
			strcpy(sockstr.ip, "invalid");

		LOGP(DL1IF, LOGL_DEBUG, " NS%d remote_ip=%s\n", i, sockstr.ip);
		rc = gprs_nsvc_create_and_connect(bts,
						  &local_sockaddr, &remote_sockaddr,
						  info_ind->nsei, info_ind->nsvci[i]);
		if (rc) {
			LOGP(DL1IF, LOGL_ERROR, "Failed to create NSVC connection to %s:%d!\n",
			     sockstr.ip, sockstr.port);
			continue;
		}

		good_nsvc++;
	}

	if (good_nsvc == 0) {
		LOGP(DL1IF, LOGL_ERROR, "No NSVC available to connect to the SGSN!\n");
		goto bssgp_failed;
	}



	bts->cs1 = !!(info_ind->flags & PCU_IF_FLAG_CS1);
	bts->cs2 = !!(info_ind->flags & PCU_IF_FLAG_CS2);
	bts->cs3 = !!(info_ind->flags & PCU_IF_FLAG_CS3);
	bts->cs4 = !!(info_ind->flags & PCU_IF_FLAG_CS4);
	if (!bts->cs1 && !bts->cs2 && !bts->cs3 && !bts->cs4)
		bts->cs1 = 1;
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
	if (!bts->force_cs) {
		if (info_ind->initial_cs < 1 || info_ind->initial_cs > 4)
			bts->initial_cs_dl = 1;
		else
			bts->initial_cs_dl = info_ind->initial_cs;
		bts->initial_cs_ul = bts->initial_cs_dl;
	}

	for (trx = 0; trx < ARRAY_SIZE(bts->trx); trx++) {
		bts->trx[trx].arfcn = info_ind->trx[trx].arfcn;
		if ((info_ind->flags & PCU_IF_FLAG_SYSMO)
		 && info_ind->trx[trx].hlayer1) {
#ifdef ENABLE_DIRECT_PHY
			LOGP(DL1IF, LOGL_DEBUG, " TRX %d hlayer1=%x\n", trx,
				info_ind->trx[trx].hlayer1);
				if (!bts->trx[trx].fl1h)
					bts->trx[trx].fl1h = l1if_open_pdch(
						trx,
						info_ind->trx[trx].hlayer1,
						bts->gsmtap);
			if (!bts->trx[trx].fl1h) {
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

		for (ts = 0; ts < ARRAY_SIZE(bts->trx[0].pdch); ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if ((info_ind->trx[trx].pdch_mask & (1 << ts))) {
				/* FIXME: activate dynamically at RLCMAC */
				if (!pdch->is_enabled()) {
#ifdef ENABLE_DIRECT_PHY
					if ((info_ind->flags &
							PCU_IF_FLAG_SYSMO))
						l1if_connect_pdch(
							bts->trx[trx].fl1h, ts);
#endif
					pcu_tx_act_req(trx, ts, 1);
					pdch->enable();
				}
				pdch->tsc = info_ind->trx[trx].ts[ts].tsc;
				LOGP(DL1IF, LOGL_INFO, "PDCH: trx=%d ts=%d\n",
					trx, ts);
			} else {
				if (pdch->is_enabled()) {
					pcu_tx_act_req(trx, ts, 0);
					pdch->free_resources();
					pdch->disable();
				}
			}
		}
	}

	bts->active = true;
	return rc;
}

static int pcu_rx_time_ind(struct gsm_pcu_if_time_ind *time_ind)
{
	uint8_t fn13 = time_ind->fn % 13;

	/* omit frame numbers not starting at a MAC block */
	if (fn13 != 0 && fn13 != 4 && fn13 != 8)
		return 0;

	LOGP(DL1IF, LOGL_DEBUG, "Time indication received: %d\n", time_ind->fn % 52);

	BTS::main_bts()->set_current_frame_number(time_ind->fn);
	return 0;
}

static int pcu_rx_pag_req(struct gsm_pcu_if_pag_req *pag_req)
{
	LOGP(DL1IF, LOGL_DEBUG, "Paging request received: chan_needed=%d "
		"length=%d\n", pag_req->chan_needed, pag_req->identity_lv[0]);

	/* check if identity does not fit: length > sizeof(lv) - 1 */
	if (pag_req->identity_lv[0] >= sizeof(pag_req->identity_lv)) {
		LOGP(DL1IF, LOGL_ERROR, "Paging identity too large (%" PRIu8 ")\n",
			pag_req->identity_lv[0]);
		return -EINVAL;
	}

	return BTS::main_bts()->add_paging(pag_req->chan_needed, &pag_req->identity_lv[1],
					   pag_req->identity_lv[0]);
}

static int pcu_rx_susp_req(struct gsm_pcu_if_susp_req *susp_req)
{
	struct bssgp_bvc_ctx *bctx = gprs_bssgp_pcu_current_bctx();
	struct gprs_ra_id ra_id;

	gsm48_parse_ra(&ra_id, susp_req->ra_id);

	LOGP(DL1IF, LOGL_INFO, "GPRS Suspend request received: TLLI=0x%08x RAI=%s\n",
		susp_req->tlli, osmo_rai_name(&ra_id));

	if (!bctx)
		return -1;

	return bssgp_tx_suspend(bctx->nsei, susp_req->tlli, &ra_id);
}

static int pcu_rx_app_info_req(struct gsm_pcu_if_app_info_req *app_info_req)
{
	LListHead<GprsMs> *ms_iter;
	BTS *bts = BTS::main_bts();
	struct gprs_rlcmac_bts *bts_data = bts->bts_data();

	LOGP(DL1IF, LOGL_DEBUG, "Application Information Request received: type=0x%08x len=%i\n",
	     app_info_req->application_type, app_info_req->len);

	bts_data->app_info_pending = 0;
	llist_for_each(ms_iter, &bts->ms_store().ms_list()) {
		GprsMs *ms = ms_iter->entry();
		if (!ms->dl_tbf())
			continue;
		bts_data->app_info_pending++;
		ms->app_info_pending = true;
	}

	if (!bts_data->app_info_pending) {
		LOGP(DL1IF, LOGL_NOTICE, "Packet Application Information will not be sent, no subscribers with active"
		     " TBF\n");
		return -1;
	}

	if (bts_data->app_info) {
		LOGP(DL1IF, LOGL_NOTICE, "Previous Packet Application Information was not sent to all subscribers,"
		     " overwriting with new one\n");
		msgb_free(bts_data->app_info);
	}

	LOGP(DL1IF, LOGL_INFO, "Sending Packet Application Information to %i subscribers with active TBF\n",
	     bts_data->app_info_pending);
	bts_data->app_info = gprs_rlcmac_app_info_msg(app_info_req);
	return 0;
}

int pcu_rx(uint8_t msg_type, struct gsm_pcu_if *pcu_prim)
{
	int rc = 0;

	switch (msg_type) {
	case PCU_IF_MSG_DATA_IND:
		rc = pcu_rx_data_ind(&pcu_prim->u.data_ind);
		break;
	case PCU_IF_MSG_DATA_CNF:
		rc = pcu_rx_data_cnf(&pcu_prim->u.data_cnf);
		break;
	case PCU_IF_MSG_RTS_REQ:
		rc = pcu_rx_rts_req(&pcu_prim->u.rts_req);
		break;
	case PCU_IF_MSG_RACH_IND:
		rc = pcu_rx_rach_ind(&pcu_prim->u.rach_ind);
		break;
	case PCU_IF_MSG_INFO_IND:
		rc = pcu_rx_info_ind(&pcu_prim->u.info_ind);
		break;
	case PCU_IF_MSG_TIME_IND:
		rc = pcu_rx_time_ind(&pcu_prim->u.time_ind);
		break;
	case PCU_IF_MSG_PAG_REQ:
		rc = pcu_rx_pag_req(&pcu_prim->u.pag_req);
		break;
	case PCU_IF_MSG_SUSP_REQ:
		rc = pcu_rx_susp_req(&pcu_prim->u.susp_req);
		break;
	case PCU_IF_MSG_APP_INFO_REQ:
		rc = pcu_rx_app_info_req(&pcu_prim->u.app_info_req);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received unknown PCU msg type %d\n",
			msg_type);
		rc = -EINVAL;
	}

	return rc;
}
