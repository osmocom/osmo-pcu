/* Copyright (C) 2015 by Yves Godin <support@nuranwireless.com>
 * based on:
 *     femto_l1_if.c
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <string.h>
#include <errno.h>

#include <nrw/litecell15/litecell15.h>
#include <nrw/litecell15/gsml1prim.h>
#include <nrw/litecell15/gsml1const.h>
#include <nrw/litecell15/gsml1types.h>

#include <osmocom/core/gsmtap.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <lc15_l1_if.h>
#include <gprs_debug.h>
#include <pcu_l1_if.h>
#include <pdch.h>
#include <bts.h>

extern void *tall_pcu_ctx;

uint32_t l1if_ts_to_hLayer2(uint8_t trx, uint8_t ts)
{
	return (ts << 16) | (trx << 24);
}

/* allocate a msgb containing a GsmL1_Prim_t */
struct msgb *l1p_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc(sizeof(GsmL1_Prim_t), "l1_prim");

	if (msg)
		msg->l1h = msgb_put(msg, sizeof(GsmL1_Prim_t));

	return msg;
}

static int l1if_req_pdch(struct lc15l1_hdl *fl1h, struct msgb *msg)
{
	struct osmo_wqueue *wqueue = &fl1h->write_q[MQ_PDTCH_WRITE];

	if (osmo_wqueue_enqueue(wqueue, msg) != 0) {
		LOGP(DL1IF, LOGL_ERROR, "PDTCH queue full. dropping message.\n");
		msgb_free(msg);
	}

	return 0;
}

static void *prim_init(GsmL1_Prim_t *prim, GsmL1_PrimId_t id, struct lc15l1_hdl *gl1)
{
	prim->id = id;

	switch (id) {
	case GsmL1_PrimId_MphInitReq:
		//prim->u.mphInitReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphCloseReq:
		prim->u.mphCloseReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphConnectReq:
		prim->u.mphConnectReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphDisconnectReq:
		prim->u.mphDisconnectReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphActivateReq:
		prim->u.mphActivateReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphDeactivateReq:
		prim->u.mphDeactivateReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphConfigReq:
		prim->u.mphConfigReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphMeasureReq:
		prim->u.mphMeasureReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_MphInitCnf:
	case GsmL1_PrimId_MphCloseCnf:
	case GsmL1_PrimId_MphConnectCnf:
	case GsmL1_PrimId_MphDisconnectCnf:
	case GsmL1_PrimId_MphActivateCnf:
	case GsmL1_PrimId_MphDeactivateCnf:
	case GsmL1_PrimId_MphConfigCnf:
	case GsmL1_PrimId_MphMeasureCnf:
		break;
	case GsmL1_PrimId_MphTimeInd:
		break;
	case GsmL1_PrimId_MphSyncInd:
		break;
	case GsmL1_PrimId_PhEmptyFrameReq:
		prim->u.phEmptyFrameReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_PhDataReq:
		prim->u.phDataReq.hLayer1 = (HANDLE)gl1->hLayer1;
		break;
	case GsmL1_PrimId_PhConnectInd:
		break;
	case GsmL1_PrimId_PhReadyToSendInd:
		break;
	case GsmL1_PrimId_PhDataInd:
		break;
	case GsmL1_PrimId_PhRaInd:
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "unknown L1 primitive %u\n", id);
		break;
	}
	return &prim->u;
}

/* connect PDTCH */
int l1if_connect_pdch(void *obj, uint8_t ts)
{
	struct lc15l1_hdl *fl1h = obj;
	struct msgb *msg = l1p_msgb_alloc();
	GsmL1_MphConnectReq_t *cr;

	cr = prim_init(msgb_l1prim(msg), GsmL1_PrimId_MphConnectReq, fl1h);
	cr->u8Tn = ts;
	cr->logChComb = GsmL1_LogChComb_XIII;

	return l1if_req_pdch(fl1h, msg);
}

static int handle_ph_readytosend_ind(struct lc15l1_hdl *fl1h,
				     GsmL1_PhReadyToSendInd_t *rts_ind)
{
	struct gsm_time g_time;
	struct gprs_rlcmac_bts *bts;
	int rc = 0;

	gsm_fn2gsmtime(&g_time, rts_ind->u32Fn);

	DEBUGP(DL1IF, "Rx PH-RTS.ind %02u/%02u/%02u SAPI=%s\n",
		g_time.t1, g_time.t2, g_time.t3,
		get_value_string(lc15bts_l1sapi_names, rts_ind->sapi));

	bts = llist_first_entry_or_null(&the_pcu->bts_list, struct gprs_rlcmac_bts, list);


	switch (rts_ind->sapi) {
	case GsmL1_Sapi_Pdtch:
	case GsmL1_Sapi_Pacch:
		rc = pcu_rx_rts_req_pdtch(bts, fl1h->trx_no, rts_ind->u8Tn,
			rts_ind->u32Fn, rts_ind->u8BlockNbr);
		break;
	case GsmL1_Sapi_Ptcch:
		rc = pcu_rx_rts_req_ptcch(bts, fl1h->trx_no, rts_ind->u8Tn,
			rts_ind->u32Fn, rts_ind->u8BlockNbr);
		break;
	default:
		break;
	}

	return rc;
}

static void get_meas(struct pcu_l1_meas *meas, const GsmL1_MeasParam_t *l1_meas)
{
	meas->rssi = (int8_t) (l1_meas->fRssi);
	meas->have_rssi = 1;
	meas->ber  = (uint8_t) (l1_meas->fBer * 100);
	meas->have_ber = 1;
	meas->bto  = (int16_t) (l1_meas->i16BurstTiming);
	meas->have_bto = 1;
	meas->link_qual  = (int16_t) (l1_meas->fLinkQuality);
	meas->have_link_qual = 1;
}

static int handle_ph_data_ind(struct lc15l1_hdl *fl1h,
	GsmL1_PhDataInd_t *data_ind, struct msgb *l1p_msg)
{
	int rc = 0;
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_pdch *pdch;
	struct pcu_l1_meas meas = {0};
	uint8_t *data;
	uint8_t data_len;

	DEBUGP(DL1IF, "(trx=%" PRIu8 ",ts=%u) FN=%u Rx PH-DATA.ind %s (hL2 %08x): %s\n",
		fl1h->trx_no, data_ind->u8Tn, data_ind->u32Fn,
		get_value_string(lc15bts_l1sapi_names, data_ind->sapi),
		data_ind->hLayer2,
		osmo_hexdump(data_ind->msgUnitParam.u8Buffer,
			     data_ind->msgUnitParam.u8Size));

	bts = llist_first_entry_or_null(&the_pcu->bts_list, struct gprs_rlcmac_bts, list);

	get_meas(&meas, &data_ind->measParam);
	bts_update_tbf_ta(bts, "PH-DATA", data_ind->u32Fn, fl1h->trx_no,
			  data_ind->u8Tn, sign_qta2ta(meas.bto), false);

	switch (data_ind->sapi) {
	case GsmL1_Sapi_Pdtch:
	case GsmL1_Sapi_Pacch:
		/* PDTCH / PACCH frame handling */
		if (data_ind->msgUnitParam.u8Size != 0 &&
		    data_ind->msgUnitParam.u8Buffer[0] == GsmL1_PdtchPlType_Full) {
			data = data_ind->msgUnitParam.u8Buffer + 1;
			data_len = data_ind->msgUnitParam.u8Size - 1;
			if (data_len == 0)
				data = NULL;
		} else {
			data = NULL;
			data_len = 0;
		}
		pdch = &bts->trx[fl1h->trx_no].pdch[data_ind->u8Tn];
		pcu_rx_data_ind_pdtch(bts, pdch, data, data_len, data_ind->u32Fn, &meas);
		break;
	default:
		LOGP(DL1IF, LOGL_NOTICE,
		     "(trx=%" PRIu8 ",ts=%u) FN=%u Rx PH-DATA.ind for unknown L1 SAPI %s\n",
		     fl1h->trx_no, data_ind->u8Tn, data_ind->u32Fn,
		     get_value_string(lc15bts_l1sapi_names, data_ind->sapi));
		break;
	}

	if (rc < 0) {
		gsmtap_send(fl1h->gsmtap, data_ind->u16Arfcn | GSMTAP_ARFCN_F_UPLINK,
				data_ind->u8Tn, GSMTAP_CHANNEL_PACCH, 0,
				data_ind->u32Fn, 0, 0, data_ind->msgUnitParam.u8Buffer+1,
				data_ind->msgUnitParam.u8Size-1);
	}

	return rc;
}

#define MIN_QUAL_RACH	5.0f

static int handle_ph_ra_ind(struct lc15l1_hdl *fl1h, GsmL1_PhRaInd_t *ra_ind)
{
	struct gprs_rlcmac_bts *bts;
	if (ra_ind->measParam.fLinkQuality < MIN_QUAL_RACH)
		return 0;

	DEBUGP(DL1IF, "Rx PH-RA.ind");

	bts = llist_first_entry_or_null(&the_pcu->bts_list, struct gprs_rlcmac_bts, list);

	switch (ra_ind->sapi) {
	case GsmL1_Sapi_Pdtch:
	case GsmL1_Sapi_Prach:
		bts_update_tbf_ta(bts, "PH-RA", ra_ind->u32Fn, fl1h->trx_no, ra_ind->u8Tn,
				  qta2ta(ra_ind->measParam.i16BurstTiming), true);
		break;
	case GsmL1_Sapi_Ptcch:
		pcu_rx_rach_ind_ptcch(bts, fl1h->trx_no, ra_ind->u8Tn, ra_ind->u32Fn,
				      ra_ind->measParam.i16BurstTiming);
		break;
	default:
		LOGP(DL1IF, LOGL_NOTICE, "Rx PH-RA.ind for unknown L1 SAPI %s\n",
		     get_value_string(lc15bts_l1sapi_names, ra_ind->sapi));
		return -ENOTSUP;
	}

	return 0;
}


/* handle any random indication from the L1 */
int l1if_handle_l1prim(int wq, struct lc15l1_hdl *fl1h, struct msgb *msg)
{
	GsmL1_Prim_t *l1p = msgb_l1prim(msg);
	int rc = 0;

	LOGP(DL1IF, LOGL_DEBUG, "Rx L1 prim %s on queue %d\n",
		get_value_string(lc15bts_l1prim_names, l1p->id), wq);

	switch (l1p->id) {
#if 0
	case GsmL1_PrimId_MphTimeInd:
		rc = handle_mph_time_ind(fl1h, &l1p->u.mphTimeInd);
		break;
	case GsmL1_PrimId_MphSyncInd:
		break;
	case GsmL1_PrimId_PhConnectInd:
		break;
#endif
	case GsmL1_PrimId_PhReadyToSendInd:
		rc = handle_ph_readytosend_ind(fl1h, &l1p->u.phReadyToSendInd);
		break;
	case GsmL1_PrimId_PhDataInd:
		rc = handle_ph_data_ind(fl1h, &l1p->u.phDataInd, msg);
		break;
	case GsmL1_PrimId_PhRaInd:
		rc = handle_ph_ra_ind(fl1h, &l1p->u.phRaInd);
		break;
	default:
		break;
	}

	msgb_free(msg);

	return rc;
}

int l1if_handle_sysprim(struct lc15l1_hdl *fl1h, struct msgb *msg)
{
	return -ENOTSUP;
}

/* send packet data request to L1 */
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn,
	uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len)
{
	struct lc15l1_hdl *fl1h = obj;
	struct msgb *msg;
	GsmL1_Prim_t *l1p;
	GsmL1_PhDataReq_t *data_req;
	GsmL1_MsgUnitParam_t *msu_param;
	struct gsm_time g_time;

	gsm_fn2gsmtime(&g_time, fn);

	DEBUGP(DL1IF, "TX packet data %02u/%02u/%02u is_ptcch=%d ts=%d "
		"block_nr=%d, arfcn=%d, len=%d\n", g_time.t1, g_time.t2,
		g_time.t3, is_ptcch, ts, block_nr, arfcn, len);

	msg = l1p_msgb_alloc();
	l1p = msgb_l1prim(msg);
	l1p->id = GsmL1_PrimId_PhDataReq;
	data_req = &l1p->u.phDataReq;
	data_req->hLayer1 = (HANDLE)fl1h->hLayer1;
	data_req->sapi = (is_ptcch) ? GsmL1_Sapi_Ptcch : GsmL1_Sapi_Pdtch;
	data_req->subCh = GsmL1_SubCh_NA;
	data_req->u8BlockNbr = block_nr;
	data_req->u8Tn = ts;
	data_req->u32Fn = fn;
	msu_param = &data_req->msgUnitParam;
	msu_param->u8Size = len;
	memcpy(msu_param->u8Buffer, data, len);

	/* transmit */
	if (osmo_wqueue_enqueue(&fl1h->write_q[MQ_PDTCH_WRITE], msg) != 0) {
		LOGP(DL1IF, LOGL_ERROR, "PDTCH queue full. dropping message.\n");
		msgb_free(msg);
	}

	return 0;
}

void *l1if_open_pdch(uint8_t trx_no, uint32_t hlayer1, struct gsmtap_inst *gsmtap)
{
	struct lc15l1_hdl *fl1h;
	int rc;

	fl1h = talloc_zero(tall_pcu_ctx, struct lc15l1_hdl);
	if (!fl1h)
		return NULL;

	fl1h->hLayer1 = hlayer1;
	fl1h->trx_no = trx_no;
	/* hardware queues are numbered starting from 0 */
	fl1h->hw_info.trx_nr = trx_no;

	DEBUGP(DL1IF, "PCU: Using TRX HW#%u\n", fl1h->hw_info.trx_nr);

	rc = l1if_transport_open(MQ_PDTCH_WRITE, fl1h);
	if (rc < 0) {
		talloc_free(fl1h);
		return NULL;
	}

	fl1h->gsmtap = gsmtap_source_init("localhost", GSMTAP_UDP_PORT, 1);
	if (fl1h->gsmtap)
		gsmtap_source_add_sink(fl1h->gsmtap);

	return fl1h;
}

int l1if_close_pdch(void *obj)
{
	struct lc15l1_hdl *fl1h = obj;
	if (fl1h)
		l1if_transport_close(MQ_PDTCH_WRITE, fl1h);
	talloc_free(fl1h);
	return 0;
}
