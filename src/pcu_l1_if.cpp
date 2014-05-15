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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
}

#include <gprs_rlcmac.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <pcuif_proto.h>
#include <bts.h>
#include <tbf.h>

// FIXME: move this, when changed from c++ to c.
extern "C" {
void *l1if_open_pdch(void *priv, uint32_t hlayer1);
int l1if_connect_pdch(void *obj, uint8_t ts);
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn,
        uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len);
}

extern void *tall_pcu_ctx;

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

	LOGP(DL1IF, LOGL_DEBUG, "Sending data request: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d block=%d data=%s\n", trx, ts, sapi, arfcn, fn,
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
#ifdef ENABLE_SYSMODSP
	struct gprs_rlcmac_bts *bts = bts_main_data();

	if (bts->trx[trx].fl1h)
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 0, fn, arfcn, block_nr,
			msg->data, msg->len);
	else
#endif
		pcu_tx_data_req(trx, ts, PCU_IF_SAPI_PDTCH, arfcn, fn, block_nr,
			msg->data, msg->len);
	msgb_free(msg);
}

void pcu_l1if_tx_ptcch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
#ifdef ENABLE_SYSMODSP
	struct gprs_rlcmac_bts *bts = bts_main_data();

	if (bts->trx[trx].fl1h)
		l1if_pdch_req(bts->trx[trx].fl1h, ts, 1, fn, arfcn, block_nr,
			msg->data, msg->len);
	else
#endif
		pcu_tx_data_req(trx, ts, PCU_IF_SAPI_PTCCH, arfcn, fn, block_nr,
			msg->data, msg->len);
	msgb_free(msg);
}

void pcu_l1if_tx_agch(bitvec * block, int plen)
{
	uint8_t data[23]; /* prefix PLEN */
	
	/* FIXME: why does OpenBTS has no PLEN and no fill in message? */
	bitvec_pack(block, data + 1);
	data[0] = (plen << 2) | 0x01;
	pcu_tx_data_req(0, 0, PCU_IF_SAPI_AGCH, 0, 0, 0, data, 23);
}

void pcu_l1if_tx_pch(bitvec * block, int plen, const char *imsi)
{
	uint8_t data[23+3]; /* prefix PLEN */

	/* paging group */
	if (!imsi || strlen(imsi) < 3)
		return;
	imsi += strlen(imsi) - 3;
	data[0] = imsi[0];
	data[1] = imsi[1];
	data[2] = imsi[2];

	bitvec_pack(block, data + 3+1);
	data[3] = (plen << 2) | 0x01;
	pcu_tx_data_req(0, 0, PCU_IF_SAPI_PCH, 0, 0, 0, data, 23+3);
}

extern "C" int pcu_rx_data_ind_pdtch(uint8_t trx_no, uint8_t ts_no, uint8_t *data,
	uint8_t len, uint32_t fn, int8_t rssi)
{
	struct gprs_rlcmac_pdch *pdch;

	pdch = &bts_main_data()->trx[trx_no].pdch[ts_no];
	return pdch->rcv_block(data, len, fn, rssi);
}

static int pcu_rx_data_ind(struct gsm_pcu_if_data *data_ind)
{
	int rc = 0;

	LOGP(DL1IF, LOGL_DEBUG, "Data indication received: sapi=%d arfcn=%d "
		"block=%d data=%s\n", data_ind->sapi,
		data_ind->arfcn, data_ind->block_nr,
		osmo_hexdump(data_ind->data, data_ind->len));

	switch (data_ind->sapi) {
	case PCU_IF_SAPI_PDTCH:
		rc = pcu_rx_data_ind_pdtch(data_ind->trx_nr, data_ind->ts_nr,
			data_ind->data, data_ind->len, data_ind->fn,
			data_ind->rssi);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data indication with "
			"unsupported sapi %d\n", data_ind->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_rx_data_cnf(struct gsm_pcu_if_data *data_cnf)
{
	int rc = 0;

	LOGP(DL1IF, LOGL_DEBUG, "Data confirm received: sapi=%d fn=%d\n",
		data_cnf->sapi, data_cnf->fn);

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
extern "C" int pcu_rx_rts_req_pdtch(uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
	return gprs_rlcmac_rcv_rts_block(bts_main_data(),
					trx, ts, arfcn, fn, block_nr);
}

static int pcu_rx_rts_req(struct gsm_pcu_if_rts_req *rts_req)
{
	int rc = 0;

	LOGP(DL1IF, LOGL_DEBUG, "RTS request received: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d block=%d\n", rts_req->trx_nr, rts_req->ts_nr,
		rts_req->sapi, rts_req->arfcn, rts_req->fn, rts_req->block_nr);

	switch (rts_req->sapi) {
	case PCU_IF_SAPI_PDTCH:
		pcu_rx_rts_req_pdtch(rts_req->trx_nr, rts_req->ts_nr,
			rts_req->arfcn, rts_req->fn, rts_req->block_nr);
		break;
	case PCU_IF_SAPI_PTCCH:
		/* FIXME */
		{
			struct msgb *msg = msgb_alloc(23, "l1_prim");
			memset(msgb_put(msg, 23), 0x2b, 23);
			pcu_l1if_tx_ptcch(msg, rts_req->trx_nr, rts_req->ts_nr,
				rts_req->arfcn, rts_req->fn, rts_req->block_nr);
		}
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU RTS request with "
			"unsupported sapi %d\n", rts_req->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_rx_rach_ind(struct gsm_pcu_if_rach_ind *rach_ind)
{
	int rc = 0;

	LOGP(DL1IF, LOGL_INFO, "RACH request received: sapi=%d "
		"qta=%d, ra=%d, fn=%d\n", rach_ind->sapi, rach_ind->qta,
		rach_ind->ra, rach_ind->fn);

	switch (rach_ind->sapi) {
	case PCU_IF_SAPI_RACH:
		rc = BTS::main_bts()->rcv_rach(
			rach_ind->ra, rach_ind->fn,
			rach_ind->qta);
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
	struct in_addr ia;
	int rc = 0;
	int trx, ts;
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
bssgp_failed:
		/* free all TBF */
		for (trx = 0; trx < 8; trx++) {
			bts->trx[trx].arfcn = info_ind->trx[trx].arfcn;
			for (ts = 0; ts < 8; ts++)
				bts->trx[trx].pdch[ts].free_resources();
		}
		gprs_bssgp_destroy_or_exit();
		return 0;
	}
	LOGP(DL1IF, LOGL_INFO, "BTS available\n");
	LOGP(DL1IF, LOGL_DEBUG, " mcc=%x\n", info_ind->mcc);
	LOGP(DL1IF, LOGL_DEBUG, " mnc=%x\n", info_ind->mnc);
	LOGP(DL1IF, LOGL_DEBUG, " lac=%d\n", info_ind->lac);
	LOGP(DL1IF, LOGL_DEBUG, " rac=%d\n", info_ind->rac);
	LOGP(DL1IF, LOGL_DEBUG, " cell_id=%d\n", ntohs(info_ind->cell_id));
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
	LOGP(DL1IF, LOGL_DEBUG, " nsvci=%d\n", info_ind->nsvci[0]);
	LOGP(DL1IF, LOGL_DEBUG, " local_port=%d\n", info_ind->local_port[0]);
	LOGP(DL1IF, LOGL_DEBUG, " remote_port=%d\n", info_ind->remote_port[0]);
	ia.s_addr = htonl(info_ind->remote_ip[0]);
	LOGP(DL1IF, LOGL_DEBUG, " remote_ip=%s\n", inet_ntoa(ia));

	pcu = gprs_bssgp_create_and_connect(bts, info_ind->local_port[0],
		info_ind->remote_ip[0], info_ind->remote_port[0],
		info_ind->nsei, info_ind->nsvci[0], info_ind->bvci,
		info_ind->mcc, info_ind->mnc, info_ind->lac, info_ind->rac,
		info_ind->cell_id);
	if (!pcu) {
		LOGP(DL1IF, LOGL_NOTICE, "SGSN not available\n");
		goto bssgp_failed;
	}

	bts->cs1 = !!(info_ind->flags & PCU_IF_FLAG_CS1);
	bts->cs2 = !!(info_ind->flags & PCU_IF_FLAG_CS2);
	bts->cs3 = !!(info_ind->flags & PCU_IF_FLAG_CS3);
	bts->cs4 = !!(info_ind->flags & PCU_IF_FLAG_CS4);
	if (!bts->cs1 && !bts->cs2 && !bts->cs3 && !bts->cs4)
		bts->cs1 = 1;
	if (info_ind->t3142) { /* if timer values are set */
		bts->t3142 = info_ind->t3142;
		bts->t3169 = info_ind->t3169;
		bts->t3191 = info_ind->t3191;
		bts->t3193_msec = info_ind->t3193_10ms * 10;
		bts->t3195 = info_ind->t3195;
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

	for (trx = 0; trx < 8; trx++) {
		bts->trx[trx].arfcn = info_ind->trx[trx].arfcn;
		if ((info_ind->flags & PCU_IF_FLAG_SYSMO)
		 && info_ind->trx[trx].hlayer1) {
#ifdef ENABLE_SYSMODSP
			LOGP(DL1IF, LOGL_DEBUG, " TRX %d hlayer1=%x\n", trx,
				info_ind->trx[trx].hlayer1);
				if (!bts->trx[trx].fl1h)
					bts->trx[trx].fl1h = l1if_open_pdch(
						(void *)trx,
						info_ind->trx[trx].hlayer1);
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

		for (ts = 0; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if ((info_ind->trx[trx].pdch_mask & (1 << ts))) {
				/* FIXME: activate dynamically at RLCMAC */
				if (!pdch->is_enabled()) {
#ifdef ENABLE_SYSMODSP
					if ((info_ind->flags &
							PCU_IF_FLAG_SYSMO))
						l1if_connect_pdch(
							bts->trx[trx].fl1h, ts);
#endif
					pcu_tx_act_req(trx, ts, 1);
					pdch->enable();
				}
				pdch->tsc = info_ind->trx[trx].tsc[ts];
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

	return rc;
}

static int pcu_rx_time_ind(struct gsm_pcu_if_time_ind *time_ind)
{
	uint8_t fn13 = time_ind->fn % 13;

	/* omit frame numbers not starting at a MAC block */
	if (fn13 != 0 && fn13 != 4 && fn13 != 8)
		return 0;
#warning uncomment
//	LOGP(DL1IF, LOGL_DEBUG, "Time indication received: %d\n",
//		time_ind->fn % 52);

	BTS::main_bts()->set_current_frame_number(time_ind->fn);
	return 0;
}

static int pcu_rx_pag_req(struct gsm_pcu_if_pag_req *pag_req)
{
	LOGP(DL1IF, LOGL_DEBUG, "Paging request received: chan_needed=%d "
		"length=%d\n", pag_req->chan_needed, pag_req->identity_lv[0]);

	return BTS::main_bts()->add_paging(pag_req->chan_needed,
						pag_req->identity_lv);
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
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received unknwon PCU msg type %d\n",
			msg_type);
		rc = -EINVAL;
	}

	return rc;
}
