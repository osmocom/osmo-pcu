/* sysmo_l1_if.cpp
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
extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
}

#include <gprs_rlcmac.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include "../../osmo-bts/include/osmo-bts/pcuif_proto.h"

static int pcu_sock_send(struct msgb *msg);
static void pcu_sock_timeout(void *_priv);

// Variable for storage current FN.
int frame_number;

int get_current_fn()
{
	return frame_number;
}

void set_current_fn(int fn)
{
	frame_number = fn;
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
	pcu_tx_data_req(trx, ts, PCU_IF_SAPI_PDTCH, arfcn, fn, block_nr,
		msg->data, msg->len);
	msgb_free(msg);
}

void pcu_l1if_tx_ptcch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn,
	uint32_t fn, uint8_t block_nr)
{
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

static void pcu_l1if_tx_bcch(uint8_t *data, int len)
{
	pcu_tx_data_req(0, 0, PCU_IF_SAPI_BCCH, 0, 0, 0, data, len);
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
		rc = gprs_rlcmac_rcv_block(data_ind->data, data_ind->len,
			data_ind->fn);
		break;
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received PCU data indication with "
			"unsupported sapi %d\n", data_ind->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_rx_rts_req(struct gsm_pcu_if_rts_req *rts_req)
{
	int rc = 0;

	LOGP(DL1IF, LOGL_DEBUG, "RTS request received: trx=%d ts=%d sapi=%d "
		"arfcn=%d fn=%d block=%d\n", rts_req->trx_nr, rts_req->ts_nr,
		rts_req->sapi, rts_req->arfcn, rts_req->fn, rts_req->block_nr);

	switch (rts_req->sapi) {
	case PCU_IF_SAPI_PDTCH:
		gprs_rlcmac_rcv_rts_block(rts_req->trx_nr, rts_req->ts_nr,
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
		rc = gprs_rlcmac_rcv_rach(rach_ind->ra, rach_ind->fn,
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
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	int rc = 0;
	int trx, ts, tfi;
	struct gprs_rlcmac_tbf *tbf;
	int i;

	LOGP(DL1IF, LOGL_DEBUG, "Info indication received:\n");

	if (!(info_ind->flags & PCU_IF_FLAG_ACTIVE)) {
		LOGP(DL1IF, LOGL_NOTICE, "BTS not available\n");
bssgp_failed:
		/* free all TBF */
		for (trx = 0; trx < 8; trx++) {
			bts->trx[trx].arfcn = info_ind->trx[trx].arfcn;
			for (ts = 0; ts < 8; ts++) {
				for (tfi = 0; tfi < 32; tfi++) {
					tbf = bts->trx[trx].pdch[ts].tbf[tfi];
					if (tbf)
						tbf_free(tbf);
				}
			}
		}
		gprs_bssgp_destroy();
		return 0;
	}
	LOGP(DL1IF, LOGL_INFO, "BTS available\n");
	LOGP(DL1IF, LOGL_DEBUG, " mcc=%d\n", info_ind->mcc);
	LOGP(DL1IF, LOGL_DEBUG, " mnc=%d\n", info_ind->mnc);
	LOGP(DL1IF, LOGL_DEBUG, " lac=%d\n", info_ind->lac);
	LOGP(DL1IF, LOGL_DEBUG, " rac=%d\n", info_ind->rac);
	LOGP(DL1IF, LOGL_DEBUG, " cell_id=%d\n", info_ind->cell_id);
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
	LOGP(DL1IF, LOGL_DEBUG, " remote_ip=%d\n", info_ind->remote_ip[0]);

	rc = gprs_bssgp_create(info_ind->remote_ip[0], info_ind->remote_port[0],
		info_ind->nsei, info_ind->nsvci[0], info_ind->bvci,
		info_ind->mcc, info_ind->mnc, info_ind->lac, info_ind->rac,
		info_ind->cell_id);
	if (rc < 0) {
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
	if (info_ind->initial_cs < 1 || info_ind->initial_cs > 4)
		bts->initial_cs = 1;
	else
		bts->initial_cs = info_ind->initial_cs;

	for (trx = 0; trx < 8; trx++) {
		bts->trx[trx].arfcn = info_ind->trx[trx].arfcn;
		for (ts = 0; ts < 8; ts++) {
			if ((info_ind->trx[trx].pdch_mask & (1 << ts))) {
				/* FIXME: activate dynamically at RLCMAC */
				if (!bts->trx[trx].pdch[ts].enable)
					pcu_tx_act_req(trx, ts, 1);
				bts->trx[trx].pdch[ts].enable = 1;
				bts->trx[trx].pdch[ts].tsc =
					info_ind->trx[trx].tsc[ts];
				LOGP(DL1IF, LOGL_INFO, "PDCH: trx=%d ts=%d\n",
					trx, ts);
			} else {
				if (bts->trx[trx].pdch[ts].enable)
					pcu_tx_act_req(trx, ts, 0);
				bts->trx[trx].pdch[ts].enable = 0;
				/* kick all tbf  FIXME: multislot  */
				for (tfi = 0; tfi < 32; tfi++) {
					tbf = bts->trx[trx].pdch[ts].tbf[tfi];
					if (tbf)
						tbf_free(tbf);
				}
			}
		}
	}

	return rc;
}

static int pcu_rx_time_ind(struct gsm_pcu_if_time_ind *time_ind)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	int trx, ts, tfi;
	struct gprs_rlcmac_tbf *tbf;
	uint32_t elapsed;
	uint8_t fn13 = time_ind->fn % 13;

	/* omit frame numbers not starting at a MAC block */
	if (fn13 != 0 && fn13 != 4 && fn13 != 8)
		return 0;

	LOGP(DL1IF, LOGL_DEBUG, "Time indication received: %d\n",
		time_ind->fn % 52);

	set_current_fn(time_ind->fn);

	/* check for poll timeout */
	for (trx = 0; trx < 8; trx++) {
		for (ts = 0; ts < 8; ts++) {
			for (tfi = 0; tfi < 32; tfi++) {
				tbf = bts->trx[trx].pdch[ts].tbf[tfi];
				if (!tbf)
					continue;
				if (tbf->poll_state != GPRS_RLCMAC_POLL_SCHED)
					continue;
				elapsed = (frame_number - tbf->poll_fn)
							% 2715648;
				if (elapsed >= 20 && elapsed < 200)
					gprs_rlcmac_poll_timeout(tbf);
			}
		}
	}

	return 0;
}

static int pcu_rx(uint8_t msg_type, struct gsm_pcu_if *pcu_prim)
{
	int rc = 0;

	switch (msg_type) {
	case PCU_IF_MSG_DATA_IND:
		rc = pcu_rx_data_ind(&pcu_prim->u.data_ind);
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
	default:
		LOGP(DL1IF, LOGL_ERROR, "Received unknwon PCU msg type %d\n",
			msg_type);
		rc = -EINVAL;
	}

	return rc;
}

/*
 * SYSMO-PCU socket functions
 */

struct pcu_sock_state {
	struct osmo_fd conn_bfd;	/* fd for connection to lcr */
	struct osmo_timer_list timer;	/* socket connect retry timer */
	struct llist_head upqueue;	/* queue for sending messages */
} *pcu_sock_state = NULL;

static int pcu_sock_send(struct msgb *msg)
{
	struct pcu_sock_state *state = pcu_sock_state;
	struct osmo_fd *conn_bfd;

	if (!state) {
		LOGP(DL1IF, LOGL_NOTICE, "PCU socket not created, dropping "
			"message\n");
		return -EINVAL;
	}
	conn_bfd = &state->conn_bfd;
	if (conn_bfd->fd <= 0) {
		LOGP(DL1IF, LOGL_NOTICE, "PCU socket not connected, dropping "
			"message\n");
		return -EIO;
	}
	msgb_enqueue(&state->upqueue, msg);
	conn_bfd->when |= BSC_FD_WRITE;

	return 0;
}

static void pcu_sock_close(struct pcu_sock_state *state)
{
	struct osmo_fd *bfd = &state->conn_bfd;
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_tbf *tbf;
	uint8_t trx, ts, tfi;

	LOGP(DL1IF, LOGL_NOTICE, "PCU socket has LOST connection\n");

	close(bfd->fd);
	bfd->fd = -1;
	osmo_fd_unregister(bfd);

	/* flush the queue */
	while (!llist_empty(&state->upqueue)) {
		struct msgb *msg = msgb_dequeue(&state->upqueue);
		msgb_free(msg);
	}

	/* disable all slots, kick all TBFs */
	for (trx = 0; trx < 8; trx++) {
		for (ts = 0; ts < 8; ts++) {
			bts->trx[trx].pdch[ts].enable = 0;
			for (tfi = 0; tfi < 32; tfi++) {
				tbf = bts->trx[trx].pdch[ts].tbf[tfi];
				if (tbf)
					tbf_free(tbf);
			}
		}
	}

	gprs_bssgp_destroy();

	state->timer.cb = pcu_sock_timeout;
	osmo_timer_schedule(&state->timer, 5, 0);
}

static int pcu_sock_read(struct osmo_fd *bfd)
{
	struct pcu_sock_state *state = (struct pcu_sock_state *)bfd->data;
	struct gsm_pcu_if *pcu_prim;
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(sizeof(*pcu_prim), "pcu_sock_rx");
	if (!msg)
		return -ENOMEM;

	pcu_prim = (struct gsm_pcu_if *) msg->tail;

	rc = recv(bfd->fd, msg->tail, msgb_tailroom(msg), 0);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		goto close;
	}

	rc = pcu_rx(pcu_prim->msg_type, pcu_prim);

	/* as we always synchronously process the message in pcu_rx() and
	 * its callbacks, we can free the message here. */
	msgb_free(msg);

	return rc;

close:
	msgb_free(msg);
	pcu_sock_close(state);
	return -1;
}

static int pcu_sock_write(struct osmo_fd *bfd)
{
	struct pcu_sock_state *state = (struct pcu_sock_state *)bfd->data;
	int rc;

	while (!llist_empty(&state->upqueue)) {
		struct msgb *msg, *msg2;
		struct gsm_pcu_if *pcu_prim;

		/* peek at the beginning of the queue */
		msg = llist_entry(state->upqueue.next, struct msgb, list);
		pcu_prim = (struct gsm_pcu_if *)msg->data;

		bfd->when &= ~BSC_FD_WRITE;

		/* bug hunter 8-): maybe someone forgot msgb_put(...) ? */
		if (!msgb_length(msg)) {
			LOGP(DL1IF, LOGL_ERROR, "message type (%d) with ZERO "
				"bytes!\n", pcu_prim->msg_type);
			goto dontsend;
		}

		/* try to send it over the socket */
		rc = write(bfd->fd, msgb_data(msg), msgb_length(msg));
		if (rc == 0)
			goto close;
		if (rc < 0) {
			if (errno == EAGAIN) {
				bfd->when |= BSC_FD_WRITE;
				break;
			}
			goto close;
		}

dontsend:
		/* _after_ we send it, we can deueue */
		msg2 = msgb_dequeue(&state->upqueue);
		assert(msg == msg2);
		msgb_free(msg);
	}
	return 0;

close:
	pcu_sock_close(state);

	return -1;
}

static int pcu_sock_cb(struct osmo_fd *bfd, unsigned int flags)
{
	int rc = 0;

	if (flags & BSC_FD_READ)
		rc = pcu_sock_read(bfd);
	if (rc < 0)
		return rc;

	if (flags & BSC_FD_WRITE)
		rc = pcu_sock_write(bfd);

	return rc;
}

int pcu_l1if_open(void)
{
	struct pcu_sock_state *state;
	struct osmo_fd *bfd;
	struct sockaddr_un local;
	unsigned int namelen;
	int rc;

	state = pcu_sock_state;
	if (!state) {
		state = talloc_zero(NULL, struct pcu_sock_state);
		if (!state)
			return -ENOMEM;
		INIT_LLIST_HEAD(&state->upqueue);
	}

	bfd = &state->conn_bfd;

	bfd->fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (bfd->fd < 0) {
		LOGP(DL1IF, LOGL_ERROR, "Failed to create PCU-SYSMO socket.\n");
		talloc_free(state);
		return -1;
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, "/tmp/pcu_bts", sizeof(local.sun_path));
	local.sun_path[sizeof(local.sun_path) - 1] = '\0';

	/* we use the same magic that X11 uses in Xtranssock.c for
	 * calculating the proper length of the sockaddr */
#if defined(BSD44SOCKETS) || defined(__UNIXWARE__)
	local.sun_len = strlen(local.sun_path);
#endif
#if defined(BSD44SOCKETS) || defined(SUN_LEN)
	namelen = SUN_LEN(&local);
#else
	namelen = strlen(local.sun_path) +
		  offsetof(struct sockaddr_un, sun_path);
#endif
	rc = connect(bfd->fd, (struct sockaddr *) &local, namelen);
	if (rc != 0) {
		LOGP(DL1IF, LOGL_ERROR, "Failed to Connect the PCU-SYSMO "
			"socket, delaying... '%s'\n", local.sun_path);
		close(bfd->fd);
		bfd->fd = -1;
		state->timer.cb = pcu_sock_timeout;
		osmo_timer_schedule(&state->timer, 5, 0);
		return 0;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = pcu_sock_cb;
	bfd->data = state;

	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		LOGP(DL1IF, LOGL_ERROR, "Could not register PCU fd: %d\n", rc);
		close(bfd->fd);
		talloc_free(state);
		return rc;
	}

	LOGP(DL1IF, LOGL_NOTICE, "PCU-SYSMO socket has been connected\n");

	pcu_sock_state = state;

	return 0;
}

void pcu_l1if_close(void)
{
	struct pcu_sock_state *state = pcu_sock_state;
	struct osmo_fd *bfd;

	if (!state)
		return;

	if (osmo_timer_pending(&state->timer))
		osmo_timer_del(&state->timer);

	bfd = &state->conn_bfd;
	if (bfd->fd > 0)
		pcu_sock_close(state);
	talloc_free(state);
	pcu_sock_state = NULL;
}

static void pcu_sock_timeout(void *_priv)
{
	pcu_l1if_open();
}




