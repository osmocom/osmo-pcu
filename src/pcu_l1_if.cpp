/* pcu_l1_if.cpp
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

#include <errno.h>
#include <string.h>
#include <gprs_rlcmac.h>
#include <gprs_bssgp_pcu.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <bitvector.h>
#include <gsmL1prim.h>
#include <sys/socket.h>
#include <arpa/inet.h>
extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm_utils.h>
}

#define MAX_UDP_LENGTH 1500

#define msgb_l1prim(msg)	((GsmL1_Prim_t *)(msg)->l1h)

struct femtol1_hdl {
	struct gsm_time gsm_time;
	uint32_t hLayer1;			/* handle to the L1 instance in the DSP */
	uint32_t dsp_trace_f;
	uint16_t clk_cal;
	struct llist_head wlc_list;

	void *priv;			/* user reference */

	struct osmo_timer_list alive_timer;
	unsigned int alive_prim_cnt;

	struct osmo_fd read_ofd;	/* osmo file descriptors */
	struct osmo_wqueue write_q;

	struct {
		uint16_t arfcn;
		uint8_t tn;
		uint8_t tsc;
		uint16_t ta;
	} channel_info;

};

struct l1fwd_hdl {
	struct sockaddr_storage remote_sa;
	socklen_t remote_sa_len;

	struct osmo_wqueue udp_wq;

	struct femtol1_hdl *fl1h;
};

struct l1fwd_hdl *l1fh = talloc_zero(NULL, struct l1fwd_hdl);

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

struct msgb *l1p_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc(sizeof(GsmL1_Prim_t), "l1_prim");

	if (msg)
		msg->l1h = msgb_put(msg, sizeof(GsmL1_Prim_t));

	return msg;
}

// Send RLC/MAC block to OpenBTS.
void pcu_l1if_tx_pdtch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn,
        uint32_t fn, uint8_t block_nr)
{
	struct msgb *nmsg = l1p_msgb_alloc();
	GsmL1_Prim_t *prim = msgb_l1prim(nmsg);
	
	prim->id = GsmL1_PrimId_PhDataReq;
	prim->u.phDataReq.sapi = GsmL1_Sapi_Pdtch;
	memcpy(prim->u.phDataReq.msgUnitParam.u8Buffer, msg->data, msg->len);
	prim->u.phDataReq.msgUnitParam.u8Size = msg->len;
	osmo_wqueue_enqueue(&l1fh->udp_wq, nmsg);
	msgb_free(msg);
}

void pcu_l1if_tx_agch(bitvec * block, int plen)
{
	struct msgb *msg = l1p_msgb_alloc();
	GsmL1_Prim_t *prim = msgb_l1prim(msg);
	
	prim->id = GsmL1_PrimId_PhDataReq;
	prim->u.phDataReq.sapi = GsmL1_Sapi_Agch;
	bitvec_pack(block, prim->u.phDataReq.msgUnitParam.u8Buffer);
#warning Please review, if OpenBTS requires AGCH frame without pseudo length:
	prim->u.phDataReq.msgUnitParam.u8Size = 22;
	osmo_wqueue_enqueue(&l1fh->udp_wq, msg);
}

int pcu_l1if_rx_pdch(GsmL1_PhDataInd_t *data_ind)
{
	gprs_rlcmac_rcv_block(data_ind->msgUnitParam.u8Buffer,
		data_ind->msgUnitParam.u8Size, data_ind->u32Fn);

	return 0;
}

static int handle_ph_connect_ind(struct femtol1_hdl *fl1, GsmL1_PhConnectInd_t *connect_ind)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

	bts->trx[0].arfcn = connect_ind->u16Arfcn;
	bts->trx[0].pdch[connect_ind->u8Tn].enable = 1;
	bts->trx[0].pdch[connect_ind->u8Tn].tsc = connect_ind->u8Tsc;
	(l1fh->fl1h)->channel_info.arfcn = connect_ind->u16Arfcn;
	(l1fh->fl1h)->channel_info.tn = connect_ind->u8Tn;
	(l1fh->fl1h)->channel_info.tsc = connect_ind->u8Tsc;
	LOGP(DL1IF, LOGL_NOTICE, "RX: [ PCU <- BTS ] PhConnectInd: ARFCN: %u TN: %u TSC: %u \n",
	        connect_ind->u16Arfcn, (unsigned)connect_ind->u8Tn, (unsigned)connect_ind->u8Tsc);

	return 0;
}

static int handle_ph_readytosend_ind(struct femtol1_hdl *fl1, GsmL1_PhReadyToSendInd_t *readytosend_ind)
{
	gprs_rlcmac_rcv_rts_block(0,0, (l1fh->fl1h)->channel_info.arfcn, readytosend_ind->u32Fn, 0);
	return 1;
}

static int handle_ph_data_ind(struct femtol1_hdl *fl1, GsmL1_PhDataInd_t *data_ind)
{
	int rc = 0;
	switch (data_ind->sapi) {
	case GsmL1_Sapi_Rach:
		break;
	case GsmL1_Sapi_Pdtch:
	case GsmL1_Sapi_Pacch:
		pcu_l1if_rx_pdch(data_ind);
		break;
	case GsmL1_Sapi_Pbcch:
	case GsmL1_Sapi_Pagch:
	case GsmL1_Sapi_Ppch:
	case GsmL1_Sapi_Pnch:
	case GsmL1_Sapi_Ptcch:
	case GsmL1_Sapi_Prach:
		break;
	default:
		LOGP(DL1IF, LOGL_NOTICE, "Rx PH-DATA.ind for unknown L1 SAPI %u \n", data_ind->sapi);
		break;
	}

	return rc;
}

static int handle_ph_ra_ind(struct femtol1_hdl *fl1, GsmL1_PhRaInd_t *ra_ind)
{
	int rc = 0;
	(l1fh->fl1h)->channel_info.ta = ra_ind->measParam.i16BurstTiming;
	rc = gprs_rlcmac_rcv_rach(ra_ind->msgUnitParam.u8Buffer[0], ra_ind->u32Fn, ra_ind->measParam.i16BurstTiming);
	return rc;
}

/* handle any random indication from the L1 */
int pcu_l1if_handle_l1prim(struct femtol1_hdl *fl1, struct msgb *msg)
{
	GsmL1_Prim_t *l1p = msgb_l1prim(msg);
	int rc = 0;

	switch (l1p->id) {
	case GsmL1_PrimId_PhConnectInd:
		rc = handle_ph_connect_ind(fl1, &l1p->u.phConnectInd);
		break;
	case GsmL1_PrimId_PhReadyToSendInd:
		rc = handle_ph_readytosend_ind(fl1, &l1p->u.phReadyToSendInd);
		break;
	case GsmL1_PrimId_PhDataInd:
		rc = handle_ph_data_ind(fl1, &l1p->u.phDataInd);
		break;
	case GsmL1_PrimId_PhRaInd:
		rc = handle_ph_ra_ind(fl1, &l1p->u.phRaInd);
		break;
	default:
		break;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);

	return rc;
}

PCU will currently not work without getting a GSM time or BFI indidication.
In order to fix this, i will discuss this on the mailing list.
Andreas

/* OpenBTS socket functions */

// TODO: We should move this parameters to config file.
#define PCU_L1_IF_PORT 5944

/* data has arrived on the udp socket */
static int udp_read_cb(struct osmo_fd *ofd)
{
	struct msgb *msg = msgb_alloc_headroom(2048, 128, "udp_rx");
	struct l1fwd_hdl *l1fh = (l1fwd_hdl *)ofd->data;
	struct femtol1_hdl *fl1h = l1fh->fl1h;
	int rc;

	if (!msg)
		return -ENOMEM;

	msg->l1h = msg->data;

	l1fh->remote_sa_len = sizeof(l1fh->remote_sa);
	rc = recvfrom(ofd->fd, msg->l1h, msgb_tailroom(msg), 0,
			(struct sockaddr *) &l1fh->remote_sa, &l1fh->remote_sa_len);
	if (rc < 0) {
		perror("read from udp");
		msgb_free(msg);
		return rc;
	} else if (rc == 0) {
		perror("len=0 read from udp");
		msgb_free(msg);
		return rc;
	}
	msgb_put(msg, rc);

	rc = pcu_l1if_handle_l1prim(fl1h, msg);
	return rc;
}

/* callback when we can write to the UDP socket */
static int udp_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	int rc;
	struct l1fwd_hdl *l1fh = (l1fwd_hdl *)ofd->data;

	//DEBUGP(DGPRS, "UDP: Writing %u bytes for MQ_L1_WRITE queue\n", msgb_l1len(msg));

	rc = sendto(ofd->fd, msg->l1h, msgb_l1len(msg), 0,
			(const struct sockaddr *)&l1fh->remote_sa, l1fh->remote_sa_len);
	if (rc < 0) {
		LOGP(DPCU, LOGL_ERROR, "error writing to L1 msg_queue: %s\n",
			strerror(errno));
		return rc;
	} else if (rc < (int)msgb_l1len(msg)) {
		LOGP(DPCU, LOGL_ERROR, "short write to L1 msg_queue: "
			"%u < %u\n", rc, msgb_l1len(msg));
		return -EIO;
	}

	return 0;
}

// TODO: We should move this parameters to config file.
#define SGSN_IP 127.0.0.1
#define SGSN_PORT 23000
#define NSEI 3
#define NSVCI 4

#define BVCI 7

#define CELL_ID 0
#define MNC 2
#define MCC 262
#define PCU_LAC 1
#define PCU_RAC 0

int pcu_l1if_open()
{
	//struct l1fwd_hdl *l1fh;
	struct femtol1_hdl *fl1h;
	int rc;

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(SGSN_PORT);
	inet_aton(SGSN_IP, &dest.sin_addr);

	rc = gprs_bssgp_create(ntohl(dest.sin_addr.s_addr), SGSN_PORT, NSEI, NSVCI, BVCI, MCC, MNC, PCU_LAC, PCU_RAC, CELL_ID);
	if (rc < 0)
		return rc;

	/* allocate new femtol1_handle */
	fl1h = talloc_zero(NULL, struct femtol1_hdl);
	INIT_LLIST_HEAD(&fl1h->wlc_list);

	l1fh->fl1h = fl1h;
	fl1h->priv = l1fh;

	struct osmo_wqueue * queue = &((l1fh->fl1h)->write_q);
	osmo_wqueue_init(queue, 10);
	queue->bfd.when |= BSC_FD_READ;
	queue->bfd.data = l1fh;
	queue->bfd.priv_nr = 0;

	/* Open UDP */
	struct osmo_wqueue *wq = &l1fh->udp_wq;

	osmo_wqueue_init(wq, 10);
	wq->write_cb = udp_write_cb;
	wq->read_cb = udp_read_cb;
	wq->bfd.when |= BSC_FD_READ;
	wq->bfd.data = l1fh;
	wq->bfd.priv_nr = 0;
	rc = osmo_sock_init_ofd(&wq->bfd, AF_UNSPEC, SOCK_DGRAM,
				IPPROTO_UDP, NULL, PCU_L1_IF_PORT,
				OSMO_SOCK_F_BIND);
	if (rc < 0) {
		perror("sock_init");
		exit(1);
	}

	return 0;
}

void pcu_l1if_close(void)
{
	gprs_bssgp_destroy();

	/* FIXME: cleanup l1if */
	talloc_free(fl1h);
}
