/* openbts_sock.cpp
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
#include <sys/socket.h>
#include <arpa/inet.h>
extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm_utils.h>
#include <pcuif_proto.h>
}

extern void *tall_pcu_ctx;

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

// TODO: We should move this parameters to config file.
#define PCU_L1_IF_PORT 5944

/* OpenBTS socket functions */

int pcu_sock_send(struct msgb *msg)
{
	if (osmo_wqueue_enqueue(&l1fh->udp_wq, msg) != 0) {
		LOGP(DPCU, LOGL_ERROR, "PCU write queue full. Dropping message.\n");
		msgb_free(msg);
	}
	return 0;
}

/* data has arrived on the udp socket */
static int udp_read_cb(struct osmo_fd *ofd)
{
	struct msgb *msg = msgb_alloc_headroom(2048, 128, "udp_rx");
	struct l1fwd_hdl *l1fh = (l1fwd_hdl *)ofd->data;
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

	struct gsm_pcu_if *pcu_prim = (gsm_pcu_if *)(msg->l1h);
	rc = pcu_rx(pcu_prim->msg_type, pcu_prim);
	msgb_free(msg);
	return rc;
}

/* callback when we can write to the UDP socket */
static int udp_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	int rc;
	struct l1fwd_hdl *l1fh = (l1fwd_hdl *)ofd->data;

	//LOGP(DPCU, LOGL_ERROR, "UDP: Writing %u bytes for MQ_L1_WRITE queue\n", msgb_length(msg));

	rc = sendto(ofd->fd, msgb_data(msg), msgb_length(msg), 0,
			(const struct sockaddr *)&l1fh->remote_sa, l1fh->remote_sa_len);
	if (rc < 0) {
		LOGP(DPCU, LOGL_ERROR, "error writing to L1 msg_queue: %s\n",
			strerror(errno));
		return rc;
	} else if (rc < (int)msgb_length(msg)) {
		LOGP(DPCU, LOGL_ERROR, "short write to L1 msg_queue: "
			"%u < %u\n", rc, msgb_length(msg));
		return -EIO;
	}

	return 0;
}

int pcu_l1if_open()
{
	struct femtol1_hdl *fl1h;
	int rc;

	/* allocate new femtol1_handle */
	fl1h = talloc_zero(tall_pcu_ctx, struct femtol1_hdl);
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
	talloc_free(l1fh->fl1h);

	exit(0);
}
