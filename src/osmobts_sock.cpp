/* osmobts_sock.cpp
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
#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
}

#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <osmocom/pcu/pcuif_proto.h>
#include <bts.h>
#include <tbf.h>
#include <pdch.h>

extern "C" {
int l1if_close_pdch(void *obj);
}

/*
 * osmo-bts PCU socket functions
 */

static struct {
	struct osmo_fd conn_bfd;	/* fd for connection to the BTS */
	struct osmo_timer_list timer;	/* socket connect retry timer */
	struct llist_head upqueue;	/* queue for sending messages */
} pcu_sock_state;

static void pcu_sock_timeout(void *_priv)
{
	pcu_l1if_open();
}

static void pcu_tx_txt_retry(void *_priv)
{
	struct gprs_rlcmac_bts *bts = bts_main_data();

	if (bts->active)
		return;

	pcu_tx_txt_ind(PCU_VERSION, "%s", PACKAGE_VERSION);
	osmo_timer_schedule(&pcu_sock_state.timer, 5, 0);
}

int pcu_sock_send(struct msgb *msg)
{
	struct osmo_fd *conn_bfd;

	conn_bfd = &pcu_sock_state.conn_bfd;
	if (conn_bfd->fd <= 0) {
		LOGP(DL1IF, LOGL_NOTICE, "PCU socket not connected, dropping "
			"message\n");
		return -EIO;
	}
	msgb_enqueue(&pcu_sock_state.upqueue, msg);
	osmo_fd_write_enable(conn_bfd);

	return 0;
}

static void pcu_sock_close(int lost)
{
	struct osmo_fd *bfd = &pcu_sock_state.conn_bfd;
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint8_t trx, ts;

	LOGP(DL1IF, LOGL_NOTICE, "PCU socket has %s connection\n",
		(lost) ? "LOST" : "closed");

	close(bfd->fd);
	bfd->fd = -1;
	osmo_fd_unregister(bfd);

	/* flush the queue */
	while (!llist_empty(&pcu_sock_state.upqueue)) {
		struct msgb *msg = msgb_dequeue(&pcu_sock_state.upqueue);
		msgb_free(msg);
	}

	/* disable all slots, kick all TBFs */
	for (trx = 0; trx < 8; trx++) {
#ifdef ENABLE_DIRECT_PHY
		if (bts->trx[trx].fl1h) {
			l1if_close_pdch(bts->trx[trx].fl1h);
			bts->trx[trx].fl1h = NULL;
		}
#endif
		for (ts = 0; ts < 8; ts++)
			bts->trx[trx].pdch[ts].disable();
/* FIXME: NOT ALL RESOURCES are freed in this case... inconsistent with the other code. Share the code with pcu_l1if.c
for the reset. */
		gprs_rlcmac_tbf::free_all(&bts->trx[trx]);
	}

	gprs_bssgp_destroy(bts);
	exit(0);
}

static int pcu_sock_read(struct osmo_fd *bfd)
{
	struct gsm_pcu_if pcu_prim;
	int rc;

	rc = recv(bfd->fd, &pcu_prim, sizeof(pcu_prim), 0);
	if (rc < 0 && errno == EAGAIN)
		return 0; /* Try again later */
	if (rc <= 0) {
		pcu_sock_close(1);
		return -EIO;
	}

	return pcu_rx(pcu_prim.msg_type, &pcu_prim);
}

static int pcu_sock_write(struct osmo_fd *bfd)
{
	int rc;

	while (!llist_empty(&pcu_sock_state.upqueue)) {
		struct msgb *msg, *msg2;
		struct gsm_pcu_if *pcu_prim;

		/* peek at the beginning of the queue */
		msg = llist_entry(pcu_sock_state.upqueue.next, struct msgb, list);
		pcu_prim = (struct gsm_pcu_if *)msg->data;

		osmo_fd_write_disable(bfd);

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
				osmo_fd_write_enable(bfd);
				break;
			}
			goto close;
		}

dontsend:
		/* _after_ we send it, we can deueue */
		msg2 = msgb_dequeue(&pcu_sock_state.upqueue);
		assert(msg == msg2);
		msgb_free(msg);
	}
	return 0;

close:
	pcu_sock_close(1);

	return -1;
}

static int pcu_sock_cb(struct osmo_fd *bfd, unsigned int flags)
{
	int rc = 0;

	if (flags & OSMO_FD_READ)
		rc = pcu_sock_read(bfd);
	if (rc < 0)
		return rc;

	if (flags & OSMO_FD_WRITE)
		rc = pcu_sock_write(bfd);

	return rc;
}

int pcu_l1if_open(void)
{
	int rc;
	struct gprs_rlcmac_bts *bts = bts_main_data();

	LOGP(DL1IF, LOGL_INFO, "Opening OsmoPCU L1 interface to OsmoBTS\n");

	memset(&pcu_sock_state, 0x00, sizeof(pcu_sock_state));
	INIT_LLIST_HEAD(&pcu_sock_state.upqueue);

	rc = osmo_sock_unix_init_ofd(&pcu_sock_state.conn_bfd, SOCK_SEQPACKET, 0,
				     bts->pcu_sock_path, OSMO_SOCK_F_CONNECT);
	if (rc < 0) {
		LOGP(DL1IF, LOGL_ERROR, "Failed to connect to the BTS (%s). "
					"Retrying...\n", bts->pcu_sock_path);
		osmo_timer_setup(&pcu_sock_state.timer, pcu_sock_timeout, NULL);
		osmo_timer_schedule(&pcu_sock_state.timer, 5, 0);
		return 0;
	}

	pcu_sock_state.conn_bfd.cb = pcu_sock_cb;
	pcu_sock_state.conn_bfd.data = NULL;

	LOGP(DL1IF, LOGL_NOTICE, "osmo-bts PCU socket %s has been connected\n",
	     bts->pcu_sock_path);

	pcu_tx_txt_ind(PCU_VERSION, "%s", PACKAGE_VERSION);

	/* Schedule a timer so we keep trying until the BTS becomes active. */
	osmo_timer_setup(&pcu_sock_state.timer, pcu_tx_txt_retry, NULL);
	osmo_timer_schedule(&pcu_sock_state.timer, 5, 0);

	return 0;
}

void pcu_l1if_close(void)
{
	struct osmo_fd *bfd;

	osmo_timer_del(&pcu_sock_state.timer);

	bfd = &pcu_sock_state.conn_bfd;
	if (bfd->fd > 0)
		pcu_sock_close(0);
}
