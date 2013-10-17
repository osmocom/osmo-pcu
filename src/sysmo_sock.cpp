/* sysmo_sock.cpp
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
#include <pcuif_proto.h>
#include <tbf.h>

extern void *tall_pcu_ctx;

extern "C" {
int l1if_close_pdch(void *obj);
}

/*
 * SYSMO-PCU socket functions
 */

struct pcu_sock_state {
	struct osmo_fd conn_bfd;	/* fd for connection to lcr */
	struct osmo_timer_list timer;	/* socket connect retry timer */
	struct llist_head upqueue;	/* queue for sending messages */
} *pcu_sock_state = NULL;

static void pcu_sock_timeout(void *_priv);

int pcu_sock_send(struct msgb *msg)
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

static void pcu_sock_close(struct pcu_sock_state *state, int lost)
{
	struct osmo_fd *bfd = &state->conn_bfd;
	struct gprs_rlcmac_bts *bts = bts_main_data();
	uint8_t trx, ts;

	LOGP(DL1IF, LOGL_NOTICE, "PCU socket has %s connection\n",
		(lost) ? "LOST" : "closed");

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
#ifdef ENABLE_SYSMODSP
		if (bts->trx[trx].fl1h) {
			l1if_close_pdch(bts->trx[trx].fl1h);
			bts->trx[trx].fl1h = NULL;
		}
#endif
		for (ts = 0; ts < 8; ts++)
			bts->trx[trx].pdch[ts].enable = 0;
		gprs_rlcmac_tbf::free_all(&bts->trx[trx]);
	}

	gprs_bssgp_destroy_or_exit();

	if (lost) {
		state->timer.cb = pcu_sock_timeout;
		osmo_timer_schedule(&state->timer, 5, 0);
	}
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
	pcu_sock_close(state, 1);
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
	pcu_sock_close(state, 1);

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
		state = talloc_zero(tall_pcu_ctx, struct pcu_sock_state);
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
		pcu_sock_state = state;
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

	osmo_timer_del(&state->timer);

	bfd = &state->conn_bfd;
	if (bfd->fd > 0)
		pcu_sock_close(state, 0);
	talloc_free(state);
	pcu_sock_state = NULL;
}

static void pcu_sock_timeout(void *_priv)
{
	pcu_l1if_open();
}
