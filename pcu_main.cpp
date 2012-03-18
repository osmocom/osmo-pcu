/* pcu_main.cpp
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

#include <gprs_bssgp_pcu.h>
#include <Threads.h>
#include <Sockets.h>
#include <pcu_l1_if.h>

// TODO: We should move this parameters to config file.
#define SGSN_IP "127.0.0.1"
#define SGSN_PORT 23000
#define NSVCI 4
#define PCU_L1_IF_PORT 5944

struct l1fwd_hdl *l1fh = talloc_zero(NULL, struct l1fwd_hdl);

int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc, struct msgb *msg, uint16_t bvci)
{
	int rc = 0;
	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = gprs_bssgp_pcu_rcvmsg(msg);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "RLCMAC: Unknown event %u from NS\n", event);
		if (msg)
			talloc_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}

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

	DEBUGP(DGPRS, "UDP: Writing %u bytes for MQ_L1_WRITE queue\n", msgb_l1len(msg));

	rc = sendto(ofd->fd, msg->l1h, msgb_l1len(msg), 0,
			(const struct sockaddr *)&l1fh->remote_sa, l1fh->remote_sa_len);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_ERROR, "error writing to L1 msg_queue: %s\n",
			strerror(errno));
		return rc;
	} else if (rc < msgb_l1len(msg)) {
		LOGP(DGPRS, LOGL_ERROR, "short write to L1 msg_queue: "
			"%u < %u\n", rc, msgb_l1len(msg));
		return -EIO;
	}

	return 0;
}

int pcu_l1if_open()
{
	//struct l1fwd_hdl *l1fh;
	struct femtol1_hdl *fl1h;
	int rc;

	/* allocate new femtol1_handle */
	fl1h = talloc_zero(NULL, struct femtol1_hdl);
	INIT_LLIST_HEAD(&fl1h->wlc_list);

	l1fh->fl1h = fl1h;
	fl1h->priv = l1fh;

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
}

int main(int argc, char *argv[])
{
	uint16_t nsvci = NSVCI;
	struct gprs_ns_inst *sgsn_nsi;
	struct gprs_nsvc *nsvc;

	osmo_init_logging(&log_info);
	pcu_l1if_open();

	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb);
	bssgp_nsi = sgsn_nsi;

	if (!bssgp_nsi)
	{
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	bctx = btsctx_alloc(BVCI, NSEI);
	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = MNC;
	bctx->ra_id.mcc = MCC;
	bctx->ra_id.lac = PCU_LAC;
	bctx->ra_id.rac = PCU_RAC;
	bctx->bvci = BVCI;
	uint8_t cause = 39;
	gprs_ns_nsip_listen(sgsn_nsi);

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(SGSN_PORT);
	inet_aton(SGSN_IP, &dest.sin_addr);

	nsvc = nsip_connect(sgsn_nsi, &dest, NSEI, nsvci);
	unsigned i = 0;
	while (1) 
	{
		osmo_select_main(0);
		if (i == 7)
		{
			bssgp_tx_bvc_reset(bctx, BVCI, cause);
		}
		i++;
	}
}

