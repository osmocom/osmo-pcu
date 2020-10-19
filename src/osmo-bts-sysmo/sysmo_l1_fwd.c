/* Interface handler for Sysmocom L1 (forwarding) */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm_utils.h>

#include <sysmocom/femtobts/superfemto.h>
#include <sysmocom/femtobts/gsml1prim.h>
#include <sysmocom/femtobts/gsml1const.h>
#include <sysmocom/femtobts/gsml1types.h>

#include "gprs_debug.h"
#include "sysmo_l1_if.h"


#define L1FWD_L1_PORT   9999
#define L1FWD_SYS_PORT  9998
#define L1FWD_TCH_PORT  9997
#define L1FWD_PDTCH_PORT 9996

static const uint16_t fwd_udp_ports[] = {
	[MQ_SYS_WRITE]	= L1FWD_SYS_PORT,
	[MQ_L1_WRITE]	= L1FWD_L1_PORT,
	[MQ_TCH_WRITE]	= L1FWD_TCH_PORT,
	[MQ_PDTCH_WRITE]= L1FWD_PDTCH_PORT,
};

static int fwd_read_cb(struct osmo_fd *ofd)
{
	struct msgb *msg = msgb_alloc_headroom(sizeof(SuperFemto_Prim_t) + 128,
		128, "udp_rx");
	struct femtol1_hdl *fl1h = ofd->data;
	int rc;

	if (!msg)
		return -ENOMEM;

	msg->l1h = msg->data;
	rc = read(ofd->fd, msg->l1h, msgb_tailroom(msg));
	if (rc < 0) {
		LOGP(DL1IF, LOGL_ERROR, "Short read from UDP\n");
		msgb_free(msg);
		return rc;
	} else if (rc == 0) {
		LOGP(DL1IF, LOGL_ERROR, "Len=0 from UDP\n");
		msgb_free(msg);
		return rc;
	}
	msgb_put(msg, rc);

	if (ofd->priv_nr == MQ_SYS_WRITE)
		rc = l1if_handle_sysprim(fl1h, msg);
	else
		rc = l1if_handle_l1prim(ofd->priv_nr, fl1h, msg);

	return rc;
}

static int prim_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	/* write to the fd */
	return write(ofd->fd, msg->head, msg->len);
}

int l1if_transport_open(int q, struct femtol1_hdl *fl1h)
{
	int rc;
	char *bts_host = getenv("L1FWD_BTS_HOST");

	printf("sizeof(GsmL1_Prim_t) = %zu\n", sizeof(GsmL1_Prim_t));
	printf("sizeof(SuperFemto_Prim_t) = %zu\n", sizeof(SuperFemto_Prim_t));

	if (!bts_host) {
		fprintf(stderr, "You have to set the L1FWD_BTS_HOST environment variable\n");
		exit(2);
	}

	struct osmo_wqueue *wq = &fl1h->write_q[q];
	struct osmo_fd *ofd = &wq->bfd;

	osmo_wqueue_init(wq, 10);
	wq->write_cb = prim_write_cb;
	wq->read_cb = fwd_read_cb;

	osmo_fd_setup(ofd, -1, OSMO_FD_READ, osmo_wqueue_bfd_cb, fl1h, q);
	rc = osmo_sock_init_ofd(ofd, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				bts_host, fwd_udp_ports[q],
				OSMO_SOCK_F_CONNECT);
	if (rc < 0)
		return rc;

	return 0;
}

int l1if_transport_close(int q, struct femtol1_hdl *fl1h)
{
	struct osmo_wqueue *wq = &fl1h->write_q[q];
	struct osmo_fd *ofd = &wq->bfd;

	osmo_wqueue_clear(wq);
	osmo_fd_unregister(ofd);
	close(ofd->fd);
	
	return 0;
}
