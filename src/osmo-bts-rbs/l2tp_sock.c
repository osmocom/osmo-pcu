/* Connection to l2tp deamon */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/write_queue.h>
#include "gprs_debug.h"
#include "l2tp_sock.h"
#include "pgsl_l1_if.h"

struct l2tp_sock_state {
	struct osmo_fd bfd;
	char path[PATH_MAX];
	struct osmo_timer_list timer;
};

static struct l2tp_sock_state sock_state;

static int l2tp_socket_close(struct osmo_fd *bfd)
{
	int rc;

	/* Prevent closing an already closed socket */
	if (bfd->fd < 0)
		return 0;

	rc = close(bfd->fd);
	if (rc < 0) {
		LOGP(DPGSL, LOGL_ERROR, "unable to close socket!\n");
		return rc;
	}

	osmo_fd_unregister(bfd);
	bfd->fd = -1;

	LOGP(DPGSL, LOGL_ERROR, "socket closed!\n");

	return rc;
}

/* Receive data from l2tp daeomen */
static int socket_rx(struct osmo_fd *bfd, unsigned int flags)
{
	struct msgb *msg = msgb_alloc(1500, "rx pgsl data");
	int rc;

	/* Read data from socket */
	rc = read(bfd->fd, msg->data, msg->data_len);
	if (rc < 8) {
		LOGP(DPGSL, LOGL_ERROR,
		     "failed to receive data from socket!\n");
		l2tp_socket_close(bfd);
		msgb_free(msg);
		return rc;
	}
	msgb_put(msg, rc);

	/* Forward pgsl data */
	pgsl_msg_rx(msg);

	msgb_free(msg);
	return 0;
}

/* Transmit message to l2tp daemon */
int l2tp_socket_tx(struct msgb *msg)
{
	if (l2tp_connected()) {
		return write(sock_state.bfd.fd, msg->data, msg->len);
	} else
		LOGP(DPGSL, LOGL_ERROR,
		     "socket not connected, transmit failed!\n");
	return -EINVAL;
}

/* Establish connection to l2tp daemon */
static int connect_socket(struct l2tp_sock_state *state)
{
	struct osmo_fd *bfd = &state->bfd;
	bfd->when = BSC_FD_READ;
	bfd->cb = socket_rx;

	bfd->fd =
	    osmo_sock_unix_init(SOCK_SEQPACKET, 0, state->path,
				OSMO_SOCK_F_CONNECT);
	if (osmo_fd_register(bfd) != 0) {
		LOGP(DPGSL, LOGL_ERROR,
		     "No connection to l2tp-daemon at socket %s, connecting...\n",
		     state->path);
		l2tp_socket_close(bfd);
		return -EINVAL;
	}
	LOGP(DPGSL, LOGL_DEBUG,
	     "Connection to l2tp-daemon at socket %s established!\n",
	     state->path);

	return 0;
}

/* A timer callback to check if the socket is still connected */
static void check_timer_cb(void *priv)
{
	struct l2tp_sock_state *state = priv;
	struct osmo_fd *bfd = &state->bfd;

	if (bfd->fd < 0)
		connect_socket(state);

	osmo_timer_schedule(&state->timer, 3, 0);
}

/* Open connection to l2tp daemon */
int l2tp_sock_init(const char *path)
{
	strcpy(sock_state.path, path);

	LOGP(DPGSL, LOGL_DEBUG, "Connecting socket at %s ...\n", path);

	/* Establish connection to l2tp daemon */
	connect_socket(&sock_state);

	sock_state.timer.cb = check_timer_cb;
	sock_state.timer.data = &sock_state;
	osmo_timer_schedule(&sock_state.timer, 3, 0);

	/* Inlitalize PGSL states */
	pgsl_init();

	return 0;
}

/* Check if PCU has an l2tp daemon connection */
bool l2tp_connected(void)
{
	if (sock_state.bfd.fd < 0)
		return false;
	return true;
}
