/* Interface handler for Nuran Wireless Litecell 1.5 L1 (real hardware) */

/* Copyright (C) 2015 by Yves Godin <support@nuranwireless.com>
 * based on:
 *     femto_l1_hw.c
 *     (C) 2011 by Harald Welte <laforge@gnumonks.org>
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

#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm_utils.h>

#include <nrw/oc2g/oc2g.h>
#include <nrw/oc2g/gsml1prim.h>
#include <nrw/oc2g/gsml1const.h>
#include <nrw/oc2g/gsml1types.h>

#include "gprs_debug.h"
#include "oc2g_l1_if.h"
#include "oc2gbts.h"

#define DEV_SYS_DSP2ARM_NAME    "/dev/msgq/oc2g_dsp2arm_trx"
#define DEV_SYS_ARM2DSP_NAME    "/dev/msgq/oc2g_arm2dsp_trx"
#define DEV_L1_DSP2ARM_NAME     "/dev/msgq/gsml1_sig_dsp2arm_trx"
#define DEV_L1_ARM2DSP_NAME     "/dev/msgq/gsml1_sig_arm2dsp_trx"

#define DEV_TCH_DSP2ARM_NAME    "/dev/msgq/gsml1_tch_dsp2arm_trx"
#define DEV_TCH_ARM2DSP_NAME    "/dev/msgq/gsml1_tch_arm2dsp_trx"
#define DEV_PDTCH_DSP2ARM_NAME  "/dev/msgq/gsml1_pdtch_dsp2arm_trx"
#define DEV_PDTCH_ARM2DSP_NAME  "/dev/msgq/gsml1_pdtch_arm2dsp_trx"

static const char *rd_devnames[] = {
        [MQ_SYS_READ]   = DEV_SYS_DSP2ARM_NAME,
        [MQ_L1_READ]    = DEV_L1_DSP2ARM_NAME,
        [MQ_TCH_READ]   = DEV_TCH_DSP2ARM_NAME,
        [MQ_PDTCH_READ] = DEV_PDTCH_DSP2ARM_NAME,
};

static const char *wr_devnames[] = {
        [MQ_SYS_WRITE]  = DEV_SYS_ARM2DSP_NAME,
        [MQ_L1_WRITE]   = DEV_L1_ARM2DSP_NAME,
        [MQ_TCH_WRITE]  = DEV_TCH_ARM2DSP_NAME,
        [MQ_PDTCH_WRITE]= DEV_PDTCH_ARM2DSP_NAME,
};

/* callback when there's something to read from the l1 msg_queue */
static int l1if_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	//struct msgb *msg = l1p_msgb_alloc();
	struct msgb *msg = msgb_alloc_headroom(sizeof(Oc2g_Prim_t) + 128,
		128, "1l_fd");
	struct oc2gl1_hdl *fl1h = ofd->data;
	int rc;

	msg->l1h = msg->data;
	rc = read(ofd->fd, msg->l1h, msgb_tailroom(msg));
	if (rc < 0) {
		if (rc != -1)
			LOGP(DL1IF, LOGL_ERROR, "error reading from L1 msg_queue: %s\n",
				strerror(errno));
		msgb_free(msg);
		return rc;
	}
	msgb_put(msg, rc);

	switch (ofd->priv_nr) {
	case MQ_SYS_WRITE:
		if (rc != sizeof(Oc2g_Prim_t))
			LOGP(DL1IF, LOGL_NOTICE, "%u != "
			     "sizeof(Oc2g_Prim_t)\n", rc);
		return l1if_handle_sysprim(fl1h, msg);
	case MQ_L1_WRITE:
	case MQ_TCH_WRITE:
	case MQ_PDTCH_WRITE:
		if (rc != sizeof(GsmL1_Prim_t))
			LOGP(DL1IF, LOGL_NOTICE, "%u != "
			     "sizeof(GsmL1_Prim_t)\n", rc);
		return l1if_handle_l1prim(ofd->priv_nr, fl1h, msg);
	default:
		/* The compiler can't know that priv_nr is an enum. Assist. */
		LOGP(DL1IF, LOGL_FATAL, "writing on a wrong queue: %d\n",
			ofd->priv_nr);
		exit(0);
		break;
	}
};

/* callback when we can write to one of the l1 msg_queue devices */
static int l1fd_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	int rc;

	rc = write(ofd->fd, msg->l1h, msgb_l1len(msg));
	if (rc < 0) {
		LOGP(DL1IF, LOGL_ERROR, "error writing to L1 msg_queue: %s\n",
			strerror(errno));
		return rc;
	} else if (rc < msg->len) {
		LOGP(DL1IF, LOGL_ERROR, "short write to L1 msg_queue: "
			"%u < %u\n", rc, msg->len);
		return -EIO;
	}

	return 0;
}

int l1if_transport_open(int q, struct oc2gl1_hdl *hdl)
{
	int rc;
        char buf[PATH_MAX];

	/* Step 1: Open all msg_queue file descriptors */
	struct osmo_fd *read_ofd = &hdl->read_ofd[q];
	struct osmo_wqueue *wq = &hdl->write_q[q];
	struct osmo_fd *write_ofd = &hdl->write_q[q].bfd;

        snprintf(buf, sizeof(buf)-1, "%s%d", rd_devnames[q], hdl->hw_info.trx_nr);
        buf[sizeof(buf)-1] = '\0';

	rc = open(buf, O_RDONLY);
	if (rc < 0) {
		LOGP(DL1IF, LOGL_FATAL, "unable to open msg_queue %s: %s\n",
			buf, strerror(errno));
		return rc;
	}
	osmo_fd_setup(read_ofd, rc, OSMO_FD_READ, l1if_fd_cb, hdl, q);
	rc = osmo_fd_register(read_ofd);
	if (rc < 0) {
		close(read_ofd->fd);
		read_ofd->fd = -1;
		return rc;
	}

        snprintf(buf, sizeof(buf)-1, "%s%d", wr_devnames[q], hdl->hw_info.trx_nr);
        buf[sizeof(buf)-1] = '\0';

	rc = open(buf, O_WRONLY);
	if (rc < 0) {
		LOGP(DL1IF, LOGL_FATAL, "unable to open msg_queue %s: %s\n",
			buf, strerror(errno));
		goto out_read;
	}
	osmo_wqueue_init(wq, 10);
	wq->write_cb = l1fd_write_cb;
	osmo_fd_setup(write_ofd, rc, OSMO_FD_WRITE, osmo_wqueue_bfd_cb, hdl, q);
	rc = osmo_fd_register(write_ofd);
	if (rc < 0) {
		close(write_ofd->fd);
		write_ofd->fd = -1;
		goto out_read;
	}

	return 0;

out_read:
	close(hdl->read_ofd[q].fd);
	osmo_fd_unregister(&hdl->read_ofd[q]);

	return rc;
}

int l1if_transport_close(int q, struct oc2gl1_hdl *hdl)
{
	struct osmo_fd *read_ofd = &hdl->read_ofd[q];
	struct osmo_fd *write_ofd = &hdl->write_q[q].bfd;

	osmo_fd_unregister(read_ofd);
	close(read_ofd->fd);
	read_ofd->fd = -1;

	osmo_fd_unregister(write_ofd);
	close(write_ofd->fd);
	write_ofd->fd = -1;

	return 0;
}
