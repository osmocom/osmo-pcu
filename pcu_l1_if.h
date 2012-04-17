/* pcu_l1_if.h
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

#ifndef PCU_L1_IF_H
#define PCU_L1_IF_H


#include <BitVector.h>
#include <gsmL1prim.h>
#include <sys/socket.h>
extern "C" {
#include <osmocom/core/write_queue.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm_utils.h>
}

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

extern struct l1fwd_hdl *l1fh;

int get_current_fn();

void pcu_l1if_tx(BitVector * block, GsmL1_Sapi_t sapi, int len = 23);

int pcu_l1if_handle_l1prim(struct femtol1_hdl *fl1h, struct msgb *msg);

void gsmtap_send_llc(uint8_t * data, unsigned len);

#endif // PCU_L1_IF_H
