/* Copyright (C) 2015 by Yves Godin <support@nuranwireless.com>
 * based on:
 *     femto_l1_if.h
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

#ifndef _LC15_L1_IF_H
#define _LC15_L1_IF_H

#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/gsm/gsm_utils.h>
#include "lc15bts.h"

enum {
	MQ_SYS_READ,
	MQ_L1_READ,
	MQ_TCH_READ,
	MQ_PDTCH_READ,
	_NUM_MQ_READ
};

enum {
	MQ_SYS_WRITE,
	MQ_L1_WRITE,
	MQ_TCH_WRITE,
	MQ_PDTCH_WRITE,
	_NUM_MQ_WRITE
};

struct lc15l1_hdl {
	struct gsm_time gsm_time;
	uint32_t hLayer1;			/* handle to the L1 instance in the DSP */
	uint32_t dsp_trace_f;
	struct llist_head wlc_list;

	struct gsmtap_inst *gsmtap;
	uint32_t gsmtap_sapi_mask;

	uint8_t trx_no;

	struct osmo_timer_list alive_timer;
	unsigned int alive_prim_cnt;

	struct osmo_fd read_ofd[_NUM_MQ_READ];	/* osmo file descriptors */
	struct osmo_wqueue write_q[_NUM_MQ_WRITE];

	struct {
		int trx_nr;	/* <1-2> */
	} hw_info;
};

#define msgb_l1prim(msg)	((GsmL1_Prim_t *)(msg)->l1h)
#define msgb_sysprim(msg)	((Litecell15_Prim_t *)(msg)->l1h)

typedef int l1if_compl_cb(struct msgb *l1_msg, void *data);

/* send a request primitive to the L1 and schedule completion call-back */
int l1if_req_compl(struct lc15l1_hdl *fl1h, struct msgb *msg,
		   int is_system_prim, l1if_compl_cb *cb, void *data);

int l1if_reset(struct lc15l1_hdl *hdl);
int l1if_activate_rf(struct lc15l1_hdl *hdl, int on);
int l1if_set_trace_flags(struct lc15l1_hdl *hdl, uint32_t flags);
int l1if_set_txpower(struct lc15l1_hdl *fl1h, float tx_power);

struct msgb *l1p_msgb_alloc(void);
struct msgb *sysp_msgb_alloc(void);

uint32_t l1if_lchan_to_hLayer2(struct gsm_lchan *lchan);
struct gsm_lchan *l1if_hLayer2_to_lchan(struct gsm_bts_trx *trx, uint32_t hLayer2);

int l1if_handle_sysprim(struct lc15l1_hdl *fl1h, struct msgb *msg);
int l1if_handle_l1prim(int wq, struct lc15l1_hdl *fl1h, struct msgb *msg);

/* tch.c */
int l1if_tch_rx(struct gsm_lchan *lchan, struct msgb *l1p_msg);
int l1if_tch_fill(struct gsm_lchan *lchan, uint8_t *l1_buffer);
struct msgb *gen_empty_tch_msg(struct gsm_lchan *lchan);

/*
 * The implementation of these functions is selected by either compiling and
 * linking sysmo_l1_hw.c or sysmo_l1_fwd.c
 */
int l1if_transport_open(int q, struct lc15l1_hdl *hdl);
int l1if_transport_close(int q, struct lc15l1_hdl *hdl);

#endif /* _SYSMO_L1_IF_H */
