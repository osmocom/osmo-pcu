/* tbf_ul_ack_fsm.h
 *
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
 */
#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <gprs_pcu.h>

struct gprs_rlcmac_tbf;
struct gprs_rlcmac_ul_tbf;
struct gprs_rlcmac_pdch;

enum tbf_ul_ack_fsm_event {
	TBF_UL_ACK_EV_SCHED_ACK, /* Tx UL ACK/NACK is pending */
	TBF_UL_ACK_EV_CREATE_RLCMAC_MSG, /* Scheduler wants to gen+Tx the Ass (rej): data=tbf_ul_ack_ev_create_rlcmac_msg_ctx */
	TBF_UL_ACK_EV_RX_CTRL_ACK, /* Received CTRL ACK answering poll set on UL ACK/NACK */
	TBF_UL_ACK_EV_POLL_TIMEOUT, /* Pdch Ul Controller signals timeout for poll set on UL ACK/NACK */
};

enum tbf_ul_ack_fsm_states {
	TBF_UL_ACK_ST_NONE = 0,
	TBF_UL_ACK_ST_SCHED_UL_ACK, /* send UL ACK/NACK on next RTS */
	TBF_UL_ACK_ST_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

struct tbf_ul_ack_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_rlcmac_ul_tbf *tbf; /* back pointer */
};

extern struct osmo_fsm tbf_ul_ack_fsm;


/* passed as data in TBF_UL_ACK_EV_CREATE_RLCMAC_MSG */
struct tbf_ul_ack_ev_create_rlcmac_msg_ctx {
	const struct gprs_rlcmac_pdch *pdch; /* TS where the created DL ctrl block is to be sent */
	uint32_t fn; /* FN where the created DL ctrl block is to be sent */
	struct msgb *msg; /* to be filled by FSM during event processing */
};


struct msgb *tbf_ul_ack_create_rlcmac_msg(const struct gprs_rlcmac_ul_tbf *ul_tbf,
					  const struct gprs_rlcmac_pdch *pdch,
					  uint32_t fn);
bool tbf_ul_ack_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_pdch *pdch);
bool tbf_ul_ack_waiting_cnf_final_ack(const struct gprs_rlcmac_ul_tbf *ul_tbf);
bool tbf_ul_ack_exp_ctrl_ack(const struct gprs_rlcmac_ul_tbf *ul_tbf, uint32_t fn, uint8_t ts);
