/* tbf_ul_ass_fsm.h
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
struct gprs_rlcmac_pdch;

enum tbf_ul_ass_fsm_event {
	TBF_UL_ASS_EV_SCHED_ASS, /* Tx Uplink Assignment is pending */
	TBF_UL_ASS_EV_SCHED_ASS_REJ, /* Tx Uplink Assignment is pending */
	TBF_UL_ASS_EV_CREATE_RLCMAC_MSG, /* Scheduler wants to gen+Tx the Ass (rej): data=tbf_ul_ass_ev_create_rlcmac_msg_ctx */
	TBF_UL_ASS_EV_RX_ASS_CTRL_ACK, /* Received CTRL ACK answering poll set on Pkt Ul Ass */
	TBF_UL_ASS_EV_ASS_POLL_TIMEOUT, /* Pdch Ul Controller signals timeout for poll set on Pkt Ul Ass */
	TBF_UL_ASS_EV_ABORT, /* TBF is starting to be RELEASED, drop in progress assignment */
};

enum tbf_ul_ass_fsm_states {
	TBF_UL_ASS_NONE = 0,
	TBF_UL_ASS_SEND_ASS, /* send uplink assignment on next RTS */
	TBF_UL_ASS_SEND_ASS_REJ, /* send assignment reject next RTS */
	TBF_UL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

struct tbf_ul_ass_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_rlcmac_tbf* tbf; /* back pointer */
};

extern const struct osmo_tdef_state_timeout tbf_ul_ass_fsm_timeouts[32];
/* Transition to a state, using the T timer defined in tbf_ul_ass_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define tbf_ul_ass_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_ass_fsm_timeouts, \
				     the_pcu->T_defs, \
				     -1)

extern struct osmo_fsm tbf_ul_ass_fsm;


/* passed as data in TBF_UL_ASS_EV_CREATE_RLCMAC_MSG */
struct tbf_ul_ass_ev_create_rlcmac_msg_ctx {
	uint32_t fn; /* FN where the created DL ctrl block is to be sent */
	uint8_t ts; /* TS where the created DL ctrl block is to be sent */
	struct msgb *msg; /* to be filled by FSM during event processing */
};


struct msgb *tbf_ul_ass_create_rlcmac_msg(const struct gprs_rlcmac_tbf* tbf, uint32_t fn, uint8_t ts);
bool tbf_ul_ass_rts(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch);
