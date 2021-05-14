/* tbf_fsm.h
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <gprs_pcu.h>

struct gprs_rlcmac_tbf;

enum tbf_fsm_event {
	TBF_EV_FOOBAR,
};

enum tbf_fsm_states {
	TBF_ST_NULL = 0,	/* new created TBF */
	TBF_ST_ASSIGN,	/* wait for downlink assignment */
	TBF_ST_FLOW,	/* RLC/MAC flow, resource needed */
	TBF_ST_FINISHED,	/* flow finished, wait for release */
	TBF_ST_WAIT_RELEASE,/* wait for release or restart of DL TBF */
	TBF_ST_RELEASING,	/* releasing, wait to free TBI/USF */
};

struct tbf_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_rlcmac_tbf* tbf; /* back pointer */
};

extern const struct osmo_tdef_state_timeout tbf_fsm_timeouts[32];
/* Transition to a state, using the T timer defined in assignment_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define tbf_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_fsm_timeouts, \
				     the_pcu->T_defs, \
				     -1)

extern struct osmo_fsm tbf_fsm;
