/* tbf_fsm.c
 *
 * Copyright (C) 2021-2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/utils.h>

#include <tbf_fsm.h>

/* Note: This file contains shared code for UL/DL TBF FSM. See tbf_dl_fsm.c and
 * tbf_ul_fsm.c for the actual implementations of the FSM */

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define tbf_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_fsm_timeouts, \
				     the_pcu->T_defs, \
				     -1)

const struct value_string tbf_fsm_event_names[] = {
	{ TBF_EV_ASSIGN_ADD_CCCH, "ASSIGN_ADD_CCCH" },
	{ TBF_EV_ASSIGN_ADD_PACCH, "ASSIGN_ADD_PACCH" },
	{ TBF_EV_ASSIGN_ACK_PACCH, "ASSIGN_ACK_PACCH" },
	{ TBF_EV_ASSIGN_READY_CCCH, "ASSIGN_READY_CCCH" },
	{ TBF_EV_ASSIGN_PCUIF_CNF, "ASSIGN_PCUIF_CNF" },
	{ TBF_EV_FIRST_UL_DATA_RECVD, "FIRST_UL_DATA_RECVD" },
	{ TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS, "CONTENTION_RESOLUTION_MS_SUCCESS" },
	{ TBF_EV_DL_ACKNACK_MISS, "DL_ACKNACK_MISS" },
	{ TBF_EV_LAST_DL_DATA_SENT, "LAST_DL_DATA_SENT" },
	{ TBF_EV_LAST_UL_DATA_RECVD, "LAST_UL_DATA_RECVD" },
	{ TBF_EV_FINAL_ACK_RECVD, "FINAL_ACK_RECVD" },
	{ TBF_EV_FINAL_UL_ACK_CONFIRMED, "FINAL_UL_ACK_CONFIRMED" },
	{ TBF_EV_MAX_N3101 , "MAX_N3101" },
	{ TBF_EV_MAX_N3103 , "MAX_N3103" },
	{ TBF_EV_MAX_N3105 , "MAX_N3105" },
	{ 0, NULL }
};
