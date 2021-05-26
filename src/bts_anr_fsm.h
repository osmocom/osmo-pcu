/* bts_anr_fsm.h
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
#include <osmocom/gsm/gsm23003.h>

#include <pcu_utils.h>

#define MAX_NEIGH_LIST_LEN 96

struct gprs_rlcmac_bts;

enum bts_anr_fsm_event {
	BTS_ANR_EV_RX_ANR_REQ, /* data: struct gsm_pcu_if_anr_req* */
	BTS_ANR_EV_SCHED_MS_MEAS,
	BTS_ANR_EV_MS_MEAS_COMPL, /* data: struct ms_anr_ev_meas_compl* */
	BTS_ANR_EV_MS_MEAS_ABORTED, /* data: struct ms_anr_ev_meas_abort* */
};

enum bts_anr_fsm_states {
	BTS_ANR_ST_DISABLED,
	BTS_ANR_ST_ENABLED
};

struct bts_anr_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct gprs_rlcmac_bts *bts; /* back pointer */
	struct arfcn_bsic cell_list[MAX_NEIGH_LIST_LEN]; /* ordered by ascending ARFCN */
	unsigned int num_cells;
	unsigned int next_cell; /* Next cell list subset starts from this index */
};

/* passed as data in BTS_ANR_EV_MS_MEAS_COMPL */

struct ms_anr_ev_meas_compl {
	const struct arfcn_bsic *cell_list; /* len() = num_cells */
	const uint8_t *meas_list; /* len() = num_cells, value 0xff means invalid */
	unsigned int num_cells;
};

/* passed as data in BTS_ANR_EV_MS_MEAS_ABORT */
struct ms_anr_ev_abort {
	const struct arfcn_bsic* cell_list;
	unsigned int num_cells;
};

struct bts_anr_fsm_ctx *bts_anr_fsm_alloc(struct gprs_rlcmac_bts* bts);
