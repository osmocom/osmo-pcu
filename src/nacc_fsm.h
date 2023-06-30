/* nacc_fsm.h
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
#include <osmocom/gsm/gsm23003.h>

#include <neigh_cache.h>

struct GprsMs;
struct gprs_rlcmac_tbf;
struct gprs_rlcmac_pdch;

enum nacc_fsm_event {
	NACC_EV_RX_CELL_CHG_NOTIFICATION, /* data: Packet_Cell_Change_Notification_t* */
	NACC_EV_RX_RAC_CI, /* RAC_CI became available in neigh_cache. NULL on failure, pointer to ctx->cgi_ps on success */
	NACC_EV_RX_SI, /* data: struct si_cache_entry* */
	NACC_EV_CREATE_RLCMAC_MSG, /* data: struct nacc_ev_create_rlcmac_msg_ctx* */
	NACC_EV_RX_CELL_CHG_CONTINUE_ACK,
	NACC_EV_TIMEOUT_CELL_CHG_CONTINUE, /* Poll Timeout */
};

enum nacc_fsm_states {
	NACC_ST_INITIAL,
	NACC_ST_WAIT_RESOLVE_RAC_CI,
	NACC_ST_WAIT_REQUEST_SI,
	NACC_ST_TX_NEIGHBOUR_DATA,
	NACC_ST_TX_CELL_CHG_CONTINUE,
	NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK,
	NACC_ST_DONE,
};

struct nacc_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct GprsMs* ms; /* back pointer */
	struct neigh_cache_entry_key neigh_key; /* target cell info from MS */
	bool neigh_key_present; /* target cell info from MS is present */
	struct osmo_cell_global_id_ps cgi_ps; /* target cell info resolved from req_{arfcn+bsic} */
	struct si_cache_value si_info; /* SI info resolved from SGSN, to be sent to MS */
	size_t si_info_bytes_sent; /* How many bytes out of si_info->si_len were already sent to MS */
	size_t container_idx; /* Next container_idx to assign when sending Packet Neighbor Data message */
	uint32_t continue_poll_fn; /* Scheduled poll FN to CTRL ACK the Pkt Cell Chg Continue */
	uint8_t continue_poll_ts; /* Scheduled poll TS to CTRL ACK the Pkt Cell Chg Continue */
};

/* passed as data in NACC_EV_CREATE_RLCMAC_MSG */
struct nacc_ev_create_rlcmac_msg_ctx {
	struct gprs_rlcmac_tbf *tbf; /* target tbf to create messages for */
	const struct gprs_rlcmac_pdch *pdch; /* TS where the created DL ctrl block is to be sent */
	uint32_t fn; /* FN where the created DL ctrl block is to be sent */
	struct msgb *msg; /* to be filled by FSM during event processing */
};

struct nacc_fsm_ctx *nacc_fsm_alloc(struct GprsMs* ms);

bool nacc_fsm_is_waiting_addr_resolution(const struct nacc_fsm_ctx *ctx,
					 const struct neigh_cache_entry_key *neigh_key);

bool nacc_fsm_is_waiting_si_resolution(const struct nacc_fsm_ctx *ctx,
				       const struct osmo_cell_global_id_ps *cgi_ps);

bool nacc_fsm_exp_ctrl_ack(const struct nacc_fsm_ctx *ctx, uint32_t fn, uint8_t ts);

bool tbf_nacc_rts(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch);
