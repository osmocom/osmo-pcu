/* ms_anr_fsm.h
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

#include "pcu_utils.h"

struct GprsMs;
struct gprs_rlcmac_tbf;

#define MAX_NEIGH_LIST_LEN 96
#define MAX_NEIGH_MEAS_LIST_LEN 32

enum ms_anr_fsm_event {
	MS_ANR_EV_START, /* data: struct ms_anr_ev_start */
	MS_ANR_EV_CREATE_RLCMAC_MSG, /* data: struct anr_ev_create_rlcmac_msg_ctx* */
	MS_ANR_EV_RX_PKT_MEAS_REPORT, /* data: Packet_Measurement_Report_t */
	MS_ANR_EV_RX_PKT_CTRL_ACK_MSG,
	MS_ANR_EV_RX_PKT_CTRL_ACK_TIMEOUT,
};

enum ms_anr_fsm_states {
	MS_ANR_ST_INITIAL,
	MS_ANR_ST_TX_PKT_MEAS_RESET1,
	MS_ANR_ST_WAIT_CTRL_ACK1,
	MS_ANR_ST_TX_PKT_MEAS_ORDER,
	MS_ANR_ST_WAIT_PKT_MEAS_REPORT,
	MS_ANR_ST_TX_PKT_MEAS_RESET2,
	MS_ANR_ST_WAIT_CTRL_ACK2,
	MS_ANR_ST_DONE,
};

struct ms_anr_fsm_ctx {
	struct osmo_fsm_inst *fi;
	struct GprsMs* ms; /* back pointer */
	struct gprs_rlcmac_tbf *tbf; /* target tbf to create messages for, selected upon first MS_ANR_EV_CREATE_RLCMAC_MSG */
	struct arfcn_bsic cell_list[MAX_NEIGH_MEAS_LIST_LEN]; /* ordered by ascending ARFCN */
	unsigned int num_cells;
	struct llist_head meas_order_queue; /* list of msgb PMO_IDX=0..PMO_COUNT */
	uint16_t nc_measurement_list[MAX_NEIGH_LIST_LEN]; /* Used to infer ARFCN from Frequency index received at Measurement Report */
	unsigned int nc_measurement_list_len;
	uint32_t poll_fn; /* Scheduled poll FN to CTRL ACK the Pkt Meas Order (reset) */
	uint8_t poll_ts; /* Scheduled poll TS to CTRL ACK the Pkt Meas Order (reset */
};

/* passed as data in MS_ANR_EV_START */
struct ms_anr_ev_start {
	struct gprs_rlcmac_tbf *tbf; /* target DL TBF to create messages for */
	const struct arfcn_bsic* cell_list;
	unsigned int num_cells;
};

/* passed as data in MS_ANR_EV_CREATE_RLCMAC_MSG */
struct ms_anr_ev_create_rlcmac_msg_ctx {
	//struct gprs_rlcmac_tbf *tbf; /* target DL TBF to create messages for */
	uint32_t fn; /* FN where the created DL ctrl block is to be sent */
	uint8_t ts; /* TS where the created DL ctrl block is to be sent */
	struct msgb *msg; /* to be filled by FSM during event processing */
};

struct ms_anr_fsm_ctx *ms_anr_fsm_alloc(struct GprsMs* ms);
void ms_anr_fsm_abort(struct ms_anr_fsm_ctx *ctx);

/* 3GPP TS44.060 Table 11.2.4.2: PACKET CELL CHANGE ORDER
 * 3GPP TS 45.008 10.1.4 Network controlled Cell re-selection*/
enum network_control_order {
	NC_0 = 0x00,
	NC_1 = 0x01,
	NC_2 = 0x02,
	NC_RESET = 0x03
};
