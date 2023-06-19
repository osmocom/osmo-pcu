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
 */
#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <gprs_pcu.h>

struct gprs_rlcmac_tbf;

enum tbf_fsm_event {
	/* For both UL/DL TBF: */
	TBF_EV_ASSIGN_ADD_CCCH,  /* An assignment is sent over CCCH and confirmation from MS is pending */
	TBF_EV_ASSIGN_ADD_PACCH, /* An assignment is sent over PACCH and confirmation from MS is pending */
	TBF_EV_ASSIGN_ACK_PACCH, /* We received a CTRL ACK confirming assignment started on PACCH */
	TBF_EV_MAX_N3105, /* MAX N3105 (max poll timeout) reached */

	/* Only for DL TBF: */
	TBF_EV_ASSIGN_READY_CCCH, /* TBF Start Time timer triggered */
	TBF_EV_ASSIGN_PCUIF_CNF, /* Transmission of IMM.ASS for to the MS confirmed by BTS over PCUIF */
	TBF_EV_DL_ACKNACK_MISS, /* We polled for DL ACK/NACK but we received none (POLL timeout) */
	TBF_EV_LAST_DL_DATA_SENT, /* Network sends RLCMAC block containing last DL avilable data buffered */
	TBF_EV_FINAL_ACK_RECVD, /* DL ACK/NACK with FINAL_ACK=1 received from MS */

	/* Only for UL TBF: */
	TBF_EV_FIRST_UL_DATA_RECVD, /* Received first UL data from MS. Equals to Contention Resolution completed on the network side */
	TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS, /* Contention resolution success at the mobile station side (first UL_ACK_NACK confirming TLLI is received at the MS) */
	TBF_EV_LAST_UL_DATA_RECVD, /* MS ends RLCMAC block containing last UL data (cv=0) */
	TBF_EV_FINAL_UL_ACK_CONFIRMED, /* MS ACKs (CtrlAck or PktResReq) our UL ACK/NACK w/ FinalAckInd=1. data = (bool) MS requests establishment of a new UL-TBF. */
	TBF_EV_MAX_N3101, /* MAX N3101 (max usf timeout) reached */
	TBF_EV_MAX_N3103, /* MAX N3103 (max Pkt Ctrl Ack for last UL ACK/NACK timeout) reached */
};

extern const struct value_string tbf_fsm_event_names[];

enum tbf_fsm_states {
	TBF_ST_NEW = 0,	/* new created TBF */
	TBF_ST_ASSIGN,	/* wait for downlink assignment */
	TBF_ST_FLOW,	/* RLC/MAC flow, resource needed */
	TBF_ST_FINISHED,	/* flow finished, wait for release */
	TBF_ST_WAIT_RELEASE,/* DL TBF: wait for release or restart */
	TBF_ST_RELEASING,	/* releasing, wait to free TFI/USF */
};

struct tbf_dl_fsm_ctx {
	union { /* back pointer. union used to easily access superclass from ctx */
		struct gprs_rlcmac_tbf *tbf;
		struct gprs_rlcmac_dl_tbf *dl_tbf;
	};
	uint32_t state_flags;
};

struct tbf_ul_fsm_ctx {
	union { /* back pointer. union used to easily access superclass from ctx */
		struct gprs_rlcmac_tbf *tbf;
		struct gprs_rlcmac_ul_tbf *ul_tbf;
	};
	uint32_t state_flags;
};

extern struct osmo_fsm tbf_dl_fsm;
extern struct osmo_fsm tbf_ul_fsm;
