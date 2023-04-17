/* tbf_ul_fsm.c
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

#include <unistd.h>

#include <talloc.h>

#include <tbf_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>

#include <bts_pch_timer.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout tbf_ul_fsm_timeouts[32] = {
	[TBF_ST_NEW] = {},
	[TBF_ST_ASSIGN] = { },
	[TBF_ST_FLOW] = { },
	[TBF_ST_FINISHED] = {},
	[TBF_ST_RELEASING] = {},
};

/* Transition to a state, using the T timer defined in tbf_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define tbf_ul_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_fsm_timeouts, \
				     the_pcu->T_defs, \
				     -1)

static void mod_ass_type(struct tbf_ul_fsm_ctx *ctx, uint8_t t, bool set)
{
	const char *ch = "UNKNOWN";
	bool prev_set = ctx->state_flags & (1 << t);

	switch (t) {
	case GPRS_RLCMAC_FLAG_CCCH:
		ch = "CCCH";
		break;
	case GPRS_RLCMAC_FLAG_PACCH:
		ch = "PACCH";
		break;
	default:
		LOGPTBFUL(ctx->ul_tbf, LOGL_ERROR,
			  "attempted to %sset unexpected ass. type %d - FIXME!\n",
			  set ? "" : "un", t);
		return;
	}

	if (set && prev_set)
		LOGPTBFUL(ctx->ul_tbf, LOGL_ERROR,
			 "attempted to set ass. type %s which is already set.\n", ch);
	else if (!set && !prev_set)
		return;

	LOGPTBFUL(ctx->ul_tbf, LOGL_INFO, "%sset ass. type %s [prev CCCH:%u, PACCH:%u]\n",
		  set ? "" : "un", ch,
		  !!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)),
		  !!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)));

	if (set) {
		ctx->state_flags |= (1 << t);
	} else {
		ctx->state_flags &= GPRS_RLCMAC_FLAG_TO_MASK; /* keep to flags */
		ctx->state_flags &= ~(1 << t);
	}
}


static void st_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		tbf_ul_fsm_state_chg(fi, TBF_ST_FLOW);
		ul_tbf_contention_resolution_start(ctx->ul_tbf);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		tbf_ul_fsm_state_chg(fi, TBF_ST_ASSIGN);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_assign_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;
	unsigned long val;
	unsigned int sec, micro;

	/* If assignment for this TBF is happening on PACCH, that means the
	 * actual Assignment procedure (tx/rx) is happening on another TBF (eg
	 * Ul TBF vs DL TBF). Hence we add a security timer here to free it in
	 * case the other TBF doesn't succeed in informing (assigning) the MS
	 * about this TBF, or simply because the scheduler takes too long to
	 * schedule it. This timer can probably be dropped once we make the
	 * other TBF always signal us assignment failure (we already get
	 * assignment success through TBF_EV_ASSIGN_ACK_PACCH) */
	if (ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)) {
		fi->T = -2001;
		val = osmo_tdef_get(the_pcu->T_defs, fi->T, OSMO_TDEF_MS, -1);
		sec = val / 1000;
		micro = (val % 1000) * 1000;
		LOGPTBFUL(ctx->ul_tbf, LOGL_DEBUG,
			  "Starting timer X2001 [assignment (PACCH)] with %u sec. %u microsec\n",
			  sec, micro);
		osmo_timer_schedule(&fi->timer, sec, micro);
	}
}

static void st_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;

	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		break;
	case TBF_EV_ASSIGN_ACK_PACCH:
		tbf_assign_control_ts(ctx->tbf);
		if (ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)) {
			/* We now know that the PACCH really existed */
			LOGPTBFUL(ctx->ul_tbf, LOGL_INFO,
				  "The TBF has been confirmed on the PACCH, "
				  "changed type from CCCH to PACCH\n");
			mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, false);
			mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		}
		tbf_ul_fsm_state_chg(fi, TBF_ST_FLOW);
		break;
	case TBF_EV_MAX_N3105:
		/* We are going to release, so abort any Pkt Ul Ass pending to be scheduled: */
		osmo_fsm_inst_dispatch(tbf_ul_ass_fi(ctx->tbf), TBF_UL_ASS_EV_ABORT, NULL);
		ctx->T_release = 3195;
		tbf_ul_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_flow(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;
	struct GprsMs *ms = tbf_ms(ctx->tbf);
	struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;

	switch (event) {
	case TBF_EV_FIRST_UL_DATA_RECVD:
		OSMO_ASSERT(tbf_direction(ctx->tbf) == GPRS_RLCMAC_UL_TBF);
		/* TS 44.060 7a.2.1.1: "The contention resolution is completed on
		 * the network side when the network receives an RLC data block that
		 * comprises the TLLI value that identifies the mobile station and the
		 * TFI value associated with the TBF." */
		bts_pch_timer_stop(ms->bts, ms);
		/* We may still have some DL-TBF waiting for assignment in PCH,
		 * which clearly won't happen since the MS is on PDCH now. Get rid
		 * of it, it will be re-assigned on PACCH when contention
		 * resolution at the MS side is done (1st UL ACK/NACK sent) */
		if ((dl_tbf = ms_dl_tbf(ms))) {
			/* Get rid of previous finished UL TBF before providing a new one */
			LOGPTBFDL(dl_tbf, LOGL_NOTICE,
					"Got first UL data while DL-TBF pending, killing it\n");
			tbf_free(dl_tbf_as_tbf(dl_tbf));
			dl_tbf = NULL;
		}
		break;
	case TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS:
		ul_tbf_contention_resolution_success(tbf_as_ul_tbf(ctx->tbf));
		break;
	case TBF_EV_LAST_UL_DATA_RECVD:
		/* All data has been sent or received, change state to FINISHED */
		tbf_ul_fsm_state_chg(fi, TBF_ST_FINISHED);
		break;
	case TBF_EV_MAX_N3101:
		ctx->T_release = 3169;
		tbf_ul_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	case TBF_EV_MAX_N3105:
		ctx->T_release = 3195;
		tbf_ul_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_finished(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;
	struct GprsMs *ms;
	bool new_ul_tbf_requested;

	switch (event) {
	case TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS:
		/* UL TBF: If MS only sends 1 RLCMAC UL block, it can be that we
		 * end up in FINISHED state before sending the first UL ACK/NACK */
		ul_tbf_contention_resolution_success(tbf_as_ul_tbf(ctx->tbf));
		break;
	case TBF_EV_FINAL_UL_ACK_CONFIRMED:
		OSMO_ASSERT(tbf_direction(ctx->tbf) == GPRS_RLCMAC_UL_TBF);
		new_ul_tbf_requested = (bool)data;
		/* Ref the MS, otherwise it may be freed after ul_tbf is
		 * detached when sending event below. */
		ms = tbf_ms(ctx->tbf);
		ms_ref(ms, __func__);
		/* UL TBF ACKed our transmitted UL ACK/NACK with final Ack
		 * Indicator set to '1'. We can free the TBF right away, the MS
		 * also just released its TBF on its side. */
		LOGPTBFUL(tbf_as_ul_tbf(ctx->tbf), LOGL_DEBUG, "[UPLINK] END\n");
		tbf_free(ctx->tbf);
		/* Here fi, ctx and ctx->tbf are already freed! */
		/* TS 44.060 9.3.3.3.2: There might be LLC packets waiting in
		 * the queue but the DL TBF assignment might have been delayed
		 * because there was no way to reach the MS (because ul_tbf was
		 * in packet-active mode with FINISHED state). If MS is going
		 * back to packet-idle mode then we can assign the DL TBF on PCH
		 * now. */
		if (!new_ul_tbf_requested && ms_need_dl_tbf(ms))
			ms_new_dl_tbf_assigned_on_pch(ms);
		ms_unref(ms, __func__);
		break;
	case TBF_EV_MAX_N3103:
		ctx->T_release = 3169;
		tbf_ul_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	case TBF_EV_MAX_N3105:
		ctx->T_release = 3195;
		tbf_ul_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_releasing_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;
	unsigned long val;

	if (!ctx->T_release)
		return;

	/* In  general we should end up here with an assigned timer in ctx->T_release. Possible values are:
	* T3195: Wait for reuse of TFI(s) when there is no response from the MS
	*	 (radio failure or cell change) for this TBF/MBMS radio bearer.
	* T3169: Wait for reuse of USF and TFI(s) after the MS uplink assignment for this TBF is invalid.
	*/
	val = osmo_tdef_get(tbf_ms(ctx->tbf)->bts->T_defs_bts, ctx->T_release, OSMO_TDEF_S, -1);
	fi->T = ctx->T_release;
	LOGPTBFUL(ctx->ul_tbf, LOGL_DEBUG, "starting timer T%u with %lu sec. %u microsec\n",
		  ctx->T_release, val, 0);
	osmo_timer_schedule(&fi->timer, val, 0);
}

static void st_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_EV_MAX_N3105:
		/* This may be received here if the TBF had several polls
		 * allocated concurrently and several failed each increasing N3105
		 * over MAX_N3015. We are already releasing, ignore.*/
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int tbf_ul_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct tbf_ul_fsm_ctx *ctx = (struct tbf_ul_fsm_ctx *)fi->priv;
	switch (fi->T) {
	case -2001:
		LOGPTBFUL(ctx->ul_tbf, LOGL_NOTICE, "releasing due to PACCH assignment timeout.\n");
		/* fall-through */
	case 3169:
	case 3195:
		tbf_free(ctx->tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state tbf_ul_fsm_states[] = {
	[TBF_ST_NEW] = {
		.in_event_mask =
			X(TBF_EV_ASSIGN_ADD_CCCH) |
			X(TBF_EV_ASSIGN_ADD_PACCH),
		.out_state_mask =
			X(TBF_ST_ASSIGN) |
			X(TBF_ST_FLOW) |
			X(TBF_ST_RELEASING),
		.name = "NEW",
		.action = st_new,
	},
	[TBF_ST_ASSIGN] = {
		.in_event_mask =
			X(TBF_EV_ASSIGN_ADD_CCCH) |
			X(TBF_EV_ASSIGN_ADD_PACCH) |
			X(TBF_EV_ASSIGN_ACK_PACCH) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_FLOW) |
			X(TBF_ST_FINISHED) |
			X(TBF_ST_RELEASING),
		.name = "ASSIGN",
		.action = st_assign,
		.onenter = st_assign_on_enter,
	},
	[TBF_ST_FLOW] = {
		.in_event_mask =
			X(TBF_EV_FIRST_UL_DATA_RECVD) |
			X(TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS) |
			X(TBF_EV_LAST_UL_DATA_RECVD) |
			X(TBF_EV_MAX_N3101) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_ASSIGN) |
			X(TBF_ST_FINISHED) |
			X(TBF_ST_RELEASING),
		.name = "FLOW",
		.action = st_flow,
	},
	[TBF_ST_FINISHED] = {
		.in_event_mask =
			X(TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS) |
			X(TBF_EV_FINAL_UL_ACK_CONFIRMED) |
			X(TBF_EV_MAX_N3103) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_RELEASING),
		.name = "FINISHED",
		.action = st_finished,
	},
	[TBF_ST_RELEASING] = {
		.in_event_mask =
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			0,
		.name = "RELEASING",
		.action = st_releasing,
		.onenter = st_releasing_on_enter,
	},
};

struct osmo_fsm tbf_ul_fsm = {
	.name = "UL_TBF",
	.states = tbf_ul_fsm_states,
	.num_states = ARRAY_SIZE(tbf_ul_fsm_states),
	.timer_cb = tbf_ul_fsm_timer_cb,
	.log_subsys = DTBFUL,
	.event_names = tbf_fsm_event_names,
};

static __attribute__((constructor)) void tbf_ul_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_ul_fsm) == 0);
}
