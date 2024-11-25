/* tbf_dl_fsm.c
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

static const struct osmo_tdef_state_timeout tbf_dl_fsm_timeouts[32] = {
	[TBF_ST_NEW] = {},
	[TBF_ST_ASSIGN] = {},
	[TBF_ST_FLOW] = {},
	[TBF_ST_FINISHED] = {},
	[TBF_ST_WAIT_RELEASE] = { .T = 3192 },
	[TBF_ST_WAIT_REUSE_TFI] = { /* .T = 3193 set manually onenter subtracting T3192 */ },
	[TBF_ST_RELEASING] = { .T = 3195 },
};

/* Transition to a state, using the T timer defined in tbf_dl_fsm_timeouts.
 * The actual timeout value is in turn obtained from T_defs_bts.
 */
#define tbf_dl_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_dl_fsm_timeouts, \
				     tbf_ms(((struct tbf_dl_fsm_ctx *)(fi->priv))->tbf)->bts->T_defs_bts, \
				     -1)

static void mod_ass_type(struct tbf_dl_fsm_ctx *ctx, uint8_t t, bool set)
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
		OSMO_ASSERT(0);
	}

	LOGPTBFDL(ctx->dl_tbf, LOGL_INFO, "%sset ass. type %s [prev CCCH:%u, PACCH:%u]\n",
		  set ? "" : "un", ch,
		  !!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)),
		  !!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)));

	if (set && prev_set) {
		LOGPTBFDL(ctx->dl_tbf, LOGL_ERROR,
			  "Attempted to set ass. type %s which is already set\n", ch);
		return;
	}

	if (!set && !prev_set)
		return;

	if (set)
		ctx->state_flags |= (1 << t);
	else
		ctx->state_flags &= ~(1 << t);
}


static void st_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		tbf_dl_fsm_state_chg(fi, TBF_ST_ASSIGN);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		tbf_dl_fsm_state_chg(fi, TBF_ST_ASSIGN);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_assign_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	struct GprsMs *ms = tbf_ms(ctx->tbf);
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
		LOGPTBFDL(ctx->dl_tbf, LOGL_DEBUG,
			  "Starting timer X2001 [assignment (PACCH)] with %u sec. %u microsec\n",
			  sec, micro);
		osmo_timer_schedule(&fi->timer, sec, micro);
	} else {
		 /* GPRS_RLCMAC_FLAG_CCCH is set, so here we submit a DL Ass
		  * through PCUIF on CCCH */
		OSMO_ASSERT(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH));
		/* Send CCCH (PCH) Immediate Assignment over PCUIF: */
		bts_snd_dl_ass(ms->bts, ctx->dl_tbf);
	}
}

static void st_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	struct GprsMs *ms;
	unsigned long val;
	unsigned int sec, micro;

	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		/* Note: This code path is not really used nowadays, since ADD_CCCH is
		 * only dispatched during dl_tbf allocation (st=NEW) */
		ms = tbf_ms(ctx->tbf);
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		/* Re-send CCCH (PCH) Immediate Assignment over PCUIF: */
		bts_snd_dl_ass(ms->bts, ctx->dl_tbf);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		break;
	case TBF_EV_ASSIGN_ACK_PACCH:
		tbf_assign_control_ts(ctx->tbf);
		if (ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)) {
			/* We now know that the PACCH really existed */
			LOGPTBFDL(ctx->dl_tbf, LOGL_INFO,
				  "The TBF has been confirmed on the PACCH, "
				  "changed type from CCCH to PACCH\n");
			mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, false);
			mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		}
		tbf_dl_fsm_state_chg(fi, TBF_ST_FLOW);
		break;
	case TBF_EV_ASSIGN_PCUIF_CNF:
		/* BTS informs us it sent Imm Ass for DL TBF over CCCH. We now
		 * have to wait for X2002 to trigger (meaning MS is already
		 * listening on PDCH) in order to move to FLOW state and start
		 * transmitting data to it. When X2002 triggers (see cb timer
		 * end of the file) it will send TBF_EV_ASSIGN_READY_CCCH back
		 * to us here.
		 */
		if (!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))) {
			/* This can happen if we initiated a CCCH DlAss from an
			 * older TBF object (same TLLI) towards BTS, and the DL-TBF
			 * was recreated and is now trying to be assigned through
			 * PACCH.
			 */
			LOGPTBFDL(ctx->dl_tbf, LOGL_INFO,
				  "Ignoring event ASSIGN_PCUIF_CNF from BTS "
				  "(CCCH was not requested on current assignment)\n");
			break;
		}
		fi->T = -2002;
		val = osmo_tdef_get(the_pcu->T_defs, fi->T, OSMO_TDEF_MS, -1);
		sec = val / 1000;
		micro = (val % 1000) * 1000;
		LOGPTBFDL(ctx->dl_tbf, LOGL_DEBUG,
			  "Starting timer X2002 [assignment (PCH)] with %u sec. %u microsec\n",
			  sec, micro);
		osmo_timer_schedule(&fi->timer, sec, micro);
		break;
	case TBF_EV_ASSIGN_READY_CCCH:
		/* change state to FLOW, so scheduler will start transmission */
		tbf_dl_fsm_state_chg(fi, TBF_ST_FLOW);
		break;
	case TBF_EV_MAX_N3105:
		/* We are going to release, so abort any Pkt Ul Ass pending to be scheduled: */
		osmo_fsm_inst_dispatch(tbf_ul_ass_fi(ctx->tbf), TBF_UL_ASS_EV_ABORT, NULL);
		tbf_dl_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_flow(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;

	switch (event) {
	case TBF_EV_ASSIGN_PCUIF_CNF:
		if (!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))) {
			/* This can happen if we initiated a CCCH DlAss from an
			 * older TBF object (same TLLI) towards BTS, and the DL-TBF
			 * was recreated (this one) and was successfully assigned over PACCH.
			 * This is usually the case if MS requests 2phase access
			 * to get an UL TBF while we were waiting for a DL TBF
			 * assignment for that same MS over PCH.
			 */
			LOGPTBFDL(ctx->dl_tbf, LOGL_INFO,
				  "Ignoring event ASSIGN_PCUIF_CNF from BTS "
				  "(CCCH was not requested on current assignment)\n");
		}
		break;
	case TBF_EV_DL_ACKNACK_MISS:
		/* DL TBF: we missed a DL ACK/NACK. If we started assignment
		 * over CCCH and never received any DL ACK/NACK yet, it means we
		 * don't even know if the MS successfully received the Imm Ass on
		 * CCCH and hence is listening on PDCH. Let's better refrain
		 * from continuing and start assignment on CCCH again */
		if ((ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)) &&
		    !dl_tbf_first_dl_ack_rcvd(ctx->dl_tbf)) {
			LOGPTBFDL(ctx->dl_tbf, LOGL_DEBUG, "Retransmit ImmAss[PktDlAss] on PCH\n");
			tbf_dl_fsm_state_chg(fi, TBF_ST_ASSIGN);
		}
		break;
	case TBF_EV_LAST_DL_DATA_SENT:
		/* All data has been sent or received, change state to FINISHED */
		tbf_dl_fsm_state_chg(fi, TBF_ST_FINISHED);
		break;
	case TBF_EV_MAX_N3105:
		tbf_dl_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_finished(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_EV_DL_ACKNACK_MISS:
		break;
	case TBF_EV_FINAL_ACK_RECVD:
		/* We received Final Ack (DL ACK/NACK) from MS. move to
		 * WAIT_RELEASE, where MS stays monitoring PDCH over T3192 span,
		 * where we can use this DL TBF to assign a new one in case we
		 * receive more DL data to Tx */
		tbf_dl_fsm_state_chg(fi, TBF_ST_WAIT_RELEASE);
		break;
	case TBF_EV_MAX_N3105:
		tbf_dl_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_release_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	struct GprsMs *ms = tbf_ms(ctx->tbf);

	/* This state was entered because FinalACK was received; now T3192 is
	 * running on the MS and has also been armed by this FSM.
	 * During that time, it is possible to reach the MS over PACCH to assign
	 * new DL TBF.
	 * Upon T3192 expiration, FSM will transition to TBF_ST_WAIT_REUSE_TFI
	 * for some more time (T3193 - T3192) until internally freeing the TBF
	 * object, at which time the resources can be reused.
	 */

	mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, false);

	/* check for LLC PDU in the LLC Queue */
	if (llc_queue_size(ms_llc_queue(ms)) > 0) {
		/* we have more data so we will re-use this tbf */
		ms_new_dl_tbf_assigned_on_pacch(ms, ctx->tbf);
	}
}

static void st_wait_release(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_EV_FINAL_ACK_RECVD:
		/* ignore, duplicate ACK, we already know about since we left ST_FINISHED */
		break;
	case TBF_EV_DL_ACKNACK_MISS:
		/* ignore, miss for retransmitted ACK, but a previous one was
		 * already ACKED since we left ST_FINISHED. This happens due to
		 * fn-advance scheduling several DL blocks in advance. */
		break;
	case TBF_EV_MAX_N3105:
		/* Triggered potentially by a poll timeout of PKT UL/DL TBF ASS.
		 * Reached N3105, the MS is not responding, so stop attempting
		 * using the TBF for DL assignment and change to ST_RELEASING in
		 * order to simply wait until resources can be reused (see
		 * st_releasing_on_enter()). */
		tbf_dl_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_reuse_tfi_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	struct GprsMs *ms = tbf_ms(ctx->tbf);
	unsigned long t3192, t3193, res;

	/* T3192 has expired, so the MS is not listening on that PACCH anymore.
	 * Still, wait until remaining of T3193 expiration (>T3192) to internally
	 * free the TBF, at which point the TFI and other allocated resources
	 * will be freed and can then be reused.
	 */

	t3192 = osmo_tdef_get(ms->bts->T_defs_bts, 3192, OSMO_TDEF_MS, -1);
	t3193 = osmo_tdef_get(ms->bts->T_defs_bts, 3193, OSMO_TDEF_MS, -1);
	/* As per spec T3193 shall be greater than T3192, but let's be safe against wrong configs: */
	res = (t3193 >= t3192) ? (t3193 - t3192) : 0;
	fi->T = 3193;
	LOGPTBF(ctx->tbf, LOGL_DEBUG, "Waiting %lu sec. %lu microsec (T3193 - T3192) [REUSE TFI]\n",
		res / 1000, (res % 1000) * 1000);
	osmo_timer_schedule(&fi->timer, res / 1000, (res % 1000) * 1000);
}

static void st_wait_reuse_tfi(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* Simply wait for T3193 timeout, it will tbf_free() */
	switch (event) {
	case TBF_EV_FINAL_ACK_RECVD:
		/* ignore, duplicate ACK, we already know about since we left ST_FINISHED */
		break;
	case TBF_EV_DL_ACKNACK_MISS:
		/* ignore, miss for retransmitted ACK, but a previous one was
		 * already ACKED since we left ST_FINISHED. This happens due to
		 * fn-advance scheduling several DL blocks in advance. */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_releasing_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* T3195 has been set entering this state: Wait for reuse of TFI(s) when
	*  there is no response from the MS (radio failure or cell change) for this
	*  TBF/MBMS radio bearer. Upon timeout, the timer_cb does tbf_free().
	*/
}

static void st_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_EV_DL_ACKNACK_MISS:
		/* Ignore, we don't care about missed DL ACK/NACK poll timeouts
		 * anymore, we are already releasing the TBF */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void handle_timeout_X2002(struct osmo_fsm_inst *fi)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	int rc;

	if (fi->state != TBF_ST_ASSIGN) {
		LOGPTBFDL(ctx->dl_tbf, LOGL_NOTICE, "Continue flow after IMM.ASS confirm\n");
		return;
	}

	/* state TBF_ST_ASSIGN: */
	tbf_assign_control_ts(ctx->tbf);

	if (!tbf_can_upgrade_to_multislot(ctx->tbf)) {
		/* change state to FLOW, so scheduler will start transmission */
		osmo_fsm_inst_dispatch(fi, TBF_EV_ASSIGN_READY_CCCH, NULL);
		return;
	}

	/* This tbf can be upgraded to use multiple DL timeslots and now that there is already
	 * one slot assigned send another DL assignment via PDCH.
	 */

	/* Reset state flags */
	ctx->state_flags = 0x00;

	rc = dl_tbf_upgrade_to_multislot(ctx->dl_tbf);
	if (rc < 0)
		tbf_free(ctx->tbf);
}

static int tbf_dl_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct tbf_dl_fsm_ctx *ctx = (struct tbf_dl_fsm_ctx *)fi->priv;
	struct GprsMs *ms = NULL;
	struct gprs_rlcmac_ul_tbf *ul_tbf = NULL;
	struct gprs_rlcmac_tbf *tbf = NULL;

	switch (fi->T) {
	case -2002:
		handle_timeout_X2002(fi);
		break;
	case 3192:
		tbf_dl_fsm_state_chg(fi, TBF_ST_WAIT_REUSE_TFI);
		break;
	case -2001:
		ms = tbf_ms(ctx->tbf);
		ul_tbf = ms_ul_tbf(ms);
		tbf = ul_tbf_as_tbf(ul_tbf);
		LOGPTBFDL(ctx->dl_tbf, LOGL_NOTICE, "releasing due to PACCH assignment timeout.\n");
		/* If a UL TBF is trying to assign us, notify it that we are
		 * dying so it avoids continuing the assignment. */
		if (ul_tbf && tbf_dl_ass_fi(tbf)->state != TBF_DL_ASS_NONE)
			osmo_fsm_inst_dispatch(tbf_dl_ass_fi(tbf), TBF_DL_ASS_EV_ABORT, NULL);
		/* fall-through */
	case 3193:
	case 3195:
		tbf_free(ctx->tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state tbf_dl_fsm_states[] = {
	[TBF_ST_NEW] = {
		.in_event_mask =
			X(TBF_EV_ASSIGN_ADD_CCCH) |
			X(TBF_EV_ASSIGN_ADD_PACCH),
		.out_state_mask =
			X(TBF_ST_ASSIGN),
		.name = "NEW",
		.action = st_new,
	},
	[TBF_ST_ASSIGN] = {
		.in_event_mask =
			X(TBF_EV_ASSIGN_ADD_CCCH) |
			X(TBF_EV_ASSIGN_ADD_PACCH) |
			X(TBF_EV_ASSIGN_ACK_PACCH) |
			X(TBF_EV_ASSIGN_PCUIF_CNF) |
			X(TBF_EV_ASSIGN_READY_CCCH) |
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
			X(TBF_EV_ASSIGN_PCUIF_CNF) |
			X(TBF_EV_DL_ACKNACK_MISS) |
			X(TBF_EV_LAST_DL_DATA_SENT) |
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
			X(TBF_EV_DL_ACKNACK_MISS) |
			X(TBF_EV_FINAL_ACK_RECVD) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_WAIT_RELEASE) |
			X(TBF_ST_RELEASING),
		.name = "FINISHED",
		.action = st_finished,
	},
	[TBF_ST_WAIT_RELEASE] = {
		.in_event_mask =
			X(TBF_EV_DL_ACKNACK_MISS) |
			X(TBF_EV_FINAL_ACK_RECVD) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_WAIT_REUSE_TFI) |
			X(TBF_ST_RELEASING),
		.name = "WAIT_RELEASE",
		.action = st_wait_release,
		.onenter = st_wait_release_on_enter,
	},
	[TBF_ST_WAIT_REUSE_TFI] = {
		.in_event_mask =
			X(TBF_EV_DL_ACKNACK_MISS) |
			X(TBF_EV_FINAL_ACK_RECVD),
		.out_state_mask =
			X(TBF_ST_RELEASING),
		.name = "WAIT_REUSE_TFI",
		.action = st_wait_reuse_tfi,
		.onenter = st_wait_reuse_tfi_on_enter,
	},
	[TBF_ST_RELEASING] = {
		.in_event_mask =
			X(TBF_EV_DL_ACKNACK_MISS),
		.out_state_mask =
			0,
		.name = "RELEASING",
		.action = st_releasing,
		.onenter = st_releasing_on_enter,
	},
};

struct osmo_fsm tbf_dl_fsm = {
	.name = "DL_TBF",
	.states = tbf_dl_fsm_states,
	.num_states = ARRAY_SIZE(tbf_dl_fsm_states),
	.timer_cb = tbf_dl_fsm_timer_cb,
	.log_subsys = DTBFDL,
	.event_names = tbf_fsm_event_names,
};

static __attribute__((constructor)) void tbf_dl_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_dl_fsm) == 0);
}
