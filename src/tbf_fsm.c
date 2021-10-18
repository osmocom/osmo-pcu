/* tbf_fsm.c
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

#include <unistd.h>

#include <talloc.h>

#include <tbf_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>

#define X(s) (1 << (s))

const struct osmo_tdef_state_timeout tbf_fsm_timeouts[32] = {
	[TBF_ST_NEW] = {},
	[TBF_ST_ASSIGN] = { },
	[TBF_ST_FLOW] = { },
	[TBF_ST_FINISHED] = {},
	[TBF_ST_WAIT_RELEASE] = {},
	[TBF_ST_RELEASING] = {},
};

const struct value_string tbf_fsm_event_names[] = {
	{ TBF_EV_ASSIGN_ADD_CCCH, "ASSIGN_ADD_CCCH" },
	{ TBF_EV_ASSIGN_ADD_PACCH, "ASSIGN_ADD_PACCH" },
	{ TBF_EV_ASSIGN_ACK_PACCH, "ASSIGN_ACK_PACCH" },
	{ TBF_EV_ASSIGN_READY_CCCH, "ASSIGN_READY_CCCH" },
	{ TBF_EV_ASSIGN_PCUIF_CNF, "ASSIGN_PCUIF_CNF" },
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

static void mod_ass_type(struct tbf_fsm_ctx *ctx, uint8_t t, bool set)
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
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			"attempted to %sset unexpected ass. type %d - FIXME!\n",
			set ? "" : "un", t);
		return;
	}

	if (set && prev_set) {
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			"attempted to set ass. type %s which is already set.\n", ch);
	} else if (!set && !prev_set) {
			return;
	}

	LOGPTBF(ctx->tbf, LOGL_INFO, "%sset ass. type %s [prev CCCH:%u, PACCH:%u]\n",
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
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		tbf_fsm_state_chg(fi, tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF ?
					TBF_ST_ASSIGN : TBF_ST_FLOW);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		tbf_fsm_state_chg(fi, TBF_ST_ASSIGN);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_assign_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
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
		LOGPTBF(ctx->tbf, LOGL_DEBUG,
			"Starting timer X2001 [assignment (PACCH)] with %u sec. %u microsec\n",
			sec, micro);
		osmo_timer_schedule(&fi->timer, sec, micro);
	} else if (tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF) {
		 /* GPRS_RLCMAC_FLAG_CCCH is set, so here we submitted an DL Ass through PCUIF on CCCH */
	}
}

static void st_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	unsigned long val;
	unsigned int sec, micro;

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
			LOGPTBF(ctx->tbf, LOGL_INFO,
				"The TBF has been confirmed on the PACCH, "
				"changed type from CCCH to PACCH\n");
			mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, false);
			mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		}
		tbf_fsm_state_chg(fi, TBF_ST_FLOW);
		break;
	case TBF_EV_ASSIGN_PCUIF_CNF:
		/* BTS informs us it sent Imm Ass for DL TBF over CCCH. We now
		 * have to wait for X2002 to trigger (meaning MS is already
		 * listening on PDCH) in order to move to FLOW state and start
		 * transmitting data to it. When X2002 triggers (see cb timer
		 * end of the file) it will send  TBF_EV_ASSIGN_READY_CCCH back
		 * to us here. */
		OSMO_ASSERT(tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF);
		fi->T = -2002;
		val = osmo_tdef_get(the_pcu->T_defs, fi->T, OSMO_TDEF_MS, -1);
		sec = val / 1000;
		micro = (val % 1000) * 1000;
		LOGPTBF(ctx->tbf, LOGL_DEBUG,
			"Starting timer X2002 [assignment (AGCH)] with %u sec. %u microsec\n",
			sec, micro);
		osmo_timer_schedule(&fi->timer, sec, micro);
		break;
	case TBF_EV_ASSIGN_READY_CCCH:
		/* change state to FLOW, so scheduler will start transmission */
		tbf_fsm_state_chg(fi, TBF_ST_FLOW);
		break;
	case TBF_EV_MAX_N3105:
		/* We are going to release, so abort any Pkt Ul Ass pending to be scheduled: */
		osmo_fsm_inst_dispatch(tbf_ul_ass_fi(ctx->tbf), TBF_UL_ASS_EV_ABORT, NULL);
		ctx->T_release = 3195;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_flow(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;

	switch (event) {
	case TBF_EV_DL_ACKNACK_MISS:
		/* DL TBF: we missed a DL ACK/NACK. If we started assignment
		 * over CCCH and never received any DL ACK/NACK yet, it means we
		 * don't even know if the MS successfuly received the Imm Ass on
		 * CCCH and hence is listening on PDCH. Let's better refrain
		 * from continuing and start assignment on CCCH again */
		if ((ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
		     && !(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK))) {
			struct GprsMs *ms = tbf_ms(ctx->tbf);
			const char *imsi = ms_imsi(ms);
			uint16_t pgroup;
			LOGPTBF(ctx->tbf, LOGL_DEBUG, "Re-send downlink assignment on PCH (IMSI=%s)\n",
				imsi);
			tbf_fsm_state_chg(fi, TBF_ST_ASSIGN);
			/* send immediate assignment */
			if ((pgroup = imsi2paging_group(imsi)) > 999)
				LOGPTBF(ctx->tbf, LOGL_ERROR, "IMSI to paging group failed! (%s)\n", imsi);
			bts_snd_dl_ass(ms->bts, ctx->tbf, pgroup);
		}
		break;
	case TBF_EV_LAST_DL_DATA_SENT:
	case TBF_EV_LAST_UL_DATA_RECVD:
		/* All data has been sent or received, change state to FINISHED */
		tbf_fsm_state_chg(fi, TBF_ST_FINISHED);
		break;
	case TBF_EV_FINAL_ACK_RECVD:
		/* We received Final Ack (DL ACK/NACK) from MS. move to
		   WAIT_RELEASE, we wait there for release or re-use the TBF in
		   case we receive more DL data to tx */
		tbf_fsm_state_chg(fi, TBF_ST_WAIT_RELEASE);
		break;
	case TBF_EV_MAX_N3101:
		ctx->T_release = 3169;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	case TBF_EV_MAX_N3105:
		ctx->T_release = 3195;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_finished(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_DL_ACKNACK_MISS:
		break;
	case TBF_EV_FINAL_ACK_RECVD:
		/* We received Final Ack (DL ACK/NACK) from MS. move to
		   WAIT_RELEASE, we wait there for release or re-use the TBF in
		   case we receive more DL data to tx */
		tbf_fsm_state_chg(fi, TBF_ST_WAIT_RELEASE);
		break;
	case TBF_EV_FINAL_UL_ACK_CONFIRMED:
		/* UL TBF ACKed our transmitted UL ACK/NACK with final Ack
		 * Indicator set to '1' t. We can free the TBF right away. */
		tbf_free(ctx->tbf);
		break;
	case TBF_EV_MAX_N3103:
		ctx->T_release = 3169;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	case TBF_EV_MAX_N3105:
		ctx->T_release = 3195;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_release_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	unsigned long val_s, val_ms, val_us;
	OSMO_ASSERT(tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF);

	fi->T = 3193;
	val_ms = osmo_tdef_get(tbf_ms(ctx->tbf)->bts->T_defs_bts, fi->T, OSMO_TDEF_MS, -1);
	val_s = val_ms / 1000;
	val_us = (val_ms % 1000) * 1000;
	LOGPTBF(ctx->tbf, LOGL_DEBUG, "starting timer T%u with %lu sec. %lu microsec\n",
		fi->T, val_s, val_us);
	osmo_timer_schedule(&fi->timer, val_s, val_us);

	mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, false);
}

static void st_wait_release(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_FINAL_ACK_RECVD:
		/* ignore, duplicate ACK, we already know about since we are in WAIT_RELEASE */
		break;
	case TBF_EV_MAX_N3101:
		ctx->T_release = 3169;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	case TBF_EV_MAX_N3105:
		ctx->T_release = 3195;
		tbf_fsm_state_chg(fi, TBF_ST_RELEASING);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_releasing_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
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
	LOGPTBF(ctx->tbf, LOGL_DEBUG, "starting timer T%u with %lu sec. %u microsec\n",
		ctx->T_release, val, 0);
	osmo_timer_schedule(&fi->timer, val, 0);
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

static void handle_timeout_X2002(struct tbf_fsm_ctx *ctx)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(ctx->tbf);

	/* X2002 is used only for DL TBF */
	OSMO_ASSERT(dl_tbf);

	if (ctx->fi->state == TBF_ST_ASSIGN) {
		tbf_assign_control_ts(ctx->tbf);

		if (!tbf_can_upgrade_to_multislot(ctx->tbf)) {
			/* change state to FLOW, so scheduler
			 * will start transmission */
			osmo_fsm_inst_dispatch(ctx->fi, TBF_EV_ASSIGN_READY_CCCH, NULL);
			return;
		}

		/* This tbf can be upgraded to use multiple DL
		 * timeslots and now that there is already one
		 * slot assigned send another DL assignment via
		 * PDCH. */

		/* keep to flags */
		ctx->state_flags &= GPRS_RLCMAC_FLAG_TO_MASK;

		tbf_update(ctx->tbf);

		tbf_dl_trigger_ass(dl_tbf, ctx->tbf);
	} else
		LOGPTBF(ctx->tbf, LOGL_NOTICE, "Continue flow after IMM.ASS confirm\n");
}

static int tbf_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (fi->T) {
	case -2002:
		handle_timeout_X2002(ctx);
		break;
	case -2001:
		LOGPTBF(ctx->tbf, LOGL_NOTICE, "releasing due to PACCH assignment timeout.\n");
		/* fall-through */
	case 3169:
	case 3193:
	case 3195:
		tbf_free(ctx->tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state tbf_fsm_states[] = {
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
			X(TBF_EV_DL_ACKNACK_MISS) |
			X(TBF_EV_LAST_DL_DATA_SENT) |
			X(TBF_EV_LAST_UL_DATA_RECVD) |
			X(TBF_EV_FINAL_ACK_RECVD) |
			X(TBF_EV_MAX_N3101) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_ASSIGN) |
			X(TBF_ST_FINISHED) |
			X(TBF_ST_WAIT_RELEASE) |
			X(TBF_ST_RELEASING),
		.name = "FLOW",
		.action = st_flow,
	},
	[TBF_ST_FINISHED] = {
		.in_event_mask =
			X(TBF_EV_DL_ACKNACK_MISS) |
			X(TBF_EV_FINAL_ACK_RECVD) |
			X(TBF_EV_FINAL_UL_ACK_CONFIRMED) |
			X(TBF_EV_MAX_N3103) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_WAIT_RELEASE) |
			X(TBF_ST_RELEASING),
		.name = "FINISHED",
		.action = st_finished,
	},
	[TBF_ST_WAIT_RELEASE] = {
		.in_event_mask =
			X(TBF_EV_FINAL_ACK_RECVD) |
			X(TBF_EV_MAX_N3101) |
			X(TBF_EV_MAX_N3105),
		.out_state_mask =
			X(TBF_ST_RELEASING),
		.name = "WAIT_RELEASE",
		.action = st_wait_release,
		.onenter = st_wait_release_on_enter,
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

struct osmo_fsm tbf_fsm = {
	.name = "TBF",
	.states = tbf_fsm_states,
	.num_states = ARRAY_SIZE(tbf_fsm_states),
	.timer_cb = tbf_fsm_timer_cb,
	.log_subsys = DTBF,
	.event_names = tbf_fsm_event_names,
};

static __attribute__((constructor)) void tbf_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_fsm) == 0);
}
