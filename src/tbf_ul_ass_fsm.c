/* tbf_ul_ass_fsm.c
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

#include <unistd.h>

#include <talloc.h>

#include <osmocom/core/bitvec.h>

#include <tbf_ul_ass_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>
#include <tbf.h>
#include <tbf_ul.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout tbf_ul_ass_fsm_timeouts[32] = {
	[TBF_UL_ASS_NONE] = {},
	[TBF_UL_ASS_SEND_ASS] = { .keep_timer = true },
	[TBF_UL_ASS_SEND_ASS_REJ] = {},
	[TBF_UL_ASS_WAIT_ACK] = { .keep_timer = true },
};

static const struct value_string tbf_ul_ass_fsm_event_names[] = {
	{ TBF_UL_ASS_EV_SCHED_ASS, "SCHED_ASS" },
	{ TBF_UL_ASS_EV_SCHED_ASS_REJ, "SCHED_ASS_REJ" },
	{ TBF_UL_ASS_EV_CREATE_RLCMAC_MSG, "CREATE_RLCMAC_MSG" },
	{ TBF_UL_ASS_EV_RX_ASS_CTRL_ACK, "RX_ASS_CTRL_ACK" },
	{ TBF_UL_ASS_EV_ASS_POLL_TIMEOUT, "ASS_POLL_TIMEOUT" },
	{ TBF_UL_ASS_EV_ABORT, "ABORT" },
	{ 0, NULL }
};

/* Transition to a state, using the T timer defined in tbf_ul_ass_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define tbf_ul_ass_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_ass_fsm_timeouts, \
				     the_pcu->T_defs, \
				     -1)

static struct msgb *create_packet_access_reject(const struct tbf_ul_ass_fsm_ctx *ctx)
{
	struct msgb *msg;
	struct GprsMs *ms = tbf_ms(ctx->tbf);

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "rlcmac_ul_ass_rej");

	struct bitvec *packet_access_rej = bitvec_alloc(GSM_MACBLOCK_LEN, ctx->tbf);

	bitvec_unhex(packet_access_rej, DUMMY_VEC);

	write_packet_access_reject(packet_access_rej, ms_tlli(ms),
				   osmo_tdef_get(ms->bts->pcu->T_defs, 3172, OSMO_TDEF_MS, -1));

	bts_do_rate_ctr_inc(ms->bts, CTR_PKT_ACCESS_REJ);

	bitvec_pack(packet_access_rej, msgb_put(msg, GSM_MACBLOCK_LEN));

	bitvec_free(packet_access_rej);
	return msg;

}

static struct msgb *create_packet_ul_assign(const struct tbf_ul_ass_fsm_ctx *ctx,
				     const struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *d)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_ul_tbf *new_tbf = NULL;
	RlcMacDownlink_t *mac_control_block = NULL;
	struct GprsMs *ms = tbf_ms(ctx->tbf);
	uint32_t tlli;
	int rc;
	unsigned int rrbp;
	uint32_t new_poll_fn;

	rc = tbf_check_polling(ctx->tbf, d->pdch, d->fn, &new_poll_fn, &rrbp);
	if (rc < 0)
		return NULL;

	new_tbf = ms_ul_tbf(ms);
	if (!new_tbf) {
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			"We have a schedule for uplink assignment, but there is no uplink TBF\n");
		tbf_ul_ass_fsm_state_chg(ctx->fi, TBF_UL_ASS_NONE);
		return NULL;
	}

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "rlcmac_ul_ass");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	struct bitvec bv = {
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, DUMMY_VEC);

	if (ctx->tbf != ul_tbf_as_tbf_const(new_tbf))
		LOGPTBF(ctx->tbf, LOGL_INFO, "start Packet Uplink Assignment (PACCH) for %s\n",
			  tbf_name(ul_tbf_as_tbf_const(new_tbf)));
	else
		LOGPTBF(ctx->tbf, LOGL_INFO, "start Packet Uplink Assignment (PACCH)\n");

	mac_control_block = (RlcMacDownlink_t *)talloc_zero(ctx->tbf, RlcMacDownlink_t);
	tlli = ms_tlli(ms);
	write_packet_uplink_assignment(mac_control_block, tbf_tfi(ctx->tbf),
		(tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF), ms_tlli(ms),
		 tlli != GSM_RESERVED_TMSI, new_tbf, 1, rrbp, bts_get_ms_pwr_alpha(ms->bts),
		the_pcu->vty.gamma, -1, tbf_is_egprs_enabled(ctx->tbf));

	LOGP(DTBF, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Assignment +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Encoding of Packet Uplink Ass failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DTBF, LOGL_DEBUG, "------------------------- TX : Packet Uplink Assignment -------------------------\n");
	bts_do_rate_ctr_inc(ms->bts, CTR_PKT_UL_ASSIGNMENT);

	tbf_set_polling(ctx->tbf, d->pdch, new_poll_fn, PDCH_ULC_POLL_UL_ASS);
	LOGPTBF(ctx->tbf, LOGL_INFO, "Scheduled UL Assignment polling on PACCH (FN=%d, TS=%d)\n",
		  new_poll_fn, d->pdch->ts_no);

	talloc_free(mac_control_block);
	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

static void st_none_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_ul_ass_fsm_ctx *ctx = (struct tbf_ul_ass_fsm_ctx *)fi->priv;
	unsigned long val;
	unsigned int sec, micro;

	if (prev_state == TBF_UL_ASS_SEND_ASS_REJ &&
	    tbf_direction(ctx->tbf) == GPRS_RLCMAC_UL_TBF) {
		/* If TBF object doing the UL assignment is also an UL TBF, and
		 * it was just rejected over PACCH, then there's nothing more to do
		 * with this UL TBF other than freeing it and waiting for MS to
		 * retry asking for another UL TBF assignment. But since we are
		 * currently being called from the scheduled (we arrived here
		 * through st_send_ass_rej(TBF_UL_ASS_EV_CREATE_RLCMAC_MSG)),
		 * then we need to delay the tbf_free() to do it asynchrosnouly
		 * in the event loop. Using a fixed 0ms internal fsm timer
		 * number would have been fine here, but since for historical
		 * reasons we have VTY-configurable X2000 for this purpose, keep
		 * using it (it is expected to be 0 usually).
		 */
		fi->T = -2000;
		val = osmo_tdef_get(the_pcu->T_defs, fi->T, OSMO_TDEF_MS, -1);
		sec = val / 1000;
		micro = (val % 1000) * 1000;
		LOGPTBF(ctx->tbf, LOGL_DEBUG, "Starting timer X2000 [delay free after Packet Access Reject (PACCH)] with %lums\n",
			val);
		osmo_timer_schedule(&fi->timer, sec, micro);
	}

}

static void st_none(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_UL_ASS_EV_SCHED_ASS:
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_SEND_ASS);
		break;
	case TBF_UL_ASS_EV_SCHED_ASS_REJ:
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_SEND_ASS_REJ);
		break;
	case TBF_UL_ASS_EV_ABORT:
		/* Nothing to do, we are already in proper state */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_send_ass_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct tbf_ul_ass_fsm_ctx *ctx = (struct tbf_ul_ass_fsm_ctx *)fi->priv;
	unsigned long val;
	unsigned int sec, micro;
	struct GprsMs *ms = tbf_ms(ctx->tbf);

	/* Here it's point in time where we received PKT RES REQ or DL ACK/NACK to request a new UL TBF,
	 * so MS will be gone after T3168 (* 4 retrans, 8.1.1.1.2) if we are unable to seize it.
	 * Hence, attempt re-scheduling PKT UL ASS (states SEND_ASS<->WAIT_ACK ping-pong) until T3168 we
	 * announced (SI13) to the MS expires:
	 */
	if (prev_state == TBF_UL_ASS_NONE) {
		/* tbf_free() called upon trigger */
		fi->T = 3168;
		val = osmo_tdef_get(ms->bts->T_defs_bts, fi->T, OSMO_TDEF_MS, -1);
		val *= 4; /* 4 PKT RES REQ retransmit */
		sec = val / 1000;
		micro = (val % 1000) * 1000;
		LOGPTBF(ctx->tbf, LOGL_DEBUG, "Starting timer T3168 [PKT UL ASS PACCH] with %u sec. %u microsec\n",
			sec, micro);
		osmo_timer_schedule(&fi->timer, sec, micro);
	}

}

static void st_send_ass(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_ass_fsm_ctx *ctx = (struct tbf_ul_ass_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case TBF_UL_ASS_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_ul_assign(ctx, data_ctx);
		if (!data_ctx->msg)
			return;
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_WAIT_ACK);
		break;
	case TBF_UL_ASS_EV_ABORT:
		/* Cancel pending schedule for Pkt Ul Ass: */
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_NONE);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_send_ass_rej(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_ass_fsm_ctx *ctx = (struct tbf_ul_ass_fsm_ctx *)fi->priv;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case TBF_UL_ASS_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_ul_ass_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_access_reject(ctx);
		if (!data_ctx->msg)
			return;
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_NONE);
		break;
	case TBF_UL_ASS_EV_ABORT:
		/* Cancel pending schedule for Pkt Ul Ass Rej: */
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_NONE);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_ass_fsm_ctx *ctx = (struct tbf_ul_ass_fsm_ctx *)fi->priv;

	switch (event) {
	case TBF_UL_ASS_EV_RX_ASS_CTRL_ACK:
		tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_NONE);
		break;
	case TBF_UL_ASS_EV_ASS_POLL_TIMEOUT:
		LOGPTBF(ctx->tbf, LOGL_NOTICE,
			"Timeout for polling PACKET CONTROL ACK for PACKET UPLINK ASSIGNMENT: %s\n",
			tbf_rlcmac_diag(ctx->tbf));
		if (tbf_state(ctx->tbf) == TBF_ST_ASSIGN) {
			/* Reschedule Pkt Ul Ass */
			tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_SEND_ASS);
		} else {
			/* We are most probably in RELEASING, so stop retrying. */
			tbf_ul_ass_fsm_state_chg(fi, TBF_UL_ASS_NONE);
		}
		break;
	case TBF_UL_ASS_EV_ABORT:
		/* There's nothing we can do here, we already transmitted and
		 * hence we must keep the POLL since the MS is already expected
		 * to transmit there. Whenever we receive event CTRL_ACK or
		 * TIMEOUT above, it will move back to ST_NONE autoamtically */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int tbf_ul_ass_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct tbf_ul_ass_fsm_ctx *ctx = (struct tbf_ul_ass_fsm_ctx *)fi->priv;
	switch (fi->T) {
	case -2000:
	case 3168:
		tbf_free(ctx->tbf);
		break;
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state tbf_ul_ass_fsm_states[] = {
	[TBF_UL_ASS_NONE] = {
		.in_event_mask =
			X(TBF_UL_ASS_EV_SCHED_ASS) |
			X(TBF_UL_ASS_EV_SCHED_ASS_REJ) |
			X(TBF_UL_ASS_EV_ABORT),
		.out_state_mask =
			X(TBF_UL_ASS_SEND_ASS) |
			X(TBF_UL_ASS_SEND_ASS_REJ),
		.name = "NONE",
		.action = st_none,
		.onenter = st_none_on_enter,
	},
	[TBF_UL_ASS_SEND_ASS] = {
		.in_event_mask =
			X(TBF_UL_ASS_EV_CREATE_RLCMAC_MSG) |
			X(TBF_UL_ASS_EV_ABORT),
		.out_state_mask =
			X(TBF_UL_ASS_WAIT_ACK) |
			X(TBF_UL_ASS_NONE),
		.name = "SEND_ASS",
		.action = st_send_ass,
		.onenter = st_send_ass_on_enter,
	},
	[TBF_UL_ASS_SEND_ASS_REJ] = {
		.in_event_mask =
			X(TBF_UL_ASS_EV_CREATE_RLCMAC_MSG) |
			X(TBF_UL_ASS_EV_ABORT),
		.out_state_mask = X(TBF_UL_ASS_NONE),
		.name = "SEND_ASS_REJ",
		.action = st_send_ass_rej,
	},
	[TBF_UL_ASS_WAIT_ACK] = {
		.in_event_mask =
			X(TBF_UL_ASS_EV_RX_ASS_CTRL_ACK) |
			X(TBF_UL_ASS_EV_ASS_POLL_TIMEOUT) |
			X(TBF_UL_ASS_EV_ABORT),
		.out_state_mask =
			X(TBF_UL_ASS_NONE) |
			X(TBF_UL_ASS_SEND_ASS),
		.name = "WAIT_ACK",
		.action = st_wait_ack,
	},
};

struct osmo_fsm tbf_ul_ass_fsm = {
	.name = "UL_ASS_TBF",
	.states = tbf_ul_ass_fsm_states,
	.num_states = ARRAY_SIZE(tbf_ul_ass_fsm_states),
	.timer_cb = tbf_ul_ass_fsm_timer_cb,
	.log_subsys = DTBF,
	.event_names = tbf_ul_ass_fsm_event_names,
};

static __attribute__((constructor)) void tbf_ul_ass_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_ul_ass_fsm) == 0);
}


struct msgb *tbf_ul_ass_create_rlcmac_msg(const struct gprs_rlcmac_tbf *tbf,
					  const struct gprs_rlcmac_pdch *pdch,
					  uint32_t fn)
{
	int rc;
	struct tbf_ul_ass_ev_create_rlcmac_msg_ctx data_ctx = {
		.pdch = pdch,
		.fn = fn,
		.msg = NULL,
	};

	rc = osmo_fsm_inst_dispatch(tbf_ul_ass_fi(tbf), TBF_UL_ASS_EV_CREATE_RLCMAC_MSG, &data_ctx);
	if (rc != 0 || !data_ctx.msg)
		return NULL;
	return data_ctx.msg;
}

bool tbf_ul_ass_rts(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch)
{
	struct osmo_fsm_inst *fi;

	if (!tbf_is_control_ts(tbf, pdch))
		return false;

	fi = tbf_ul_ass_fi(tbf);
	return fi->state == TBF_UL_ASS_SEND_ASS || fi->state == TBF_UL_ASS_SEND_ASS_REJ;
}
