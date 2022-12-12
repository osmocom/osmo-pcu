/* tbf_dl_ass_fsm.c
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

#include <tbf_dl_ass_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>
#include <tbf.h>
#include <tbf_dl.h>

#define X(s) (1 << (s))

const struct osmo_tdef_state_timeout tbf_dl_ass_fsm_timeouts[32] = {
	[TBF_DL_ASS_NONE] = {},
	[TBF_DL_ASS_SEND_ASS] = {},
	[TBF_DL_ASS_WAIT_ACK] = {},
};

const struct value_string tbf_dl_ass_fsm_event_names[] = {
	{ TBF_DL_ASS_EV_SCHED_ASS, "SCHED_ASS" },
	{ TBF_DL_ASS_EV_CREATE_RLCMAC_MSG, "CREATE_RLCMAC_MSG" },
	{ TBF_DL_ASS_EV_RX_ASS_CTRL_ACK, "RX_ASS_CTRL_ACK" },
	{ TBF_DL_ASS_EV_ASS_POLL_TIMEOUT, "ASS_POLL_TIMEOUT" },
	{ 0, NULL }
};

struct msgb *create_packet_dl_assign(const struct tbf_dl_ass_fsm_ctx *ctx,
				     const struct tbf_dl_ass_ev_create_rlcmac_msg_ctx *d)
{
	struct msgb *msg;
	struct gprs_rlcmac_dl_tbf *new_dl_tbf = NULL;
	RlcMacDownlink_t *mac_control_block = NULL;
	struct GprsMs *ms = tbf_ms(ctx->tbf);
	const int poll_ass_dl = 1;
	unsigned int rrbp = 0;
	uint32_t new_poll_fn = 0;
	int rc;
	bool old_tfi_is_valid = tbf_is_tfi_assigned(ctx->tbf);

	/* We only use this function in control TS (PACCH) so that MS can always answer the poll */
	OSMO_ASSERT(tbf_is_control_ts(ctx->tbf, d->pdch));

	rc = tbf_check_polling(ctx->tbf, d->fn, d->pdch->ts_no, &new_poll_fn, &rrbp);
	if (rc < 0)
		return NULL;

	new_dl_tbf = ms_dl_tbf(ms);
	if (!new_dl_tbf) {
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			  "We have a schedule for downlink assignment, but there is no downlink TBF\n");
		tbf_dl_ass_fsm_state_chg(ctx->fi, TBF_DL_ASS_NONE);
		return NULL;
	}

	if (old_tfi_is_valid && ms_tlli(ms) == GSM_RESERVED_TMSI) {
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			  "The old TFI is not assigned and there is no TLLI. New TBF %s\n",
			  tbf_name((struct gprs_rlcmac_tbf *)new_dl_tbf));
		tbf_dl_ass_fsm_state_chg(ctx->fi, TBF_DL_ASS_NONE);
		return NULL;
	}

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "rlcmac_dl_ass");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	struct bitvec bv = {
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, DUMMY_VEC);

	if (ctx->tbf != (struct gprs_rlcmac_tbf *)new_dl_tbf)
		LOGPTBF(ctx->tbf, LOGL_INFO, "start Packet Downlink Assignment (PACCH) for %s\n",
			  tbf_name((const struct gprs_rlcmac_tbf *)new_dl_tbf));
	else
		LOGPTBF(ctx->tbf, LOGL_INFO, "start Packet Downlink Assignment (PACCH)\n");

	mac_control_block = (RlcMacDownlink_t *)talloc_zero(ctx->tbf, RlcMacDownlink_t);
	write_packet_downlink_assignment(mac_control_block, old_tfi_is_valid,
		tbf_tfi(ctx->tbf), (tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF),
		new_dl_tbf, poll_ass_dl, rrbp,
		bts_get_ms_pwr_alpha(ms->bts), the_pcu->vty.gamma, -1, 0,
		tbf_is_egprs_enabled(ctx->tbf), tbf_state(ctx->tbf) == TBF_ST_WAIT_RELEASE);
	LOGP(DTBF, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Downlink Assignment +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Encoding of Packet Downlink Ass failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DTBF, LOGL_DEBUG, "------------------------- TX : Packet Downlink Assignment -------------------------\n");
	bts_do_rate_ctr_inc(ms->bts, CTR_PKT_DL_ASSIGNMENT);

	tbf_set_polling(ctx->tbf, new_poll_fn, d->pdch->ts_no, PDCH_ULC_POLL_DL_ASS);
	LOGPTBF(ctx->tbf, LOGL_INFO, "Scheduled DL Assignment polling on PACCH (FN=%d, TS=%d)\n",
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
}

static void st_none(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_DL_ASS_EV_SCHED_ASS:
		tbf_dl_ass_fsm_state_chg(fi, TBF_DL_ASS_SEND_ASS);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_send_ass(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_dl_ass_fsm_ctx *ctx = (struct tbf_dl_ass_fsm_ctx *)fi->priv;
	struct tbf_dl_ass_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case TBF_DL_ASS_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_dl_ass_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_dl_assign(ctx, data_ctx);
		if (!data_ctx->msg)
			return;
		tbf_dl_ass_fsm_state_chg(fi, TBF_DL_ASS_WAIT_ACK);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_dl_ass_fsm_ctx *ctx = (struct tbf_dl_ass_fsm_ctx *)fi->priv;

	switch (event) {
	case TBF_DL_ASS_EV_RX_ASS_CTRL_ACK:
		tbf_dl_ass_fsm_state_chg(fi, TBF_DL_ASS_NONE);
		break;
	case TBF_DL_ASS_EV_ASS_POLL_TIMEOUT:
		LOGPTBF(ctx->tbf, LOGL_NOTICE,
			"Timeout for polling PACKET CONTROL ACK for PACKET DOWNLINK ASSIGNMENT: %s\n",
			tbf_rlcmac_diag(ctx->tbf));
		/* Reschedule Pkt Dl Ass */
		tbf_dl_ass_fsm_state_chg(fi, TBF_DL_ASS_SEND_ASS);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int tbf_dl_ass_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state tbf_dl_ass_fsm_states[] = {
	[TBF_DL_ASS_NONE] = {
		.in_event_mask =
			X(TBF_DL_ASS_EV_SCHED_ASS),
		.out_state_mask =
			X(TBF_DL_ASS_SEND_ASS),
		.name = "NONE",
		.action = st_none,
		.onenter = st_none_on_enter,
	},
	[TBF_DL_ASS_SEND_ASS] = {
		.in_event_mask = X(TBF_DL_ASS_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(TBF_DL_ASS_WAIT_ACK) |
			X(TBF_DL_ASS_NONE),
		.name = "SEND_ASS",
		.action = st_send_ass,
	},
	[TBF_DL_ASS_WAIT_ACK] = {
		.in_event_mask =
			X(TBF_DL_ASS_EV_RX_ASS_CTRL_ACK) |
			X(TBF_DL_ASS_EV_ASS_POLL_TIMEOUT),
		.out_state_mask =
			X(TBF_DL_ASS_NONE) |
			X(TBF_DL_ASS_SEND_ASS),
		.name = "WAIT_ACK",
		.action = st_wait_ack,
	},
};

struct osmo_fsm tbf_dl_ass_fsm = {
	.name = "DL_ASS_TBF",
	.states = tbf_dl_ass_fsm_states,
	.num_states = ARRAY_SIZE(tbf_dl_ass_fsm_states),
	.timer_cb = tbf_dl_ass_fsm_timer_cb,
	.log_subsys = DTBF,
	.event_names = tbf_dl_ass_fsm_event_names,
};

static __attribute__((constructor)) void tbf_dl_ass_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_dl_ass_fsm) == 0);
}


struct msgb *tbf_dl_ass_create_rlcmac_msg(const struct gprs_rlcmac_tbf *tbf,
					  const struct gprs_rlcmac_pdch *pdch,
					  uint32_t fn)
{
	int rc;
	struct tbf_dl_ass_ev_create_rlcmac_msg_ctx data_ctx = {
		.pdch = pdch,
		.fn = fn,
		.msg = NULL,
	};

	rc = osmo_fsm_inst_dispatch(tbf_dl_ass_fi(tbf), TBF_DL_ASS_EV_CREATE_RLCMAC_MSG, &data_ctx);
	if (rc != 0 || !data_ctx.msg)
		return NULL;
	return data_ctx.msg;
}

bool tbf_dl_ass_rts(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch)
{
	struct osmo_fsm_inst *fi;

	if (!tbf_is_control_ts(tbf, pdch))
		return false;

	fi = tbf_dl_ass_fi(tbf);
	if (fi->state != TBF_DL_ASS_SEND_ASS)
		return false;

	if (tbf_ul_ass_fi(tbf)->state == TBF_UL_ASS_WAIT_ACK) {
		LOGPTBF(tbf, LOGL_DEBUG,
			"Polling is already scheduled, so we must wait for the uplink assignment...\n");
		return false;
	}

	/* on uplink TBF we get the downlink TBF to be assigned. */
	if (tbf_direction(tbf) == GPRS_RLCMAC_UL_TBF) {
		const struct gprs_rlcmac_ul_tbf *ul_tbf = (const struct gprs_rlcmac_ul_tbf *)tbf;
		/* be sure to check first, if contention resolution is done,
		 * otherwise we cannot send the assignment yet (3GPP TS 44.060 sec 7.1.3.1) */
		if (!ul_tbf_contention_resolution_done(ul_tbf)) {
			LOGPTBF(tbf, LOGL_DEBUG,
				"Cannot assign DL TBF now, because contention resolution is not finished.\n");
			return false;
		}
	}
	return true;
}
