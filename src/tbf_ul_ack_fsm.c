/* tbf_ul_ack_fsm.c
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

#include <tbf_ul_ack_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>
#include <tbf.h>
#include <tbf_ul.h>

#include <tbf_ul_ack_fsm.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout tbf_ul_ack_fsm_timeouts[32] = {
	[TBF_UL_ACK_ST_NONE] = {},
	[TBF_UL_ACK_ST_SCHED_UL_ACK] = {},
	[TBF_UL_ACK_ST_WAIT_ACK] = {},
};

static const struct value_string tbf_ul_ack_fsm_event_names[] = {
	{ TBF_UL_ACK_EV_SCHED_ACK, "SCHED_ACK" },
	{ TBF_UL_ACK_EV_CREATE_RLCMAC_MSG, "CREATE_RLCMAC_MSG" },
	{ TBF_UL_ACK_EV_RX_CTRL_ACK, "RX_CTRL_ACK" },
	{ TBF_UL_ACK_EV_POLL_TIMEOUT, "POLL_TIMEOUT" },
	{ 0, NULL }
};

/* Transition to a state, using the T timer defined in tbf_ul_ack_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define tbf_ul_ack_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     tbf_ul_ack_fsm_timeouts, \
				     the_pcu->T_defs, \
				     -1)

static struct msgb *create_ul_ack_nack(const struct tbf_ul_ack_fsm_ctx *ctx,
				       const struct tbf_ul_ack_ev_create_rlcmac_msg_ctx *d,
				       bool final)
{
	struct msgb *msg;
	int rc;
	unsigned int rrbp = 0;
	uint32_t new_poll_fn = 0;
	struct gprs_rlcmac_tbf *tbf = ul_tbf_as_tbf(ctx->tbf);

	if (final) {
		rc = tbf_check_polling(tbf, d->pdch, d->fn, &new_poll_fn, &rrbp);
		if (rc < 0)
			return NULL;
	}

	msg = msgb_alloc(23, "rlcmac_ul_ack");
	if (!msg)
		return NULL;
	struct bitvec *ack_vec = bitvec_alloc(23, tbf);
	if (!ack_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ack_vec, DUMMY_VEC);
	write_packet_uplink_ack(ack_vec, ctx->tbf, final, rrbp);
	bitvec_pack(ack_vec, msgb_put(msg, 23));
	bitvec_free(ack_vec);

	if (final) {
		tbf_set_polling(tbf, d->pdch, new_poll_fn, PDCH_ULC_POLL_UL_ACK);
		LOGPTBFUL(ctx->tbf, LOGL_DEBUG,
			"Scheduled UL Acknowledgement polling on PACCH (FN=%d, TS=%d)\n",
			new_poll_fn, d->pdch->ts_no);
	}

	return msg;
}

static void st_none(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TBF_UL_ACK_EV_SCHED_ACK:
		tbf_ul_ack_fsm_state_chg(fi, TBF_UL_ACK_ST_SCHED_UL_ACK);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_sched_ul_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_ack_fsm_ctx *ctx = (struct tbf_ul_ack_fsm_ctx *)fi->priv;
	struct gprs_rlcmac_ul_tbf *tbf = ctx->tbf;
	struct GprsMs *ms = tbf_ms(ul_tbf_as_tbf(tbf));
	struct tbf_ul_ack_ev_create_rlcmac_msg_ctx *data_ctx;
	bool final;

	switch (event) {
	case TBF_UL_ACK_EV_SCHED_ACK:
		LOGPTBFUL(tbf, LOGL_DEBUG,
			  "Sending Ack/Nack already scheduled, no need to re-schedule\n");
		break;
	case TBF_UL_ACK_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct tbf_ul_ack_ev_create_rlcmac_msg_ctx *)data;
		final = tbf_state(ul_tbf_as_tbf(tbf)) == TBF_ST_FINISHED;
		data_ctx->msg = create_ul_ack_nack(ctx, data_ctx, final);
		if (!data_ctx->msg)
			return;
		if (final) /* poll set */
			tbf_ul_ack_fsm_state_chg(fi, TBF_UL_ACK_ST_WAIT_ACK);
		else
			tbf_ul_ack_fsm_state_chg(fi, TBF_UL_ACK_ST_NONE);

		/* TS 44.060 7a.2.1.1: "The contention resolution is completed on
		* the network side when the network receives an RLC data block that
		* comprises the TLLI value that identifies the mobile station and the
		* TFI value associated with the TBF." (see TBF_EV_FIRST_UL_DATA_RECVD).
		*
		* However, it's handier for us to mark contention resolution success here
		* since upon rx UL ACK is the time at which MS realizes contention resolution
		* succeeds:
		* TS 44.060 7.1.2.3: "The contention resolution is successfully completed
		* on the mobile station side when the mobile station receives a
		* PACKET UPLINK ACK/NACK"
		*
		* This event must be triggered here *after* potentially transitioning
		* to ST_WAIT_ACK above, so that gprs_ms knows whether it can create a
		* DL TBF on PACCH of the UL_TBF or not (not possible if we are in
		* ST_WAIT_ACK, since UL TBF is terminating sending the final PKT CTRL
		* ACK).
		*/
		if (ms_tlli(ms) != GSM_RESERVED_TMSI && !ul_tbf_contention_resolution_done(ctx->tbf))
			osmo_fsm_inst_dispatch(tbf_state_fi(ul_tbf_as_tbf(ctx->tbf)), TBF_EV_CONTENTION_RESOLUTION_MS_SUCCESS, NULL);

		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_ctrl_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_ul_ack_fsm_ctx *ctx = (struct tbf_ul_ack_fsm_ctx *)fi->priv;
	struct gprs_rlcmac_ul_tbf *tbf = ctx->tbf;

	switch (event) {
	case TBF_UL_ACK_EV_SCHED_ACK:
		/* ignore, we are in the middle of waiting for a response */
		break;
	case TBF_UL_ACK_EV_RX_CTRL_ACK:
		tbf_ul_ack_fsm_state_chg(fi, TBF_UL_ACK_ST_NONE);
		break;
	case TBF_UL_ACK_EV_POLL_TIMEOUT:
		LOGPTBFUL(tbf, LOGL_NOTICE,
			"Timeout for polling PACKET CONTROL ACK for PACKET UPLINK ACK: %s\n",
			tbf_rlcmac_diag(ul_tbf_as_tbf(tbf)));
		/* Reschedule Ul Ack/NAck */
		tbf_ul_ack_fsm_state_chg(fi, TBF_UL_ACK_ST_SCHED_UL_ACK);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int tbf_ul_ack_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	default:
		OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state tbf_ul_ack_fsm_states[] = {
	[TBF_UL_ACK_ST_NONE] = {
		.in_event_mask =
			X(TBF_UL_ACK_EV_SCHED_ACK),
		.out_state_mask =
			X(TBF_UL_ACK_ST_SCHED_UL_ACK),
		.name = "NONE",
		.action = st_none,
	},
	[TBF_UL_ACK_ST_SCHED_UL_ACK] = {
		.in_event_mask =
			X(TBF_UL_ACK_EV_SCHED_ACK) |
			X(TBF_UL_ACK_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(TBF_UL_ACK_ST_NONE) |
			X(TBF_UL_ACK_ST_WAIT_ACK),
		.name = "SCHED_UL_ACK",
		.action = st_sched_ul_ack,
	},
	[TBF_UL_ACK_ST_WAIT_ACK] = {
		.in_event_mask =
			X(TBF_UL_ACK_EV_SCHED_ACK) |
			X(TBF_UL_ACK_EV_RX_CTRL_ACK) |
			X(TBF_UL_ACK_EV_POLL_TIMEOUT),
		.out_state_mask =
			X(TBF_UL_ACK_ST_NONE) |
			X(TBF_UL_ACK_ST_SCHED_UL_ACK),
		.name = "WAIT_ACK",
		.action = st_wait_ctrl_ack,
	},
};

struct osmo_fsm tbf_ul_ack_fsm = {
	.name = "UL_ACK_TBF",
	.states = tbf_ul_ack_fsm_states,
	.num_states = ARRAY_SIZE(tbf_ul_ack_fsm_states),
	.timer_cb = tbf_ul_ack_fsm_timer_cb,
	.log_subsys = DTBFUL,
	.event_names = tbf_ul_ack_fsm_event_names,
};

static __attribute__((constructor)) void tbf_ul_ack_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_ul_ack_fsm) == 0);
}


struct msgb *tbf_ul_ack_create_rlcmac_msg(const struct gprs_rlcmac_ul_tbf *ul_tbf,
					  const struct gprs_rlcmac_pdch *pdch,
					  uint32_t fn)
{
	int rc;
	struct tbf_ul_ack_ev_create_rlcmac_msg_ctx data_ctx = {
		.pdch = pdch,
		.fn = fn,
		.msg = NULL,
	};

	rc = osmo_fsm_inst_dispatch(tbf_ul_ack_fi(ul_tbf), TBF_UL_ACK_EV_CREATE_RLCMAC_MSG, &data_ctx);
	if (rc != 0 || !data_ctx.msg)
		return NULL;
	return data_ctx.msg;
}

bool tbf_ul_ack_rts(const struct gprs_rlcmac_ul_tbf *ul_tbf, const struct gprs_rlcmac_pdch *pdch)
{
	struct osmo_fsm_inst *fi;

	if (!tbf_is_control_ts(ul_tbf_as_tbf_const(ul_tbf), pdch))
		return false;

	fi = tbf_ul_ack_fi(ul_tbf);
	return fi->state == TBF_UL_ACK_ST_SCHED_UL_ACK;
}

/* Did we already send the Final ACK and we are waiting for its confirmation (CTRL ACK) ? */
bool tbf_ul_ack_waiting_cnf_final_ack(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	struct osmo_fsm_inst *fi = tbf_ul_ack_fi(ul_tbf);
	return fi->state == TBF_UL_ACK_ST_WAIT_ACK;
}

bool tbf_ul_ack_exp_ctrl_ack(const struct gprs_rlcmac_ul_tbf *ul_tbf, uint32_t fn, uint8_t ts)
{
	struct osmo_fsm_inst *fi = tbf_ul_ack_fi(ul_tbf);
	return fi->state == TBF_UL_ACK_ST_WAIT_ACK;
	/* FIXME: validate FN and TS match: && ctx->poll_fn = fn && ctx->poll_ts == ts */
}
