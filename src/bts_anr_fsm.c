/* bts_anr_fsm.c
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

#include <osmocom/core/rate_ctr.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

#include <bts_anr_fsm.h>
#include <ms_anr_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>
#include <neigh_cache.h>

#define X(s) (1 << (s))

/* Ask the MS to measure up to 5 neighbors at a time */
#define ANR_MAX_NEIGH_SUBSET 5

static const struct osmo_tdef_state_timeout bts_anr_fsm_timeouts[32] = {
	[BTS_ANR_ST_DISABLED] = {},
	[BTS_ANR_ST_ENABLED] = { .T = PCU_TDEF_ANR_SCHED_TBF },
};

/* Transition to a state, using the T timer defined in assignment_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */

#define bts_anr_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     bts_anr_fsm_timeouts, \
				     ((struct bts_anr_fsm_ctx*)(fi->priv))->bts->pcu->T_defs, \
				     -1)

const struct value_string bts_anr_fsm_event_names[] = {
	{ BTS_ANR_EV_RX_ANR_REQ, "RX_ANR_REQ" },
	{ BTS_ANR_EV_SCHED_MS_MEAS, "SCHED_MS_MEAS" },
	{ BTS_ANR_EV_MS_MEAS_COMPL, "MS_MEAS_COMPL" },
	{ BTS_ANR_EV_MS_MEAS_ABORTED, "MS_MEAS_ABORTED" },
	{ 0, NULL }
};

static void copy_sort_arfcn_bsic(struct bts_anr_fsm_ctx *ctx, const struct gsm48_cell_desc *cell_list, unsigned int num_cells)
{
	OSMO_ASSERT(num_cells <= ARRAY_SIZE(ctx->cell_list));
	uint16_t last_min_arfcn = 0;
	uint8_t last_min_bsic = 0;
	ctx->num_cells = 0;
	struct gprs_rlcmac_bts *bts = ctx->bts;

	/* Copy over ARFCN+BSIC in an ARFCN then BSIC ascending ordered way */
	while (ctx->num_cells < num_cells) {
		bool found = false;
		uint16_t curr_min_arfcn = 0xffff;
		uint8_t curr_min_bsic = 0xff;
		int i;
		for (i = 0; i < num_cells; i++) {
			uint16_t arfcn = (cell_list[i].arfcn_hi << 8) | cell_list[i].arfcn_lo;
			uint8_t bsic = (cell_list[i].ncc << 3) | cell_list[i].bcc;
			if ((arfcn > last_min_arfcn || (arfcn == last_min_arfcn && bsic > last_min_bsic)) &&
			    (arfcn < curr_min_arfcn || (arfcn == curr_min_arfcn && bsic < curr_min_bsic))) {
				found = true;
				curr_min_arfcn = arfcn;
				curr_min_bsic = bsic;
			}
		}
		if (!found)
			break; /* we are done before copying all, probably due to duplicated arfcn in list */

		/* Copy lower ARFCN+BSIC to dst */
		if (curr_min_arfcn != bts->trx[0].arfcn || curr_min_bsic != bts->bsic) {
			ctx->cell_list[ctx->num_cells] = (struct arfcn_bsic){
				.arfcn = curr_min_arfcn,
				.bsic =  curr_min_bsic,
			};
			ctx->num_cells++;
			LOGPFSML(ctx->fi, LOGL_DEBUG, "Added neigh cell to ANR list: ARFCN=%u BSIC=%u\n",
				 curr_min_arfcn, curr_min_bsic);
		} else {
			LOGPFSML(ctx->fi, LOGL_DEBUG, "Skip neigh cell to ANR list (itself): ARFCN=%u BSIC=%u\n",
				 curr_min_arfcn, curr_min_bsic);
		}
		last_min_arfcn = curr_min_arfcn;
		last_min_bsic = curr_min_bsic;
	}
}

static void rx_new_cell_list(struct bts_anr_fsm_ctx *ctx, const struct gsm_pcu_if_anr_req *anr_req)
{
	unsigned int num_cells = anr_req->num_cells;
	if (anr_req->num_cells > ARRAY_SIZE(anr_req->cell_list)) {
		LOGPFSML(ctx->fi, LOGL_ERROR, "Too many cells received %u > %zu (max), trimming it\n",
			 anr_req->num_cells, ARRAY_SIZE(anr_req->cell_list));
		num_cells = ARRAY_SIZE(anr_req->cell_list);
	}
	copy_sort_arfcn_bsic(ctx, (const struct gsm48_cell_desc *)anr_req->cell_list, num_cells);
}

static struct GprsMs *select_candidate_ms(struct gprs_rlcmac_bts *bts)
{
	struct llist_head *tmp;
	/* prio top to bottom: 0,1,2: */
	struct GprsMs *ms_dl_tbf_assign = NULL;

	/* We'll need a DL TBF. Take with higher priority an MS which already
	 * has one, otherwise one in process of acquiring one. In last place an
	 * MS which has no DL-TBF yet. */
	llist_for_each(tmp, bts_ms_list(bts)) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		if (ms->anr) /* Don't pick MS already busy doing ANR */
			continue;
		if (!ms->dl_tbf)
			continue;
		switch (tbf_state((struct gprs_rlcmac_tbf*)ms->dl_tbf)) {
		case TBF_ST_FLOW: /* Pick active DL-TBF as best option, early return: */
			return ms;
		case TBF_ST_ASSIGN:
			ms_dl_tbf_assign = ms;
			break;
		default:
			continue;
		}
	}

	if (ms_dl_tbf_assign)
		return ms_dl_tbf_assign;

	llist_for_each(tmp, bts_ms_list(bts)) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		if (ms->anr) /* Don't pick MS already busy doing ANR */
			continue;
		if (!ms->dl_tbf) {
			/* Trigger a Pkt Dl Assignment and do ANR procedure once it is active: */
			struct gprs_rlcmac_dl_tbf *new_dl_tbf;
			int rc;
			rc = tbf_new_dl_assignment(ms->bts, ms, &new_dl_tbf);
			if (rc < 0)
				continue;
			/* Fill the TBF with some LLC Dummy Command, since everyone expectes we send something to that DL TBF... */
			uint16_t delay_csec = 0xffff;
			/* The shortest dummy command (the spec requests at least 6 octets) */
			const uint8_t llc_dummy_command[] = {
			0x43, 0xc0, 0x01, 0x2b, 0x2b, 0x2b
			};
			dl_tbf_append_data(new_dl_tbf, delay_csec, &llc_dummy_command[0], ARRAY_SIZE(llc_dummy_command));
			return ms;
		}
	}
	return NULL;
}

/* Build up cell list subset for this MS to measure: */
static size_t take_next_cell_list_chunk(struct bts_anr_fsm_ctx *ctx, struct arfcn_bsic ms_cell_li[MAX_NEIGH_LIST_LEN])
{
	unsigned int subset_len = ANR_MAX_NEIGH_SUBSET;
	if (ctx->num_cells <= subset_len) {
		memcpy(ms_cell_li, ctx->cell_list, ctx->num_cells * sizeof(ctx->cell_list[0]));
		subset_len = ctx->num_cells;
	} else if ((ctx->num_cells - ctx->next_cell) >= subset_len) {
		memcpy(ms_cell_li, &ctx->cell_list[ctx->next_cell], subset_len * sizeof(ctx->cell_list[0]));
		ctx->next_cell = (ctx->next_cell + subset_len) % ctx->num_cells;
	} else {
		unsigned int len = (ctx->num_cells - ctx->next_cell);
		memcpy(ms_cell_li, &ctx->cell_list[ctx->next_cell], len * sizeof(ctx->cell_list[0]));
		memcpy(&ms_cell_li[len], &ctx->cell_list[0], subset_len - len);
		ctx->next_cell = subset_len - len;
	}
	return subset_len;
}

static void sched_ms_meas_report(struct bts_anr_fsm_ctx *ctx, const struct arfcn_bsic* cell_list,
				unsigned int num_cells)
{
	struct gprs_rlcmac_bts *bts = ctx->bts;
	struct GprsMs *ms;
	struct arfcn_bsic ms_cell_li[MAX_NEIGH_LIST_LEN];
	/* HERE we'll:
	 * 1- Select a TBF candidate in the BTS
	 * 2- Pick a subset from ctx->cell_list (increasing index round buffer in array)
	 * 3- Send event to it to schedule the meas report [osmo_fsm_inst_dispatch(ms->meas_rep_fsm, MEAS_REP_EV_SCHEDULE, cell_sublist)]
	 * 4- Wait for event BTS_ANR_EV_MEAS_REP containing "Packet Measurement Report" as data
	 * 5- Filter out the list and submit it back over PCUIF */

	/* First poor-man impl: pick first MS having a FLOW TBF: */
	ms = select_candidate_ms(bts);
	if (!ms) {
		LOGPFSML(ctx->fi, LOGL_INFO, "Unable to find MS to start ANR measurements\n");
		return;
	}
	LOGPMS(ms, DANR, LOGL_DEBUG, "Selected for ANR measurements\n");

	/* Build up cell list subset for this MS to measure: */
	if (!cell_list) {
		num_cells = take_next_cell_list_chunk(ctx, &ms_cell_li[0]);
		cell_list = &ms_cell_li[0];
	}

	if (ms_anr_start(ms, cell_list, num_cells) < 0)
		LOGPFSML(ctx->fi, LOGL_ERROR, "Unable to start ANR measurements on MS\n");
}

static void handle_ms_meas_report(struct bts_anr_fsm_ctx *ctx, const struct ms_anr_ev_meas_compl* result)
{
	struct gprs_rlcmac_bts *bts = ctx->bts;
	pcu_tx_anr_cnf(bts, result->cell_list, result->meas_list, result->num_cells);
}

////////////////
// FSM states //
////////////////

static void st_disabled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bts_anr_fsm_ctx *ctx = (struct bts_anr_fsm_ctx *)fi->priv;
	struct llist_head *tmp;

	/* Abort ongoing scheduled ms_anr_fsm: */
	llist_for_each(tmp, bts_ms_list(ctx->bts)) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		/* Remark: ms_anr_fsm_abort does NOT send BTS_ANR_EV_MS_MEAS_ABORTED back at us */
		if (ms->anr)
			ms_anr_fsm_abort(ms->anr);
	}
}

static void st_disabled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bts_anr_fsm_ctx *ctx = (struct bts_anr_fsm_ctx *)fi->priv;
	const struct gsm_pcu_if_anr_req *anr_req;

	switch (event) {
	case BTS_ANR_EV_RX_ANR_REQ:
		anr_req = (const struct gsm_pcu_if_anr_req *)data;
		rx_new_cell_list(ctx, anr_req);
		if (ctx->num_cells > 0)
			bts_anr_fsm_state_chg(fi, BTS_ANR_ST_ENABLED);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_enabled_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bts_anr_fsm_ctx *ctx = (struct bts_anr_fsm_ctx *)fi->priv;
	sched_ms_meas_report(ctx, NULL, 0);
}

static void st_enabled(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bts_anr_fsm_ctx *ctx = (struct bts_anr_fsm_ctx *)fi->priv;
	const struct gsm_pcu_if_anr_req *anr_req;
	struct ms_anr_ev_abort *ev_abort_data;

	switch (event) {
	case BTS_ANR_EV_RX_ANR_REQ:
		anr_req = (const struct gsm_pcu_if_anr_req *)data;
		rx_new_cell_list(ctx, anr_req);
		if (ctx->num_cells == 0)
			bts_anr_fsm_state_chg(fi, BTS_ANR_ST_DISABLED);
		break;
	case BTS_ANR_EV_SCHED_MS_MEAS:
		sched_ms_meas_report(ctx, NULL, 0);
		break;
	case BTS_ANR_EV_MS_MEAS_ABORTED:
		ev_abort_data = (struct ms_anr_ev_abort*)data;
		sched_ms_meas_report(ctx, ev_abort_data->cell_list, ev_abort_data->num_cells);
		break;
	case BTS_ANR_EV_MS_MEAS_COMPL:
		handle_ms_meas_report(ctx, (const struct ms_anr_ev_meas_compl*)data);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/*TODO: we need to track how many chunks are created, how many are in progress, how many are completed, etc. */
static int bts_anr_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	unsigned long timeout;

	switch (fi->T) {
	case PCU_TDEF_ANR_SCHED_TBF:
		/* Re-schedule the timer */
		timeout = osmo_tdef_get(((struct bts_anr_fsm_ctx*)(fi->priv))->bts->pcu->T_defs,
					fi->T, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, timeout, 0);
		/* Dispatch the schedule TBF MEAS event */
		osmo_fsm_inst_dispatch(fi, BTS_ANR_EV_SCHED_MS_MEAS, NULL);
		break;
	}
	return 0;
}

static struct osmo_fsm_state bts_anr_fsm_states[] = {
	[BTS_ANR_ST_DISABLED] = {
		.in_event_mask =
			X(BTS_ANR_EV_RX_ANR_REQ),
		.out_state_mask =
			X(BTS_ANR_ST_ENABLED),
		.name = "DISABLED",
		.onenter = st_disabled_on_enter,
		.action = st_disabled,
	},
	[BTS_ANR_ST_ENABLED] = {
		.in_event_mask =
			X(BTS_ANR_EV_RX_ANR_REQ) |
			X(BTS_ANR_EV_SCHED_MS_MEAS) |
			X(BTS_ANR_EV_MS_MEAS_COMPL) |
			X(BTS_ANR_EV_MS_MEAS_ABORTED),
		.out_state_mask =
			X(BTS_ANR_ST_DISABLED),
		.name = "ENABLED",
		.onenter = st_enabled_on_enter,
		.action = st_enabled,
	},
};

static struct osmo_fsm bts_anr_fsm = {
	.name = "BTS_ANR",
	.states = bts_anr_fsm_states,
	.num_states = ARRAY_SIZE(bts_anr_fsm_states),
	.timer_cb = bts_anr_fsm_timer_cb,
	.log_subsys = DANR,
	.event_names = bts_anr_fsm_event_names,
};

static __attribute__((constructor)) void bts_anr_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&bts_anr_fsm) == 0);
}

static int bts_anr_fsm_ctx_talloc_destructor(struct bts_anr_fsm_ctx *ctx)
{
	if (ctx->fi) {
		osmo_fsm_inst_free(ctx->fi);
		ctx->fi = NULL;
	}

	return 0;
}

struct bts_anr_fsm_ctx *bts_anr_fsm_alloc(struct gprs_rlcmac_bts* bts)
{
	struct bts_anr_fsm_ctx *ctx = talloc_zero(bts, struct bts_anr_fsm_ctx);
	char buf[64];

	talloc_set_destructor(ctx, bts_anr_fsm_ctx_talloc_destructor);

	ctx->bts = bts;

	snprintf(buf, sizeof(buf), "BTS-%u", bts->nr);
	ctx->fi = osmo_fsm_inst_alloc(&bts_anr_fsm, ctx, ctx, LOGL_INFO, buf);
	if (!ctx->fi)
		goto free_ret;

	return ctx;
free_ret:
	talloc_free(ctx);
	return NULL;
}
