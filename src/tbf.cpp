/* Copied from gprs_bssgp_pcu.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include <new>
#include <sstream>

#include <bts.h>
#include <tbf.h>
#include <tbf_dl.h>
#include <tbf_ul.h>
#include <rlc.h>
#include <encoding.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <pcu_utils.h>
#include <sba.h>
#include <pdch.h>
#include <alloc_algo.h>

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include "gsm_rlcmac.h"
#include "coding_scheme.h"
#include "nacc_fsm.h"
}

#include <errno.h>
#include <string.h>

extern void *tall_pcu_ctx;

unsigned int next_tbf_ctr_group_id = 0; /* Incrementing group id */

static const struct value_string tbf_counters_names[] = {
	OSMO_VALUE_STRING(N3101),
	OSMO_VALUE_STRING(N3103),
	OSMO_VALUE_STRING(N3105),
	{ 0, NULL }
};

static const struct value_string tbf_timers_names[] = {
	OSMO_VALUE_STRING(T3141),
	OSMO_VALUE_STRING(T3191),
	{ 0, NULL }
};

static const struct rate_ctr_desc tbf_ctr_description[] = {
        { "rlc:nacked",                     "RLC Nacked " },
};

const struct rate_ctr_group_desc tbf_ctrg_desc = {
        "pcu:tbf",
        "TBF Statistics",
        OSMO_STATS_CLASS_SUBSCRIBER,
        ARRAY_SIZE(tbf_ctr_description),
        tbf_ctr_description,
};

gprs_rlcmac_tbf::Meas::Meas() :
	rssi_sum(0),
	rssi_num(0)
{
	timespecclear(&rssi_tv);
}

gprs_rlcmac_tbf::gprs_rlcmac_tbf(struct gprs_rlcmac_bts *bts_, GprsMs *ms, gprs_rlcmac_tbf_direction dir) :
	direction(dir),
	trx(NULL),
	control_ts(NULL),
	fT(0),
	num_fT_exp(0),
	upgrade_to_multislot(false),
	bts(bts_),
	m_tfi(TBF_TFI_UNSET),
	m_created_ts(0),
	m_ctrs(NULL),
	m_ms(ms),
	m_egprs_enabled(false)
{
	/* The classes of these members do not have proper constructors yet.
	 * Just set them to 0 like talloc_zero did */
	memset(&pdch, 0, sizeof(pdch));
	memset(&Tarr, 0, sizeof(Tarr));
	memset(&Narr, 0, sizeof(Narr));

	memset(&m_ms_list, 0, sizeof(m_ms_list));
	m_ms_list.entry = this;

	memset(&m_trx_list, 0, sizeof(m_trx_list));
	m_trx_list.entry = this;

	memset(&ul_ass_fsm, 0, sizeof(ul_ass_fsm));
	ul_ass_fsm.tbf = this;
	ul_ass_fsm.fi = osmo_fsm_inst_alloc(&tbf_ul_ass_fsm, this, &ul_ass_fsm, LOGL_INFO, NULL);
	OSMO_ASSERT(ul_ass_fsm.fi);
	memset(&dl_ass_fsm, 0, sizeof(dl_ass_fsm));
	dl_ass_fsm.tbf = this;
	dl_ass_fsm.fi = osmo_fsm_inst_alloc(&tbf_dl_ass_fsm, this, &dl_ass_fsm, LOGL_INFO, NULL);
	OSMO_ASSERT(dl_ass_fsm.fi);

	m_rlc.init();
	llc_init(&m_llc);

	m_name_buf[0] = '\0';

	m_created_ts = time(NULL);
	/* set timestamp */
	osmo_clock_gettime(CLOCK_MONOTONIC, &meas.rssi_tv);

	m_ctrs = rate_ctr_group_alloc(this, &tbf_ctrg_desc, next_tbf_ctr_group_id++);
	OSMO_ASSERT(m_ctrs);
}


gprs_rlcmac_tbf::~gprs_rlcmac_tbf()
{
	osmo_fsm_inst_free(state_fi);
	state_fi = NULL;

	osmo_fsm_inst_free(ul_ass_fsm.fi);
	ul_ass_fsm.fi = NULL;
	osmo_fsm_inst_free(dl_ass_fsm.fi);
	dl_ass_fsm.fi = NULL;

	rate_ctr_group_free(m_ctrs);
}

uint32_t gprs_rlcmac_tbf::tlli() const
{
	return m_ms ? ms_tlli(m_ms) : GSM_RESERVED_TMSI;
}

const char *gprs_rlcmac_tbf::imsi() const
{
	return ms_imsi(m_ms);
}

uint8_t gprs_rlcmac_tbf::ta() const
{
	return ms_ta(m_ms);
}

void gprs_rlcmac_tbf::set_ta(uint8_t ta)
{
	ms_set_ta(m_ms, ta);
}

uint8_t gprs_rlcmac_tbf::ms_class() const
{
	return ms_ms_class(m_ms);
}

enum CodingScheme gprs_rlcmac_tbf::current_cs() const
{
	enum CodingScheme cs;
	enum mcs_kind req_mcs_kind = is_egprs_enabled() ? EGPRS : GPRS;

	if (direction == GPRS_RLCMAC_UL_TBF)
		cs = ms_current_cs_ul(m_ms);
	else
		cs = ms_current_cs_dl(m_ms, req_mcs_kind);

	return cs;
}

gprs_llc_queue *gprs_rlcmac_tbf::llc_queue()
{
	return ms_llc_queue(m_ms);
}

const gprs_llc_queue *gprs_rlcmac_tbf::llc_queue() const
{
	return ms_llc_queue(m_ms);
}

void gprs_rlcmac_tbf::set_ms(GprsMs *ms)
{
	if (m_ms == ms)
		return;

	if (m_ms)
		ms_detach_tbf(m_ms, this);

	m_ms = ms;

	if (m_ms)
		ms_attach_tbf(m_ms, this);
}

void tbf_unlink_pdch(struct gprs_rlcmac_tbf *tbf)
{
	int ts;

	/* During assignment (state=ASSIGN), tbf may be temporarily using
	 * tbf->control_ts from a previous TBF/SBA to transmit the UL/DL
	 * Assignment, which may not be necessarily be a TS where the current TBF
	 * is attached to. This will be the case until a TBF receives proper
	 * confirmation from the MS and goes through the FLOW state. Hence, we
	 * may have ULC pollings ongoing and we need to make sure we drop all
	 * reserved nodes there: */
	if (tbf->control_ts) {
		pdch_ulc_release_tbf(tbf->control_ts->ulc, tbf);
		tbf->control_ts = NULL;
	}

	/* Now simply detach from all attached PDCHs */
	for (ts = 0; ts < 8; ts++) {
		if (!tbf->pdch[ts])
			continue;

		tbf->pdch[ts]->detach_tbf(tbf);
		tbf->pdch[ts] = NULL;
	}

	/* Detach from TRX: */
	if (tbf->trx) {
		llist_del(tbf_trx_list(tbf));
		tbf->trx = NULL;
	}
}

void tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	/* update counters */
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_UL_FREED);
		if (tbf->state_is(TBF_ST_FLOW))
			bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_UL_ABORTED);
	} else {
		gprs_rlcmac_dl_tbf *dl_tbf = tbf_as_dl_tbf(tbf);
		gprs_rlc_dl_window *win = static_cast<gprs_rlc_dl_window *>(dl_tbf->window());

		bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_DL_FREED);
		if (tbf->state_is(TBF_ST_FLOW)) {
			bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_DL_ABORTED);
			/* range V(A)..V(S)-1 */
			uint16_t lost = win->count_unacked();
			/* report all outstanding packets as lost */
			gprs_rlcmac_received_lost(dl_tbf, 0, lost);
			/* TODO: Reschedule all LLC frames starting with the one that is
			 * (partly) encoded in chunk 1 of block V(A). (optional) */
		}
		/* reset rlc states */
		win->reset();
	}

	LOGPTBF(tbf, LOGL_INFO, "free\n");
	tbf->stop_timers("freeing TBF");
	/* TODO: Could/Should generate  bssgp_tx_llc_discarded */
	tbf_unlink_pdch(tbf);

	if (tbf->ms())
		tbf->set_ms(NULL);

	LOGP(DTBF, LOGL_DEBUG, "********** %s-TBF ends here **********\n",
	     (tbf->direction != GPRS_RLCMAC_UL_TBF) ? "DL" : "UL");
	talloc_free(tbf);
}

uint16_t egprs_window_size(const struct gprs_rlcmac_bts *bts, uint8_t slots)
{
	uint8_t num_pdch = pcu_bitcount(slots);

	return OSMO_MIN((num_pdch != 1) ? (128 * num_pdch) : 192,
			OSMO_MAX(64, (the_pcu->vty.ws_base + num_pdch * the_pcu->vty.ws_pdch) / 32 * 32));
}

void tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf)
{
	char buf[128];
	struct gprs_rlcmac_pdch *first_common = ms_first_common_ts(tbf_ms(tbf));
	OSMO_ASSERT(first_common);

	if (!tbf->control_ts)
		LOGPTBF(tbf, LOGL_INFO, "Setting Control TS %s\n",
			pdch_name(first_common));
	else if (tbf->control_ts != first_common)
		LOGPTBF(tbf, LOGL_INFO, "Changing Control TS %s -> %s\n",
			pdch_name_buf(tbf->control_ts, buf, sizeof(buf)),
			pdch_name(first_common));
	tbf->control_ts = first_common;
}

void gprs_rlcmac_tbf::n_reset(enum tbf_counters n)
{
	OSMO_ASSERT(n < N_MAX);

	switch(n) {
	case N3101:
		OSMO_ASSERT(direction == GPRS_RLCMAC_UL_TBF);
		break;
	case N3103:
		OSMO_ASSERT(direction == GPRS_RLCMAC_UL_TBF);
		break;
	case N3105:
		OSMO_ASSERT(direction == GPRS_RLCMAC_DL_TBF);
		break;
	default:
		break;
	}

	Narr[n] = 0;
}

/* Increment counter and check for MAX value (return true if we hit it) */
bool gprs_rlcmac_tbf::n_inc(enum tbf_counters n)
{
	uint8_t chk;

	OSMO_ASSERT(n < N_MAX);

	Narr[n]++;

	switch(n) {
	case N3101:
		OSMO_ASSERT(direction == GPRS_RLCMAC_UL_TBF);
		chk = bts->n3101;
		break;
	case N3103:
		OSMO_ASSERT(direction == GPRS_RLCMAC_UL_TBF);
		chk = bts->n3103;
		break;
	case N3105:
		OSMO_ASSERT(direction == GPRS_RLCMAC_DL_TBF);
		chk = bts->n3105;
		break;
	default:
		LOGPTBF(this, LOGL_ERROR, "unhandled counter %s\n",
			get_value_string(tbf_counters_names, n));
		return true;
	}

	if (Narr[n] == chk) {
		LOGPTBF(this, LOGL_NOTICE, "%s exceeded MAX (%u)\n",
			get_value_string(tbf_counters_names, n), chk);
		return true;
	} else {
		LOGPTBF(this, LOGL_DEBUG, "%s %" PRIu8 " => %" PRIu8 " (< MAX %" PRIu8 ")\n",
			get_value_string(tbf_counters_names, n), Narr[n] - 1, Narr[n], chk);
		return false;
	}
}

void gprs_rlcmac_tbf::t_stop(enum tbf_timers t, const char *reason)
{
	if (t >= T_MAX) {
		LOGPTBF(this, LOGL_ERROR, "attempting to stop unknown timer %s [%s]\n",
			get_value_string(tbf_timers_names, t), reason);
		return;
	}

	if (osmo_timer_pending(&Tarr[t])) {
		LOGPTBF(this, LOGL_DEBUG, "stopping timer %s [%s]\n",
			get_value_string(tbf_timers_names, t), reason);
		osmo_timer_del(&Tarr[t]);
	}
}

/* check if any of T31xx timer(s) are pending */
bool gprs_rlcmac_tbf::timers_pending(enum tbf_timers t)
{
	uint8_t i;

	if (t != T_MAX)
		return osmo_timer_pending(&Tarr[t]);

	for (i = T3141; i < T_MAX; i++)
		if (osmo_timer_pending(&Tarr[i]))
			return true;

	return false;
}

void gprs_rlcmac_tbf::stop_timers(const char *reason)
{
	uint8_t i;
	for (i = T3141; i < T_MAX; i++)
		t_stop((enum tbf_timers)i, reason);
}

static inline void tbf_timeout_free(struct gprs_rlcmac_tbf *tbf, enum tbf_timers t, bool run_diag)
{
	if (run_diag) {
		LOGPTBF(tbf, LOGL_NOTICE, "%s timeout expired, freeing TBF: %s\n",
			get_value_string(tbf_timers_names, t), tbf_rlcmac_diag(tbf));
	} else {
		LOGPTBF(tbf, LOGL_NOTICE, "%s timeout expired, freeing TBF\n",
			get_value_string(tbf_timers_names, t));
	}

	tbf_free(tbf);
}

#define T_CBACK(t, diag) static void cb_##t(void *_tbf) { tbf_timeout_free((struct gprs_rlcmac_tbf *)_tbf, t, diag); }

/* 3GPP TS 44.018 sec 3.5.2.1.5: On the network side, if timer T3141 elapses
 * before a successful contention resolution procedure is completed, the newly
 * allocated temporary block flow is released as specified in 3GPP TS 44.060 and
 * the packet access is forgotten.*/
T_CBACK(T3141, true)
T_CBACK(T3191, true)

void gprs_rlcmac_tbf::t_start(enum tbf_timers t, int T, const char *reason, bool force,
			      const char *file, unsigned line)
{
	int current_fn = bts_current_frame_number(bts);
	int sec;
	int microsec;
	struct osmo_tdef *tdef;

	if (!(tdef = osmo_tdef_get_entry(bts->T_defs_bts, T)))
		tdef = osmo_tdef_get_entry(bts->pcu->T_defs, T);

	if (t >= T_MAX || !tdef) {
		LOGPSRC(DTBF, LOGL_ERROR, file, line, "%s attempting to start unknown timer %s [%s], cur_fn=%d\n",
			tbf_name(this), get_value_string(tbf_timers_names, t), reason, current_fn);
		return;
	}

	if (!force && osmo_timer_pending(&Tarr[t]))
		return;

	switch (tdef->unit) {
	case OSMO_TDEF_MS:
		sec = 0;
		microsec = tdef->val * 1000;
		break;
	case OSMO_TDEF_S:
		sec = tdef->val;
		microsec = 0;
		break;
	default:
		/* so far only timers using MS and S */
		OSMO_ASSERT(false);
	}

	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s %sstarting timer %s [%s] with %u sec. %u microsec, cur_fn=%d\n",
	     tbf_name(this), osmo_timer_pending(&Tarr[t]) ? "re" : "",
	     get_value_string(tbf_timers_names, t), reason, sec, microsec, current_fn);

	Tarr[t].data = this;

	switch(t) {
	case T3141:
		Tarr[t].cb = cb_T3141;
		break;
	case T3191:
		Tarr[t].cb = cb_T3191;
		break;
	default:
		LOGPSRC(DTBF, LOGL_ERROR, file, line, "%s attempting to set callback for unknown timer %s [%s], cur_fn=%d\n",
		     tbf_name(this), get_value_string(tbf_timers_names, t), reason, current_fn);
	}

	osmo_timer_schedule(&Tarr[t], sec, microsec);
}

void gprs_rlcmac_tbf::poll_timeout(struct gprs_rlcmac_pdch *pdch, uint32_t poll_fn, enum pdch_ulc_tbf_poll_reason reason)
{
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_dl_tbf *dl_tbf;

	LOGPTBF(this, LOGL_NOTICE, "poll timeout for FN=%d, TS=%d (curr FN %d)\n",
		poll_fn, pdch->ts_no, bts_current_frame_number(bts));

	switch (reason) {
	case PDCH_ULC_POLL_UL_ACK:
		ul_tbf = tbf_as_ul_tbf(this);
		OSMO_ASSERT(ul_tbf);
		if (!tbf_ul_ack_exp_ctrl_ack(ul_tbf, poll_fn, pdch->ts_no)) {
			LOGPTBF(this, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_UL_ACK not expected!\n",
				poll_fn, pdch->ts_no, bts_current_frame_number(bts));
			return;
		}
		bts_do_rate_ctr_inc(bts, CTR_RLC_ACK_TIMEDOUT);
		bts_do_rate_ctr_inc(bts, CTR_PUAN_POLL_TIMEDOUT);
		if (state_is(TBF_ST_FINISHED)) {
			if (ul_tbf->n_inc(N3103)) {
				bts_do_rate_ctr_inc(bts, CTR_PUAN_POLL_FAILED);
				osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_MAX_N3103, NULL);
				return;
			}
		}
		osmo_fsm_inst_dispatch(ul_tbf->ul_ack_fsm.fi, TBF_UL_ACK_EV_POLL_TIMEOUT, NULL);
		break;

	case PDCH_ULC_POLL_UL_ASS:
		if (!ul_ass_state_is(TBF_UL_ASS_WAIT_ACK)) {
			LOGPTBF(this, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_UL_ASS not expected! state is %s\n",
				poll_fn, pdch->ts_no, bts_current_frame_number(bts),
				osmo_fsm_inst_state_name(tbf_ul_ass_fi(this)));
			return;
		}
		bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_TIMEDOUT);
		bts_do_rate_ctr_inc(bts, CTR_PUA_POLL_TIMEDOUT);
		if (this->direction == GPRS_RLCMAC_DL_TBF && n_inc(N3105)) {
			osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_MAX_N3105, NULL);
			bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_FAILED);
			bts_do_rate_ctr_inc(bts, CTR_PUA_POLL_FAILED);
			return;
		}
		/* Signal timeout to FSM to reschedule UL assignment */
		osmo_fsm_inst_dispatch(this->ul_ass_fsm.fi, TBF_UL_ASS_EV_ASS_POLL_TIMEOUT, NULL);
		break;

	case PDCH_ULC_POLL_DL_ASS:
		if (!dl_ass_state_is(TBF_DL_ASS_WAIT_ACK)) {
			LOGPTBF(this, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_DL_ASS not expected! state is %s\n",
				poll_fn, pdch->ts_no, bts_current_frame_number(bts),
				osmo_fsm_inst_state_name(tbf_dl_ass_fi(this)));
			return;
		}
		bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_TIMEDOUT);
		bts_do_rate_ctr_inc(bts, CTR_PDA_POLL_TIMEDOUT);
		if (this->direction == GPRS_RLCMAC_DL_TBF && n_inc(N3105)) {
			osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_MAX_N3105, NULL);
			bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_FAILED);
			bts_do_rate_ctr_inc(bts, CTR_PDA_POLL_FAILED);
			return;
		}
		/* Signal timeout to FSM to reschedule DL assignment */
		osmo_fsm_inst_dispatch(this->dl_ass_fsm.fi, TBF_DL_ASS_EV_ASS_POLL_TIMEOUT, NULL);
		break;

	case PDCH_ULC_POLL_CELL_CHG_CONTINUE:
		if (!m_ms->nacc || !nacc_fsm_exp_ctrl_ack(m_ms->nacc, poll_fn, pdch->ts_no)) {
			LOGPTBF(this, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_CELL_CHG_CONTINUE not expected!\n",
				poll_fn, pdch->ts_no, bts_current_frame_number(bts));
			return;
		}
		/* Timeout waiting for CTRL ACK acking Pkt Cell Change Continue */
		osmo_fsm_inst_dispatch(m_ms->nacc->fi, NACC_EV_TIMEOUT_CELL_CHG_CONTINUE, NULL);
		break;

	case PDCH_ULC_POLL_DL_ACK:
		dl_tbf = tbf_as_dl_tbf(this);
		/* POLL Timeout expecting DL ACK/NACK: implies direction == GPRS_RLCMAC_DL_TBF */
		OSMO_ASSERT(dl_tbf);
		if (!dl_tbf->m_last_dl_poll_ack_lost) {
			LOGPTBF(this, LOGL_NOTICE,
				"Timeout for polling PACKET DOWNLINK ACK: %s\n",
				tbf_rlcmac_diag(dl_tbf));
			dl_tbf->m_last_dl_poll_ack_lost = true;
		}
		if (dl_tbf->state_is(TBF_ST_RELEASING))
			bts_do_rate_ctr_inc(bts, CTR_RLC_REL_TIMEDOUT);
		else {
			bts_do_rate_ctr_inc(bts, CTR_RLC_ACK_TIMEDOUT);
			bts_do_rate_ctr_inc(bts, CTR_PDAN_POLL_TIMEDOUT);
		}
		if (dl_tbf->n_inc(N3105)) {
			osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_MAX_N3105, NULL);
			bts_do_rate_ctr_inc(bts, CTR_PDAN_POLL_FAILED);
			bts_do_rate_ctr_inc(bts, CTR_RLC_ACK_FAILED);
			return;
		}
		/* resend IMM.ASS on CCCH on timeout */
		osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_DL_ACKNACK_MISS, NULL);
		break;

	default:
		LOGPTBF(this, LOGL_ERROR, "Poll Timeout, reason %s unhandled!\n",
			get_value_string(pdch_ulc_tbf_poll_reason_names, reason));
	}
}

const char *tbf_name(const gprs_rlcmac_tbf *tbf)
{
	return tbf ? tbf->name() : "(no TBF)";
}

const char *gprs_rlcmac_tbf::name(bool enclousure) const
{
	struct osmo_strbuf sb = { .buf = m_name_buf, .len = sizeof(m_name_buf) };

	if (enclousure)
		OSMO_STRBUF_PRINTF(sb, "TBF(");
	OSMO_STRBUF_PRINTF(sb, "%s", direction == GPRS_RLCMAC_UL_TBF ? "UL" : "DL");
	if (this->trx) { /* This may not be available during TBF alloc func time */
		int8_t tfi = (m_tfi == TBF_TFI_UNSET) ? -1 : m_tfi;
		OSMO_STRBUF_PRINTF(sb, ":TFI-%u-%u-%d",
				   this->trx->bts->nr, this->trx->trx_no, tfi);
	}
	OSMO_STRBUF_PRINTF(sb, ":%c", is_egprs_enabled() ? 'E' : 'G');
	if (m_ms) {
		uint32_t tlli = ms_tlli(m_ms);
		if (ms_imsi_is_valid(m_ms))
			OSMO_STRBUF_PRINTF(sb, ":IMSI-%s", ms_imsi(m_ms));
		if (tlli != GSM_RESERVED_TMSI)
			OSMO_STRBUF_PRINTF(sb, ":TLLI-0x%08x", tlli);
	}
	if (enclousure)
		OSMO_STRBUF_PRINTF(sb, "){%s}", state_name());
	return m_name_buf;
}

void tbf_update_state_fsm_name(struct gprs_rlcmac_tbf *tbf)
{
	const char *buf = tbf->name(false);

	osmo_fsm_inst_update_id(tbf->state_fi, buf);
	osmo_fsm_inst_update_id(tbf->ul_ass_fsm.fi, buf);
	osmo_fsm_inst_update_id(tbf->dl_ass_fsm.fi, buf);

	if (tbf_direction(tbf) == GPRS_RLCMAC_UL_TBF) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = tbf_as_ul_tbf(tbf);
		osmo_fsm_inst_update_id(ul_tbf->ul_ack_fsm.fi, buf);
	}

}

void gprs_rlcmac_tbf::rotate_in_list()
{
	llist_del(tbf_trx_list((struct gprs_rlcmac_tbf *)this));
	if (direction == GPRS_RLCMAC_UL_TBF)
		llist_add(tbf_trx_list((struct gprs_rlcmac_tbf *)this), &trx->ul_tbfs);
	else
		llist_add(tbf_trx_list((struct gprs_rlcmac_tbf *)this), &trx->dl_tbfs);
}

uint8_t gprs_rlcmac_tbf::dl_slots() const
{
	uint8_t slots = 0;
	size_t i;

	if (direction == GPRS_RLCMAC_UL_TBF)
		return 0;

	for (i = 0; i < ARRAY_SIZE(pdch); i += 1)
		if (pdch[i])
			slots |= 1 << i;

	return slots;
}

uint8_t gprs_rlcmac_tbf::ul_slots() const
{
	uint8_t slots = 0;
	size_t i;
	struct gprs_rlcmac_pdch *first_common;

	if (direction == GPRS_RLCMAC_DL_TBF) {
		if (control_ts)
			slots |= 1 << control_ts->ts_no;
		first_common = ms_first_common_ts(tbf_ms(this));
		if (first_common)
			slots |= 1 << first_common->ts_no;

		return slots;
	}

	for (i = 0; i < ARRAY_SIZE(pdch); i += 1)
		if (pdch[i])
			slots |= 1 << i;

	return slots;
}

void gprs_rlcmac_tbf::enable_egprs()
{
	/* Decrease GPRS TBF count of attached PDCHs */
	for (size_t ts = 0; ts < ARRAY_SIZE(pdch); ts++) {
		if (pdch[ts])
			pdch[ts]->num_tbfs_update(this, false);
	}

	m_egprs_enabled = true;
	window()->set_sns(RLC_EGPRS_SNS);

	/* Increase EGPRS TBF count of attached PDCHs */
	for (size_t ts = 0; ts < ARRAY_SIZE(pdch); ts++) {
		if (pdch[ts])
			pdch[ts]->num_tbfs_update(this, true);
	}
}

/* C API */
enum tbf_fsm_states tbf_state(const struct gprs_rlcmac_tbf *tbf)
{
	return (enum tbf_fsm_states)tbf->state_fi->state;
}

struct osmo_fsm_inst *tbf_state_fi(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->state_fi;
}

struct osmo_fsm_inst *tbf_ul_ass_fi(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->ul_ass_fsm.fi;
}

struct osmo_fsm_inst *tbf_dl_ass_fi(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->dl_ass_fsm.fi;
}

enum gprs_rlcmac_tbf_direction tbf_direction(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->direction;
}

void tbf_set_ms(struct gprs_rlcmac_tbf *tbf, GprsMs *ms)
{
	tbf->set_ms(ms);
}

struct llist_head *tbf_ms_list(struct gprs_rlcmac_tbf *tbf)
{
	return &tbf->m_ms_list.list;
}

struct llist_head *tbf_trx_list(struct gprs_rlcmac_tbf *tbf)
{
	return &tbf->m_trx_list.list;
}

struct GprsMs *tbf_ms(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->ms();
}

bool tbf_timers_pending(struct gprs_rlcmac_tbf *tbf, enum tbf_timers t)
{
	return tbf->timers_pending(t);
}

struct gprs_llc *tbf_llc(struct gprs_rlcmac_tbf *tbf)
{
	return &tbf->m_llc;
}

uint8_t tbf_dl_slots(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->dl_slots();
}
uint8_t tbf_ul_slots(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->ul_slots();
}

bool tbf_is_tfi_assigned(const struct gprs_rlcmac_tbf *tbf)
{
	const struct gprs_rlcmac_dl_tbf *dl_tbf;

	/* The TBF is established: */
	if (tbf->state_fi->state > TBF_ST_ASSIGN)
		return true;

	/* The DL TBF has been assigned by a IMM.ASS: */
	dl_tbf = tbf_as_dl_tbf_const(tbf);
	if (tbf->state_fi->state == TBF_ST_ASSIGN && dl_tbf &&
	    (dl_tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)))
		return true;

	return false;
}

uint8_t tbf_tfi(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->tfi();
}

bool tbf_is_egprs_enabled(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->is_egprs_enabled();
}

int tbf_check_polling(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch,
		      uint32_t fn, uint32_t *poll_fn, unsigned int *rrbp)
{
	int rc;
	OSMO_ASSERT(pdch);

	if (!tbf_is_control_ts(tbf, pdch)) {
		char buf[128];
		LOGPTBF(tbf, LOGL_NOTICE, "Polling cannot be "
			"scheduled in this TS %s (control TS %s)\n",
			pdch_name(pdch),
			tbf->control_ts ? pdch_name_buf(tbf->control_ts, buf, sizeof(buf)) : "none");
		return -EINVAL;
	}

	if ((rc = pdch_ulc_get_next_free_rrbp_fn(pdch->ulc, fn, poll_fn, rrbp)) < 0) {
		LOGPTBF(tbf, LOGL_NOTICE,
			"FN=%u No suitable free RRBP offset found on %s!\n",
			fn, pdch_name(pdch));
		return rc;
	}

	return 0;
}

void tbf_set_polling(struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch, uint32_t new_poll_fn, enum pdch_ulc_tbf_poll_reason t)
{
	/* schedule polling */
	if (pdch_ulc_reserve_tbf_poll(pdch->ulc, new_poll_fn, tbf, t) < 0)
		LOGPTBF(tbf, LOGL_ERROR, "FN=%u Failed scheduling poll on PACCH %s\n",
			  new_poll_fn, pdch_name(pdch));
}

void tbf_poll_timeout(struct gprs_rlcmac_tbf *tbf, struct gprs_rlcmac_pdch *pdch, uint32_t poll_fn, enum pdch_ulc_tbf_poll_reason reason)
{
	tbf->poll_timeout(pdch, poll_fn, reason);
}

bool tbf_is_control_ts(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch)
{
	return tbf->control_ts == pdch;
}

bool tbf_can_upgrade_to_multislot(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->upgrade_to_multislot;
}
/* first TS used by TBF */
struct gprs_rlcmac_pdch *tbf_get_first_ts(struct gprs_rlcmac_tbf *tbf)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tbf->pdch); i++) {
		struct gprs_rlcmac_pdch *pdch;
		pdch = tbf->pdch[i];
		if (pdch)
			return pdch;
	}
	return NULL;
}
const struct gprs_rlcmac_pdch *tbf_get_first_ts_const(const struct gprs_rlcmac_tbf *tbf)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tbf->pdch); i++) {
		const struct gprs_rlcmac_pdch *pdch;
		pdch = tbf->pdch[i];
		if (pdch)
			return pdch;
	}
	return NULL;
}

const char* tbf_rlcmac_diag(const struct gprs_rlcmac_tbf *tbf)
{
	static char buf[256];
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };

	OSMO_STRBUF_PRINTF(sb, "|");
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		const struct gprs_rlcmac_ul_tbf *ul_tbf = tbf_as_ul_tbf_const(tbf);
		if (ul_tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
			OSMO_STRBUF_PRINTF(sb, "Assignment was on CCCH|");
		if (ul_tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))
			OSMO_STRBUF_PRINTF(sb, "Assignment was on PACCH|");
		if (ul_tbf->m_rx_counter)
			OSMO_STRBUF_PRINTF(sb, "Uplink data was received|");
		else
			OSMO_STRBUF_PRINTF(sb, "No uplink data received yet|");
	} else {
		const struct gprs_rlcmac_dl_tbf *dl_tbf = tbf_as_dl_tbf_const(tbf);
		if (dl_tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
			OSMO_STRBUF_PRINTF(sb, "Assignment was on CCCH|");
		if (dl_tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))
			OSMO_STRBUF_PRINTF(sb, "Assignment was on PACCH|");
		if (dl_tbf->m_first_dl_ack_rcvd)
			OSMO_STRBUF_PRINTF(sb, "Downlink ACK was received|");
		else
			OSMO_STRBUF_PRINTF(sb, "No downlink ACK received yet|");
	}

	return buf;
}

struct gprs_rlcmac_trx *tbf_get_trx(struct gprs_rlcmac_tbf *tbf)
{
	return tbf->trx;
}

void tbf_stop_timers(struct gprs_rlcmac_tbf *tbf, const char *reason)
{
	tbf->stop_timers(reason);
}