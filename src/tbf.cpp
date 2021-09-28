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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include <gprs_ms_storage.h>
#include <sba.h>
#include <pdch.h>

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
	first_ts(0),
	first_common_ts(0),
	control_ts(0xff),
	fT(0),
	num_fT_exp(0),
	upgrade_to_multislot(false),
	bts(bts_),
	m_tfi(0),
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

	memset(&state_fsm, 0, sizeof(state_fsm));
	state_fsm.tbf = this;
	state_fsm.fi = osmo_fsm_inst_alloc(&tbf_fsm, this, &state_fsm, LOGL_INFO, NULL);

	memset(&ul_ass_fsm, 0, sizeof(ul_ass_fsm));
	ul_ass_fsm.tbf = this;
	ul_ass_fsm.fi = osmo_fsm_inst_alloc(&tbf_ul_ass_fsm, this, &ul_ass_fsm, LOGL_INFO, NULL);
	memset(&dl_ass_fsm, 0, sizeof(dl_ass_fsm));
	dl_ass_fsm.tbf = this;
	dl_ass_fsm.fi = osmo_fsm_inst_alloc(&tbf_dl_ass_fsm, this, &dl_ass_fsm, LOGL_INFO, NULL);

	m_rlc.init();
	m_llc.init();

	m_name_buf[0] = '\0';
}


gprs_rlcmac_tbf::~gprs_rlcmac_tbf()
{
	osmo_fsm_inst_free(state_fsm.fi);
	state_fsm.fi = NULL;

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

	if (m_ms) {
		ms_detach_tbf(m_ms, this);
	}

	m_ms = ms;

	if (m_ms)
		ms_attach_tbf(m_ms, this);
}

void gprs_rlcmac_tbf::update_ms(uint32_t tlli, enum gprs_rlcmac_tbf_direction dir)
{
	if (tlli == GSM_RESERVED_TMSI)
		return;

	/* TODO: When the TLLI does not match the ms, check if there is another
	 * MS object that belongs to that TLLI and if yes make sure one of them
	 * gets deleted. This is the same problem that can arise with
	 * IMSI in gprs_rlcmac_dl_tbf::handle() so there should be a unified solution */
	if (!ms_check_tlli(ms(), tlli)) {
		GprsMs *old_ms;

		old_ms = bts_ms_store(bts)->get_ms(tlli, 0, NULL);
		if (old_ms)
			ms_merge_and_clear_ms(ms(), old_ms);
	}

	if (dir == GPRS_RLCMAC_UL_TBF)
		ms_set_tlli(ms(), tlli);
	else
		ms_confirm_tlli(ms(), tlli);
}

static void tbf_unlink_pdch(struct gprs_rlcmac_tbf *tbf)
{
	int ts;

	for (ts = 0; ts < 8; ts++) {
		if (!tbf->pdch[ts])
			continue;

		tbf->pdch[ts]->detach_tbf(tbf);
		tbf->pdch[ts] = NULL;
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
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf);
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
	llist_del(tbf_trx_list(tbf));

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

int gprs_rlcmac_tbf::update()
{
	int rc;

	if (direction != GPRS_RLCMAC_DL_TBF)
		return -EINVAL;

	LOGP(DTBF, LOGL_DEBUG, "********** DL-TBF update **********\n");

	tbf_unlink_pdch(this);
	rc = the_pcu->alloc_algorithm(bts, this, false, -1);
	/* if no resource */
	if (rc < 0) {
		LOGPTBF(this, LOGL_ERROR, "No resource after update???\n");
		bts_do_rate_ctr_inc(bts, CTR_TBF_ALLOC_FAIL);
		return -rc;
	}

	if (is_egprs_enabled()) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);
		if (dl_tbf)
			dl_tbf->set_window_size();
	}

	return 0;
}

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->control_ts == 0xff)
		LOGPTBF(tbf, LOGL_INFO, "Setting Control TS %d\n",
			tbf->first_common_ts);
	else if (tbf->control_ts != tbf->first_common_ts)
		LOGPTBF(tbf, LOGL_INFO, "Changing Control TS %d -> %d\n",
			tbf->control_ts, tbf->first_common_ts);
	tbf->control_ts = tbf->first_common_ts;

	return 0;
}

void gprs_rlcmac_tbf::n_reset(enum tbf_counters n)
{
	if (n >= N_MAX) {
		LOGPTBF(this, LOGL_ERROR, "attempting to reset unknown counter %s\n",
			get_value_string(tbf_counters_names, n));
		return;
	}

	Narr[n] = 0;
}

/* Increment counter and check for MAX value (return true if we hit it) */
bool gprs_rlcmac_tbf::n_inc(enum tbf_counters n)
{
	uint8_t chk;

	if (n >= N_MAX) {
		LOGPTBF(this, LOGL_ERROR, "attempting to increment unknown counter %s\n",
			get_value_string(tbf_counters_names, n));
		return true;
	}

	Narr[n]++;

	switch(n) {
	case N3101:
		chk = bts->n3101;
		break;
	case N3103:
		chk = bts->n3103;
		break;
	case N3105:
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

int gprs_rlcmac_tbf::check_polling(uint32_t fn, uint8_t ts,
	uint32_t *poll_fn_, unsigned int *rrbp_) const
{
	int rc;
	if (!is_control_ts(ts)) {
		LOGPTBF(this, LOGL_DEBUG, "Polling cannot be "
			"scheduled in this TS %d (first control TS %d)\n",
			ts, control_ts);
		return -EINVAL;
	}

	if ((rc = pdch_ulc_get_next_free_rrbp_fn(trx->pdch[ts].ulc, fn, poll_fn_, rrbp_)) < 0) {
		LOGPTBF(this, LOGL_DEBUG,
			"(bts=%u,trx=%u,ts=%u) FN=%u No suitable free RRBP offset found!\n",
			trx->bts->nr, trx->trx_no, ts, fn);
		return rc;
	}

	return 0;
}

void gprs_rlcmac_tbf::set_polling(uint32_t new_poll_fn, uint8_t ts, enum pdch_ulc_tbf_poll_reason reason)
{
	/* schedule polling */
	if (pdch_ulc_reserve_tbf_poll(trx->pdch[ts].ulc, new_poll_fn, this, reason) < 0)
		LOGPTBFDL(this, LOGL_ERROR, "Failed scheduling poll on PACCH (FN=%d, TS=%d)\n",
			  new_poll_fn, ts);
}

void gprs_rlcmac_tbf::poll_timeout(struct gprs_rlcmac_pdch *pdch, uint32_t poll_fn, enum pdch_ulc_tbf_poll_reason reason)
{
	gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(this);

	LOGPTBF(this, LOGL_NOTICE, "poll timeout for FN=%d, TS=%d (curr FN %d)\n",
		poll_fn, pdch->ts_no, bts_current_frame_number(bts));

	if (ul_tbf && reason == PDCH_ULC_POLL_UL_ACK && tbf_ul_ack_exp_ctrl_ack(ul_tbf, poll_fn, pdch->ts_no)) {
		bts_do_rate_ctr_inc(bts, CTR_RLC_ACK_TIMEDOUT);
		bts_do_rate_ctr_inc(bts, CTR_PUAN_POLL_TIMEDOUT);
		if (state_is(TBF_ST_FINISHED)) {
			if (ul_tbf->n_inc(N3103)) {
				bts_do_rate_ctr_inc(bts, CTR_PUAN_POLL_FAILED);
				osmo_fsm_inst_dispatch(this->state_fsm.fi, TBF_EV_MAX_N3103, NULL);
				return;
			}
		}
		osmo_fsm_inst_dispatch(ul_tbf->ul_ack_fsm.fi, TBF_UL_ACK_EV_POLL_TIMEOUT, NULL);
	} else if (reason == PDCH_ULC_POLL_UL_ASS && ul_ass_state_is(TBF_UL_ASS_WAIT_ACK)) {
		bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_TIMEDOUT);
		bts_do_rate_ctr_inc(bts, CTR_PUA_POLL_TIMEDOUT);
		if (n_inc(N3105)) {
			osmo_fsm_inst_dispatch(this->state_fsm.fi, TBF_EV_MAX_N3105, NULL);
			bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_FAILED);
			bts_do_rate_ctr_inc(bts, CTR_PUA_POLL_FAILED);
			return;
		}
		/* Signal timeout to FSM to reschedule UL assignment */
		osmo_fsm_inst_dispatch(this->ul_ass_fsm.fi, TBF_UL_ASS_EV_ASS_POLL_TIMEOUT, NULL);
	} else if (reason == PDCH_ULC_POLL_DL_ASS && dl_ass_state_is(TBF_DL_ASS_WAIT_ACK)) {
		bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_TIMEDOUT);
		bts_do_rate_ctr_inc(bts, CTR_PDA_POLL_TIMEDOUT);
		if (n_inc(N3105)) {
			osmo_fsm_inst_dispatch(this->state_fsm.fi, TBF_EV_MAX_N3105, NULL);
			bts_do_rate_ctr_inc(bts, CTR_RLC_ASS_FAILED);
			bts_do_rate_ctr_inc(bts, CTR_PDA_POLL_FAILED);
			return;
		}
		/* Signal timeout to FSM to reschedule DL assignment */
		osmo_fsm_inst_dispatch(this->dl_ass_fsm.fi, TBF_DL_ASS_EV_ASS_POLL_TIMEOUT, NULL);
	} else if (reason == PDCH_ULC_POLL_CELL_CHG_CONTINUE && m_ms->nacc && m_ms->nacc->fi->state == NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK &&
		   m_ms->nacc->continue_poll_fn == poll_fn && m_ms->nacc->continue_poll_ts == pdch->ts_no) {
		/* Timeout waiting for CTRL ACK acking Pkt Cell Change Continue */
		osmo_fsm_inst_dispatch(m_ms->nacc->fi, NACC_EV_TIMEOUT_CELL_CHG_CONTINUE, NULL);
		return;
	} else if (reason == PDCH_ULC_POLL_DL_ACK) {
		/* POLL Timeout expecting DL ACK/NACK: implies direction == GPRS_RLCMAC_DL_TBF */
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);

		if (!(dl_tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK))) {
			LOGPTBF(this, LOGL_NOTICE,
				"Timeout for polling PACKET DOWNLINK ACK: %s\n",
				tbf_rlcmac_diag(dl_tbf));
			dl_tbf->state_fsm.state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);
		}

		if (dl_tbf->state_is(TBF_ST_RELEASING))
			bts_do_rate_ctr_inc(bts, CTR_RLC_REL_TIMEDOUT);
		else {
			bts_do_rate_ctr_inc(bts, CTR_RLC_ACK_TIMEDOUT);
			bts_do_rate_ctr_inc(bts, CTR_PDAN_POLL_TIMEDOUT);
		}

		if (dl_tbf->n_inc(N3105)) {
			osmo_fsm_inst_dispatch(this->state_fsm.fi, TBF_EV_MAX_N3105, NULL);
			bts_do_rate_ctr_inc(bts, CTR_PDAN_POLL_FAILED);
			bts_do_rate_ctr_inc(bts, CTR_RLC_ACK_FAILED);
			return;
		}
		/* resend IMM.ASS on CCCH on timeout */
		osmo_fsm_inst_dispatch(this->state_fsm.fi, TBF_EV_DL_ACKNACK_MISS, NULL);
	} else
		LOGPTBF(this, LOGL_ERROR, "Poll Timeout, but no event!\n");
}

int gprs_rlcmac_tbf::setup(int8_t use_trx, bool single_slot)
{
	int rc;

	if (ms_mode(m_ms) != GPRS)
		enable_egprs();

	m_created_ts = time(NULL);
	/* select algorithm */
	rc = the_pcu->alloc_algorithm(bts, this, single_slot, use_trx);
	/* if no resource */
	if (rc < 0) {
		LOGPTBF(this, LOGL_NOTICE,
			"Timeslot Allocation failed: trx = %d, single_slot = %d\n",
			use_trx, single_slot);
		bts_do_rate_ctr_inc(bts, CTR_TBF_ALLOC_FAIL);
		return -1;
	}
	/* assign control ts */
	rc = tbf_assign_control_ts(this);
	/* if no resource */
	if (rc < 0) {
		LOGPTBF(this, LOGL_ERROR, "Failed to assign control TS\n");
		return -1;
	}

	/* set timestamp */
	osmo_clock_gettime(CLOCK_MONOTONIC, &meas.rssi_tv);

	LOGPTBF(this, LOGL_INFO,
		"Allocated: trx = %d, ul_slots = %02x, dl_slots = %02x\n",
		this->trx->trx_no, ul_slots(), dl_slots());

	m_ctrs = rate_ctr_group_alloc(this, &tbf_ctrg_desc, next_tbf_ctr_group_id++);
	if (!m_ctrs) {
		LOGPTBF(this, LOGL_ERROR, "Couldn't allocate TBF counters\n");
		return -1;
	}

	tbf_update_state_fsm_name(this);

	ms_attach_tbf(m_ms, this);

	return 0;
}

int gprs_rlcmac_tbf::establish_dl_tbf_on_pacch()
{
	struct gprs_rlcmac_dl_tbf *new_tbf = NULL;

	bts_do_rate_ctr_inc(bts, CTR_TBF_REUSED);

	new_tbf = tbf_alloc_dl_tbf(bts, ms(),
		this->trx->trx_no, false);

	if (!new_tbf) {
		LOGP(DTBF, LOGL_NOTICE, "No PDCH resource\n");
		return -1;
	}

	LOGPTBF(this, LOGL_DEBUG, "Trigger downlink assignment on PACCH\n");
	new_tbf->trigger_ass(this);

	return 0;
}

const char *tbf_name(const gprs_rlcmac_tbf *tbf)
{
	return tbf ? tbf->name() : "(no TBF)";
}

const char *gprs_rlcmac_tbf::name() const
{
	snprintf(m_name_buf, sizeof(m_name_buf) - 1,
		"TBF(TFI=%d TLLI=0x%08x DIR=%s STATE=%s%s)",
		m_tfi, tlli(),
		direction == GPRS_RLCMAC_UL_TBF ? "UL" : "DL",
		state_name(),
		is_egprs_enabled() ? " EGPRS" : ""
		);
	m_name_buf[sizeof(m_name_buf) - 1] = '\0';
	return m_name_buf;
}

void tbf_update_state_fsm_name(struct gprs_rlcmac_tbf *tbf)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "%s-TFI_%d",
		 tbf_direction(tbf) == GPRS_RLCMAC_UL_TBF ? "UL" : "DL",
		 tbf_tfi(tbf));
	osmo_identifier_sanitize_buf(buf, NULL, '_');

	osmo_fsm_inst_update_id(tbf->state_fsm.fi, buf);
	osmo_fsm_inst_update_id(tbf->ul_ass_fsm.fi, buf);
	osmo_fsm_inst_update_id(tbf->dl_ass_fsm.fi, buf);

	if (tbf_direction(tbf) == GPRS_RLCMAC_UL_TBF) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(tbf);
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

uint8_t gprs_rlcmac_tbf::tsc() const
{
	return trx->pdch[first_ts].tsc;
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

	if (direction == GPRS_RLCMAC_DL_TBF) {
		if (control_ts < 8)
			slots |= 1 << control_ts;
		if (first_common_ts < 8)
			slots |= 1 << first_common_ts;

		return slots;
	}

	for (i = 0; i < ARRAY_SIZE(pdch); i += 1)
		if (pdch[i])
			slots |= 1 << i;

	return slots;
}

bool gprs_rlcmac_tbf::is_control_ts(uint8_t ts) const
{
	return ts == control_ts;
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
	return (enum tbf_fsm_states)tbf->state_fsm.fi->state;
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

uint8_t tbf_first_common_ts(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->first_common_ts;
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
	return tbf->is_tfi_assigned();
}

uint8_t tbf_tfi(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->tfi();
}

bool tbf_is_egprs_enabled(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->is_egprs_enabled();
}

int tbf_check_polling(const struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts, uint32_t *poll_fn, unsigned int *rrbp)
{
	return tbf->check_polling(fn, ts, poll_fn, rrbp);
}

void tbf_set_polling(struct gprs_rlcmac_tbf *tbf, uint32_t new_poll_fn, uint8_t ts, enum pdch_ulc_tbf_poll_reason t)
{
	return tbf->set_polling(new_poll_fn, ts, t);
}

void tbf_poll_timeout(struct gprs_rlcmac_tbf *tbf, struct gprs_rlcmac_pdch *pdch, uint32_t poll_fn, enum pdch_ulc_tbf_poll_reason reason)
{
	tbf->poll_timeout(pdch, poll_fn, reason);
}

bool tbf_is_control_ts(const struct gprs_rlcmac_tbf *tbf, uint8_t ts)
{
	return tbf->is_control_ts(ts);
}

bool tbf_can_upgrade_to_multislot(const struct gprs_rlcmac_tbf *tbf)
{
	return tbf->upgrade_to_multislot;
}

int tbf_update(struct gprs_rlcmac_tbf *tbf)
{
	return tbf->update();
}

const char* tbf_rlcmac_diag(const struct gprs_rlcmac_tbf *tbf)
{
	static char buf[256];
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };

	OSMO_STRBUF_PRINTF(sb, "|");
	if (tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
		OSMO_STRBUF_PRINTF(sb, "Assignment was on CCCH|");
	if (tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))
		OSMO_STRBUF_PRINTF(sb, "Assignment was on PACCH|");
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		const struct gprs_rlcmac_ul_tbf *ul_tbf = static_cast<const gprs_rlcmac_ul_tbf *>(tbf);
		if (ul_tbf->m_rx_counter)
			OSMO_STRBUF_PRINTF(sb, "Uplink data was received|");
		else
			OSMO_STRBUF_PRINTF(sb, "No uplink data received yet|");
	} else {
		if (tbf->state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK))
			OSMO_STRBUF_PRINTF(sb, "Downlink ACK was received|");
		else
			OSMO_STRBUF_PRINTF(sb, "No downlink ACK received yet|");
	}

	return buf;
}
