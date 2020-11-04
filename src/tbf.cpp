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
#include <gsm_timer.h>
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
}

#include <errno.h>
#include <string.h>

extern void *tall_pcu_ctx;

unsigned int next_tbf_ctr_group_id = 0; /* Incrementing group id */

static void tbf_timer_cb(void *_tbf);

const struct value_string gprs_rlcmac_tbf_poll_state_names[] = {
	OSMO_VALUE_STRING(GPRS_RLCMAC_POLL_NONE),
	OSMO_VALUE_STRING(GPRS_RLCMAC_POLL_SCHED), /* a polling was scheduled */
	{ 0, NULL }
};

const struct value_string gprs_rlcmac_tbf_dl_ass_state_names[] = {
	OSMO_VALUE_STRING(GPRS_RLCMAC_DL_ASS_NONE),
	OSMO_VALUE_STRING(GPRS_RLCMAC_DL_ASS_SEND_ASS),
	OSMO_VALUE_STRING(GPRS_RLCMAC_DL_ASS_WAIT_ACK),
 	{ 0, NULL }
};

const struct value_string gprs_rlcmac_tbf_ul_ass_state_names[] = {
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ASS_NONE),
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ASS_SEND_ASS),
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ),
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ASS_WAIT_ACK),
 	{ 0, NULL }
};

const struct value_string gprs_rlcmac_tbf_ul_ack_state_names[] = {
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ACK_NONE),
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ACK_SEND_ACK), /* send acknowledge on next RTS */
	OSMO_VALUE_STRING(GPRS_RLCMAC_UL_ACK_WAIT_ACK), /* wait for PACKET CONTROL ACK */
	{ 0, NULL }
};

static const struct value_string tbf_counters_names[] = {
	OSMO_VALUE_STRING(N3101),
	OSMO_VALUE_STRING(N3103),
	OSMO_VALUE_STRING(N3105),
	{ 0, NULL }
};

static const struct value_string tbf_timers_names[] = {
	OSMO_VALUE_STRING(T0),
	OSMO_VALUE_STRING(T3169),
	OSMO_VALUE_STRING(T3191),
	OSMO_VALUE_STRING(T3193),
	OSMO_VALUE_STRING(T3195),
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

gprs_rlcmac_tbf::gprs_rlcmac_tbf(BTS *bts_, GprsMs *ms, gprs_rlcmac_tbf_direction dir) :
	state_flags(0),
	direction(dir),
	trx(NULL),
	first_ts(0),
	first_common_ts(0),
	control_ts(0xff),
	poll_fn(0),
	poll_ts(0),
	fT(0),
	num_fT_exp(0),
	was_releasing(0),
	upgrade_to_multislot(0),
	bts(bts_),
	m_tfi(0),
	m_created_ts(0),
	m_ctrs(NULL),
	m_ms(ms),
	state(GPRS_RLCMAC_NULL),
	dl_ass_state(GPRS_RLCMAC_DL_ASS_NONE),
	ul_ass_state(GPRS_RLCMAC_UL_ASS_NONE),
	ul_ack_state(GPRS_RLCMAC_UL_ACK_NONE),
	poll_state(GPRS_RLCMAC_POLL_NONE),
	m_list(this),
	m_ms_list(this),
	m_egprs_enabled(false)
{
	/* The classes of these members do not have proper constructors yet.
	 * Just set them to 0 like talloc_zero did */
	memset(&pdch, 0, sizeof(pdch));
	memset(&Tarr, 0, sizeof(Tarr));
	memset(&Narr, 0, sizeof(Narr));
	memset(&gsm_timer, 0, sizeof(gsm_timer));

	m_rlc.init();
	m_llc.init();

	m_name_buf[0] = '\0';
}

gprs_rlcmac_bts *gprs_rlcmac_tbf::bts_data() const
{
	return bts->bts_data();
}

uint32_t gprs_rlcmac_tbf::tlli() const
{
	return m_ms ? m_ms->tlli() : 0;
}

const char *gprs_rlcmac_tbf::imsi() const
{
	return m_ms->imsi();
}

uint8_t gprs_rlcmac_tbf::ta() const
{
	return m_ms->ta();
}

void gprs_rlcmac_tbf::set_ta(uint8_t ta)
{
	ms()->set_ta(ta);
}

uint8_t gprs_rlcmac_tbf::ms_class() const
{
	return m_ms->ms_class();
}

enum CodingScheme gprs_rlcmac_tbf::current_cs() const
{
	enum CodingScheme cs;

	if (direction == GPRS_RLCMAC_UL_TBF)
		cs = m_ms ? m_ms->current_cs_ul() : UNKNOWN;
	else
		cs = m_ms ? m_ms->current_cs_dl() : UNKNOWN;

	return cs;
}

gprs_llc_queue *gprs_rlcmac_tbf::llc_queue()
{
	return m_ms ? m_ms->llc_queue() : NULL;
}

const gprs_llc_queue *gprs_rlcmac_tbf::llc_queue() const
{
	return m_ms ? m_ms->llc_queue() : NULL;
}

size_t gprs_rlcmac_tbf::llc_queue_size() const
{
	/* m_ms->llc_queue() never returns NULL: GprsMs::m_llc_queue is a
	 * member instance. */
	return m_ms ? m_ms->llc_queue()->size() : 0;
}

void gprs_rlcmac_tbf::set_ms(GprsMs *ms)
{
	if (m_ms == ms)
		return;

	if (m_ms) {
		m_ms->detach_tbf(this);
	}

	m_ms = ms;

	if (m_ms)
		m_ms->attach_tbf(this);
}

void gprs_rlcmac_tbf::update_ms(uint32_t tlli, enum gprs_rlcmac_tbf_direction dir)
{
	if (!tlli)
		return;

	/* TODO: When the TLLI does not match the ms, check if there is another
	 * MS object that belongs to that TLLI and if yes make sure one of them
	 * gets deleted. This is the same problem that can arise with
	 * IMSI in gprs_rlcmac_dl_tbf::handle() so there should be a unified solution */
	if (!ms()->check_tlli(tlli)) {
		GprsMs *old_ms;

		old_ms = bts->ms_store().get_ms(tlli, 0, NULL);
		if (old_ms)
			ms()->merge_and_clear_ms(old_ms);
	}

	if (dir == GPRS_RLCMAC_UL_TBF)
		ms()->set_tlli(tlli);
	else
		ms()->confirm_tlli(tlli);
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
		gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(tbf);
		tbf->bts->do_rate_ctr_inc(CTR_TBF_UL_FREED);
		if (tbf->state_is(GPRS_RLCMAC_FLOW))
			tbf->bts->do_rate_ctr_inc(CTR_TBF_UL_ABORTED);
		rate_ctr_group_free(ul_tbf->m_ul_egprs_ctrs);
		rate_ctr_group_free(ul_tbf->m_ul_gprs_ctrs);
	} else {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf);
		if (tbf->is_egprs_enabled()) {
			rate_ctr_group_free(dl_tbf->m_dl_egprs_ctrs);
		} else {
			rate_ctr_group_free(dl_tbf->m_dl_gprs_ctrs);
		}
		tbf->bts->do_rate_ctr_inc(CTR_TBF_DL_FREED);
		if (tbf->state_is(GPRS_RLCMAC_FLOW))
			tbf->bts->do_rate_ctr_inc(CTR_TBF_DL_ABORTED);
	}

	/* Give final measurement report */
	gprs_rlcmac_rssi_rep(tbf);
	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf);

		dl_tbf->abort();
		dl_tbf->cleanup();
	}

	LOGPTBF(tbf, LOGL_INFO, "free\n");
	tbf->check_pending_ass();
	tbf->stop_timers("freeing TBF");
	/* TODO: Could/Should generate  bssgp_tx_llc_discarded */
	tbf_unlink_pdch(tbf);
	llist_del(&tbf->list());

	if (tbf->ms())
		tbf->set_ms(NULL);

	rate_ctr_group_free(tbf->m_ctrs);

	LOGP(DTBF, LOGL_DEBUG, "********** %s-TBF ends here **********\n",
	     (tbf->direction != GPRS_RLCMAC_UL_TBF) ? "DL" : "UL");
	talloc_free(tbf);
}

uint16_t egprs_window_size(const struct gprs_rlcmac_bts *bts_data, uint8_t slots)
{
	uint8_t num_pdch = pcu_bitcount(slots);

	return OSMO_MIN((num_pdch != 1) ? (128 * num_pdch) : 192,
			OSMO_MAX(64, (bts_data->ws_base + num_pdch * bts_data->ws_pdch) / 32 * 32));
}

int gprs_rlcmac_tbf::update()
{
	struct gprs_rlcmac_bts *bts_data = bts->bts_data();
	int rc;

	if (direction != GPRS_RLCMAC_DL_TBF)
		return -EINVAL;

	LOGP(DTBF, LOGL_DEBUG, "********** DL-TBF update **********\n");

	tbf_unlink_pdch(this);
	rc = bts_data->alloc_algorithm(bts_data, ms(), this, false, -1);
	/* if no resource */
	if (rc < 0) {
		LOGPTBF(this, LOGL_ERROR, "No resource after update???\n");
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
		LOGPTBF(tbf, LOGL_INFO, "Changing Control TS %d\n",
			tbf->first_common_ts);
	tbf->control_ts = tbf->first_common_ts;

	return 0;
}

const char *gprs_rlcmac_tbf::tbf_state_name[] = {
	"NULL",
	"ASSIGN",
	"FLOW",
	"FINISHED",
	"WAIT RELEASE",
	"RELEASING",
};

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
		chk = bts->bts_data()->n3101;
		break;
	case N3103:
		chk = bts->bts_data()->n3103;
		break;
	case N3105:
		chk = bts->bts_data()->n3105;
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
	}

	return false;
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

	/* we don't start with T0 because it's internal timer which requires special handling */
	for (i = T3169; i < T_MAX; i++)
		if (osmo_timer_pending(&Tarr[i]))
			return true;

	return false;
}

void gprs_rlcmac_tbf::stop_timers(const char *reason)
{
	uint8_t i;
	/* we start with T0 because timer reset does not require any special handling */
	for (i = T0; i < T_MAX; i++)
		t_stop((enum tbf_timers)i, reason);
}

static inline void tbf_timeout_free(struct gprs_rlcmac_tbf *tbf, enum tbf_timers t, bool run_diag)
{
	LOGPTBF(tbf, LOGL_NOTICE, "%s timeout expired, freeing TBF\n",
		get_value_string(tbf_timers_names, t));

	if (run_diag) {
		LOGPTBF(tbf, LOGL_NOTICE, "%s timeout expired, freeing TBF: %s\n",
			get_value_string(tbf_timers_names, t), tbf->rlcmac_diag().c_str());
	} else {
		LOGPTBF(tbf, LOGL_NOTICE, "%s timeout expired, freeing TBF\n",
			get_value_string(tbf_timers_names, t));
	}

	tbf_free(tbf);
}

#define T_CBACK(t, diag) static void cb_##t(void *_tbf) { tbf_timeout_free((struct gprs_rlcmac_tbf *)_tbf, t, diag); }

T_CBACK(T3169, true)
T_CBACK(T3191, true)
T_CBACK(T3193, false)
T_CBACK(T3195, true)

void gprs_rlcmac_tbf::t_start(enum tbf_timers t, int T, const char *reason, bool force,
			      const char *file, unsigned line)
{
	int current_fn = get_current_fn();
	int sec;
	int microsec;
	struct osmo_tdef *tdef;

	if (!(tdef = osmo_tdef_get_entry(bts->bts_data()->T_defs_bts, T)))
		tdef = osmo_tdef_get_entry(bts->bts_data()->T_defs_pcu, T);

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
	case T0:
		Tarr[t].cb = tbf_timer_cb;
		break;
	case T3169:
		Tarr[t].cb = cb_T3169;
		break;
	case T3191:
		Tarr[t].cb = cb_T3191;
		break;
	case T3193:
		Tarr[t].cb = cb_T3193;
		break;
	case T3195:
		Tarr[t].cb = cb_T3195;
		break;
	default:
		LOGPSRC(DTBF, LOGL_ERROR, file, line, "%s attempting to set callback for unknown timer %s [%s], cur_fn=%d\n",
		     tbf_name(this), get_value_string(tbf_timers_names, t), reason, current_fn);
	}

	osmo_timer_schedule(&Tarr[t], sec, microsec);
}

int gprs_rlcmac_tbf::check_polling(uint32_t fn, uint8_t ts,
	uint32_t *poll_fn_, unsigned int *rrbp_)
{
	uint32_t new_poll_fn = next_fn(fn, 13);

	if (!is_control_ts(ts)) {
		LOGPTBF(this, LOGL_DEBUG, "Polling cannot be "
			"scheduled in this TS %d (first control TS %d)\n",
			ts, control_ts);
		return -EINVAL;
	}
	if (poll_state != GPRS_RLCMAC_POLL_NONE) {
		LOGPTBF(this, LOGL_DEBUG, "Polling is already scheduled\n");
		return -EBUSY;
	}
	if (bts->sba()->find(trx->trx_no, ts, next_fn(fn, 13))) {
		LOGPTBF(this, LOGL_DEBUG, "Polling is already scheduled "
			"for single block allocation at FN %d TS %d ...\n",
			new_poll_fn, ts);
		return -EBUSY;
	}

	*poll_fn_ = new_poll_fn;
	*rrbp_ = 0;

	return 0;
}

void gprs_rlcmac_tbf::set_polling(uint32_t new_poll_fn, uint8_t ts, enum gprs_rlcmac_tbf_poll_type t)
{
	const char *chan = "UNKNOWN";

	if (state_flags & (1 << (GPRS_RLCMAC_FLAG_CCCH)))
		chan = "CCCH";

	if (state_flags & (1 << (GPRS_RLCMAC_FLAG_PACCH)))
		chan = "PACCH";

	if ((state_flags & (1 << (GPRS_RLCMAC_FLAG_PACCH))) && (state_flags & (1 << (GPRS_RLCMAC_FLAG_CCCH))))
		LOGPTBFDL(this, LOGL_ERROR,
			  "Attempt to schedule polling on %s (FN=%d, TS=%d) with both CCCH and PACCH flags set - FIXME!\n",
			  chan, poll_fn, poll_ts);

	/* schedule polling */
	poll_state = GPRS_RLCMAC_POLL_SCHED;
	poll_fn = new_poll_fn;
	poll_ts = ts;

	switch (t) {
	case GPRS_RLCMAC_POLL_UL_ASS:
		ul_ass_state = GPRS_RLCMAC_UL_ASS_WAIT_ACK;

		LOGPTBFDL(this, LOGL_INFO, "Scheduled UL Assignment polling on %s (FN=%d, TS=%d)\n",
			  chan, poll_fn, poll_ts);
		break;
	case GPRS_RLCMAC_POLL_DL_ASS:
		dl_ass_state = GPRS_RLCMAC_DL_ASS_WAIT_ACK;

		LOGPTBFDL(this, LOGL_INFO, "Scheduled DL Assignment polling on %s (FN=%d, TS=%d)\n",
			  chan, poll_fn, poll_ts);
		break;
	case GPRS_RLCMAC_POLL_UL_ACK:
		ul_ack_state = GPRS_RLCMAC_UL_ACK_WAIT_ACK;

		LOGPTBFUL(this, LOGL_DEBUG, "Scheduled UL Acknowledgement polling on %s (FN=%d, TS=%d)\n",
			  chan, poll_fn, poll_ts);
		break;
	case GPRS_RLCMAC_POLL_DL_ACK:
		LOGPTBFDL(this, LOGL_DEBUG, "Scheduled DL Acknowledgement polling on %s (FN=%d, TS=%d)\n",
			  chan, poll_fn, poll_ts);
		break;
	}
}

void gprs_rlcmac_tbf::poll_timeout()
{
	uint16_t pgroup;
	gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(this);

	LOGPTBF(this, LOGL_NOTICE, "poll timeout for FN=%d, TS=%d (curr FN %d)\n",
		poll_fn, poll_ts, bts->current_frame_number());

	poll_state = GPRS_RLCMAC_POLL_NONE;

	if (n_inc(N3101)) {
		TBF_SET_STATE(this, GPRS_RLCMAC_RELEASING);
		T_START(this, T3169, 3169, "MAX N3101 reached", false);
		return;
	}

	if (ul_tbf && ul_tbf->handle_ctrl_ack()) {
		if (!ul_tbf->ctrl_ack_to_toggle()) {
			LOGPTBF(this, LOGL_NOTICE,
				"Timeout for polling PACKET CONTROL ACK for PACKET UPLINK ACK: %s\n",
				rlcmac_diag().c_str());
		}
		bts->do_rate_ctr_inc(CTR_RLC_ACK_TIMEDOUT);
		bts->do_rate_ctr_inc(CTR_PUAN_POLL_TIMEDOUT);
		if (state_is(GPRS_RLCMAC_FINISHED)) {
			if (ul_tbf->n_inc(N3103)) {
				bts->do_rate_ctr_inc(CTR_PUAN_POLL_FAILED);
				TBF_SET_STATE(ul_tbf, GPRS_RLCMAC_RELEASING);
				T_START(ul_tbf, T3169, 3169, "MAX N3103 reached", false);
				return;
			}
			/* reschedule UL ack */
			ul_tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_SEND_ACK;
		}

	} else if (ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
		if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_TO_UL_ASS))) {
			LOGPTBF(this, LOGL_NOTICE,
				"Timeout for polling PACKET CONTROL ACK for PACKET UPLINK ASSIGNMENT: %s\n",
				rlcmac_diag().c_str());
			state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_UL_ASS);
		}
		ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
		bts->do_rate_ctr_inc(CTR_RLC_ASS_TIMEDOUT);
		bts->do_rate_ctr_inc(CTR_PUA_POLL_TIMEDOUT);
		if (n_inc(N3105)) {
			TBF_SET_STATE(this, GPRS_RLCMAC_RELEASING);
			T_START(this, T3195, 3195, "MAX N3105 reached", true);
			bts->do_rate_ctr_inc(CTR_RLC_ASS_FAILED);
			bts->do_rate_ctr_inc(CTR_PUA_POLL_FAILED);
			return;
		}
		/* reschedule UL assignment */
		ul_ass_state = GPRS_RLCMAC_UL_ASS_SEND_ASS;
	} else if (dl_ass_state == GPRS_RLCMAC_DL_ASS_WAIT_ACK) {
		if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ASS))) {
			LOGPTBF(this, LOGL_NOTICE,
				"Timeout for polling PACKET CONTROL ACK for PACKET DOWNLINK ASSIGNMENT: %s\n",
				rlcmac_diag().c_str());
			state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_DL_ASS);
		}
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		bts->do_rate_ctr_inc(CTR_RLC_ASS_TIMEDOUT);
		bts->do_rate_ctr_inc(CTR_PDA_POLL_TIMEDOUT);
		if (n_inc(N3105)) {
			TBF_SET_STATE(this, GPRS_RLCMAC_RELEASING);
			T_START(this, T3195, 3195, "MAX N3105 reached", true);
			bts->do_rate_ctr_inc(CTR_RLC_ASS_FAILED);
			bts->do_rate_ctr_inc(CTR_PDA_POLL_FAILED);
			return;
		}
		/* reschedule DL assignment */
		dl_ass_state = GPRS_RLCMAC_DL_ASS_SEND_ASS;
	} else if (direction == GPRS_RLCMAC_DL_TBF) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);

		if (!(dl_tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK))) {
			LOGPTBF(this, LOGL_NOTICE,
				"Timeout for polling PACKET DOWNLINK ACK: %s\n",
				dl_tbf->rlcmac_diag().c_str());
			dl_tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);
		}

		if (dl_tbf->state_is(GPRS_RLCMAC_RELEASING))
			bts->do_rate_ctr_inc(CTR_RLC_REL_TIMEDOUT);
		else {
			bts->do_rate_ctr_inc(CTR_RLC_ACK_TIMEDOUT);
			bts->do_rate_ctr_inc(CTR_PDAN_POLL_TIMEDOUT);
		}

		if (dl_tbf->n_inc(N3105)) {
			TBF_SET_STATE(dl_tbf, GPRS_RLCMAC_RELEASING);
			T_START(dl_tbf, T3195, 3195, "MAX N3105 reached", true);
			bts->do_rate_ctr_inc(CTR_PDAN_POLL_FAILED);
			bts->do_rate_ctr_inc(CTR_RLC_ACK_FAILED);
			return;
		}
		/* resend IMM.ASS on CCCH on timeout */
		if ((dl_tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
		 && !(dl_tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK))) {
			LOGPTBF(dl_tbf, LOGL_DEBUG, "Re-send dowlink assignment on PCH (IMSI=%s)\n",
				imsi());
			/* send immediate assignment */
			if ((pgroup = imsi2paging_group(imsi())) > 999)
				LOGPTBF(dl_tbf, LOGL_ERROR, "IMSI to paging group failed! (%s)\n", imsi());
			dl_tbf->bts->snd_dl_ass(dl_tbf, false, pgroup);
			dl_tbf->m_wait_confirm = 1;
		}
	} else
		LOGPTBF(this, LOGL_ERROR, "Poll Timeout, but no event!\n");
}

int gprs_rlcmac_tbf::setup(int8_t use_trx, bool single_slot)
{
	struct gprs_rlcmac_bts *bts_data = bts->bts_data();
	int rc;

	if (m_ms->mode() != GPRS)
		enable_egprs();

	m_created_ts = time(NULL);
	/* select algorithm */
	rc = bts_data->alloc_algorithm(bts_data, m_ms, this, single_slot, use_trx);
	/* if no resource */
	if (rc < 0) {
		return -1;
	}
	/* assign control ts */
	rc = tbf_assign_control_ts(this);
	/* if no resource */
	if (rc < 0) {
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

	m_ms->attach_tbf(this);

	return 0;
}

static void tbf_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;
	tbf->handle_timeout();
}

void gprs_rlcmac_tbf::handle_timeout()
{
	int current_fn = get_current_fn();

	LOGPTBF(this, LOGL_DEBUG, "timer 0 expired. cur_fn=%d\n", current_fn);

	/* assignment */
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))) {
		if (state_is(GPRS_RLCMAC_ASSIGN)) {
			LOGPTBF(this, LOGL_NOTICE, "releasing due to PACCH assignment timeout.\n");
			tbf_free(this);
			return;
		} else
			LOGPTBF(this, LOGL_ERROR, "Error: TBF is not in assign state\n");
	}

	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);
		dl_tbf->m_wait_confirm = 0;
		if (dl_tbf->state_is(GPRS_RLCMAC_ASSIGN)) {
			tbf_assign_control_ts(dl_tbf);

			if (!dl_tbf->upgrade_to_multislot) {
				/* change state to FLOW, so scheduler
				 * will start transmission */
				TBF_SET_STATE(dl_tbf, GPRS_RLCMAC_FLOW);
				return;
			}

			/* This tbf can be upgraded to use multiple DL
			 * timeslots and now that there is already one
			 * slot assigned send another DL assignment via
			 * PDCH. */

			/* keep to flags */
			dl_tbf->state_flags &= GPRS_RLCMAC_FLAG_TO_MASK;

			dl_tbf->update();

			dl_tbf->trigger_ass(dl_tbf);
		} else
			LOGPTBF(dl_tbf, LOGL_NOTICE, "Continue flow after IMM.ASS confirm\n");
	}
}

std::string gprs_rlcmac_tbf::rlcmac_diag()
{
	std::ostringstream os;
	os << "|";
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)))
		os << "Assignment was on CCCH|";
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)))
		os << "Assignment was on PACCH|";
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_UL_DATA)))
		os << "Uplink data was received|";
	else if (direction == GPRS_RLCMAC_UL_TBF)
		os << "No uplink data received yet|";
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK)))
		os << "Downlink ACK was received|";
	else if (direction == GPRS_RLCMAC_DL_TBF)
		os << "No downlink ACK received yet|";

	return os.str();
}

struct msgb *gprs_rlcmac_tbf::create_dl_ass(uint32_t fn, uint8_t ts)
{
	struct msgb *msg;
	struct gprs_rlcmac_dl_tbf *new_dl_tbf = NULL;
	RlcMacDownlink_t *mac_control_block = NULL;
	int poll_ass_dl = 1;
	unsigned int rrbp = 0;
	uint32_t new_poll_fn = 0;
	int rc;
	bool old_tfi_is_valid = is_tfi_assigned();

	if (direction == GPRS_RLCMAC_DL_TBF && !is_control_ts(ts)) {
		LOGPTBF(this, LOGL_NOTICE,
			"Cannot poll for downlink assignment, because MS cannot reply. (TS=%d, first common TS=%d)\n",
			ts, first_common_ts);
		poll_ass_dl = 0;
	}
	if (poll_ass_dl) {
		if (poll_state == GPRS_RLCMAC_POLL_SCHED &&
			ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK)
		{
			LOGPTBF(this, LOGL_DEBUG,
				  "Polling is already scheduled, so we must wait for the uplink assignment...\n");
			return NULL;
		}
		rc = check_polling(fn, ts, &new_poll_fn, &rrbp);
		if (rc < 0)
			return NULL;
	}

	/* on uplink TBF we get the downlink TBF to be assigned. */
	if (direction == GPRS_RLCMAC_UL_TBF) {
		gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(this);

		/* be sure to check first, if contention resolution is done,
		 * otherwise we cannot send the assignment yet */
		if (!ul_tbf->m_contention_resolution_done) {
			LOGPTBF(this, LOGL_DEBUG,
				"Cannot assign DL TBF now, because contention resolution is not finished.\n");
			return NULL;
		}
	}

	if (ms())
		new_dl_tbf = ms()->dl_tbf();

	if (!new_dl_tbf) {
		LOGPTBFDL(this, LOGL_ERROR,
			  "We have a schedule for downlink assignment, but there is no downlink TBF\n");
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		return NULL;
	}

	if (new_dl_tbf == as_dl_tbf(this))
		LOGPTBF(this, LOGL_DEBUG, "New and old TBF are the same.\n");

	if (old_tfi_is_valid && !new_dl_tbf->is_tlli_valid()) {
		LOGPTBF(this, LOGL_ERROR,
			  "The old TFI is not assigned and there is no TLLI. New TBF %s\n",
			  new_dl_tbf->name());
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		return NULL;
	}

	new_dl_tbf->was_releasing = was_releasing;
	msg = msgb_alloc(GSM_MACBLOCK_LEN, "rlcmac_dl_ass");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer.
	 * Old G++ does not support non-trivial designated initializers. Sigh. */
	struct bitvec bv = { };
	bv.data = msgb_put(msg, GSM_MACBLOCK_LEN);
	bv.data_len = GSM_MACBLOCK_LEN;
	bitvec_unhex(&bv, DUMMY_VEC);

	LOGPTBF(new_dl_tbf, LOGL_INFO, "start Packet Downlink Assignment (PACCH)\n");
	mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	Encoding::write_packet_downlink_assignment(mac_control_block,
		old_tfi_is_valid, m_tfi, (direction == GPRS_RLCMAC_DL_TBF),
		new_dl_tbf, poll_ass_dl, rrbp,
		bts_data()->alpha, bts_data()->gamma, -1, 0,
		is_egprs_enabled());
	LOGP(DTBF, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Downlink Assignment +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Decoding of Packet Downlink Ass failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DTBF, LOGL_DEBUG, "------------------------- TX : Packet Downlink Assignment -------------------------\n");
	bts->do_rate_ctr_inc(CTR_PKT_DL_ASSIGNMENT);

	if (poll_ass_dl) {
		set_polling(new_poll_fn, ts, GPRS_RLCMAC_POLL_DL_ASS);
	} else {
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		TBF_SET_STATE(new_dl_tbf, GPRS_RLCMAC_FLOW);
		tbf_assign_control_ts(new_dl_tbf);
		/* stop pending assignment timer */
		new_dl_tbf->t_stop(T0, "assignment (DL-TBF)");

	}

	talloc_free(mac_control_block);
	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

struct msgb *gprs_rlcmac_tbf::create_packet_access_reject()
{
	struct msgb *msg;

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "rlcmac_ul_ass_rej");

	bitvec *packet_access_rej = bitvec_alloc(GSM_MACBLOCK_LEN, tall_pcu_ctx);

	bitvec_unhex(packet_access_rej, DUMMY_VEC);

	Encoding::write_packet_access_reject(
		packet_access_rej, tlli());

	bts->do_rate_ctr_inc(CTR_PKT_ACCESS_REJ);

	bitvec_pack(packet_access_rej, msgb_put(msg, GSM_MACBLOCK_LEN));

	bitvec_free(packet_access_rej);
	ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;

	/* Start Tmr only if it is UL TBF */
	if (direction == GPRS_RLCMAC_UL_TBF)
		T_START(this, T0, -2000, "reject (PACCH)", true);

	return msg;

}

struct msgb *gprs_rlcmac_tbf::create_ul_ass(uint32_t fn, uint8_t ts)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_ul_tbf *new_tbf = NULL;
	RlcMacDownlink_t *mac_control_block = NULL;
	int rc;
	unsigned int rrbp;
	uint32_t new_poll_fn;

	if (poll_state == GPRS_RLCMAC_POLL_SCHED &&
		ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
		LOGPTBFUL(this, LOGL_DEBUG,
			  "Polling is already scheduled, so we must wait for the uplink assignment...\n");
		return NULL;
	}

	rc = check_polling(fn, ts, &new_poll_fn, &rrbp);
	if (rc < 0)
		return NULL;

	if (ms())
		new_tbf = ms()->ul_tbf();
	if (!new_tbf) {
		LOGPTBFUL(this, LOGL_ERROR,
			  "We have a schedule for uplink assignment, but there is no uplink TBF\n");
		ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
		return NULL;
	}

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "rlcmac_ul_ass");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer.
	 * Old G++ does not support non-trivial designated initializers. Sigh. */
	struct bitvec bv = { };
	bv.data = msgb_put(msg, GSM_MACBLOCK_LEN);
	bv.data_len = GSM_MACBLOCK_LEN;
	bitvec_unhex(&bv, DUMMY_VEC);

	LOGPTBF(new_tbf, LOGL_INFO, "start Packet Uplink Assignment (PACCH)\n");
	mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	Encoding::write_packet_uplink_assignment(mac_control_block, m_tfi,
		(direction == GPRS_RLCMAC_DL_TBF), tlli(),
		is_tlli_valid(), new_tbf, 1, rrbp, bts_data()->alpha,
		bts_data()->gamma, -1, is_egprs_enabled());

	LOGP(DTBF, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Assignment +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Encoding of Packet Uplink Ass failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DTBF, LOGL_DEBUG, "------------------------- TX : Packet Uplink Assignment -------------------------\n");
	bts->do_rate_ctr_inc(CTR_PKT_UL_ASSIGNMENT);

	set_polling(new_poll_fn, ts, GPRS_RLCMAC_POLL_UL_ASS);

	talloc_free(mac_control_block);
	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

void gprs_rlcmac_tbf::free_all(struct gprs_rlcmac_trx *trx)
{
	for (uint8_t ts = 0; ts < 8; ts++)
		free_all(&trx->pdch[ts]);
}

void gprs_rlcmac_tbf::free_all(struct gprs_rlcmac_pdch *pdch)
{
	for (uint8_t tfi = 0; tfi < 32; tfi++) {
		struct gprs_rlcmac_tbf *tbf;

		tbf = pdch->ul_tbf_by_tfi(tfi);
		if (tbf)
			tbf_free(tbf);
		tbf = pdch->dl_tbf_by_tfi(tfi);
		if (tbf)
			tbf_free(tbf);
	}
}

int gprs_rlcmac_tbf::establish_dl_tbf_on_pacch()
{
	struct gprs_rlcmac_dl_tbf *new_tbf = NULL;

	bts->do_rate_ctr_inc(CTR_TBF_REUSED);

	new_tbf = tbf_alloc_dl_tbf(bts->bts_data(), ms(),
		this->trx->trx_no, false);

	if (!new_tbf) {
		LOGP(DTBF, LOGL_NOTICE, "No PDCH resource\n");
		return -1;
	}

	LOGPTBF(this, LOGL_DEBUG, "Trigger downlink assignment on PACCH\n");
	new_tbf->trigger_ass(this);

	return 0;
}

const char *tbf_name(gprs_rlcmac_tbf *tbf)
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

void gprs_rlcmac_tbf::rotate_in_list()
{
	llist_del(&list());
	if (direction == GPRS_RLCMAC_UL_TBF)
		llist_add(&list(), &bts->ul_tbfs());
	else
		llist_add(&list(), &bts->dl_tbfs());
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
