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

#include <bts.h>
#include <tbf.h>
#include <rlc.h>
#include <encoding.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <gprs_ms.h>
#include <decoding.h>
#include <pcu_utils.h>

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>
}

#include <errno.h>
#include <string.h>

extern void *tall_pcu_ctx;

static void tbf_timer_cb(void *_tbf);

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

static const struct rate_ctr_desc tbf_ctr_description[] = {
        { "rlc.nacked",                     "RLC Nacked " },
};

static const struct rate_ctr_desc tbf_dl_gprs_ctr_description[] = {
        { "gprs.downlink.cs1",              "CS1        " },
        { "gprs.downlink.cs2",              "CS2        " },
        { "gprs.downlink.cs3",              "CS3        " },
        { "gprs.downlink.cs4",              "CS4        " },
};

static const struct rate_ctr_desc tbf_dl_egprs_ctr_description[] = {
        { "egprs.downlink.mcs1",            "MCS1        " },
        { "egprs.downlink.mcs2",            "MCS2        " },
        { "egprs.downlink.mcs3",            "MCS3        " },
        { "egprs.downlink.mcs4",            "MCS4        " },
        { "egprs.downlink.mcs5",            "MCS5        " },
        { "egprs.downlink.mcs6",            "MCS6        " },
        { "egprs.downlink.mcs7",            "MCS7        " },
        { "egprs.downlink.mcs8",            "MCS8        " },
        { "egprs.downlink.mcs9",            "MCS9        " },
};

static const struct rate_ctr_desc tbf_ul_gprs_ctr_description[] = {
        { "gprs.uplink.cs1",              "CS1        " },
        { "gprs.uplink.cs2",              "CS2        " },
        { "gprs.uplink.cs3",              "CS3        " },
        { "gprs.uplink.cs4",              "CS4        " },
};

static const struct rate_ctr_desc tbf_ul_egprs_ctr_description[] = {
        { "egprs.uplink.mcs1",            "MCS1        " },
        { "egprs.uplink.mcs2",            "MCS2        " },
        { "egprs.uplink.mcs3",            "MCS3        " },
        { "egprs.uplink.mcs4",            "MCS4        " },
        { "egprs.uplink.mcs5",            "MCS5        " },
        { "egprs.uplink.mcs6",            "MCS6        " },
        { "egprs.uplink.mcs7",            "MCS7        " },
        { "egprs.uplink.mcs8",            "MCS8        " },
        { "egprs.uplink.mcs9",            "MCS9        " },
};

static const struct rate_ctr_group_desc tbf_ctrg_desc = {
        "pcu.tbf",
        "TBF Statistics",
        OSMO_STATS_CLASS_SUBSCRIBER,
        ARRAY_SIZE(tbf_ctr_description),
        tbf_ctr_description,
};

static const struct rate_ctr_group_desc tbf_dl_gprs_ctrg_desc = {
        "tbf.gprs",
        "Data Blocks",
        OSMO_STATS_CLASS_SUBSCRIBER,
        ARRAY_SIZE(tbf_dl_gprs_ctr_description),
        tbf_dl_gprs_ctr_description,
};

static const struct rate_ctr_group_desc tbf_dl_egprs_ctrg_desc = {
        "tbf.egprs",
        "Data Blocks",
        OSMO_STATS_CLASS_SUBSCRIBER,
        ARRAY_SIZE(tbf_dl_egprs_ctr_description),
        tbf_dl_egprs_ctr_description,
};

static const struct rate_ctr_group_desc tbf_ul_gprs_ctrg_desc = {
        "tbf.gprs",
        "Data Blocks",
        OSMO_STATS_CLASS_SUBSCRIBER,
        ARRAY_SIZE(tbf_ul_gprs_ctr_description),
        tbf_ul_gprs_ctr_description,
};

static const struct rate_ctr_group_desc tbf_ul_egprs_ctrg_desc = {
        "tbf.egprs",
        "Data Blocks",
        OSMO_STATS_CLASS_SUBSCRIBER,
        ARRAY_SIZE(tbf_ul_egprs_ctr_description),
        tbf_ul_egprs_ctr_description,
};

gprs_rlcmac_tbf::Meas::Meas() :
	rssi_sum(0),
	rssi_num(0)
{
	timerclear(&rssi_tv);
}

gprs_rlcmac_tbf::gprs_rlcmac_tbf(BTS *bts_, gprs_rlcmac_tbf_direction dir) :
	state_flags(0),
	direction(dir),
	trx(NULL),
	first_ts(0),
	first_common_ts(0),
	control_ts(0xff),
	dl_ass_state(GPRS_RLCMAC_DL_ASS_NONE),
	ul_ass_state(GPRS_RLCMAC_UL_ASS_NONE),
	ul_ack_state(GPRS_RLCMAC_UL_ACK_NONE),
	poll_state(GPRS_RLCMAC_POLL_NONE),
	poll_fn(0),
	poll_ts(0),
	n3105(0),
	T(0),
	num_T_exp(0),
	fT(0),
	num_fT_exp(0),
	state(GPRS_RLCMAC_NULL),
	was_releasing(0),
	upgrade_to_multislot(0),
	bts(bts_),
	m_tfi(0),
	m_created_ts(0),
	m_ctrs(NULL),
	m_ms(NULL),
	m_ta(GSM48_TA_INVALID),
	m_ms_class(0),
	m_list(this),
	m_ms_list(this),
	m_egprs_enabled(false)
{
	/* The classes of these members do not have proper constructors yet.
	 * Just set them to 0 like talloc_zero did */
	memset(&pdch, 0, sizeof(pdch));
	memset(&timer, 0, sizeof(timer));
	memset(&m_rlc, 0, sizeof(m_rlc));
	memset(&gsm_timer, 0, sizeof(gsm_timer));

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
	static const char nullc = 0;
	return m_ms ? m_ms->imsi() : &nullc;
}

void gprs_rlcmac_tbf::assign_imsi(const char *imsi_)
{
	GprsMs *old_ms;

	if (!imsi_ || !m_ms) {
		LOGP(DRLCMAC, LOGL_ERROR,
			"%s failed to assign IMSI: missing IMSI or MS object\n",
			name());
		return;
	}

	if (strcmp(imsi_, imsi()) == 0)
		return;

	/* really change the IMSI */

	old_ms = bts->ms_store().get_ms(0, 0, imsi_);
	if (old_ms) {
		/* We cannot find m_ms by IMSI since we know that it has a
		 * different IMSI */
		OSMO_ASSERT(old_ms != m_ms);

		LOGP(DRLCMAC, LOGL_INFO,
			"%s the IMSI '%s' was already assigned to another "
			"MS object: TLLI = 0x%08x, that IMSI will be removed\n",
			name(), imsi_, old_ms->tlli());

		merge_and_clear_ms(old_ms);
	}

	m_ms->set_imsi(imsi_);
}

uint8_t gprs_rlcmac_tbf::ta() const
{
	return m_ms ? m_ms->ta() : m_ta;
}

void gprs_rlcmac_tbf::set_ta(uint8_t ta)
{
	if (ms())
		ms()->set_ta(ta);

	if (gsm48_ta_is_valid(ta))
		m_ta = ta;
}

uint8_t gprs_rlcmac_tbf::ms_class() const
{
	return m_ms ? m_ms->ms_class() : m_ms_class;
}

void gprs_rlcmac_tbf::set_ms_class(uint8_t ms_class_)
{
	if (ms())
		ms()->set_ms_class(ms_class_);

	m_ms_class = ms_class_;
}

GprsCodingScheme gprs_rlcmac_tbf::current_cs() const
{
	GprsCodingScheme cs;
	if (direction == GPRS_RLCMAC_UL_TBF)
		cs = m_ms ? m_ms->current_cs_ul() : GprsCodingScheme();
	else
		cs = m_ms ? m_ms->current_cs_dl() : GprsCodingScheme();

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

int gprs_rlcmac_tbf::llc_queue_size() const
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
		/* Save the TA locally. This will also be called, if the MS
		 * object detaches itself from the TBF, for instance if
		 * attach_tbf() is called */
		m_ta = m_ms->ta();

		m_ms->detach_tbf(this);
	}

	m_ms = ms;

	if (m_ms)
		m_ms->attach_tbf(this);
}

void gprs_rlcmac_tbf::merge_and_clear_ms(GprsMs *old_ms)
{
	if (old_ms == ms())
		return;

	GprsMs::Guard guard_old(old_ms);

	/* Clean up the old MS object */
	/* TODO: Use timer? */
	if (old_ms->ul_tbf() && old_ms->ul_tbf()->T == 0) {
		if (old_ms->ul_tbf() == this) {
			LOGP(DRLCMAC, LOGL_ERROR,
				"%s is referred by the old MS "
				"and will not be deleted\n",
				name());
			set_ms(NULL);
		} else {
			tbf_free(old_ms->ul_tbf());
		}
	}
	if (old_ms->dl_tbf() && old_ms->dl_tbf()->T == 0) {
		if (old_ms->dl_tbf() == this) {
			LOGP(DRLCMAC, LOGL_ERROR,
				"%s is referred by the old MS "
				"and will not be deleted\n",
				name());
			set_ms(NULL);
		} else {
			tbf_free(old_ms->dl_tbf());
		}
	}

	ms()->merge_old_ms(old_ms);
}

void gprs_rlcmac_tbf::update_ms(uint32_t tlli, enum gprs_rlcmac_tbf_direction dir)
{
	if (!ms())
		return;

	if (!tlli)
		return;

	/* TODO: When the TLLI does not match the ms, check if there is another
	 * MS object that belongs to that TLLI and if yes make sure one of them
	 * gets deleted. This is the same problem that can arise with
	 * assign_imsi() so there should be a unified solution */
	if (!ms()->check_tlli(tlli)) {
		GprsMs *old_ms;

		old_ms = bts->ms_store().get_ms(tlli, 0, NULL);
		if (old_ms)
			merge_and_clear_ms(old_ms);
	}

	if (dir == GPRS_RLCMAC_UL_TBF)
		ms()->set_tlli(tlli);
	else
		ms()->confirm_tlli(tlli);
}

gprs_rlcmac_ul_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts,
	int8_t use_trx, uint8_t ms_class, uint8_t egprs_ms_class,
	uint32_t tlli, uint8_t ta, GprsMs *ms)
{
	struct gprs_rlcmac_ul_tbf *tbf;

/* FIXME: Copy and paste with tbf_new_dl_assignment */
	/* create new TBF, use same TRX as DL TBF */
	/* use multislot class of downlink TBF */
	tbf = tbf_alloc_ul_tbf(bts, ms, use_trx, ms_class, egprs_ms_class, 0);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource\n");
		/* FIXME: send reject */
		return NULL;
	}
	tbf->m_contention_resolution_done = 1;
	tbf->set_state(GPRS_RLCMAC_ASSIGN);
	tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_PACCH);
	tbf_timer_start(tbf, 3169, bts->t3169, 0, "allocation (UL-TBF)");
	tbf->update_ms(tlli, GPRS_RLCMAC_UL_TBF);
	OSMO_ASSERT(tbf->ms());

	tbf->ms()->set_ta(ta);

	return tbf;
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
		tbf->bts->tbf_ul_freed();
		if (tbf->state_is(GPRS_RLCMAC_FLOW))
			tbf->bts->tbf_ul_aborted();
		rate_ctr_group_free(ul_tbf->m_ul_egprs_ctrs);
		rate_ctr_group_free(ul_tbf->m_ul_gprs_ctrs);
	} else {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf);
		if (tbf->is_egprs_enabled()) {
			rate_ctr_group_free(dl_tbf->m_dl_egprs_ctrs);
		} else {
			rate_ctr_group_free(dl_tbf->m_dl_gprs_ctrs);
		}
		tbf->bts->tbf_dl_freed();
		if (tbf->state_is(GPRS_RLCMAC_FLOW))
			tbf->bts->tbf_dl_aborted();
	}

	/* Give final measurement report */
	gprs_rlcmac_rssi_rep(tbf);
	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf);

		dl_tbf->abort();
		dl_tbf->cleanup();
	}

	LOGP(DRLCMAC, LOGL_INFO, "%s free\n", tbf_name(tbf));
	if (tbf->ul_ass_state != GPRS_RLCMAC_UL_ASS_NONE)
		LOGP(DRLCMAC, LOGL_ERROR, "%s Software error: Pending uplink "
		     "assignment in state %s. This may not happen, because the "
			"assignment message never gets transmitted. Please "
			"be sure not to free in this state. PLEASE FIX!\n",
		     tbf_name(tbf),
		     get_value_string(gprs_rlcmac_tbf_ul_ass_state_names,
				      tbf->ul_ass_state));
	if (tbf->dl_ass_state != GPRS_RLCMAC_DL_ASS_NONE)
		LOGP(DRLCMAC, LOGL_ERROR, "%s Software error: Pending downlink "
		     "assignment in state %s. This may not happen, because the "
			"assignment message never gets transmitted. Please "
			"be sure not to free in this state. PLEASE FIX!\n",
		     tbf_name(tbf),
		     get_value_string(gprs_rlcmac_tbf_dl_ass_state_names,
				      tbf->dl_ass_state));
	tbf->stop_timer("freeing TBF");
	/* TODO: Could/Should generate  bssgp_tx_llc_discarded */
	tbf_unlink_pdch(tbf);
	llist_del(&tbf->list());

	if (tbf->ms())
		tbf->set_ms(NULL);

	rate_ctr_group_free(tbf->m_ctrs);

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF ends here **********\n");
	talloc_free(tbf);
}

int gprs_rlcmac_tbf::update()
{
	struct gprs_rlcmac_bts *bts_data = bts->bts_data();
	int rc;

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF update **********\n");

	if (direction != GPRS_RLCMAC_DL_TBF)
		return -EINVAL;

	tbf_unlink_pdch(this);
	rc = bts_data->alloc_algorithm(bts_data, ms(), this,
		bts_data->alloc_algorithm_curst, 0, -1);
	/* if no resource */
	if (rc < 0) {
		LOGP(DRLCMAC, LOGL_ERROR, "No resource after update???\n");
		return -rc;
	}

	if (is_egprs_enabled()) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);
		if (dl_tbf)
			dl_tbf->egprs_calc_window_size();
	}

	return 0;
}

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->control_ts == 0xff)
		LOGP(DRLCMAC, LOGL_INFO, "- Setting Control TS %d\n",
			tbf->first_common_ts);
	else if (tbf->control_ts != tbf->first_common_ts)
		LOGP(DRLCMAC, LOGL_INFO, "- Changing Control TS %d\n",
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

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
		     unsigned int seconds, unsigned int microseconds, const char *reason)
{
	LOGPC(DRLCMAC, (T != tbf->T) ? LOGL_ERROR : LOGL_DEBUG,
	      "%s %sstarting timer T%u [%s] with %u sec. %u microsec.",
	      tbf_name(tbf), osmo_timer_pending(&tbf->timer) ? "re" : "", T, reason, seconds, microseconds);

	if (T != tbf->T && osmo_timer_pending(&tbf->timer))
		LOGPC(DRLCMAC, LOGL_ERROR, " while old timer T%u pending", tbf->T);

	LOGPC(DRLCMAC, (T != tbf->T) ? LOGL_ERROR : LOGL_DEBUG, "\n");

	tbf->T = T;
	tbf->num_T_exp = 0;

	/* Tunning timers can be safely re-scheduled. */
	tbf->timer.data = tbf;
	tbf->timer.cb = &tbf_timer_cb;

	osmo_timer_schedule(&tbf->timer, seconds, microseconds);
}

void gprs_rlcmac_tbf::stop_t3191()
{
	return stop_timer("T3191");
}

void gprs_rlcmac_tbf::stop_timer(const char *reason)
{
	if (osmo_timer_pending(&timer)) {
		LOGP(DRLCMAC, LOGL_DEBUG, "%s stopping timer T%u [%s]\n",
		     tbf_name(this), T, reason);
		osmo_timer_del(&timer);
	}
}

int gprs_rlcmac_tbf::check_polling(uint32_t fn, uint8_t ts,
	uint32_t *poll_fn_, unsigned int *rrbp_)
{
	uint32_t new_poll_fn = next_fn(fn, 13);

	if (!is_control_ts(ts)) {
		LOGP(DRLCMAC, LOGL_DEBUG, "Polling cannot be "
			"scheduled in this TS %d (first control TS %d)\n",
			ts, control_ts);
		return -EINVAL;
	}
	if (poll_state != GPRS_RLCMAC_POLL_NONE) {
		LOGP(DRLCMAC, LOGL_DEBUG,
			"Polling is already scheduled for %s\n",
			name());
		return -EBUSY;
	}
	if (bts->sba()->find(trx->trx_no, ts, next_fn(fn, 13))) {
		LOGP(DRLCMAC, LOGL_DEBUG, "%s: Polling is already scheduled "
			"for single block allocation at FN %d TS %d ...\n",
			name(), new_poll_fn, ts);
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
		LOGP(DRLCMACDL, LOGL_ERROR,
		     "%s Attempt to schedule polling on %s (FN=%d, TS=%d) with both CCCH and PACCH flags set - FIXME!\n",
		     name(), chan, poll_fn, poll_ts);

	/* schedule polling */
	poll_state = GPRS_RLCMAC_POLL_SCHED;
	poll_fn = new_poll_fn;
	poll_ts = ts;

	switch (t) {
	case GPRS_RLCMAC_POLL_UL_ASS:
		ul_ass_state = GPRS_RLCMAC_UL_ASS_WAIT_ACK;

		LOGP(DRLCMACDL, LOGL_INFO, "%s Scheduled UL Assignment polling on %s (FN=%d, TS=%d)\n",
		     name(), chan, poll_fn, poll_ts);
		break;
	case GPRS_RLCMAC_POLL_DL_ASS:
		dl_ass_state = GPRS_RLCMAC_DL_ASS_WAIT_ACK;

		LOGP(DRLCMACDL, LOGL_INFO, "%s Scheduled DL Assignment polling on %s (FN=%d, TS=%d)\n",
		     name(), chan, poll_fn, poll_ts);
		break;
	case GPRS_RLCMAC_POLL_UL_ACK:
		ul_ack_state = GPRS_RLCMAC_UL_ACK_WAIT_ACK;

		LOGP(DRLCMACUL, LOGL_DEBUG, "%s Scheduled UL Acknowledgement polling on %s (FN=%d, TS=%d)\n",
		     name(), chan, poll_fn, poll_ts);
		break;
	case GPRS_RLCMAC_POLL_DL_ACK:
		LOGP(DRLCMACDL, LOGL_DEBUG, "%s Scheduled DL Acknowledgement polling on %s (FN=%d, TS=%d)\n",
		     name(), chan, poll_fn, poll_ts);
		break;
	}
}

void gprs_rlcmac_tbf::poll_timeout()
{
	gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(this);

	LOGP(DRLCMAC, LOGL_NOTICE, "%s poll timeout for FN=%d, TS=%d (curr FN %d)\n",
		tbf_name(this), poll_fn, poll_ts, bts->current_frame_number());

	poll_state = GPRS_RLCMAC_POLL_NONE;

	if (ul_tbf && ul_tbf->handle_ctrl_ack()) {
		if (!ul_tbf->ctrl_ack_to_toggle()) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Timeout for polling PACKET CONTROL ACK for PACKET UPLINK ACK\n");
			rlcmac_diag();
		}
		bts->rlc_ack_timedout();
		bts->pkt_ul_ack_nack_poll_timedout();
		if (state_is(GPRS_RLCMAC_FINISHED)) {
			ul_tbf->m_n3103++;
			if (ul_tbf->m_n3103 == ul_tbf->bts->bts_data()->n3103) {
				LOGP(DRLCMAC, LOGL_NOTICE,
				     "- N3103 exceeded\n");
				bts->pkt_ul_ack_nack_poll_failed();
				ul_tbf->set_state(GPRS_RLCMAC_RELEASING);
				tbf_timer_start(ul_tbf, 3169, ul_tbf->bts->bts_data()->t3169, 0, "MAX N3103 reached");
				return;
			}
			/* reschedule UL ack */
			ul_tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_SEND_ACK;
		}

	} else if (ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
		if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_TO_UL_ASS))) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Timeout for polling "
			     "PACKET CONTROL ACK for PACKET UPLINK "
			     "ASSIGNMENT.\n");
				rlcmac_diag();
				state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_UL_ASS);
		}
		ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
		n3105++;
		bts->rlc_ass_timedout();
		bts->pua_poll_timedout();
		if (n3105 == bts_data()->n3105) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- N3105 exceeded\n");
			set_state(GPRS_RLCMAC_RELEASING);
			tbf_timer_start(this, 3195, bts_data()->t3195, 0, "MAX N3105 reached");
			bts->rlc_ass_failed();
			bts->pua_poll_failed();
			return;
		}
		/* reschedule UL assignment */
		ul_ass_state = GPRS_RLCMAC_UL_ASS_SEND_ASS;
	} else if (dl_ass_state == GPRS_RLCMAC_DL_ASS_WAIT_ACK) {
		if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ASS))) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Timeout for polling "
				"PACKET CONTROL ACK for PACKET DOWNLINK "
				"ASSIGNMENT.\n");
			rlcmac_diag();
			state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_DL_ASS);
		}
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		n3105++;
		bts->rlc_ass_timedout();
		bts->pda_poll_timedout();
		if (n3105 == bts->bts_data()->n3105) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- N3105 exceeded\n");
			set_state(GPRS_RLCMAC_RELEASING);
			tbf_timer_start(this, 3195, bts_data()->t3195, 0, "MAX N3105 reached");
			bts->rlc_ass_failed();
			bts->pda_poll_failed();
			return;
		}
		/* reschedule DL assignment */
		dl_ass_state = GPRS_RLCMAC_DL_ASS_SEND_ASS;
	} else if (direction == GPRS_RLCMAC_DL_TBF) {
		gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);

		if (!(dl_tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK))) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Timeout for polling "
				"PACKET DOWNLINK ACK.\n");
			dl_tbf->rlcmac_diag();
			dl_tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);
		}
		dl_tbf->n3105++;
		if (dl_tbf->state_is(GPRS_RLCMAC_RELEASING))
			bts->rlc_rel_timedout();
		else {
			bts->rlc_ack_timedout();
			bts->pkt_dl_ack_nack_poll_timedout();
		}
		if (dl_tbf->n3105 == dl_tbf->bts->bts_data()->n3105) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- N3105 exceeded\n");
			dl_tbf->set_state(GPRS_RLCMAC_RELEASING);
			tbf_timer_start(dl_tbf, 3195, dl_tbf->bts_data()->t3195, 0, "MAX N3105 reached");
			bts->pkt_dl_ack_nack_poll_failed();
			bts->rlc_ack_failed();
			return;
		}
		/* resend IMM.ASS on CCCH on timeout */
		if ((dl_tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
		 && !(dl_tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK))) {
			LOGP(DRLCMAC, LOGL_DEBUG, "Re-send dowlink assignment "
				"for %s on PCH (IMSI=%s)\n",
				tbf_name(dl_tbf),
				imsi());
			/* send immediate assignment */
			dl_tbf->bts->snd_dl_ass(dl_tbf, 0, imsi());
			dl_tbf->m_wait_confirm = 1;
		}
	} else
		LOGP(DRLCMAC, LOGL_ERROR, "- Poll Timeout, but no event!\n");
}

static int setup_tbf(struct gprs_rlcmac_tbf *tbf,
	GprsMs *ms, int8_t use_trx,
	uint8_t ms_class, uint8_t egprs_ms_class, uint8_t single_slot)
{
	int rc;
	struct gprs_rlcmac_bts *bts;
	if (!tbf)
		return -1;

	bts = tbf->bts->bts_data();

	if (ms->mode() == GprsCodingScheme::EGPRS)
		ms_class = egprs_ms_class;

	tbf->m_created_ts = time(NULL);
	tbf->set_ms_class(ms_class);
	/* select algorithm */
	rc = bts->alloc_algorithm(bts, ms, tbf, bts->alloc_algorithm_curst,
		single_slot, use_trx);
	/* if no resource */
	if (rc < 0) {
		return -1;
	}
	/* assign control ts */
	rc = tbf_assign_control_ts(tbf);
	/* if no resource */
	if (rc < 0) {
		return -1;
	}

	/* set timestamp */
	gettimeofday(&tbf->meas.rssi_tv, NULL);

	tbf->set_ms(ms);

	LOGP(DRLCMAC, LOGL_INFO,
		"Allocated %s: trx = %d, ul_slots = %02x, dl_slots = %02x\n",
		tbf->name(), tbf->trx->trx_no, tbf->ul_slots(), tbf->dl_slots());

	tbf->m_ctrs = rate_ctr_group_alloc(tbf, &tbf_ctrg_desc, 0);
	if (!tbf->m_ctrs) {
		LOGP(DRLCMAC, LOGL_ERROR, "Couldn't allocate TBF counters\n");
		return -1;
	}

	return 0;
}

gprs_rlcmac_ul_tbf::gprs_rlcmac_ul_tbf(BTS *bts_) :
	gprs_rlcmac_tbf(bts_, GPRS_RLCMAC_UL_TBF),
	m_rx_counter(0),
	m_n3103(0),
	m_contention_resolution_done(0),
	m_final_ack_sent(0),
	m_ul_gprs_ctrs(NULL),
	m_ul_egprs_ctrs(NULL)
{
	memset(&m_usf, 0, sizeof(m_usf));
}

static int ul_tbf_dtor(struct gprs_rlcmac_ul_tbf *tbf)
{
	tbf->~gprs_rlcmac_ul_tbf();
	return 0;
}

static void setup_egprs_mode(gprs_rlcmac_bts *bts, GprsMs *ms)
{
	if (GprsCodingScheme::getEgprsByNum(bts->max_mcs_ul).isEgprsGmsk() &&
		GprsCodingScheme::getEgprsByNum(bts->max_mcs_dl).isEgprsGmsk() &&
		ms->mode() != GprsCodingScheme::EGPRS)
	{
		ms->set_mode(GprsCodingScheme::EGPRS_GMSK);
	} else {
		ms->set_mode(GprsCodingScheme::EGPRS);
	}
}

struct gprs_rlcmac_ul_tbf *tbf_alloc_ul_tbf(struct gprs_rlcmac_bts *bts,
	GprsMs *ms, int8_t use_trx,
	uint8_t ms_class, uint8_t egprs_ms_class, uint8_t single_slot)
{
	struct gprs_rlcmac_ul_tbf *tbf;
	int rc;

	if (egprs_ms_class == 0 && bts->egprs_enabled) {
		LOGP(DRLCMAC, LOGL_NOTICE,
			"Not accepting non-EGPRS phone in EGPRS-only mode\n");
		bts->bts->tbf_failed_egprs_only();
		return NULL;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF starts here **********\n");
	LOGP(DRLCMAC, LOGL_INFO, "Allocating %s TBF: MS_CLASS=%d/%d\n",
		"UL", ms_class, egprs_ms_class);

	tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_ul_tbf);

	if (!tbf)
		return NULL;

	talloc_set_destructor(tbf, ul_tbf_dtor);
	new (tbf) gprs_rlcmac_ul_tbf(bts->bts);

	if (!ms)
		ms = bts->bts->ms_alloc(ms_class, egprs_ms_class);

	if (egprs_ms_class > 0 && bts->egprs_enabled) {
		tbf->enable_egprs();
		setup_egprs_mode(bts, ms);
		LOGP(DRLCMAC, LOGL_INFO, "Enabled EGPRS for %s, mode %s\n",
			tbf->name(), GprsCodingScheme::modeName(ms->mode()));
	}

	rc = setup_tbf(tbf, ms, use_trx, ms_class, egprs_ms_class, single_slot);

	if (tbf->is_egprs_enabled())
		tbf->egprs_calc_ulwindow_size();

	/* if no resource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}

	tbf->m_ul_egprs_ctrs = rate_ctr_group_alloc(tbf, &tbf_ul_egprs_ctrg_desc, 0);
	tbf->m_ul_gprs_ctrs = rate_ctr_group_alloc(tbf, &tbf_ul_gprs_ctrg_desc, 0);
	if (!tbf->m_ul_egprs_ctrs || !tbf->m_ul_gprs_ctrs) {
		LOGP(DRLCMAC, LOGL_ERROR, "Couldn't allocate TBF UL counters\n");
		talloc_free(tbf);
		return NULL;
	}

	llist_add(&tbf->list(), &bts->bts->ul_tbfs());
	tbf->bts->tbf_ul_created();

	return tbf;
}

gprs_rlcmac_dl_tbf::BandWidth::BandWidth() :
	dl_bw_octets(0),
	dl_throughput(0),
	dl_loss_lost(0),
	dl_loss_received(0)
{
	timerclear(&dl_bw_tv);
	timerclear(&dl_loss_tv);
}

gprs_rlcmac_dl_tbf::gprs_rlcmac_dl_tbf(BTS *bts_) :
	gprs_rlcmac_tbf(bts_, GPRS_RLCMAC_DL_TBF),
	m_tx_counter(0),
	m_wait_confirm(0),
	m_dl_ack_requested(false),
	m_last_dl_poll_fn(0),
	m_last_dl_drained_fn(0),
	m_dl_gprs_ctrs(NULL),
	m_dl_egprs_ctrs(NULL)
{
	memset(&m_llc_timer, 0, sizeof(m_llc_timer));
}

static int dl_tbf_dtor(struct gprs_rlcmac_dl_tbf *tbf)
{
	tbf->~gprs_rlcmac_dl_tbf();
	return 0;
}

struct gprs_rlcmac_dl_tbf *tbf_alloc_dl_tbf(struct gprs_rlcmac_bts *bts,
	GprsMs *ms, int8_t use_trx,
	uint8_t ms_class, uint8_t egprs_ms_class, uint8_t single_slot)
{
	struct gprs_rlcmac_dl_tbf *tbf;
	int rc;

	if (egprs_ms_class == 0 && bts->egprs_enabled) {
		if (ms_class > 0) {
			LOGP(DRLCMAC, LOGL_NOTICE,
				"Not accepting non-EGPRS phone in EGPRS-only mode\n");
			bts->bts->tbf_failed_egprs_only();
			return NULL;
		}
		egprs_ms_class = 1;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF starts here **********\n");
	LOGP(DRLCMAC, LOGL_INFO, "Allocating %s TBF: MS_CLASS=%d/%d\n",
		"DL", ms_class, egprs_ms_class);

	tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_dl_tbf);

	if (!tbf)
		return NULL;

	talloc_set_destructor(tbf, dl_tbf_dtor);
	new (tbf) gprs_rlcmac_dl_tbf(bts->bts);

	if (!ms)
		ms = bts->bts->ms_alloc(ms_class, egprs_ms_class);

	if (egprs_ms_class > 0 && bts->egprs_enabled) {
		tbf->enable_egprs();
		setup_egprs_mode(bts, ms);
		LOGP(DRLCMAC, LOGL_INFO, "Enabled EGPRS for %s, mode %s\n",
			tbf->name(), GprsCodingScheme::modeName(ms->mode()));
	}

	rc = setup_tbf(tbf, ms, use_trx, ms_class, 0, single_slot);
	/* if no resource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}

	if (tbf->is_egprs_enabled()) {
		tbf->egprs_calc_window_size();
		tbf->m_dl_egprs_ctrs = rate_ctr_group_alloc(tbf, &tbf_dl_egprs_ctrg_desc, 0);
		if (!tbf->m_dl_egprs_ctrs) {
			LOGP(DRLCMAC, LOGL_ERROR, "Couldn't allocate EGPRS DL counters\n");
			talloc_free(tbf);
			return NULL;
		}
	} else {
		tbf->m_dl_gprs_ctrs = rate_ctr_group_alloc(tbf, &tbf_dl_gprs_ctrg_desc, 0);
		if (!tbf->m_dl_gprs_ctrs) {
			LOGP(DRLCMAC, LOGL_ERROR, "Couldn't allocate GPRS DL counters\n");
			talloc_free(tbf);
			return NULL;
		}
	}

	llist_add(&tbf->list(), &bts->bts->dl_tbfs());
	tbf->bts->tbf_dl_created();

	tbf->m_last_dl_poll_fn = -1;
	tbf->m_last_dl_drained_fn = -1;

	gettimeofday(&tbf->m_bw.dl_bw_tv, NULL);
	gettimeofday(&tbf->m_bw.dl_loss_tv, NULL);

	return tbf;
}

static void tbf_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;
	tbf->handle_timeout();
}

void gprs_rlcmac_tbf::handle_timeout()
{
	LOGP(DRLCMAC, LOGL_DEBUG, "%s timer %u expired.\n",
		tbf_name(this), T);

	num_T_exp++;

	switch (T) {
	case 0: /* assignment */
		if ((state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))) {
			if (state_is(GPRS_RLCMAC_ASSIGN)) {
				LOGP(DRLCMAC, LOGL_NOTICE, "%s releasing due to "
					"PACCH assignment timeout.\n", tbf_name(this));
				tbf_free(this);
				return;
			} else
				LOGP(DRLCMAC, LOGL_ERROR, "Error: %s is not "
					"in assign state\n", tbf_name(this));
		}
		if ((state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))) {
			gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(this);
			dl_tbf->m_wait_confirm = 0;
			if (dl_tbf->state_is(GPRS_RLCMAC_ASSIGN)) {
				tbf_assign_control_ts(dl_tbf);

				if (!dl_tbf->upgrade_to_multislot) {
					/* change state to FLOW, so scheduler
					 * will start transmission */
					dl_tbf->set_state(GPRS_RLCMAC_FLOW);
					break;
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
				LOGP(DRLCMAC, LOGL_NOTICE, "%s Continue flow after "
					"IMM.ASS confirm\n", tbf_name(dl_tbf));
		}
		break;
	case 3169:
	case 3191:
	case 3195:
		LOGP(DRLCMAC, LOGL_NOTICE, "%s T%d timeout during "
			"transsmission\n", tbf_name(this), T);
		rlcmac_diag();
		/* fall through */
	case 3193:
		LOGP(DRLCMAC, LOGL_DEBUG,
			"%s will be freed due to timeout\n", tbf_name(this));
		/* free TBF */
		tbf_free(this);
		return;
		break;
	default:
		LOGP(DRLCMAC, LOGL_ERROR,
			"%s timer expired in unknown mode: %u\n", tbf_name(this), T);
	}
}

int gprs_rlcmac_tbf::rlcmac_diag()
{
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Assignment was on CCCH\n");
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Assignment was on PACCH\n");
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_UL_DATA)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Uplink data was received\n");
	else if (direction == GPRS_RLCMAC_UL_TBF)
		LOGP(DRLCMAC, LOGL_NOTICE, "- No uplink data received yet\n");
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Downlink ACK was received\n");
	else if (direction == GPRS_RLCMAC_DL_TBF)
		LOGP(DRLCMAC, LOGL_NOTICE, "- No downlink ACK received yet\n");

	return 0;
}

struct msgb *gprs_rlcmac_tbf::create_dl_ass(uint32_t fn, uint8_t ts)
{
	struct msgb *msg;
	struct gprs_rlcmac_dl_tbf *new_dl_tbf = NULL;
	int poll_ass_dl = 1;
	unsigned int rrbp = 0;
	uint32_t new_poll_fn = 0;
	int rc;
	bool old_tfi_is_valid = is_tfi_assigned();

	if (direction == GPRS_RLCMAC_DL_TBF && !is_control_ts(ts)) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Cannot poll for downlink "
			"assigment, because MS cannot reply. (TS=%d, "
			"first common TS=%d)\n", ts,
			first_common_ts);
		poll_ass_dl = 0;
	}
	if (poll_ass_dl) {
		if (poll_state == GPRS_RLCMAC_POLL_SCHED &&
			ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK)
		{
			LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
				"scheduled for %s, so we must wait for the uplink "
				"assignment...\n", tbf_name(this));
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
			LOGP(DRLCMAC, LOGL_DEBUG, "Cannot assign DL TBF now, "
				"because contention resolution is not "
				"finished.\n");
			return NULL;
		}
	}

	if (ms())
		new_dl_tbf = ms()->dl_tbf();

	if (!new_dl_tbf) {
		LOGP(DRLCMACDL, LOGL_ERROR, "We have a schedule for downlink "
			"assignment at %s, but there is no downlink "
			"TBF\n", tbf_name(this));
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		return NULL;
	}

	if (new_dl_tbf == as_dl_tbf(this))
		LOGP(DRLCMAC, LOGL_DEBUG,
			"New and old TBF are the same %s\n", name());

	if (old_tfi_is_valid && !new_dl_tbf->is_tlli_valid()) {
		LOGP(DRLCMACDL, LOGL_ERROR,
			"The old TFI is not assigned and there is no "
			"TLLI. Old TBF %s, new TBF %s\n",
			name(), new_dl_tbf->name());
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		return NULL;
	}

	new_dl_tbf->was_releasing = was_releasing;
	msg = msgb_alloc(23, "rlcmac_dl_ass");
	if (!msg)
		return NULL;
	bitvec *ass_vec = bitvec_alloc(23, tall_pcu_ctx);
	if (!ass_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ass_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	LOGP(DRLCMAC, LOGL_INFO, "%s  start Packet Downlink Assignment (PACCH)\n", tbf_name(new_dl_tbf));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	Encoding::write_packet_downlink_assignment(mac_control_block,
		old_tfi_is_valid, m_tfi, (direction == GPRS_RLCMAC_DL_TBF),
		new_dl_tbf, poll_ass_dl, rrbp,
		bts_data()->alpha, bts_data()->gamma, -1, 0,
		is_egprs_enabled());
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Downlink Assignment +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink(ass_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Downlink Assignment -------------------------\n");
	bts->pkt_dl_assignemnt();
	bitvec_pack(ass_vec, msgb_put(msg, 23));
	bitvec_free(ass_vec);
	talloc_free(mac_control_block);

	if (poll_ass_dl) {
		set_polling(new_poll_fn, ts, GPRS_RLCMAC_POLL_DL_ASS);
	} else {
		dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		new_dl_tbf->set_state(GPRS_RLCMAC_FLOW);
		tbf_assign_control_ts(new_dl_tbf);
		/* stop pending assignment timer */
		new_dl_tbf->stop_timer("assignment (DL-TBF)");

	}

	return msg;
}

struct msgb *gprs_rlcmac_tbf::create_packet_access_reject()
{
	struct msgb *msg;

	msg = msgb_alloc(23, "rlcmac_ul_ass_rej");

	bitvec *packet_access_rej = bitvec_alloc(23, tall_pcu_ctx);

	bitvec_unhex(packet_access_rej,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	Encoding::write_packet_access_reject(
		packet_access_rej, tlli());

	bts->pkt_access_reject();

	bitvec_pack(packet_access_rej, msgb_put(msg, 23));

	bitvec_free(packet_access_rej);
	ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;

	/* Start Tmr only if it is UL TBF */
	if (direction == GPRS_RLCMAC_UL_TBF)
		tbf_timer_start(this, 0, Treject_pacch, "reject (PACCH)");

	return msg;

}

struct msgb *gprs_rlcmac_tbf::create_ul_ass(uint32_t fn, uint8_t ts)
{
	struct msgb *msg;
	struct gprs_rlcmac_ul_tbf *new_tbf = NULL;
	int rc;
	unsigned int rrbp;
	uint32_t new_poll_fn;

	if (poll_state == GPRS_RLCMAC_POLL_SCHED &&
		ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
			"scheduled for %s, so we must wait for the uplink "
			"assignment...\n", tbf_name(this));
			return NULL;
	}

	rc = check_polling(fn, ts, &new_poll_fn, &rrbp);
	if (rc < 0)
		return NULL;

	if (ms())
		new_tbf = ms()->ul_tbf();
	if (!new_tbf) {
		LOGP(DRLCMACUL, LOGL_ERROR, "We have a schedule for uplink "
			"assignment at downlink %s, but there is no uplink "
			"TBF\n", tbf_name(this));
		ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
		return NULL;
	}

	msg = msgb_alloc(23, "rlcmac_ul_ass");
	if (!msg)
		return NULL;
	LOGP(DRLCMAC, LOGL_INFO, "%ss start Packet Uplink Assignment (PACCH)\n", tbf_name(new_tbf));
	bitvec *ass_vec = bitvec_alloc(23, tall_pcu_ctx);
	if (!ass_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ass_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	Encoding::write_packet_uplink_assignment(bts_data(), ass_vec, m_tfi,
		(direction == GPRS_RLCMAC_DL_TBF), tlli(),
		is_tlli_valid(), new_tbf, 1, rrbp, bts_data()->alpha,
		bts_data()->gamma, -1, is_egprs_enabled());
	bitvec_pack(ass_vec, msgb_put(msg, 23));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Assignment +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(ass_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Uplink Assignment -------------------------\n");
	bts->pkt_ul_assignment();
	bitvec_free(ass_vec);
	talloc_free(mac_control_block);

	set_polling(new_poll_fn, ts, GPRS_RLCMAC_POLL_UL_ASS);

	return msg;
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

	bts->tbf_reused();

	new_tbf = tbf_alloc_dl_tbf(bts->bts_data(), ms(),
		this->trx->trx_no, ms_class(),
		ms() ?  ms()->egprs_ms_class() : 0, 0);

	if (!new_tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource\n");
		return -1;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "%s Trigger downlink assignment on PACCH\n",
		tbf_name(this));
	new_tbf->trigger_ass(this);

	return 0;
}

int gprs_rlcmac_tbf::set_tlli_from_ul(uint32_t new_tlli)
{
	struct gprs_rlcmac_tbf *dl_tbf = NULL;
	struct gprs_rlcmac_tbf *ul_tbf = NULL;
	GprsMs *old_ms;

	OSMO_ASSERT(direction == GPRS_RLCMAC_UL_TBF);

	old_ms = bts->ms_by_tlli(new_tlli);
	/* Keep the old MS object for the update_ms() */
	GprsMs::Guard guard(old_ms);
	if (old_ms) {
		/* Get them before calling set_ms() */
		dl_tbf = old_ms->dl_tbf();
		ul_tbf = old_ms->ul_tbf();

		if (!ms())
			set_ms(old_ms);
	}

	if (dl_tbf && dl_tbf->ms() != ms()) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "Got RACH from "
			"TLLI=0x%08x while %s still exists. "
			"Killing pending DL TBF\n", new_tlli,
			tbf_name(dl_tbf));
		tbf_free(dl_tbf);
		dl_tbf = NULL;
	}
	if (ul_tbf && ul_tbf->ms() != ms()) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "Got RACH from "
			"TLLI=0x%08x while %s still exists. "
			"Killing pending UL TBF\n", new_tlli,
			tbf_name(ul_tbf));
		tbf_free(ul_tbf);
		ul_tbf = NULL;
	}

	/* The TLLI has been taken from an UL message */
	update_ms(new_tlli, GPRS_RLCMAC_UL_TBF);

#if 0 /* REMOVEME ??? */
	if (ms()->need_dl_tbf())
		establish_dl_tbf_on_pacch();
#endif
	return 1;
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

struct gprs_rlcmac_ul_tbf *handle_tbf_reject(struct gprs_rlcmac_bts *bts,
			GprsMs *ms, uint32_t tlli, uint8_t trx_no, uint8_t ts)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf = NULL;
	struct gprs_rlcmac_trx *trx = &bts->trx[trx_no];

	ul_tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_ul_tbf);
	if (!ul_tbf)
		return ul_tbf;

	talloc_set_destructor(ul_tbf, ul_tbf_dtor);
	new (ul_tbf) gprs_rlcmac_ul_tbf(bts->bts);
	if (!ms)
		ms = bts->bts->ms_alloc(0, 0);

	ms->set_tlli(tlli);

	llist_add(&ul_tbf->list(), &bts->bts->ul_tbfs());
	ul_tbf->bts->tbf_ul_created();
	ul_tbf->set_state(GPRS_RLCMAC_ASSIGN);
	ul_tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_PACCH);

	ul_tbf->set_ms(ms);
	ul_tbf->update_ms(tlli, GPRS_RLCMAC_UL_TBF);
	ul_tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ;
	ul_tbf->control_ts = ts;
	ul_tbf->trx = trx;
	ul_tbf->m_ctrs = rate_ctr_group_alloc(ul_tbf, &tbf_ctrg_desc, 0);
	ul_tbf->m_ul_egprs_ctrs = rate_ctr_group_alloc(ul_tbf,
					&tbf_ul_egprs_ctrg_desc, 0);
	ul_tbf->m_ul_gprs_ctrs = rate_ctr_group_alloc(ul_tbf,
					&tbf_ul_gprs_ctrg_desc, 0);
	if (!ul_tbf->m_ctrs || !ul_tbf->m_ul_egprs_ctrs || !ul_tbf->m_ul_gprs_ctrs) {
		LOGP(DRLCMAC, LOGL_ERROR, "Cound not allocate TBF UL rate counters\n");
		talloc_free(ul_tbf);
		return NULL;
	}

	return ul_tbf;
}
