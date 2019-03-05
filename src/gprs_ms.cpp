/* gprs_ms.cpp
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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


#include "gprs_ms.h"
#include <gprs_coding_scheme.h>
#include "bts.h"
#include "tbf.h"
#include "gprs_debug.h"
#include "gprs_codel.h"
#include "pcu_utils.h"

#include <time.h>

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/utils.h>
	#include <osmocom/gsm/protocol/gsm_04_08.h>
	#include <osmocom/core/logging.h>
	#include "coding_scheme.h"
}

#define GPRS_CODEL_SLOW_INTERVAL_MS 4000

extern void *tall_pcu_ctx;

static int64_t now_msec()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

struct GprsMsDefaultCallback: public GprsMs::Callback {
	virtual void ms_idle(class GprsMs *ms) {
		delete ms;
	}
	virtual void ms_active(class GprsMs *) {}
};

static GprsMsDefaultCallback gprs_default_cb;

GprsMs::Guard::Guard(GprsMs *ms) :
	m_ms(ms ? ms->ref() : NULL)
{
}

GprsMs::Guard::~Guard()
{
	if (m_ms)
		m_ms->unref();
}

bool GprsMs::Guard::is_idle() const
{
	if (!m_ms)
		return true;

	return !m_ms->m_ul_tbf && !m_ms->m_dl_tbf && m_ms->m_ref == 1;
}

void GprsMs::timeout(void *priv_)
{
	GprsMs *ms = static_cast<GprsMs *>(priv_);

	LOGP(DRLCMAC, LOGL_INFO, "Timeout for MS object, TLLI = 0x%08x\n",
		ms->tlli());

	if (ms->m_timer.data) {
		ms->m_timer.data = NULL;
		ms->unref();
	}
}

GprsMs::GprsMs(BTS *bts, uint32_t tlli) :
	m_bts(bts),
	m_cb(&gprs_default_cb),
	m_ul_tbf(NULL),
	m_dl_tbf(NULL),
	m_tlli(tlli),
	m_new_ul_tlli(0),
	m_new_dl_tlli(0),
	m_ta(GSM48_TA_INVALID),
	m_ms_class(0),
	m_egprs_ms_class(0),
	m_is_idle(true),
	m_ref(0),
	m_list(this),
	m_delay(0),
	m_nack_rate_dl(0),
	m_reserved_dl_slots(0),
	m_reserved_ul_slots(0),
	m_current_trx(NULL),
	m_codel_state(NULL),
	m_mode(GprsCodingScheme::GPRS),
	m_dl_ctrl_msg(0)
{
	int codel_interval = LLC_CODEL_USE_DEFAULT;

	LOGP(DRLCMAC, LOGL_INFO, "Creating MS object, TLLI = 0x%08x\n", tlli);

	m_imsi[0] = 0;
	memset(&m_timer, 0, sizeof(m_timer));
	m_timer.cb = GprsMs::timeout;
	m_llc_queue.init();

	set_mode(m_mode);

	if (m_bts)
		codel_interval = m_bts->bts_data()->llc_codel_interval_msec;

	if (codel_interval) {
		if (codel_interval == LLC_CODEL_USE_DEFAULT)
			codel_interval = GPRS_CODEL_SLOW_INTERVAL_MS;
		m_codel_state = talloc(this, struct gprs_codel);
		gprs_codel_init(m_codel_state);
		gprs_codel_set_interval(m_codel_state, codel_interval);
	}
	m_last_cs_not_low = now_msec();
}

GprsMs::~GprsMs()
{
	LListHead<gprs_rlcmac_tbf> *pos, *tmp;

	LOGP(DRLCMAC, LOGL_INFO, "Destroying MS object, TLLI = 0x%08x\n", tlli());

	set_reserved_slots(NULL, 0, 0);

	if (osmo_timer_pending(&m_timer))
		osmo_timer_del(&m_timer);

	if (m_ul_tbf) {
		m_ul_tbf->set_ms(NULL);
		m_ul_tbf = NULL;
	}

	if (m_dl_tbf) {
		m_dl_tbf->set_ms(NULL);
		m_dl_tbf = NULL;
	}

	llist_for_each_safe(pos, tmp, &m_old_tbfs)
		pos->entry()->set_ms(NULL);

	m_llc_queue.clear(m_bts);
}

void* GprsMs::operator new(size_t size)
{
	static void *tall_ms_ctx = NULL;
	if (!tall_ms_ctx)
		tall_ms_ctx = talloc_named_const(tall_pcu_ctx, 0, __PRETTY_FUNCTION__);

	return talloc_size(tall_ms_ctx, size);
}

void GprsMs::operator delete(void* p)
{
	talloc_free(p);
}

GprsMs *GprsMs::ref()
{
	m_ref += 1;
	return this;
}

void GprsMs::unref()
{
	OSMO_ASSERT(m_ref >= 0);
	m_ref -= 1;
	if (m_ref == 0)
		update_status();
}

void GprsMs::start_timer()
{
	if (m_delay == 0)
		return;

	if (!m_timer.data)
		m_timer.data = ref();

	osmo_timer_schedule(&m_timer, m_delay, 0);
}

void GprsMs::stop_timer()
{
	if (!m_timer.data)
		return;

	osmo_timer_del(&m_timer);
	m_timer.data = NULL;
	unref();
}

void GprsMs::set_mode(GprsCodingScheme::Mode mode)
{
	m_mode = mode;

	if (!m_bts)
		return;

	switch (m_mode) {
	case GprsCodingScheme::GPRS:
		if (!m_current_cs_ul.isGprs()) {
			m_current_cs_ul = GprsCodingScheme::getGprsByNum(
				m_bts->bts_data()->initial_cs_ul);
			if (!m_current_cs_ul.isValid())
				m_current_cs_ul = CS1;
		}
		if (!m_current_cs_dl.isGprs()) {
			m_current_cs_dl = GprsCodingScheme::getGprsByNum(
				m_bts->bts_data()->initial_cs_dl);
			if (!m_current_cs_dl.isValid())
				m_current_cs_dl = CS1;
		}
		break;

	case GprsCodingScheme::EGPRS_GMSK:
	case GprsCodingScheme::EGPRS:
		if (!m_current_cs_ul.isEgprs()) {
			m_current_cs_ul = GprsCodingScheme::getEgprsByNum(
				m_bts->bts_data()->initial_mcs_ul);
			if (!m_current_cs_ul.isValid())
				m_current_cs_ul = MCS1;
		}
		if (!m_current_cs_dl.isEgprs()) {
			m_current_cs_dl = GprsCodingScheme::getEgprsByNum(
				m_bts->bts_data()->initial_mcs_dl);
			if (!m_current_cs_dl.isValid())
				m_current_cs_dl = MCS1;
		}
		break;
	}
}

void GprsMs::attach_tbf(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction == GPRS_RLCMAC_DL_TBF)
		attach_dl_tbf(as_dl_tbf(tbf));
	else
		attach_ul_tbf(as_ul_tbf(tbf));
}

void GprsMs::attach_ul_tbf(struct gprs_rlcmac_ul_tbf *tbf)
{
	if (m_ul_tbf == tbf)
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Attaching TBF to MS object, TLLI = 0x%08x, TBF = %s\n",
		tlli(), tbf->name());

	Guard guard(this);

	if (m_ul_tbf)
		llist_add_tail(&m_ul_tbf->ms_list(), &m_old_tbfs);

	m_ul_tbf = tbf;

	if (tbf)
		stop_timer();
}

void GprsMs::attach_dl_tbf(struct gprs_rlcmac_dl_tbf *tbf)
{
	if (m_dl_tbf == tbf)
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Attaching TBF to MS object, TLLI = 0x%08x, TBF = %s\n",
		tlli(), tbf->name());

	Guard guard(this);

	if (m_dl_tbf)
		llist_add_tail(&m_dl_tbf->ms_list(), &m_old_tbfs);

	m_dl_tbf = tbf;

	if (tbf)
		stop_timer();
}

void GprsMs::detach_tbf(gprs_rlcmac_tbf *tbf)
{
	if (tbf == static_cast<gprs_rlcmac_tbf *>(m_ul_tbf)) {
		m_ul_tbf = NULL;
	} else if (tbf == static_cast<gprs_rlcmac_tbf *>(m_dl_tbf)) {
		m_dl_tbf = NULL;
	} else {
		bool found = false;

		LListHead<gprs_rlcmac_tbf> *pos, *tmp;
		llist_for_each_safe(pos, tmp, &m_old_tbfs) {
			if (pos->entry() == tbf) {
				llist_del(pos);
				found = true;
				break;
			}
		}

		/* Protect against recursive calls via set_ms() */
		if (!found)
			return;
	}

	LOGP(DRLCMAC, LOGL_INFO, "Detaching TBF from MS object, TLLI = 0x%08x, TBF = %s\n",
		tlli(), tbf->name());

	if (tbf->ms() == this)
		tbf->set_ms(NULL);

	if (!m_dl_tbf && !m_ul_tbf) {
		set_reserved_slots(NULL, 0, 0);

		if (tlli() != 0)
			start_timer();
	}

	update_status();
}

void GprsMs::update_status()
{
	if (m_ref > 0)
		return;

	if (is_idle() && !m_is_idle) {
		m_is_idle = true;
		m_cb->ms_idle(this);
		/* this can be deleted by now, do not access it */
		return;
	}

	if (!is_idle() && m_is_idle) {
		m_is_idle = false;
		m_cb->ms_active(this);
	}
}

void GprsMs::reset()
{
	LOGP(DRLCMAC, LOGL_INFO,
		"Clearing MS object, TLLI: 0x%08x, IMSI: '%s'\n",
		tlli(), imsi());

	stop_timer();

	m_tlli = 0;
	m_new_dl_tlli = 0;
	m_new_ul_tlli = 0;
	m_imsi[0] = '\0';
}

void GprsMs::merge_old_ms(GprsMs *old_ms)
{
	if (old_ms == this)
		return;

	if (strlen(imsi()) == 0 && strlen(old_ms->imsi()) != 0)
		set_imsi(old_ms->imsi());

	if (!ms_class() && old_ms->ms_class())
		set_ms_class(old_ms->ms_class());

	m_llc_queue.move_and_merge(&old_ms->m_llc_queue);

	old_ms->reset();
}

void GprsMs::set_tlli(uint32_t tlli)
{
	if (tlli == m_tlli || tlli == m_new_ul_tlli)
		return;

	if (tlli != m_new_dl_tlli) {
		LOGP(DRLCMAC, LOGL_INFO,
			"Modifying MS object, UL TLLI: 0x%08x -> 0x%08x, "
			"not yet confirmed\n",
			this->tlli(), tlli);
		m_new_ul_tlli = tlli;
		return;
	}

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI: 0x%08x -> 0x%08x, "
		"already confirmed partly\n",
		m_tlli, tlli);

	m_tlli = tlli;
	m_new_dl_tlli = 0;
	m_new_ul_tlli = 0;
}

bool GprsMs::confirm_tlli(uint32_t tlli)
{
	if (tlli == m_tlli || tlli == m_new_dl_tlli)
		return false;

	if (tlli != m_new_ul_tlli) {
		/* The MS has not sent a message with the new TLLI, which may
		 * happen according to the spec [TODO: add reference]. */

		LOGP(DRLCMAC, LOGL_INFO,
			"The MS object cannot fully confirm an unexpected TLLI: 0x%08x, "
			"partly confirmed\n", tlli);
		/* Use the network's idea of TLLI as candidate, this does not
		 * change the result value of tlli() */
		m_new_dl_tlli = tlli;
		return false;
	}

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI: 0x%08x confirmed\n", tlli);

	m_tlli = tlli;
	m_new_dl_tlli = 0;
	m_new_ul_tlli = 0;

	return true;
}

void GprsMs::set_imsi(const char *imsi)
{
	if (!imsi) {
		LOGP(DRLCMAC, LOGL_ERROR, "Expected IMSI!\n");
		return;
	}

	if (imsi[0] && strlen(imsi) < 3) {
		LOGP(DRLCMAC, LOGL_ERROR, "No valid IMSI '%s'!\n",
			imsi);
		return;
	}

	if (strcmp(imsi, m_imsi) == 0)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI = 0x%08x, IMSI '%s' -> '%s'\n",
		tlli(), m_imsi, imsi);

	strncpy(m_imsi, imsi, sizeof(m_imsi));
	m_imsi[sizeof(m_imsi) - 1] = '\0';
}

void GprsMs::set_ta(uint8_t ta_)
{
	if (ta_ == m_ta)
		return;

	if (gsm48_ta_is_valid(ta_)) {
		LOGP(DRLCMAC, LOGL_INFO,
		     "Modifying MS object, TLLI = 0x%08x, TA %d -> %d\n",
		     tlli(), m_ta, ta_);
		m_ta = ta_;
	} else
		LOGP(DRLCMAC, LOGL_NOTICE,
		     "MS object, TLLI = 0x%08x, invalid TA %d rejected (old "
		     "value %d kept)\n", tlli(), ta_, m_ta);
}

void GprsMs::set_ms_class(uint8_t ms_class_)
{
	if (ms_class_ == m_ms_class)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI = 0x%08x, MS class %d -> %d\n",
		tlli(), m_ms_class, ms_class_);

	m_ms_class = ms_class_;
}

void GprsMs::set_egprs_ms_class(uint8_t ms_class_)
{
	if (ms_class_ == m_egprs_ms_class)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI = 0x%08x, EGPRS MS class %d -> %d\n",
		tlli(), m_egprs_ms_class, ms_class_);

	m_egprs_ms_class = ms_class_;
}

void GprsMs::update_error_rate(gprs_rlcmac_tbf *tbf, int error_rate)
{
	struct gprs_rlcmac_bts *bts_data;
	int64_t now;
	GprsCodingScheme max_cs_dl = this->max_cs_dl();

	OSMO_ASSERT(max_cs_dl);
	bts_data = m_bts->bts_data();

	if (error_rate < 0)
		return;

	now = now_msec();

	/* TODO: Check for TBF direction */
	/* TODO: Support different CS values for UL and DL */

	m_nack_rate_dl = error_rate;

	if (error_rate > bts_data->cs_adj_upper_limit) {
		if (m_current_cs_dl.to_num() > 1) {
			m_current_cs_dl.dec(mode());
			LOGP(DRLCMACDL, LOGL_INFO,
				"MS (IMSI %s): High error rate %d%%, "
				"reducing CS level to %s\n",
				imsi(), error_rate, mcs_name(m_current_cs_dl));
			m_last_cs_not_low = now;
		}
	} else if (error_rate < bts_data->cs_adj_lower_limit) {
		if (m_current_cs_dl < max_cs_dl) {
		       if (now - m_last_cs_not_low > 1000) {
			       m_current_cs_dl.inc(mode());

			       LOGP(DRLCMACDL, LOGL_INFO,
				       "MS (IMSI %s): Low error rate %d%%, "
				       "increasing DL CS level to %s\n",
				       imsi(), error_rate,
				       mcs_name(m_current_cs_dl));
			       m_last_cs_not_low = now;
		       } else {
			       LOGP(DRLCMACDL, LOGL_DEBUG,
				       "MS (IMSI %s): Low error rate %d%%, "
				       "ignored (within blocking period)\n",
				       imsi(), error_rate);
		       }
		}
	} else {
		LOGP(DRLCMACDL, LOGL_DEBUG,
			"MS (IMSI %s): Medium error rate %d%%, ignored\n",
			imsi(), error_rate);
		m_last_cs_not_low = now;
	}
}

GprsCodingScheme GprsMs::max_cs_ul() const
{
	struct gprs_rlcmac_bts *bts_data;

	OSMO_ASSERT(m_bts != NULL);
	bts_data = m_bts->bts_data();

	if (m_current_cs_ul.isGprs()) {
		if (!bts_data->max_cs_ul)
			return GprsCodingScheme(CS4);

		return GprsCodingScheme::getGprsByNum(bts_data->max_cs_ul);
	}

	if (!m_current_cs_ul.isEgprs())
		return GprsCodingScheme(); /* UNKNOWN */

	if (bts_data->max_mcs_ul)
		return GprsCodingScheme::getEgprsByNum(bts_data->max_mcs_ul);
	else if (bts_data->max_cs_ul)
		return GprsCodingScheme::getEgprsByNum(bts_data->max_cs_ul);

	return GprsCodingScheme(MCS4);
}

void GprsMs::set_current_cs_dl(CodingScheme scheme)
{
	m_current_cs_dl = scheme;
}

GprsCodingScheme GprsMs::max_cs_dl() const
{
	struct gprs_rlcmac_bts *bts_data;

	OSMO_ASSERT(m_bts != NULL);
	bts_data = m_bts->bts_data();

	if (m_current_cs_dl.isGprs()) {
		if (!bts_data->max_cs_dl)
			return GprsCodingScheme(CS4);

		return GprsCodingScheme::getGprsByNum(bts_data->max_cs_dl);
	}

	if (!m_current_cs_dl.isEgprs())
		return GprsCodingScheme(); /* UNKNOWN */

	if (bts_data->max_mcs_dl)
		return GprsCodingScheme::getEgprsByNum(bts_data->max_mcs_dl);
	else if (bts_data->max_cs_dl)
		return GprsCodingScheme::getEgprsByNum(bts_data->max_cs_dl);

	return GprsCodingScheme(MCS4);
}

void GprsMs::update_cs_ul(const pcu_l1_meas *meas)
{
	struct gprs_rlcmac_bts *bts_data;
	GprsCodingScheme max_cs_ul = this->max_cs_ul();

	int old_link_qual;
	int low;
	int high;
	GprsCodingScheme new_cs_ul = m_current_cs_ul;
	uint8_t current_cs_num = m_current_cs_ul.to_num();

	bts_data = m_bts->bts_data();

	if (!max_cs_ul) {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
			"max_cs_ul cannot be derived (current UL CS: %s)\n",
			mcs_name(m_current_cs_ul));
		return;
	}

	OSMO_ASSERT(current_cs_num > 0);

	if (!m_current_cs_ul) {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
		     "Unable to update UL (M)CS because it's not set: %s\n",
		     mcs_name(m_current_cs_ul));
		return;
	}

	if (!meas->have_link_qual) {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
		     "Unable to update UL (M)CS %s because we don't have link quality measurements.\n",
		     mcs_name(m_current_cs_ul));
		return;
	}

	old_link_qual = meas->link_qual;

	if (m_current_cs_ul.isGprs()) {
		if (current_cs_num > MAX_GPRS_CS)
			current_cs_num = MAX_GPRS_CS;
		low  = bts_data->cs_lqual_ranges[current_cs_num-1].low;
		high = bts_data->cs_lqual_ranges[current_cs_num-1].high;
	} else if (m_current_cs_ul.isEgprs()) {
		if (current_cs_num > MAX_EDGE_MCS)
			current_cs_num = MAX_EDGE_MCS;
		low  = bts_data->mcs_lqual_ranges[current_cs_num-1].low;
		high = bts_data->mcs_lqual_ranges[current_cs_num-1].high;
	} else {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
		     "Unable to update UL (M)CS because it's neither GPRS nor EDGE: %s\n",
		     mcs_name(m_current_cs_ul));
		return;
	}

	if (m_l1_meas.have_link_qual)
		old_link_qual = m_l1_meas.link_qual;

	if (meas->link_qual < low &&  old_link_qual < low)
		new_cs_ul.dec(mode());
	else if (meas->link_qual > high &&  old_link_qual > high &&
		m_current_cs_ul < max_cs_ul)
		new_cs_ul.inc(mode());

	if (m_current_cs_ul != new_cs_ul) {
		LOGP(DRLCMACMEAS, LOGL_INFO,
			"MS (IMSI %s): "
			"Link quality %ddB (%ddB) left window [%d, %d], "
			"modifying uplink CS level: %s -> %s\n",
			imsi(), meas->link_qual, old_link_qual,
			low, high,
			mcs_name(m_current_cs_ul), mcs_name(new_cs_ul));

		m_current_cs_ul = new_cs_ul;
	}
}

void GprsMs::update_l1_meas(const pcu_l1_meas *meas)
{
	unsigned i;

	update_cs_ul(meas);

	if (meas->have_rssi)
		m_l1_meas.set_rssi(meas->rssi);
	if (meas->have_bto)
		m_l1_meas.set_bto(meas->bto);
	if (meas->have_ber)
		m_l1_meas.set_ber(meas->ber);
	if (meas->have_link_qual)
		m_l1_meas.set_link_qual(meas->link_qual);

	if (meas->have_ms_rx_qual)
		m_l1_meas.set_ms_rx_qual(meas->ms_rx_qual);
	if (meas->have_ms_c_value)
		m_l1_meas.set_ms_c_value(meas->ms_c_value);
	if (meas->have_ms_sign_var)
		m_l1_meas.set_ms_sign_var(meas->ms_sign_var);

	if (meas->have_ms_i_level) {
		for (i = 0; i < ARRAY_SIZE(meas->ts); ++i) {
			if (meas->ts[i].have_ms_i_level)
				m_l1_meas.set_ms_i_level(i, meas->ts[i].ms_i_level);
			else
				m_l1_meas.ts[i].have_ms_i_level = 0;
		}
	}
}

GprsCodingScheme GprsMs::current_cs_dl() const
{
	GprsCodingScheme cs = m_current_cs_dl;
	size_t unencoded_octets;

	if (!m_bts)
		return cs;

	unencoded_octets = m_llc_queue.octets();

	/* If the DL TBF is active, add number of unencoded chunk octets */
	if (m_dl_tbf)
		unencoded_octets += m_dl_tbf->m_llc.chunk_size();

	/* There are many unencoded octets, don't reduce */
	if (unencoded_octets >= m_bts->bts_data()->cs_downgrade_threshold)
		return cs;

	/* RF conditions are good, don't reduce */
	if (m_nack_rate_dl < m_bts->bts_data()->cs_adj_lower_limit)
		return cs;

	/* The throughput would probably be better if the CS level was reduced */
	cs.dec(mode());

	/* CS-2 doesn't gain throughput with small packets, further reduce to CS-1 */
	if (cs == GprsCodingScheme(CS2))
		cs.dec(mode());

	return cs;
}

int GprsMs::first_common_ts() const
{
	if (m_dl_tbf)
		return m_dl_tbf->first_common_ts;

	if (m_ul_tbf)
		return m_ul_tbf->first_common_ts;

	return -1;
}

uint8_t GprsMs::dl_slots() const
{
	uint8_t slots = 0;

	if (m_dl_tbf)
		slots |= m_dl_tbf->dl_slots();

	if (m_ul_tbf)
		slots |= m_ul_tbf->dl_slots();

	return slots;
}

uint8_t GprsMs::ul_slots() const
{
	uint8_t slots = 0;

	if (m_dl_tbf)
		slots |= m_dl_tbf->ul_slots();

	if (m_ul_tbf)
		slots |= m_ul_tbf->ul_slots();

	return slots;
}

uint8_t GprsMs::current_pacch_slots() const
{
	uint8_t slots = 0;

	bool is_dl_active = m_dl_tbf && m_dl_tbf->is_tfi_assigned();
	bool is_ul_active = m_ul_tbf && m_ul_tbf->is_tfi_assigned();

	if (!is_dl_active && !is_ul_active)
		return 0;

	/* see TS 44.060, 8.1.1.2.2 */
	if (is_dl_active && !is_ul_active)
		slots =  m_dl_tbf->dl_slots();
	else if (!is_dl_active && is_ul_active)
		slots =  m_ul_tbf->ul_slots();
	else
		slots =  m_ul_tbf->ul_slots() & m_dl_tbf->dl_slots();

	/* Assume a multislot class 1 device */
	/* TODO: For class 2 devices, this could be removed */
	slots = pcu_lsb(slots);

	return slots;
}

void GprsMs::set_reserved_slots(gprs_rlcmac_trx *trx,
	uint8_t ul_slots, uint8_t dl_slots)
{
	if (m_current_trx) {
		m_current_trx->unreserve_slots(GPRS_RLCMAC_DL_TBF,
			m_reserved_dl_slots);
		m_current_trx->unreserve_slots(GPRS_RLCMAC_UL_TBF,
			m_reserved_ul_slots);
		m_reserved_dl_slots = 0;
		m_reserved_ul_slots = 0;
	}
	m_current_trx = trx;
	if (trx) {
		m_reserved_dl_slots = dl_slots;
		m_reserved_ul_slots = ul_slots;
		m_current_trx->reserve_slots(GPRS_RLCMAC_DL_TBF,
			m_reserved_dl_slots);
		m_current_trx->reserve_slots(GPRS_RLCMAC_UL_TBF,
			m_reserved_ul_slots);
	}
}

gprs_rlcmac_tbf *GprsMs::tbf(enum gprs_rlcmac_tbf_direction dir) const
{
	switch (dir) {
	case GPRS_RLCMAC_DL_TBF: return m_dl_tbf;
	case GPRS_RLCMAC_UL_TBF: return m_ul_tbf;
	}

	return NULL;
}
