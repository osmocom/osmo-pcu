/* gprs_ms.c
 *
 * Copyright (C) 2015-2020 by Sysmocom s.f.m.c. GmbH
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
#include "bts.h"
#include "tbf.h"
#include "tbf_ul.h"
#include "gprs_debug.h"
#include "gprs_codel.h"
#include "pcu_utils.h"

#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/stats.h>
#include "coding_scheme.h"

#define GPRS_CODEL_SLOW_INTERVAL_MS 4000

extern void *tall_pcu_ctx;
static unsigned int next_ms_ctr_group_id;

static const struct rate_ctr_desc ms_ctr_description[] = {
	[MS_CTR_DL_CTRL_MSG_SCHED] = { "ms:dl_ctrl_msg_sched", "Amount of DL CTRL messages scheduled" },
};

static const struct rate_ctr_group_desc ms_ctrg_desc = {
	.group_name_prefix = "pcu:ms",
	.group_description = "MS Statistics",
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
	.num_ctr = ARRAY_SIZE(ms_ctr_description),
	.ctr_desc = ms_ctr_description,
};

static int64_t now_msec()
{
	struct timespec ts;
	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);

	return (int64_t)(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

void gprs_default_cb_ms_idle(struct GprsMs *ms)
{
	talloc_free(ms);
}

void gprs_default_cb_ms_active(struct GprsMs *ms)
{
	/* do nothing */
}

static struct gpr_ms_callback gprs_default_cb = {
	.ms_idle = gprs_default_cb_ms_idle,
	.ms_active = gprs_default_cb_ms_active,
};

void ms_timeout(void *data)
{
	struct GprsMs *ms = (struct GprsMs *) data;
	LOGP(DRLCMAC, LOGL_INFO, "Timeout for MS object, TLLI = 0x%08x\n",
		ms_tlli(ms));

	if (ms->timer.data) {
		ms->timer.data = NULL;
		ms_unref(ms);
	}
}

static int ms_talloc_destructor(struct GprsMs *ms);
struct GprsMs *ms_alloc(struct BTS *bts, uint32_t tlli)
{
	struct GprsMs *ms = talloc_zero(tall_pcu_ctx, struct GprsMs);

	talloc_set_destructor(ms, ms_talloc_destructor);

	ms->bts = bts;
	ms->cb = gprs_default_cb;
	ms->tlli = tlli;
	ms->new_ul_tlli = GSM_RESERVED_TMSI;
	ms->new_dl_tlli = GSM_RESERVED_TMSI;
	ms->ta = GSM48_TA_INVALID;
	ms->current_cs_ul = UNKNOWN;
	ms->current_cs_dl = UNKNOWN;
	ms->is_idle = true;
	INIT_LLIST_HEAD(&ms->list);
	INIT_LLIST_HEAD(&ms->old_tbfs);

	int codel_interval = LLC_CODEL_USE_DEFAULT;

	LOGP(DRLCMAC, LOGL_INFO, "Creating MS object, TLLI = 0x%08x\n", tlli);

	ms->imsi[0] = '\0';
	memset(&ms->timer, 0, sizeof(ms->timer));
	ms->timer.cb = ms_timeout;
	llc_queue_init(&ms->llc_queue);

	ms_set_mode(ms, GPRS);

	if (ms->bts)
		codel_interval = bts_data(ms->bts)->llc_codel_interval_msec;

	if (codel_interval) {
		if (codel_interval == LLC_CODEL_USE_DEFAULT)
			codel_interval = GPRS_CODEL_SLOW_INTERVAL_MS;
		ms->codel_state = talloc(ms, struct gprs_codel);
		gprs_codel_init(ms->codel_state);
		gprs_codel_set_interval(ms->codel_state, codel_interval);
	}
	ms->last_cs_not_low = now_msec();
	ms->app_info_pending = false;

	ms->ctrs = rate_ctr_group_alloc(ms, &ms_ctrg_desc, next_ms_ctr_group_id++);
	if (!ms->ctrs)
		goto free_ret;

	return ms;
free_ret:
	talloc_free(ms);
	return NULL;
}

static int ms_talloc_destructor(struct GprsMs *ms)
{
	struct llist_item *pos, *tmp;

	LOGP(DRLCMAC, LOGL_INFO, "Destroying MS object, TLLI = 0x%08x\n", ms_tlli(ms));

	ms_set_reserved_slots(ms, NULL, 0, 0);

	if (osmo_timer_pending(&ms->timer))
		osmo_timer_del(&ms->timer);

	if (ms->ul_tbf) {
		tbf_set_ms((struct gprs_rlcmac_tbf *)ms->ul_tbf, NULL);
		ms->ul_tbf = NULL;
	}

	if (ms->dl_tbf) {
		tbf_set_ms((struct gprs_rlcmac_tbf *)ms->dl_tbf, NULL);
		ms->dl_tbf = NULL;
	}

	llist_for_each_entry_safe(pos, tmp, &ms->old_tbfs, list) {
		struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)pos->entry;
		tbf_set_ms(tbf, NULL);
	}

	llc_queue_clear(&ms->llc_queue, ms->bts);

	if (ms->ctrs)
		rate_ctr_group_free(ms->ctrs);
	return 0;
}


void ms_set_callback(struct GprsMs *ms, struct gpr_ms_callback *cb)
{
	if (cb)
		ms->cb = *cb;
	else
		ms->cb = gprs_default_cb;
}

static void ms_update_status(struct GprsMs *ms)
{
	if (ms->ref > 0)
		return;

	if (ms_is_idle(ms) && !ms->is_idle) {
		ms->is_idle = true;
		ms->cb.ms_idle(ms);
		/* this can be deleted by now, do not access it */
		return;
	}

	if (!ms_is_idle(ms) && ms->is_idle) {
		ms->is_idle = false;
		ms->cb.ms_active(ms);
	}
}

struct GprsMs *ms_ref(struct GprsMs *ms)
{
	ms->ref += 1;
	return ms;
}

void ms_unref(struct GprsMs *ms)
{
	OSMO_ASSERT(ms->ref >= 0);
	ms->ref -= 1;
	if (ms->ref == 0)
		ms_update_status(ms);
}

void ms_start_timer(struct GprsMs *ms)
{
	if (ms->delay == 0)
		return;

	if (!ms->timer.data)
		ms->timer.data = ms_ref(ms);

	osmo_timer_schedule(&ms->timer, ms->delay, 0);
}

void ms_stop_timer(struct GprsMs *ms)
{
	if (!ms->timer.data)
		return;

	osmo_timer_del(&ms->timer);
	ms->timer.data = NULL;
	ms_unref(ms);
}

void ms_set_mode(struct GprsMs *ms, enum mcs_kind mode)
{
	ms->mode = mode;

	if (!ms->bts)
		return;

	switch (ms->mode) {
	case GPRS:
		if (!mcs_is_gprs(ms->current_cs_ul)) {
			ms->current_cs_ul = mcs_get_gprs_by_num(
				bts_data(ms->bts)->initial_cs_ul);
			if (!mcs_is_valid(ms->current_cs_ul))
				ms->current_cs_ul = CS1;
		}
		if (!mcs_is_gprs(ms->current_cs_dl)) {
			ms->current_cs_dl = mcs_get_gprs_by_num(
				bts_data(ms->bts)->initial_cs_dl);
			if (!mcs_is_valid(ms->current_cs_dl))
				ms->current_cs_dl = CS1;
		}
		break;

	case EGPRS_GMSK:
	case EGPRS:
		if (!mcs_is_edge(ms->current_cs_ul)) {
			ms->current_cs_ul = mcs_get_egprs_by_num(
				bts_data(ms->bts)->initial_mcs_ul);
			if (!mcs_is_valid(ms->current_cs_ul))
				ms->current_cs_ul = MCS1;
		}
		if (!mcs_is_edge(ms->current_cs_dl)) {
			ms->current_cs_dl = mcs_get_egprs_by_num(
				bts_data(ms->bts)->initial_mcs_dl);
			if (!mcs_is_valid(ms->current_cs_dl))
				ms->current_cs_dl = MCS1;
		}
		break;
	}
}

static void ms_attach_ul_tbf(struct GprsMs *ms, struct gprs_rlcmac_ul_tbf *tbf)
{
	if (ms->ul_tbf == tbf)
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Attaching TBF to MS object, TLLI = 0x%08x, TBF = %s\n",
		ms_tlli(ms), tbf_name((struct gprs_rlcmac_tbf *)tbf));

	ms_ref(ms);

	if (ms->ul_tbf)
		llist_add_tail(tbf_ms_list((struct gprs_rlcmac_tbf *)ms->ul_tbf), &ms->old_tbfs);

	ms->ul_tbf = tbf;

	if (tbf)
		ms_stop_timer(ms);

	ms_unref(ms);
}

static void ms_attach_dl_tbf(struct GprsMs *ms, struct gprs_rlcmac_dl_tbf *tbf)
{
	if (ms->dl_tbf == tbf)
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Attaching TBF to MS object, TLLI = 0x%08x, TBF = %s\n",
		ms_tlli(ms), tbf_name((struct gprs_rlcmac_tbf *)tbf));

	ms_ref(ms);

	if (ms->dl_tbf)
		llist_add_tail(tbf_ms_list((struct gprs_rlcmac_tbf *)ms->dl_tbf), &ms->old_tbfs);

	ms->dl_tbf = tbf;

	if (tbf)
		ms_stop_timer(ms);

	ms_unref(ms);
}

void ms_attach_tbf(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf)
{
	if (tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF)
		ms_attach_dl_tbf(ms, as_dl_tbf(tbf));
	else
		ms_attach_ul_tbf(ms, as_ul_tbf(tbf));
}

void ms_detach_tbf(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf)
{
	if (tbf == (struct gprs_rlcmac_tbf *)(ms->ul_tbf)) {
		ms->ul_tbf = NULL;
	} else if (tbf == (struct gprs_rlcmac_tbf *)(ms->dl_tbf)) {
		ms->dl_tbf = NULL;
	} else {
		bool found = false;

		struct llist_item *pos, *tmp;
		llist_for_each_entry_safe(pos, tmp, &ms->old_tbfs, list) {
			struct gprs_rlcmac_tbf *tmp_tbf = (struct gprs_rlcmac_tbf *)pos->entry;
			if (tmp_tbf == tbf) {
				llist_del(&pos->list);
				found = true;
				break;
			}
		}

		/* Protect against recursive calls via set_ms() */
		if (!found)
			return;
	}

	LOGP(DRLCMAC, LOGL_INFO, "Detaching TBF from MS object, TLLI = 0x%08x, TBF = %s\n",
		ms_tlli(ms), tbf_name(tbf));

	if (tbf_ms(tbf) == ms)
		tbf_set_ms(tbf, NULL);

	if (!ms->dl_tbf && !ms->ul_tbf) {
		ms_set_reserved_slots(ms, NULL, 0, 0);

		if (ms_tlli(ms) != 0)
			ms_start_timer(ms);
	}

	ms_update_status(ms);
}

void ms_reset(struct GprsMs *ms)
{
	LOGP(DRLCMAC, LOGL_INFO,
		"Clearing MS object, TLLI: 0x%08x, IMSI: '%s'\n",
		ms_tlli(ms), ms_imsi(ms));

	ms_stop_timer(ms);

	ms->tlli = GSM_RESERVED_TMSI;
	ms->new_dl_tlli = ms->tlli;
	ms->new_ul_tlli = ms->tlli;
	ms->imsi[0] = '\0';
}

static void ms_merge_old_ms(struct GprsMs *ms, struct GprsMs *old_ms)
{
	OSMO_ASSERT(old_ms != ms);

	if (strlen(ms_imsi(ms)) == 0 && strlen(ms_imsi(old_ms)) != 0)
		osmo_strlcpy(ms->imsi, ms_imsi(old_ms), sizeof(ms->imsi));

	if (!ms_ms_class(ms) && ms_ms_class(old_ms))
		ms_set_ms_class(ms, ms_ms_class(old_ms));

	if (!ms_egprs_ms_class(ms) && ms_egprs_ms_class(old_ms))
		ms_set_egprs_ms_class(ms, ms_egprs_ms_class(old_ms));

	llc_queue_move_and_merge(&ms->llc_queue, &old_ms->llc_queue);

	ms_reset(old_ms);
}

void ms_merge_and_clear_ms(struct GprsMs *ms, struct GprsMs *old_ms)
{
	OSMO_ASSERT(old_ms != ms);

	ms_ref(old_ms);

	/* Clean up the old MS object */
	/* TODO: Use timer? */
	if (ms_ul_tbf(old_ms) && !tbf_timers_pending((struct gprs_rlcmac_tbf *)ms_ul_tbf(old_ms), T_MAX))
			tbf_free((struct gprs_rlcmac_tbf *)ms_ul_tbf(old_ms));
	if (ms_dl_tbf(old_ms) && !tbf_timers_pending((struct gprs_rlcmac_tbf *)ms_dl_tbf(old_ms), T_MAX))
			tbf_free((struct gprs_rlcmac_tbf *)ms_dl_tbf(old_ms));

	ms_merge_old_ms(ms, old_ms);

	ms_unref(old_ms);
}

void ms_set_tlli(struct GprsMs *ms, uint32_t tlli)
{
	if (tlli == ms->tlli || tlli == ms->new_ul_tlli)
		return;

	if (tlli != ms->new_dl_tlli) {
		LOGP(DRLCMAC, LOGL_INFO,
			"Modifying MS object, UL TLLI: 0x%08x -> 0x%08x, "
			"not yet confirmed\n",
			ms_tlli(ms), tlli);
		ms->new_ul_tlli = tlli;
		return;
	}

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI: 0x%08x -> 0x%08x, "
		"already confirmed partly\n",
		ms->tlli, tlli);

	ms->tlli = tlli;
	ms->new_dl_tlli = GSM_RESERVED_TMSI;
	ms->new_ul_tlli = GSM_RESERVED_TMSI;
}

bool ms_confirm_tlli(struct GprsMs *ms, uint32_t tlli)
{
	if (tlli == ms->tlli || tlli == ms->new_dl_tlli)
		return false;

	if (tlli != ms->new_ul_tlli) {
		/* The MS has not sent a message with the new TLLI, which may
		 * happen according to the spec [TODO: add reference]. */

		LOGP(DRLCMAC, LOGL_INFO,
			"The MS object cannot fully confirm an unexpected TLLI: 0x%08x, "
			"partly confirmed\n", tlli);
		/* Use the network's idea of TLLI as candidate, this does not
		 * change the result value of tlli() */
		ms->new_dl_tlli = tlli;
		return false;
	}

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI: 0x%08x confirmed\n", tlli);

	ms->tlli = tlli;
	ms->new_dl_tlli = GSM_RESERVED_TMSI;
	ms->new_ul_tlli = GSM_RESERVED_TMSI;

	return true;
}

void ms_set_imsi(struct GprsMs *ms, const char *imsi)
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

	if (strcmp(imsi, ms->imsi) == 0)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI = 0x%08x, IMSI '%s' -> '%s'\n",
		ms_tlli(ms), ms->imsi, imsi);

	struct GprsMs *old_ms = bts_ms_by_imsi(ms->bts, imsi);
	/* Check if we are going to store a different MS object with already
	   existing IMSI. This is probably a bug in code calling this function,
	   since it should take care of this explicitly */
	if (old_ms) {
		/* We cannot find ms->ms by IMSI since we know that it has a
		* different IMSI */
		OSMO_ASSERT(old_ms != ms);

		LOGPMS(ms, DRLCMAC, LOGL_NOTICE,
		       "IMSI '%s' was already assigned to another "
		       "MS object: TLLI = 0x%08x, that IMSI will be removed\n",
		       imsi, ms_tlli(old_ms));

		ms_merge_and_clear_ms(ms, old_ms);
	}


	osmo_strlcpy(ms->imsi, imsi, sizeof(ms->imsi));
}

void ms_set_ta(struct GprsMs *ms, uint8_t ta_)
{
	if (ta_ == ms->ta)
		return;

	if (gsm48_ta_is_valid(ta_)) {
		LOGP(DRLCMAC, LOGL_INFO,
		     "Modifying MS object, TLLI = 0x%08x, TA %d -> %d\n",
		     ms_tlli(ms), ms->ta, ta_);
		ms->ta = ta_;
	} else
		LOGP(DRLCMAC, LOGL_NOTICE,
		     "MS object, TLLI = 0x%08x, invalid TA %d rejected (old "
		     "value %d kept)\n", ms_tlli(ms), ta_, ms->ta);
}

void ms_set_ms_class(struct GprsMs *ms, uint8_t ms_class_)
{
	if (ms_class_ == ms->ms_class)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI = 0x%08x, MS class %d -> %d\n",
		ms_tlli(ms), ms->ms_class, ms_class_);

	ms->ms_class = ms_class_;
}

void ms_set_egprs_ms_class(struct GprsMs *ms, uint8_t ms_class_)
{
	if (ms_class_ == ms->egprs_ms_class)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI = 0x%08x, EGPRS MS class %d -> %d\n",
		ms_tlli(ms), ms->egprs_ms_class, ms_class_);

	ms->egprs_ms_class = ms_class_;

	if (!bts_max_mcs_ul(ms->bts) || !bts_max_mcs_dl(ms->bts)) {
		LOGPMS(ms, DRLCMAC, LOGL_DEBUG,
		       "Avoid enabling EGPRS because use of MCS is disabled: ul=%u dl=%u\n",
			bts_max_mcs_ul(ms->bts), bts_max_mcs_dl(ms->bts));
		return;
	}

	if (mcs_is_edge_gmsk(mcs_get_egprs_by_num(bts_max_mcs_ul(ms->bts))) &&
		mcs_is_edge_gmsk(mcs_get_egprs_by_num(bts_max_mcs_dl(ms->bts))) &&
		ms_mode(ms) != EGPRS)
	{
		ms_set_mode(ms, EGPRS_GMSK);
	} else {
		ms_set_mode(ms, EGPRS);
	}
	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Enabled EGPRS, mode %s\n", mode_name(ms_mode(ms)));
}

void ms_update_error_rate(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf, int error_rate)
{
	int64_t now;
	enum CodingScheme max_cs_dl = ms_max_cs_dl(ms);
	OSMO_ASSERT(max_cs_dl);

	if (error_rate < 0)
		return;

	now = now_msec();

	/* TODO: Check for TBF direction */
	/* TODO: Support different CS values for UL and DL */

	ms->nack_rate_dl = error_rate;

	if (error_rate > the_pcu->vty.cs_adj_upper_limit) {
		if (mcs_chan_code(ms->current_cs_dl) > 0) {
			mcs_dec_kind(&ms->current_cs_dl, ms_mode(ms));
			LOGP(DRLCMACDL, LOGL_INFO,
				"MS (IMSI %s): High error rate %d%%, "
				"reducing CS level to %s\n",
				ms_imsi(ms), error_rate, mcs_name(ms->current_cs_dl));
			ms->last_cs_not_low = now;
		}
	} else if (error_rate < the_pcu->vty.cs_adj_lower_limit) {
		if (ms->current_cs_dl < max_cs_dl) {
		       if (now - ms->last_cs_not_low > 1000) {
			       mcs_inc_kind(&ms->current_cs_dl, ms_mode(ms));

			       LOGP(DRLCMACDL, LOGL_INFO,
				       "MS (IMSI %s): Low error rate %d%%, "
				       "increasing DL CS level to %s\n",
				       ms_imsi(ms), error_rate,
				       mcs_name(ms->current_cs_dl));
			       ms->last_cs_not_low = now;
		       } else {
			       LOGP(DRLCMACDL, LOGL_DEBUG,
				       "MS (IMSI %s): Low error rate %d%%, "
				       "ignored (within blocking period)\n",
				       ms_imsi(ms), error_rate);
		       }
		}
	} else {
		LOGP(DRLCMACDL, LOGL_DEBUG,
			"MS (IMSI %s): Medium error rate %d%%, ignored\n",
			ms_imsi(ms), error_rate);
		ms->last_cs_not_low = now;
	}
}

enum CodingScheme ms_max_cs_ul(const struct GprsMs *ms)
{
	OSMO_ASSERT(ms->bts != NULL);

	if (mcs_is_gprs(ms->current_cs_ul)) {
		if (!bts_max_cs_ul(ms->bts)) {
			return CS4;
		}

		return mcs_get_gprs_by_num(bts_max_cs_ul(ms->bts));
	}

	if (!mcs_is_edge(ms->current_cs_ul))
		return UNKNOWN;

	if (bts_max_mcs_ul(ms->bts))
		return mcs_get_egprs_by_num(bts_max_mcs_ul(ms->bts));
	else if (bts_max_cs_ul(ms->bts))
		return mcs_get_gprs_by_num(bts_max_cs_ul(ms->bts));

	return MCS4;
}

void ms_set_current_cs_dl(struct GprsMs *ms, enum CodingScheme scheme)
{
	ms->current_cs_dl = scheme;
}

enum CodingScheme ms_max_cs_dl(const struct GprsMs *ms)
{
	OSMO_ASSERT(ms->bts != NULL);

	if (mcs_is_gprs(ms->current_cs_dl)) {
		if (!bts_max_cs_dl(ms->bts)) {
			return CS4;
		}

		return mcs_get_gprs_by_num(bts_max_cs_dl(ms->bts));
	}

	if (!mcs_is_edge(ms->current_cs_dl))
		return UNKNOWN;

	if (bts_max_mcs_dl(ms->bts))
		return mcs_get_egprs_by_num(bts_max_mcs_dl(ms->bts));
	else if (bts_max_cs_dl(ms->bts))
		return mcs_get_gprs_by_num(bts_max_cs_dl(ms->bts));

	return MCS4;
}

void ms_update_cs_ul(struct GprsMs *ms, const struct pcu_l1_meas *meas)
{
	struct gprs_rlcmac_bts *bts_;
	enum CodingScheme max_cs_ul = ms_max_cs_ul(ms);

	int old_link_qual;
	int low;
	int high;
	enum CodingScheme new_cs_ul = ms->current_cs_ul;
	uint8_t current_cs = mcs_chan_code(ms->current_cs_ul);

	bts_ = bts_data(ms->bts);

	if (!max_cs_ul) {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
			"max_cs_ul cannot be derived (current UL CS: %s)\n",
			mcs_name(ms->current_cs_ul));
		return;
	}

	if (!ms->current_cs_ul) {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
		     "Unable to update UL (M)CS because it's not set: %s\n",
		     mcs_name(ms->current_cs_ul));
		return;
	}

	if (!meas->have_link_qual) {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
		     "Unable to update UL (M)CS %s because we don't have link quality measurements.\n",
		     mcs_name(ms->current_cs_ul));
		return;
	}

	if (mcs_is_gprs(ms->current_cs_ul)) {
		if (current_cs >= MAX_GPRS_CS)
			current_cs = MAX_GPRS_CS - 1;
		low  = bts_->cs_lqual_ranges[current_cs].low;
		high = bts_->cs_lqual_ranges[current_cs].high;
	} else if (mcs_is_edge(ms->current_cs_ul)) {
		if (current_cs >= MAX_EDGE_MCS)
			current_cs = MAX_EDGE_MCS - 1;
		low  = bts_->mcs_lqual_ranges[current_cs].low;
		high = bts_->mcs_lqual_ranges[current_cs].high;
	} else {
		LOGP(DRLCMACMEAS, LOGL_ERROR,
		     "Unable to update UL (M)CS because it's neither GPRS nor EDGE: %s\n",
		     mcs_name(ms->current_cs_ul));
		return;
	}

	/* To avoid rapid changes of the coding scheme, we also take
	 * the old link quality value into account (if present). */
	if (ms->l1_meas.have_link_qual)
		old_link_qual = ms->l1_meas.link_qual;
	else
		old_link_qual = meas->link_qual;

	if (meas->link_qual < low &&  old_link_qual < low)
		mcs_dec_kind(&new_cs_ul, ms_mode(ms));
	else if (meas->link_qual > high &&  old_link_qual > high &&
		ms->current_cs_ul < max_cs_ul)
		mcs_inc_kind(&new_cs_ul, ms_mode(ms));

	if (ms->current_cs_ul != new_cs_ul) {
		LOGPMS(ms, DRLCMACMEAS, LOGL_INFO,
		       "Link quality %ddB (old %ddB) left window [%d, %d], "
		       "modifying uplink CS level: %s -> %s\n",
		       meas->link_qual, old_link_qual,
		       low, high,
		       mcs_name(ms->current_cs_ul), mcs_name(new_cs_ul));

		ms->current_cs_ul = new_cs_ul;
	}
}

void ms_update_l1_meas(struct GprsMs *ms, const struct pcu_l1_meas *meas)
{
	unsigned i;

	ms_update_cs_ul(ms, meas);

	if (meas->have_rssi)
		pcu_l1_meas_set_rssi(&ms->l1_meas, meas->rssi);
	if (meas->have_bto)
		pcu_l1_meas_set_bto(&ms->l1_meas, meas->bto);
	if (meas->have_ber)
		pcu_l1_meas_set_ber(&ms->l1_meas, meas->ber);
	if (meas->have_link_qual)
		pcu_l1_meas_set_link_qual(&ms->l1_meas, meas->link_qual);

	if (meas->have_ms_rx_qual)
		pcu_l1_meas_set_ms_rx_qual(&ms->l1_meas, meas->ms_rx_qual);
	if (meas->have_ms_c_value)
		pcu_l1_meas_set_ms_c_value(&ms->l1_meas, meas->ms_c_value);
	if (meas->have_ms_sign_var)
		pcu_l1_meas_set_ms_sign_var(&ms->l1_meas, meas->ms_sign_var);

	if (meas->have_ms_i_level) {
		for (i = 0; i < ARRAY_SIZE(meas->ts); ++i) {
			if (meas->ts[i].have_ms_i_level)
				pcu_l1_meas_set_ms_i_level(&ms->l1_meas, i, meas->ts[i].ms_i_level);
			else
				ms->l1_meas.ts[i].have_ms_i_level = 0;
		}
	}
}

enum CodingScheme ms_current_cs_dl(const struct GprsMs *ms)
{
	enum CodingScheme cs = ms->current_cs_dl;
	size_t unencoded_octets;

	if (!ms->bts)
		return cs;

	unencoded_octets = llc_queue_octets(&ms->llc_queue);

	/* If the DL TBF is active, add number of unencoded chunk octets */
	if (ms->dl_tbf)
		unencoded_octets += llc_chunk_size(tbf_llc((struct gprs_rlcmac_tbf *)ms->dl_tbf));

	/* There are many unencoded octets, don't reduce */
	if (unencoded_octets >= the_pcu->vty.cs_downgrade_threshold)
		return cs;

	/* RF conditions are good, don't reduce */
	if (ms->nack_rate_dl < the_pcu->vty.cs_adj_lower_limit)
		return cs;

	/* The throughput would probably be better if the CS level was reduced */
	mcs_dec_kind(&cs, ms_mode(ms));

	/* CS-2 doesn't gain throughput with small packets, further reduce to CS-1 */
	if (cs == CS2)
		mcs_dec_kind(&cs, ms_mode(ms));

	return cs;
}

int ms_first_common_ts(const struct GprsMs *ms)
{
	if (ms->dl_tbf)
		return tbf_first_common_ts((struct gprs_rlcmac_tbf *)ms->dl_tbf);

	if (ms->ul_tbf)
		return tbf_first_common_ts((struct gprs_rlcmac_tbf *)ms->ul_tbf);

	return -1;
}

uint8_t ms_dl_slots(const struct GprsMs *ms)
{
	uint8_t slots = 0;

	if (ms->dl_tbf)
		slots |= tbf_dl_slots((struct gprs_rlcmac_tbf *)ms->dl_tbf);

	if (ms->ul_tbf)
		slots |= tbf_dl_slots((struct gprs_rlcmac_tbf *)ms->ul_tbf);

	return slots;
}

uint8_t ms_ul_slots(const struct GprsMs *ms)
{
	uint8_t slots = 0;

	if (ms->dl_tbf)
		slots |= tbf_ul_slots((struct gprs_rlcmac_tbf *)ms->dl_tbf);

	if (ms->ul_tbf)
		slots |= tbf_ul_slots((struct gprs_rlcmac_tbf *)ms->ul_tbf);

	return slots;
}

uint8_t ms_current_pacch_slots(const struct GprsMs *ms)
{
	uint8_t slots = 0;

	bool is_dl_active = ms->dl_tbf && tbf_is_tfi_assigned((struct gprs_rlcmac_tbf *)ms->dl_tbf);
	bool is_ul_active = ms->ul_tbf && tbf_is_tfi_assigned((struct gprs_rlcmac_tbf *)ms->ul_tbf);

	if (!is_dl_active && !is_ul_active)
		return 0;

	/* see TS 44.060, 8.1.1.2.2 */
	if (is_dl_active && !is_ul_active)
		slots =  tbf_dl_slots((struct gprs_rlcmac_tbf *)ms->dl_tbf);
	else if (!is_dl_active && is_ul_active)
		slots =  tbf_ul_slots((struct gprs_rlcmac_tbf *)ms->ul_tbf);
	else
		slots =  tbf_ul_slots((struct gprs_rlcmac_tbf *)ms->ul_tbf) &
			 tbf_dl_slots((struct gprs_rlcmac_tbf *)ms->dl_tbf);

	/* Assume a multislot class 1 device */
	/* TODO: For class 2 devices, this could be removed */
	slots = pcu_lsb(slots);

	return slots;
}

void ms_set_reserved_slots(struct GprsMs *ms, struct gprs_rlcmac_trx *trx,
	uint8_t ul_slots, uint8_t dl_slots)
{
	if (ms->current_trx) {
		bts_trx_unreserve_slots(ms->current_trx, GPRS_RLCMAC_DL_TBF,
			ms->reserved_dl_slots);
		bts_trx_unreserve_slots(ms->current_trx, GPRS_RLCMAC_UL_TBF,
			ms->reserved_ul_slots);
		ms->reserved_dl_slots = 0;
		ms->reserved_ul_slots = 0;
	}
	ms->current_trx = trx;
	if (trx) {
		ms->reserved_dl_slots = dl_slots;
		ms->reserved_ul_slots = ul_slots;
		bts_trx_reserve_slots(ms->current_trx, GPRS_RLCMAC_DL_TBF,
			ms->reserved_dl_slots);
		bts_trx_reserve_slots(ms->current_trx, GPRS_RLCMAC_UL_TBF,
			ms->reserved_ul_slots);
	}
}

struct gprs_rlcmac_tbf *ms_tbf(const struct GprsMs *ms, enum gprs_rlcmac_tbf_direction dir)
{
	switch (dir) {
	case GPRS_RLCMAC_DL_TBF: return (struct gprs_rlcmac_tbf *)ms->dl_tbf;
	case GPRS_RLCMAC_UL_TBF: return (struct gprs_rlcmac_tbf *)ms->ul_tbf;
	}

	return NULL;
}
