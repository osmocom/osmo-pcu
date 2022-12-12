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
 */


#include "gprs_ms.h"
#include "bts.h"
#include "tbf.h"
#include "tbf_ul.h"
#include "gprs_debug.h"
#include "gprs_codel.h"
#include "pcu_utils.h"
#include "nacc_fsm.h"
#include "tbf_ul_ack_fsm.h"
#include "gprs_ms_storage.h"

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

static void ms_release_timer_cb(void *data)
{
	struct GprsMs *ms = (struct GprsMs *) data;
	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Release timer expired\n");

	if (ms->timer.data) {
		ms->timer.data = NULL;
		ms_unref(ms);
	}
}

static void ms_llc_timer_cb(void *_ms)
{
	struct GprsMs *ms = _ms;
	struct gprs_rlcmac_dl_tbf *dl_tbf = ms_dl_tbf(ms);

	if (!dl_tbf)
		return;
	if (tbf_state(dl_tbf_as_tbf_const(dl_tbf)) != TBF_ST_FLOW)
		return;

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "LLC receive timeout, requesting DL ACK\n");

	dl_tbf_request_dl_ack(dl_tbf);
}

static int ms_talloc_destructor(struct GprsMs *ms);
struct GprsMs *ms_alloc(struct gprs_rlcmac_bts *bts, uint32_t tlli)
{
	struct GprsMs *ms = talloc_zero(tall_pcu_ctx, struct GprsMs);
	OSMO_ASSERT(bts);

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
	ms->first_common_ts = TBF_TS_UNSET;
	INIT_LLIST_HEAD(&ms->list);
	INIT_LLIST_HEAD(&ms->old_tbfs);

	int codel_interval = LLC_CODEL_USE_DEFAULT;

	LOGP(DRLCMAC, LOGL_INFO, "Creating MS object, TLLI = 0x%08x\n", tlli);

	ms->imsi[0] = '\0';
	osmo_timer_setup(&ms->timer, ms_release_timer_cb, NULL);
	llc_queue_init(&ms->llc_queue, ms);
	memset(&ms->llc_timer, 0, sizeof(ms->llc_timer));
	osmo_timer_setup(&ms->llc_timer, ms_llc_timer_cb, ms);

	ms_set_mode(ms, GPRS);

	codel_interval = the_pcu->vty.llc_codel_interval_msec;
	if (codel_interval == LLC_CODEL_USE_DEFAULT)
		codel_interval = GPRS_CODEL_SLOW_INTERVAL_MS;
	llc_queue_set_codel_interval(&ms->llc_queue, codel_interval);

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

	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Destroying MS object\n");

	ms_set_reserved_slots(ms, NULL, 0, 0);

	osmo_timer_del(&ms->timer);

	if (ms->ul_tbf) {
		tbf_set_ms(ul_tbf_as_tbf(ms->ul_tbf), NULL);
		ms->ul_tbf = NULL;
	}

	if (ms->dl_tbf) {
		tbf_set_ms(dl_tbf_as_tbf(ms->dl_tbf), NULL);
		ms->dl_tbf = NULL;
	}

	llist_for_each_entry_safe(pos, tmp, &ms->old_tbfs, list) {
		struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)pos->entry;
		tbf_set_ms(tbf, NULL);
	}

	llc_queue_clear(&ms->llc_queue, ms->bts);
	osmo_timer_del(&ms->llc_timer);

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

static void ms_release_timer_start(struct GprsMs *ms)
{
	if (ms->delay == 0)
		return;

	LOGPMS(ms, DRLCMAC, LOGL_DEBUG, "Schedule MS release in %u secs\n", ms->delay);

	if (!ms->timer.data)
		ms->timer.data = ms_ref(ms);

	osmo_timer_schedule(&ms->timer, ms->delay, 0);
}

static void ms_release_timer_stop(struct GprsMs *ms)
{
	if (!ms->timer.data)
		return;

	LOGPMS(ms, DRLCMAC, LOGL_DEBUG, "Cancel scheduled MS release\n");

	osmo_timer_del(&ms->timer);
	ms->timer.data = NULL;
	ms_unref(ms);
}

void ms_set_mode(struct GprsMs *ms, enum mcs_kind mode)
{
	ms->mode = mode;

	switch (ms->mode) {
	case GPRS:
		if (!mcs_is_gprs(ms->current_cs_ul)) {
			ms->current_cs_ul = mcs_get_gprs_by_num(
				ms->bts->initial_cs_ul);
			if (!mcs_is_valid(ms->current_cs_ul))
				ms->current_cs_ul = CS1;
		}
		if (!mcs_is_gprs(ms->current_cs_dl)) {
			ms->current_cs_dl = mcs_get_gprs_by_num(
				ms->bts->initial_cs_dl);
			if (!mcs_is_valid(ms->current_cs_dl))
				ms->current_cs_dl = CS1;
		}
		break;

	case EGPRS_GMSK:
		if (!mcs_is_edge_gmsk(ms->current_cs_ul)) {
			ms->current_cs_ul = mcs_get_egprs_by_num(
				ms->bts->initial_mcs_ul);
			if (!mcs_is_valid(ms->current_cs_ul))
				ms->current_cs_ul = MCS1;
		}
		if (!mcs_is_edge_gmsk(ms->current_cs_dl)) {
			ms->current_cs_dl = mcs_get_egprs_by_num(
				ms->bts->initial_mcs_dl);
			if (!mcs_is_valid(ms->current_cs_dl))
				ms->current_cs_dl = MCS1;
		}
		break;
	case EGPRS:
		if (!mcs_is_edge(ms->current_cs_ul)) {
			ms->current_cs_ul = mcs_get_egprs_by_num(
				ms->bts->initial_mcs_ul);
			if (!mcs_is_valid(ms->current_cs_ul))
				ms->current_cs_ul = MCS1;
		}
		if (!mcs_is_edge(ms->current_cs_dl)) {
			ms->current_cs_dl = mcs_get_egprs_by_num(
				ms->bts->initial_mcs_dl);
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

	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Attaching UL TBF: %s\n", tbf_name((struct gprs_rlcmac_tbf *)tbf));

	ms_ref(ms);

	if (ms->ul_tbf)
		llist_add_tail(tbf_ms_list(ul_tbf_as_tbf(ms->ul_tbf)), &ms->old_tbfs);

	ms->ul_tbf = tbf;

	if (tbf)
		ms_release_timer_stop(ms);

	ms_unref(ms);
}

static void ms_attach_dl_tbf(struct GprsMs *ms, struct gprs_rlcmac_dl_tbf *tbf)
{
	if (ms->dl_tbf == tbf)
		return;

	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Attaching DL TBF: %s\n", tbf_name((struct gprs_rlcmac_tbf *)tbf));

	ms_ref(ms);

	if (ms->dl_tbf)
		llist_add_tail(tbf_ms_list(dl_tbf_as_tbf(ms->dl_tbf)), &ms->old_tbfs);

	ms->dl_tbf = tbf;

	if (tbf)
		ms_release_timer_stop(ms);

	ms_unref(ms);
}

void ms_attach_tbf(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf)
{
	if (tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF)
		ms_attach_dl_tbf(ms, tbf_as_dl_tbf(tbf));
	else
		ms_attach_ul_tbf(ms, tbf_as_ul_tbf(tbf));
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

	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Detaching TBF: %s\n",
	       tbf_name(tbf));

	if (tbf_ms(tbf) == ms)
		tbf_set_ms(tbf, NULL);

	if (!ms->dl_tbf && !ms->ul_tbf) {
		ms_set_reserved_slots(ms, NULL, 0, 0);
		ms->first_common_ts = TBF_TS_UNSET;

		if (ms_tlli(ms) != 0)
			ms_release_timer_start(ms);
	}

	ms_update_status(ms);
}

void ms_reset(struct GprsMs *ms)
{
	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Clearing MS object\n");

	ms_release_timer_stop(ms);

	ms->tlli = GSM_RESERVED_TMSI;
	ms->new_dl_tlli = ms->tlli;
	ms->new_ul_tlli = ms->tlli;
	ms->imsi[0] = '\0';
}

/* This function should be called on the MS object of a TBF each time an RLCMAC
 * block is received for it with TLLI information.
 * Besides updating the TLLI field on the MS object, it also seeks for other MS
 * objects in the store and merges them into the current MS object. The MS
 * duplication happened because we don't learn the TLLI of the created TBF until
 * a later point. */
void ms_update_announced_tlli(struct GprsMs *ms, uint32_t tlli)
{
	struct GprsMs *old_ms = NULL;

	if (tlli == GSM_RESERVED_TMSI)
		return;

	/* When the TLLI does not match the ms, check if there is another
	 * MS object that belongs to that TLLI and if yes make sure one of them
	 * gets deleted. */
	if (!ms_check_tlli(ms, tlli))
		old_ms = ms_store_get_ms(bts_ms_store(ms->bts), tlli, GSM_RESERVED_TMSI, NULL);

	ms_set_tlli(ms, tlli);

	if (old_ms)
		ms_merge_and_clear_ms(ms, old_ms);
	/* old_ms may no longer be available here */
}

/* Merge 'old_ms' object into 'ms' object.
 * 'old_ms' may be freed during the call to this function, don't use the pointer to it afterwards */
void ms_merge_and_clear_ms(struct GprsMs *ms, struct GprsMs *old_ms)
{
	char old_ms_name[128];
	OSMO_ASSERT(old_ms != ms);
	ms_ref(old_ms);

	ms_name_buf(old_ms, old_ms_name, sizeof(old_ms_name));

	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Merge MS: %s\n", old_ms_name);

	if (strlen(ms_imsi(ms)) == 0 && strlen(ms_imsi(old_ms)) != 0)
		osmo_strlcpy(ms->imsi, ms_imsi(old_ms), sizeof(ms->imsi));

	if (!ms_ms_class(ms) && ms_ms_class(old_ms))
		ms_set_ms_class(ms, ms_ms_class(old_ms));

	if (!ms_egprs_ms_class(ms) && ms_egprs_ms_class(old_ms))
		ms_set_egprs_ms_class(ms, ms_egprs_ms_class(old_ms));

	llc_queue_move_and_merge(&ms->llc_queue, &old_ms->llc_queue);

	if (!ms_dl_tbf(ms) && ms_dl_tbf(old_ms)) {
		struct gprs_rlcmac_dl_tbf *dl_tbf = ms_dl_tbf(old_ms);
		LOGPTBFDL(dl_tbf, LOGL_NOTICE,
			  "Merge MS: Move DL TBF: %s => %s\n",
			  old_ms_name, ms_name(ms));
		/* Move the DL TBF to the new MS */
		tbf_set_ms(dl_tbf_as_tbf(dl_tbf), ms);
	}

	/* Clean up the old MS object */
	/* TODO: Use timer? */
	if (ms_ul_tbf(old_ms) && !tbf_timers_pending((struct gprs_rlcmac_tbf *)ms_ul_tbf(old_ms), T_MAX))
			tbf_free((struct gprs_rlcmac_tbf *)ms_ul_tbf(old_ms));
	if (ms_dl_tbf(old_ms) && !tbf_timers_pending((struct gprs_rlcmac_tbf *)ms_dl_tbf(old_ms), T_MAX))
			tbf_free((struct gprs_rlcmac_tbf *)ms_dl_tbf(old_ms));

	ms_reset(old_ms);

	ms_unref(old_ms);
}

/* Apply changes to the TLLI directly, used interally by functions below: */
static void ms_apply_tlli_change(struct GprsMs *ms, uint32_t tlli)
{
	ms->tlli = tlli;
	ms->new_dl_tlli = GSM_RESERVED_TMSI;
	ms->new_ul_tlli = GSM_RESERVED_TMSI;

	/* Update TBF FSM names: */
	if (ms->ul_tbf)
		tbf_update_state_fsm_name(ul_tbf_as_tbf(ms->ul_tbf));
	if (ms->dl_tbf)
		tbf_update_state_fsm_name(dl_tbf_as_tbf(ms->dl_tbf));
}

/* Set/update the MS object TLLI based on knowledge gained from the MS side (Uplink direction) */
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

	ms_apply_tlli_change(ms, tlli);
}

/* Set/update the MS object TLLI based on knowledge gained from the SGSN side (Downlink direction) */
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

	ms_apply_tlli_change(ms, tlli);

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
		/* old_ms may no longer be available here */
	}

	/* Store the new IMSI: */
	osmo_strlcpy(ms->imsi, imsi, sizeof(ms->imsi));

	/* Update TBF FSM names: */
	if (ms->ul_tbf)
		tbf_update_state_fsm_name(ul_tbf_as_tbf(ms->ul_tbf));
	if (ms->dl_tbf)
		tbf_update_state_fsm_name(dl_tbf_as_tbf(ms->dl_tbf));
}

uint16_t ms_paging_group(struct GprsMs *ms)
{
	uint16_t pgroup;
	if (!ms_imsi_is_valid(ms))
		return 0; /* 000 is the special "all paging" group */
	if ((pgroup = imsi2paging_group(ms_imsi(ms))) > 999) {
		LOGPMS(ms, DRLCMAC, LOGL_ERROR, "IMSI to paging group failed!\n");
		return 0;
	}
	return pgroup;
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
	enum CodingScheme cs;
	OSMO_ASSERT(ms->bts != NULL);

	if (mcs_is_gprs(ms->current_cs_ul)) {
		if (!bts_max_cs_ul(ms->bts)) {
			return CS4;
		}

		return mcs_get_gprs_by_num(bts_max_cs_ul(ms->bts));
	}

	cs = mcs_get_egprs_by_num(bts_max_mcs_ul(ms->bts));
	if (ms_mode(ms) == EGPRS_GMSK && cs > MCS4)
		cs = MCS4;
	return cs;
}

void ms_set_current_cs_dl(struct GprsMs *ms, enum CodingScheme scheme)
{
	ms->current_cs_dl = scheme;
}

enum CodingScheme ms_max_cs_dl(const struct GprsMs *ms)
{
	enum CodingScheme cs;
	OSMO_ASSERT(ms->bts != NULL);

	if (mcs_is_gprs(ms->current_cs_dl)) {
		if (!bts_max_cs_dl(ms->bts)) {
			return CS4;
		}

		return mcs_get_gprs_by_num(bts_max_cs_dl(ms->bts));
	}

	cs = mcs_get_egprs_by_num(bts_max_mcs_dl(ms->bts));
	if (ms_mode(ms) == EGPRS_GMSK && cs > MCS4)
		cs = MCS4;
	return cs;
}

void ms_update_cs_ul(struct GprsMs *ms, const struct pcu_l1_meas *meas)
{
	enum CodingScheme max_cs_ul = ms_max_cs_ul(ms);

	int old_link_qual;
	int low;
	int high;
	enum CodingScheme new_cs_ul = ms->current_cs_ul;
	uint8_t current_cs = mcs_chan_code(ms->current_cs_ul);

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
		low  = the_pcu->vty.cs_lqual_ranges[current_cs].low;
		high = the_pcu->vty.cs_lqual_ranges[current_cs].high;
	} else if (mcs_is_edge(ms->current_cs_ul)) {
		if (current_cs >= MAX_EDGE_MCS)
			current_cs = MAX_EDGE_MCS - 1;
		low  = the_pcu->vty.mcs_lqual_ranges[current_cs].low;
		high = the_pcu->vty.mcs_lqual_ranges[current_cs].high;
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

/* req_mcs_kind acts as a set filter, where EGPRS means any and GPRS is the most restrictive */
enum CodingScheme ms_current_cs_dl(const struct GprsMs *ms, enum mcs_kind req_mcs_kind)
{
	enum CodingScheme orig_cs = ms->current_cs_dl;
	struct gprs_rlcmac_bts *bts = ms->bts;
	size_t unencoded_octets;
	enum CodingScheme cs;

	/* It could be that a TBF requests a GPRS CS despite the MS currently
	   being upgraded to EGPRS (hence reporting MCS). That could happen
	   because the TBF was created early in the process where we didn't have
	   yet enough information about the MS, and only AFTER it was created we
	   upgraded the MS to be EGPRS capable.
	   As a result, when  the MS is queried for the target CS here, we could be
	   returning an MCS despite the current TBF being established as GPRS,
	   but we rather stick to the TBF type we assigned to the MS rather than
	   magically sending EGPRS data blocks to a GPRS TBF.
	   It could also be that the caller requests specific MCS kind
	   explicitly too due to scheduling restrictions (GPRS+EGPRS multiplexing). */
	if (req_mcs_kind == EGPRS_GMSK && mcs_is_edge(orig_cs) && orig_cs > MCS4) {
		cs = bts_cs_dl_is_supported(bts, MCS4) ? MCS4 :
		     bts_cs_dl_is_supported(bts, MCS3) ? MCS3 :
		     bts_cs_dl_is_supported(bts, MCS2) ? MCS2 :
		     MCS1;
	} else if (req_mcs_kind == GPRS && mcs_is_edge(orig_cs)) { /* GPRS */
			int i;
			cs = orig_cs > MCS4 ? MCS4 : orig_cs;
			cs -= (MCS1 - CS1); /* MCSx -> CSx */
			/* Find suitable CS starting from equivalent MCS which is supported by BTS: */
			for (i = mcs_chan_code(cs); !bts_cs_dl_is_supported(bts, CS1 + i); i--);
			OSMO_ASSERT(i >= 0 && i <= 3); /* CS1 is always supported */
			cs = CS1 + i;
	} else {
		cs = orig_cs;
	}

	if (orig_cs != cs)
		LOGPMS(ms, DRLCMACDL, LOGL_INFO, "MS (mode=%s) suggests transmitting "
			"DL %s, downgrade to %s in order to match TBF & scheduler requirements\n",
			mode_name(ms_mode(ms)), mcs_name(orig_cs), mcs_name(cs));

	unencoded_octets = llc_queue_octets(&ms->llc_queue);

	/* If the DL TBF is active, add number of unencoded chunk octets */
	if (ms->dl_tbf)
		unencoded_octets += llc_chunk_size(tbf_llc(dl_tbf_as_tbf(ms->dl_tbf)));

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

int8_t ms_first_common_ts(const struct GprsMs *ms)
{
	return ms->first_common_ts;
}

void ms_set_first_common_ts(struct GprsMs *ms, uint8_t first_common_ts)
{
	OSMO_ASSERT(first_common_ts < 8);
	ms->first_common_ts = first_common_ts;
}

uint8_t ms_dl_slots(const struct GprsMs *ms)
{
	uint8_t slots = 0;

	if (ms->dl_tbf)
		slots |= tbf_dl_slots(dl_tbf_as_tbf(ms->dl_tbf));

	if (ms->ul_tbf)
		slots |= tbf_dl_slots(ul_tbf_as_tbf(ms->ul_tbf));

	return slots;
}

uint8_t ms_ul_slots(const struct GprsMs *ms)
{
	uint8_t slots = 0;

	if (ms->dl_tbf)
		slots |= tbf_ul_slots(dl_tbf_as_tbf(ms->dl_tbf));

	if (ms->ul_tbf)
		slots |= tbf_ul_slots(ul_tbf_as_tbf(ms->ul_tbf));

	return slots;
}

uint8_t ms_current_pacch_slots(const struct GprsMs *ms)
{
	uint8_t slots = 0;

	bool is_dl_active = ms->dl_tbf && tbf_is_tfi_assigned(dl_tbf_as_tbf(ms->dl_tbf));
	bool is_ul_active = ms->ul_tbf && tbf_is_tfi_assigned(ul_tbf_as_tbf(ms->ul_tbf));

	if (!is_dl_active && !is_ul_active)
		return 0;

	/* see TS 44.060, 8.1.1.2.2 */
	if (is_dl_active && !is_ul_active)
		slots =  tbf_dl_slots(dl_tbf_as_tbf(ms->dl_tbf));
	else if (!is_dl_active && is_ul_active)
		slots =  tbf_ul_slots(ul_tbf_as_tbf(ms->ul_tbf));
	else
		slots =  tbf_ul_slots(ul_tbf_as_tbf(ms->ul_tbf)) &
			 tbf_dl_slots(dl_tbf_as_tbf(ms->dl_tbf));

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
	case GPRS_RLCMAC_DL_TBF: return dl_tbf_as_tbf(ms->dl_tbf);
	case GPRS_RLCMAC_UL_TBF: return ul_tbf_as_tbf(ms->ul_tbf);
	}

	return NULL;
}

const char *ms_name(const struct GprsMs *ms)
{
	static char _ms_name_buf[128];
	return ms_name_buf(ms, _ms_name_buf, sizeof(_ms_name_buf));
}

char *ms_name_buf(const struct GprsMs *ms, char *buf, unsigned int buf_size)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_size };
	uint32_t tlli = ms_tlli(ms);

	OSMO_STRBUF_PRINTF(sb, "MS(");
	if (ms_imsi_is_valid(ms))
		OSMO_STRBUF_PRINTF(sb, "IMSI-%s:", ms_imsi(ms));
	if (tlli != GSM_RESERVED_TMSI)
		OSMO_STRBUF_PRINTF(sb, "TLLI-0x%08x:", tlli);
	OSMO_STRBUF_PRINTF(sb, "TA-%" PRIu8 ":MSCLS-%" PRIu8 "-%" PRIu8,
			   ms_ta(ms), ms_ms_class(ms), ms_egprs_ms_class(ms));
	if (ms->ul_tbf)
		OSMO_STRBUF_PRINTF(sb, ":UL");
	if (ms->dl_tbf)
		OSMO_STRBUF_PRINTF(sb, ":DL");

	OSMO_STRBUF_PRINTF(sb, ")");
	return buf;
}

int ms_nacc_start(struct GprsMs *ms, Packet_Cell_Change_Notification_t *notif)
{
	if (!ms->nacc)
		ms->nacc = nacc_fsm_alloc(ms);
	if (!ms->nacc)
		return -EINVAL;
	return osmo_fsm_inst_dispatch(ms->nacc->fi, NACC_EV_RX_CELL_CHG_NOTIFICATION, notif);
}

bool ms_nacc_rts(const struct GprsMs *ms)
{
	if (!ms->nacc)
		return false;
	if (ms->nacc->fi->state == NACC_ST_TX_NEIGHBOUR_DATA ||
	    ms->nacc->fi->state == NACC_ST_TX_CELL_CHG_CONTINUE)
		return true;
	return false;
}

struct msgb *ms_nacc_create_rlcmac_msg(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf,
				       const struct gprs_rlcmac_pdch *pdch, uint32_t fn)
{
	int rc;
	struct nacc_ev_create_rlcmac_msg_ctx data_ctx;

	data_ctx = (struct nacc_ev_create_rlcmac_msg_ctx) {
			.tbf = tbf,
			.pdch = pdch,
			.fn = fn,
			.msg = NULL,
	};

	rc = osmo_fsm_inst_dispatch(ms->nacc->fi, NACC_EV_CREATE_RLCMAC_MSG, &data_ctx);
	if (rc != 0 || !data_ctx.msg)
		return NULL;
	return data_ctx.msg;
}

static void ms_start_llc_timer(struct GprsMs *ms)
{
	if (the_pcu->vty.llc_idle_ack_csec > 0) {
		struct timespec tv;
		csecs_to_timespec(the_pcu->vty.llc_idle_ack_csec, &tv);
		osmo_timer_schedule(&ms->llc_timer, tv.tv_sec, tv.tv_nsec / 1000);
	}
}

/* Can we get to send a DL TBF ass to the MS? */
static bool ms_is_reachable_for_dl_ass(const struct GprsMs *ms)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf = ms_ul_tbf(ms);

	/* This function assumes it is called when no DL TBF is present */
	OSMO_ASSERT(!ms_dl_tbf(ms));

	/* 3GPP TS 44.060 sec 7.1.3.1 Initiation of the Packet resource request procedure:
	* "Furthermore, the mobile station shall not respond to PACKET DOWNLINK ASSIGNMENT
	* or MULTIPLE TBF DOWNLINK ASSIGNMENT messages before contention resolution is
	* completed on the mobile station side." */
	/* The possible uplink TBF is used to trigger downlink assignment:
	* - If there is no uplink TBF the MS is potentially in packet idle mode
	* and hence assignment will be done over CCCH (PCH)
	* - If there's an uplink TBF but it is finished (waiting for last PKT
	* CTRL ACK after sending last Pkt UL ACK/NACK with FINAL_ACK=1, then we
	* have no ways to contact the MS right now. Assignment will be delayed
	* until PKT CTRL ACK is received and the TBF is released at the MS side
	* (then assignment goes through PCH).
	*/
	if (!ul_tbf)
		return true;
	if (ul_tbf_contention_resolution_done(ul_tbf) &&
	    !tbf_ul_ack_waiting_cnf_final_ack(ul_tbf))
		return true;

	return false;

}

/* Alloc a UL TBF to be assigned over PACCH. Called when an MS requests to
 * create a new UL TBF during the end of life of a previous UL TBF (or an SBA).
 * In summary, this TBF is allocated as a consequence of receiving a "Pkt
 * Resource Req" or "Pkt Ctrl Ack" from the MS.
 * See TS 44.060 9.3.2.4.2 "Non-extended uplink TBF mode".
 */
struct gprs_rlcmac_ul_tbf *ms_new_ul_tbf_assigned_pacch(struct GprsMs *ms, int8_t use_trx)
{
	const bool single_slot = false;
	struct gprs_rlcmac_ul_tbf *ul_tbf;

	ul_tbf = ul_tbf_alloc(ms->bts, ms, use_trx, single_slot);
	if (!ul_tbf) {
		LOGPMS(ms, DTBF, LOGL_NOTICE, "No PDCH resource\n");
		/* Caller will most probably send a Imm Ass Reject after return */
		return NULL;
	}
	osmo_fsm_inst_dispatch(tbf_state_fi(ul_tbf_as_tbf(ul_tbf)), TBF_EV_ASSIGN_ADD_PACCH, NULL);
	/* Contention resolution is considered to be done since TLLI is known in MS */
	return ul_tbf;
}

/* Alloc a UL TBF to be assigned over AGCH. Used by request of a "One phase
 * packet access", where MS requested only 1 PDCH TS (TS 44.018 Table 9.1.8.1). */
struct gprs_rlcmac_ul_tbf *ms_new_ul_tbf_assigned_agch(struct GprsMs *ms)
{
	const int8_t trx_no = -1;
	const bool single_slot = true;
	struct gprs_rlcmac_ul_tbf *ul_tbf;

	ul_tbf = ul_tbf_alloc(ms->bts, ms, trx_no, single_slot);
	if (!ul_tbf) {
		LOGP(DTBF, LOGL_NOTICE, "No PDCH resource for Uplink TBF\n");
		/* Caller will most probably send a Imm Ass Reject after return */
		return NULL;
	}
	osmo_fsm_inst_dispatch(tbf_state_fi(ul_tbf_as_tbf(ul_tbf)), TBF_EV_ASSIGN_ADD_CCCH, NULL);
	return ul_tbf;
}

/* A new DL-TBF is allocated and assigned through PACCH using "tbf".
 * "tbf" may be either a UL-TBF or a DL-TBF.
 * Note: This should be called only when MS is reachable, see ms_is_reachable_for_dl_ass().
 */
int ms_new_dl_tbf_assigned_on_pacch(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf)
{
	OSMO_ASSERT(tbf);
	const int8_t trx_no = tbf_get_trx(tbf)->trx_no;
	const bool single_slot = false;
	struct gprs_rlcmac_dl_tbf *dl_tbf;

	dl_tbf = dl_tbf_alloc(ms->bts, ms, trx_no, single_slot);
	if (!dl_tbf) {
		LOGPMS(ms, DTBF, LOGL_NOTICE, "No PDCH resource\n");
		return -EBUSY;
	}

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "[DOWNLINK] START (PACCH)\n");
	dl_tbf_trigger_ass_on_pacch(dl_tbf, tbf);
	return 0;
}

/* A new DL-TBF is allocated and assigned through PCH.
 * Note: This should be called only when MS is reachable, see ms_is_reachable_for_dl_ass().
 */
int ms_new_dl_tbf_assigned_on_pch(struct GprsMs *ms)
{
	const int8_t trx_no = -1;
	const bool single_slot = true;
	struct gprs_rlcmac_dl_tbf *dl_tbf;

	dl_tbf = dl_tbf_alloc(ms->bts, ms, trx_no, single_slot);
	if (!dl_tbf) {
		LOGPMS(ms, DTBF, LOGL_NOTICE, "No PDCH resource\n");
		return -EBUSY;
	}

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "[DOWNLINK] START (PCH)\n");
	dl_tbf_trigger_ass_on_pch(dl_tbf);
	return 0;
}

int ms_append_llc_dl_data(struct GprsMs *ms, uint16_t pdu_delay_csec, const uint8_t *data, uint16_t len)
{
	struct timespec expire_time;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	int rc = 0;

	LOGPMS(ms, DTBFDL, LOGL_DEBUG, "appending %u bytes to DL LLC queue\n", len);

	struct msgb *llc_msg = msgb_alloc(len, "llc_pdu_queue");
	if (!llc_msg)
		return -ENOMEM;

	llc_queue_calc_pdu_lifetime(ms->bts, pdu_delay_csec, &expire_time);
	memcpy(msgb_put(llc_msg, len), data, len);
	llc_queue_enqueue(ms_llc_queue(ms), llc_msg, &expire_time);
	ms_start_llc_timer(ms);

	dl_tbf = ms_dl_tbf(ms);
	if (dl_tbf) {
		if (tbf_state(dl_tbf_as_tbf_const(dl_tbf)) == TBF_ST_WAIT_RELEASE) {
			LOGPTBFDL(dl_tbf, LOGL_DEBUG, "in WAIT RELEASE state (T3193), so reuse TBF\n");
			rc = ms_new_dl_tbf_assigned_on_pacch(ms, dl_tbf_as_tbf(dl_tbf));
		}
	} else {
		/* Check if we can create a DL TBF to start sending the enqueued
		 * data. Otherwise it will be triggered later when it is reachable
		* again. */
		if (ms_is_reachable_for_dl_ass(ms)) {
			if (ms_ul_tbf(ms))
				rc = ms_new_dl_tbf_assigned_on_pacch(ms, ul_tbf_as_tbf(ms_ul_tbf(ms)));
			else
				rc = ms_new_dl_tbf_assigned_on_pch(ms);
		}
	}
	return rc;
}
