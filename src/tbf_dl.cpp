/* Copied from tbf.cpp
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

#include <bts.h>
#include <tbf.h>
#include <tbf_dl.h>
#include <tbf_ul.h>
#include <rlc.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <gprs_codel.h>
#include <decoding.h>
#include <encoding.h>
#include <gprs_ms.h>
#include <llc.h>
#include "pcu_utils.h"
#include "alloc_algo.h"

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_bssgp_bss.h>
	#include <osmocom/core/bitvec.h>
	#include <osmocom/core/linuxlist.h>
	#include <osmocom/core/logging.h>
	#include <osmocom/core/rate_ctr.h>
	#include <osmocom/core/stats.h>
	#include <osmocom/core/timer.h>
	#include <osmocom/core/utils.h>
	#include <osmocom/gsm/gsm_utils.h>
	#include <osmocom/gsm/protocol/gsm_04_08.h>
	#include "coding_scheme.h"
}

#include <errno.h>
#include <string.h>

/* After sending these frames, we poll for ack/nack. */
#define POLL_ACK_AFTER_FRAMES 20

extern void *tall_pcu_ctx;

static const struct rate_ctr_desc tbf_dl_gprs_ctr_description[] = {
	{ "gprs:downlink:cs1",              "CS1        " },
	{ "gprs:downlink:cs2",              "CS2        " },
	{ "gprs:downlink:cs3",              "CS3        " },
	{ "gprs:downlink:cs4",              "CS4        " },
};

static const struct rate_ctr_desc tbf_dl_egprs_ctr_description[] = {
	{ "egprs:downlink:mcs1",            "MCS1        " },
	{ "egprs:downlink:mcs2",            "MCS2        " },
	{ "egprs:downlink:mcs3",            "MCS3        " },
	{ "egprs:downlink:mcs4",            "MCS4        " },
	{ "egprs:downlink:mcs5",            "MCS5        " },
	{ "egprs:downlink:mcs6",            "MCS6        " },
	{ "egprs:downlink:mcs7",            "MCS7        " },
	{ "egprs:downlink:mcs8",            "MCS8        " },
	{ "egprs:downlink:mcs9",            "MCS9        " },
};

static const struct rate_ctr_group_desc tbf_dl_gprs_ctrg_desc = {
	"tbf:gprs",
	"Data Blocks",
	OSMO_STATS_CLASS_SUBSCRIBER,
	ARRAY_SIZE(tbf_dl_gprs_ctr_description),
	tbf_dl_gprs_ctr_description,
};

static const struct rate_ctr_group_desc tbf_dl_egprs_ctrg_desc = {
	"tbf:egprs",
	"Data Blocks",
	OSMO_STATS_CLASS_SUBSCRIBER,
	ARRAY_SIZE(tbf_dl_egprs_ctr_description),
	tbf_dl_egprs_ctr_description,
};

gprs_rlcmac_dl_tbf::BandWidth::BandWidth() :
	dl_bw_octets(0),
	dl_throughput(0),
	dl_loss_lost(0),
	dl_loss_received(0)
{
	osmo_clock_gettime(CLOCK_MONOTONIC, &dl_bw_tv);
	osmo_clock_gettime(CLOCK_MONOTONIC, &dl_loss_tv);
}

static int dl_tbf_dtor(struct gprs_rlcmac_dl_tbf *tbf)
{
	tbf->~gprs_rlcmac_dl_tbf();
	return 0;
}

struct gprs_rlcmac_dl_tbf *dl_tbf_alloc(struct gprs_rlcmac_bts *bts, struct GprsMs *ms)
{
	struct gprs_rlcmac_dl_tbf *tbf;

	OSMO_ASSERT(ms != NULL);

	LOGPMS(ms, DTBF, LOGL_DEBUG, "********** DL-TBF starts here **********\n");
	LOGPMS(ms, DTBF, LOGL_INFO, "Allocating DL TBF\n");

	tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_dl_tbf);

	if (!tbf)
		return NULL;

	talloc_set_destructor(tbf, dl_tbf_dtor);
	new (tbf) gprs_rlcmac_dl_tbf(bts, ms);

	if (tbf->is_egprs_enabled()) {
		tbf->m_dl_egprs_ctrs = rate_ctr_group_alloc(tbf,
							&tbf_dl_egprs_ctrg_desc,
							tbf->m_ctrs->idx);
		if (!tbf->m_dl_egprs_ctrs) {
			LOGPTBF(tbf, LOGL_ERROR, "Couldn't allocate EGPRS DL counters\n");
			talloc_free(tbf);
			return NULL;
		}
	} else {
		tbf->m_dl_gprs_ctrs = rate_ctr_group_alloc(tbf,
							&tbf_dl_gprs_ctrg_desc,
							tbf->m_ctrs->idx);
		if (!tbf->m_dl_gprs_ctrs) {
			LOGPTBF(tbf, LOGL_ERROR, "Couldn't allocate GPRS DL counters\n");
			talloc_free(tbf);
			return NULL;
		}
	}
	bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_DL_ALLOCATED);

	return tbf;
}

gprs_rlcmac_dl_tbf::~gprs_rlcmac_dl_tbf()
{
	if (is_egprs_enabled()) {
		rate_ctr_group_free(m_dl_egprs_ctrs);
	} else {
		rate_ctr_group_free(m_dl_gprs_ctrs);
	}
	/* ~gprs_rlcmac_tbf() is called automatically upon return */
}

gprs_rlcmac_dl_tbf::gprs_rlcmac_dl_tbf(struct gprs_rlcmac_bts *bts_, GprsMs *ms) :
	gprs_rlcmac_tbf(bts_, ms, GPRS_RLCMAC_DL_TBF),
	m_tx_counter(0),
	m_dl_ack_requested(false),
	m_last_dl_poll_fn(-1),
	m_last_dl_poll_ack_lost(false),
	m_last_dl_drained_fn(-1),
	m_first_dl_ack_rcvd(false),
	m_dl_gprs_ctrs(NULL),
	m_dl_egprs_ctrs(NULL)
{
	memset(&state_fsm, 0, sizeof(state_fsm));
	state_fsm.dl_tbf = this;
	state_fi = osmo_fsm_inst_alloc(&tbf_dl_fsm, this, &state_fsm, LOGL_INFO, NULL);
	OSMO_ASSERT(state_fi);

	INIT_LLIST_HEAD(&this->tx_llc_until_first_dl_ack_rcvd);

	/* This has to be called in child constructor because enable_egprs()
	 * uses the window() virtual function which is dependent on subclass. */
	if (ms_mode(m_ms) != GPRS)
		enable_egprs();
}

/**
 * TODO: split into unit test-able parts...
 */
int dl_tbf_handle(struct gprs_rlcmac_bts *bts,
		  const uint32_t tlli, const uint32_t tlli_old, const char *imsi,
		  uint8_t ms_class, uint8_t egprs_ms_class,
		  const uint16_t delay_csec,
		  const uint8_t *data, const uint16_t len)
{
	int rc;
	GprsMs *ms, *ms_old;
	bool ms_allocated = false;

	/* check for existing TBF */
	ms = bts_get_ms(bts, tlli, tlli_old, imsi);

	/* If we got MS by TLLI above let's see if we already have another MS
	 * object identified by IMSI and merge them */
	if (ms) {
		if (!ms_imsi_is_valid(ms) && imsi) {
			ms_old = bts_get_ms_by_imsi(bts, imsi);
			if (ms_old && ms_old != ms) {
				/* The TLLI has changed (RAU), so there are two MS
				* objects for the same MS */
				LOGP(DTBF, LOGL_NOTICE,
				"There is a new MS object for the same MS: (0x%08x, '%s') -> (0x%08x, '%s')\n",
				ms_tlli(ms_old), ms_imsi(ms_old), ms_tlli(ms), ms_imsi(ms));
				ms_merge_and_clear_ms(ms, ms_old);
				/* old_ms may no longer be available here */
			}
		}
	} else {
		ms = ms_alloc(bts, __func__);
		/* Remember we have to unref the alloc reference at the end: */
		ms_allocated = true;
	}
	if (imsi)
		ms_set_imsi(ms, imsi);
	ms_confirm_tlli(ms, tlli);
	if (!ms_ms_class(ms) && ms_class) {
		ms_set_ms_class(ms, ms_class);
	}
	if (!ms_egprs_ms_class(ms) && egprs_ms_class) {
		ms_set_egprs_ms_class(ms, egprs_ms_class);
	}

	rc = ms_append_llc_dl_data(ms, delay_csec, data, len);
	if (ms_allocated) {
		ms_unref(ms, __func__);
		/* Here "ms" may be freed if ms_append_llc_dl_data() failed to
		 * allocate a DL TBF and it has no more TBFs attached */
	}
	return rc;
}

bool gprs_rlcmac_dl_tbf::restart_bsn_cycle()
{
	/* If V(S) == V(A) and finished state, we would have received
	 * acknowledgement of all transmitted block.  In this case we would
	 * have transmitted the final block, and received ack from MS. But in
	 * this case we did not receive the final ack indication from MS.  This
	 * should never happen if MS works correctly.
	 */
	if (m_window.window_empty()) {
		LOGPTBFDL(this, LOGL_DEBUG, "MS acked all blocks\n");
		return false;
	}

	/* cycle through all unacked blocks */
	int resend = m_window.mark_for_resend();

	/* At this point there should be at least one unacked block
	 * to be resent. If not, this is an software error. */
	if (resend == 0) {
		LOGPTBFDL(this, LOGL_ERROR,
			  "FIXME: Software error: There are no unacknowledged blocks, but V(A) != V(S). PLEASE FIX!\n");
		return false;
	}

	return true;
}

int gprs_rlcmac_dl_tbf::take_next_bsn(uint32_t fn,
	int previous_bsn, enum mcs_kind req_mcs_kind, bool *may_combine)
{
	int bsn;
	int data_len2, force_data_len = -1;
	enum CodingScheme tx_cs;

	/* Scheduler may be fine with sending any kind of data, but if
	   the selected TBF is GPRS-only, then let's filter out EGPRS
	   here */
	if (!is_egprs_enabled())
		req_mcs_kind = GPRS;

	/* search for a nacked or resend marked bsn */
	bsn = m_window.resend_needed();

	if (previous_bsn >= 0) {
		tx_cs = m_rlc.block(previous_bsn)->cs_current_trans;
		if (!mcs_is_edge(tx_cs))
			return -1;
		force_data_len = m_rlc.block(previous_bsn)->len;
	} else {
		tx_cs = ms_current_cs_dl(ms(), req_mcs_kind);
	}

	if (bsn >= 0) {
		/* resend an unacked bsn or resend bsn. */
		if (previous_bsn == bsn)
			return -1;

		if (previous_bsn >= 0 &&
			m_window.mod_sns(bsn - previous_bsn) > RLC_EGPRS_MAX_BSN_DELTA)
			return -1;

		if (is_egprs_enabled()) {
			/* Table 8.1.1.2 and Table 8.1.1.1 of 44.060 */
			m_rlc.block(bsn)->cs_current_trans = get_retx_mcs(m_rlc.block(bsn)->cs_init, tx_cs,
									  bts->pcu->vty.dl_arq_type == EGPRS_ARQ1);

			LOGPTBFDL(this, LOGL_DEBUG,
				  "initial_cs_dl(%s) last_mcs(%s) demanded_mcs(%s) cs_trans(%s) arq_type(%d) bsn(%d)\n",
				  mcs_name(m_rlc.block(bsn)->cs_init),
				  mcs_name(m_rlc.block(bsn)->cs_last),
				  mcs_name(tx_cs),
				  mcs_name(m_rlc.block(bsn)->cs_current_trans),
				  the_pcu->vty.dl_arq_type, bsn);

			/* TODO: Need to remove this check when MCS-8 -> MCS-6
			 * transistion is handled.
			 * Refer commit be881c028fc4da00c4046ecd9296727975c206a3
			 */
			if (m_rlc.block(bsn)->cs_init == MCS8)
				m_rlc.block(bsn)->cs_current_trans =
					MCS8;
		} else {
			/* gprs */
			m_rlc.block(bsn)->cs_current_trans =
					m_rlc.block(bsn)->cs_last;
		}

		data_len2 = m_rlc.block(bsn)->len;
		if (force_data_len > 0 && force_data_len != data_len2)
			return -1;
		LOGPTBFDL(this, LOGL_DEBUG, "Resending BSN %d\n", bsn);
		/* re-send block with negative aknowlegement */
		m_window.m_v_b.mark_unacked(bsn);
		bts_do_rate_ctr_inc(bts, CTR_RLC_RESENT);
	} else if (state_is(TBF_ST_FINISHED)) {
		/* If the TBF is in finished, we already sent all packages at least once.
		 * If any packages could have been sent (because of unacked) it should have
		 * been catched up by the upper if(bsn >= 0) */
		LOGPTBFDL(this, LOGL_DEBUG,
			  "Restarting at BSN %d, because all blocks have been transmitted.\n",
			  m_window.v_a());
		bts_do_rate_ctr_inc(bts, CTR_RLC_RESTARTED);
		if (restart_bsn_cycle())
			return take_next_bsn(fn, previous_bsn, req_mcs_kind, may_combine);
	} else if (dl_window_stalled()) {
		/* There are no more packages to send, but the window is stalled.
		 * Restart the bsn_cycle to resend all unacked messages */
		LOGPTBFDL(this, LOGL_NOTICE,
			  "Restarting at BSN %d, because the window is stalled.\n",
			  m_window.v_a());
		bts_do_rate_ctr_inc(bts, CTR_RLC_STALLED);
		if (restart_bsn_cycle())
			return take_next_bsn(fn, previous_bsn, req_mcs_kind, may_combine);
	} else if (have_data()) {
		/* The window has space left, generate new bsn */
		LOGPTBFDL(this, LOGL_DEBUG,
			  "Sending new block at BSN %d, CS=%s%s\n",
			  m_window.v_s(), mcs_name(tx_cs),
			  force_data_len != -1 ? " (forced)" : "");

		bsn = create_new_bsn(fn, tx_cs);
	} else if (bts->pcu->vty.dl_tbf_preemptive_retransmission && !m_window.window_empty()) {
		/* The window contains unacked packages, but not acked.
		 * Mark unacked bsns as RESEND */
		LOGPTBFDL(this, LOGL_DEBUG,
			  "Restarting at BSN %d, because all blocks have been transmitted (FLOW).\n",
			  m_window.v_a());
		bts_do_rate_ctr_inc(bts, CTR_RLC_RESTARTED);
		if (restart_bsn_cycle())
			return take_next_bsn(fn, previous_bsn, req_mcs_kind, may_combine);
	} else {
		/* Nothing left to send, create dummy LLC commands */
		LOGPTBFDL(this, LOGL_DEBUG,
			  "Sending new dummy block at BSN %d, CS=%s\n",
			  m_window.v_s(), mcs_name(tx_cs));
		bsn = create_new_bsn(fn, tx_cs);
		/* Don't send a second block, so don't set cs_current_trans */
	}

	if (bsn < 0) {
		/* we just send final block again */
		LOGPTBFDL(this, LOGL_DEBUG,
			  "Nothing else to send, Re-transmit final block!\n");
		bsn = m_window.v_s_mod(-1);
		bts_do_rate_ctr_inc(bts, CTR_RLC_FINAL_BLOCK_RESENT);
		bts_do_rate_ctr_inc(bts, CTR_RLC_RESENT);
	}

	*may_combine = num_data_blocks(mcs_header_type(m_rlc.block(bsn)->cs_current_trans)) > 1;

	return bsn;
}

/*
 * Create DL data block
 * The messages are fragmented and forwarded as data blocks.
 */
struct msgb *gprs_rlcmac_dl_tbf::create_dl_acked_block(uint32_t fn, const struct gprs_rlcmac_pdch *pdch, enum mcs_kind req_mcs_kind)
{
	int bsn, bsn2 = -1;
	bool may_combine;

	LOGPTBFDL(this, LOGL_DEBUG, "downlink (V(A)==%d .. V(S)==%d) mcs_mode_restrict=%s\n",
		  m_window.v_a(), m_window.v_s(), mode_name(req_mcs_kind));

	bsn = take_next_bsn(fn, -1, req_mcs_kind, &may_combine);
	if (bsn < 0)
		return NULL;

	if (may_combine)
		bsn2 = take_next_bsn(fn, bsn, req_mcs_kind, &may_combine);

	return create_dl_acked_block(fn, pdch, bsn, bsn2);
}

void gprs_rlcmac_dl_tbf::apply_allocated_resources(const struct alloc_resources_res *res)
{
	uint8_t ts;

	if (this->trx)
		llist_del(&this->m_trx_list.list);

	llist_add(&this->m_trx_list.list, &res->trx->dl_tbfs);

	this->trx = res->trx;
	this->upgrade_to_multislot = res->upgrade_to_multislot;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
		OSMO_ASSERT(!this->pdch[pdch->ts_no]);
		if (!(res->ass_slots_mask & (1 << ts)))
			continue;
		LOGPTBFDL(this, LOGL_DEBUG, "Assigning TS=%u TFI=%d\n",
			  ts, res->tfi);

		this->m_tfi = res->tfi;

		this->pdch[pdch->ts_no] = pdch;
		pdch->attach_tbf(this);
	}

	/* assign initial control ts */
	tbf_assign_control_ts(this);

	LOGPTBF(this, LOGL_INFO,
		"Allocated: trx = %d, ul_slots = %02x, dl_slots = %02x\n",
		this->trx->trx_no, ul_slots(), dl_slots());

	if (tbf_is_egprs_enabled(this))
		this->set_window_size();

	tbf_update_state_fsm_name(this);
}

void dl_tbf_apply_allocated_resources(struct gprs_rlcmac_dl_tbf *dl_tbf, const struct alloc_resources_res *res)
{
	dl_tbf->apply_allocated_resources(res);
}

/* old_tbf (UL TBF or DL TBF) will send a Pkt Dl Ass on PACCH to assign tbf.
 * Note: It is possible that "tbf == old_tbf" if the TBF is being updated. This can
 * happen when we first assign over PCH (only single slot is possible) and we want
 * to upgrade the DL-TBF to be multislot. See code calling tbf_update() for more
 * information.
 */
void dl_tbf_trigger_ass_on_pacch(struct gprs_rlcmac_dl_tbf *tbf, struct gprs_rlcmac_tbf *old_tbf)
{
	OSMO_ASSERT(tbf);
	OSMO_ASSERT(old_tbf);
	/* stop pending timer */
	tbf_stop_timers(tbf, "DL assignment (PACCH)");

	LOGPTBFDL(tbf, LOGL_DEBUG, "Send downlink assignment on PACCH, because %s exists\n", old_tbf->name());
	osmo_fsm_inst_dispatch(old_tbf->dl_ass_fsm.fi, TBF_DL_ASS_EV_SCHED_ASS, NULL);

	/* change state */
	osmo_fsm_inst_dispatch(tbf->state_fi, TBF_EV_ASSIGN_ADD_PACCH, NULL);

}

void dl_tbf_trigger_ass_on_pch(struct gprs_rlcmac_dl_tbf *tbf)
{
	/* stop pending timer */
	struct GprsMs *ms = tbf_ms(tbf);

	tbf_stop_timers(tbf, "DL assignment (PCH)");

	LOGPTBFDL(tbf, LOGL_DEBUG, "Send downlink assignment on PCH, no TBF exist (IMSI=%s)\n", ms_imsi(ms));

	/* change state */
	osmo_fsm_inst_dispatch(tbf->state_fi, TBF_EV_ASSIGN_ADD_CCCH, NULL);
}

int dl_tbf_upgrade_to_multislot(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	int rc;
	struct gprs_rlcmac_tbf *tbf = dl_tbf_as_tbf(dl_tbf);
	struct gprs_rlcmac_trx *trx = tbf_get_trx(dl_tbf);
	struct gprs_rlcmac_bts *bts = trx->bts;
	struct GprsMs *ms = tbf->ms();

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "Upgrade to multislot\n");

	tbf_unlink_pdch(dl_tbf);

	const struct alloc_resources_req req = {
		.bts = bts,
		.ms = ms,
		.direction = tbf_direction(tbf),
		.single = false,
		.use_trx = -1,
	};
	struct alloc_resources_res res = {};

	rc = the_pcu->alloc_algorithm(&req, &res);
	/* if no resource */
	if (rc < 0) {
		LOGPTBFDL(dl_tbf, LOGL_ERROR, "No resources allocated during upgrade to multislot!\n");
		bts_do_rate_ctr_inc(bts, CTR_TBF_ALLOC_FAIL);
		return rc;
	}

	/* Update MS, really allocate the resources */
	if (res.reserved_ul_slots != ms_reserved_ul_slots(ms) ||
	    res.reserved_dl_slots != ms_reserved_dl_slots(ms)) {
		/* The reserved slots have changed, update the MS */
		ms_set_reserved_slots(ms, res.trx, res.reserved_ul_slots, res.reserved_dl_slots);
	}
	ms_set_first_common_ts(ms, res.first_common_ts);

	/* Apply allocated resources to TBF: */
	dl_tbf_apply_allocated_resources(dl_tbf, &res);

	/* Note: No need to call ms_attach_tbf(), tbf is already attached to the MS */

	/* Now trigger the assignment using the pre-existing TBF: */
	dl_tbf_trigger_ass_on_pacch(dl_tbf, tbf);
	return 0;
}

void gprs_rlcmac_dl_tbf::schedule_next_frame()
{
	struct msgb *msg;

	if (llc_frame_length(&m_llc) != 0)
		return;

	/* dequeue next LLC frame, if any */
	msg = llc_queue_dequeue(llc_queue(), &m_llc.prio, &m_llc.meta_info);
	if (!msg)
		return;

	LOGPTBFDL(this, LOGL_DEBUG, "Dequeue next LLC (len=%d)\n", msg->len);

	llc_put_frame(&m_llc, msg->data, msg->len);
	bts_do_rate_ctr_inc(bts, CTR_LLC_FRAME_SCHED);
	msgb_free(msg);
	m_last_dl_drained_fn = -1;
}

int gprs_rlcmac_dl_tbf::create_new_bsn(const uint32_t fn, enum CodingScheme cs)
{
	uint8_t *data;
	gprs_rlc_data *rlc_data;
	const uint16_t bsn = m_window.v_s();
	gprs_rlc_data_block_info *rdbi;
	int num_chunks = 0;
	int write_offset = 0;
	Encoding::AppendResult ar;

	if (llc_frame_length(&m_llc) == 0)
		schedule_next_frame();

	OSMO_ASSERT(mcs_is_valid(cs));

	/* length of usable data block (single data unit w/o header) */
	const uint8_t block_data_len = mcs_max_data_block_bytes(cs);

	/* now we still have untransmitted LLC data, so we fill mac block */
	rlc_data = m_rlc.block(bsn);
	data = prepare(rlc_data, block_data_len);
	rlc_data->cs_last = cs;
	rlc_data->cs_current_trans = cs;

	/* Initialise the variable related to DL SPB */
	rlc_data->spb_status.block_status_dl = EGPRS_RESEG_DL_DEFAULT;
	rlc_data->cs_init = cs;

	rlc_data->len = block_data_len;

	rdbi = &(rlc_data->block_info);
	memset(rdbi, 0, sizeof(*rdbi));
	rdbi->data_len = block_data_len;

	rdbi->cv = 15; /* Final Block Indicator, set late, if true */
	rdbi->bsn = bsn; /* Block Sequence Number */
	rdbi->e = 1; /* Extension bit, maybe set later (1: no extension) */

	do {
		bool is_final;
		int payload_written = 0;

		if (llc_frame_length(&m_llc) == 0) {
			/* The data just drained, store the current fn */
			if (m_last_dl_drained_fn < 0)
				m_last_dl_drained_fn = fn;

			/* It is not clear, when the next real data will
			 * arrive, so request a DL ack/nack now */
			request_dl_ack();

			int space = block_data_len - write_offset;

			if (num_chunks != 0) {
				/* Nothing to send, and we already put some data in
				 * rlcmac data block, we are done */
				LOGPTBFDL(this, LOGL_DEBUG,
					  "LLC queue completely drained and there's "
					  "still %d free bytes in rlcmac data block\n", space);

				/* We may need to update fbi in header here
				 * since m_last_dl_drained_fn was updated above
				 * Specially important when X2031 is 0. */
				is_final = llc_queue_size(llc_queue()) == 0 && !keep_open(fn);
				if (is_final) {
					rdbi->cv = 0;
					osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_LAST_DL_DATA_SENT, NULL);
				}

				if (mcs_is_edge(cs)) {
					/* in EGPRS there's no M bit, so we need
					 * to flag padding with LI=127 */
					Encoding::rlc_data_to_dl_append_egprs_li_padding(rdbi,
											 &write_offset,
											 &num_chunks,
											 data);
				}
				break;
			}

			/* Nothing to send from upper layers (LLC), but still
			 * requested to send something to MS to delay the
			 * release of the TBF. See 3GPP TS 44.060 9.3.1a
			 * "Delayed release of downlink Temporary Block Flow" */
			/* A header will need to by added, so we just need
			 * space-1 octets */
			llc_put_dummy_frame(&m_llc, space - 1);

			LOGPTBFDL(this, LOGL_DEBUG,
				  "Empty chunk, added LLC dummy command of size %d, drained_since=%d\n",
				  llc_frame_length(&m_llc), frames_since_last_drain(fn));
		}

		is_final = llc_queue_size(llc_queue()) == 0 && !keep_open(fn);

		ar = Encoding::rlc_data_to_dl_append(rdbi, cs,
			&m_llc, &write_offset, &num_chunks, data, is_final, &payload_written);

		if (payload_written > 0)
			bts_do_rate_ctr_add(bts, CTR_RLC_DL_PAYLOAD_BYTES, payload_written);

		if (ar == Encoding::AR_NEED_MORE_BLOCKS)
			break;

		LOGPTBFDL(this, LOGL_DEBUG, "Complete DL frame, len=%d\n", llc_frame_length(&m_llc));
		gprs_rlcmac_dl_bw(this, llc_frame_length(&m_llc));
		bts_do_rate_ctr_add(bts, CTR_LLC_DL_BYTES, llc_frame_length(&m_llc));

		/* Keep transmitted LLC PDUs until first ACK to avoid lossing them if MS is not there. */
		if (!this->m_first_dl_ack_rcvd) {
			struct gprs_dl_llc_llist_item *llc_it = talloc(this, struct gprs_dl_llc_llist_item);
			memcpy(&llc_it->llc, &m_llc, sizeof(llc_it->llc));
			/* Prepend to list to store them in inverse order of transmission, see
			 * dl_tbf_copy_unacked_pdus_to_llc_queue() for the complete picture. */
			llist_add(&llc_it->list, &this->tx_llc_until_first_dl_ack_rcvd);
		}
		llc_reset(&m_llc);

		if (is_final) {
			request_dl_ack();
			osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_LAST_DL_DATA_SENT, NULL);
		}

		/* dequeue next LLC frame, if any */
		schedule_next_frame();
	} while (ar == Encoding::AR_COMPLETED_SPACE_LEFT);

	LOGPTBFDL(this, LOGL_DEBUG, "data block (BSN %d, %s): %s\n",
		  bsn, mcs_name(rlc_data->cs_last),
		  osmo_hexdump(rlc_data->block, block_data_len));
	/* raise send state and set ack state array */
	m_window.m_v_b.mark_unacked(bsn);
	m_window.increment_send();

	return bsn;
}

struct msgb *gprs_rlcmac_dl_tbf::create_dl_acked_block(
				const uint32_t fn, const struct gprs_rlcmac_pdch *pdch,
				int index, int index2)
{
	uint8_t *msg_data;
	struct msgb *dl_msg;
	unsigned msg_len;
	/* TODO: support MCS-7 - MCS-9, where data_block_idx can be 1 */
	uint8_t data_block_idx = 0;
	unsigned int rrbp;
	uint32_t new_poll_fn;
	int rc;
	bool is_final = false;
	gprs_rlc_data_info rlc;
	enum CodingScheme cs;
	int bsns[ARRAY_SIZE(rlc.block_info)];
	unsigned num_bsns;
	bool need_padding = false;
	enum egprs_rlcmac_dl_spb spb = EGPRS_RLCMAC_DL_NO_RETX;
	unsigned int spb_status = get_egprs_dl_spb_status(index);

	enum egprs_puncturing_values punct[2] = {
		EGPRS_PS_INVALID, EGPRS_PS_INVALID
	};
	osmo_static_assert(ARRAY_SIZE(rlc.block_info) == 2,
			   rlc_block_info_size_is_two);

	/*
	 * TODO: This is an experimental work-around to put 2 BSN into
	 * MSC-7 to MCS-9 encoded messages. It just sends the same BSN
	 * twice in the block. The cs should be derived from the TBF's
	 * current CS such that both BSNs (that must be compatible) can
	 * be put into the data area, even if the resulting CS is higher than
	 * the current limit.
	 */
	cs = m_rlc.block(index)->cs_current_trans;
	enum CodingScheme cs_init = m_rlc.block(index)->cs_init;
	bsns[0] = index;
	num_bsns = 1;

	if (index2 >= 0) {
		bsns[num_bsns] = index2;
		num_bsns += 1;
	}

	update_coding_scheme_counter_dl(cs);
	/*
	 * if the intial mcs is 8 and retransmission mcs is either 6 or 3
	 * we have to include the padding of 6 octets in first segment
	 */
	if ((cs_init == MCS8) &&
	    (cs == MCS6 || cs == MCS3)) {
		if (spb_status == EGPRS_RESEG_DL_DEFAULT ||
		    spb_status == EGPRS_RESEG_SECOND_SEG_SENT)
			need_padding  = true;
	} else if (num_bsns == 1) {
		/* TODO: remove the conditional when MCS-6 padding isn't
		 * failing to be decoded by MEs anymore */
		/* TODO: support of MCS-8 -> MCS-6 transition should be
		 * handled
		 * Refer commit be881c028fc4da00c4046ecd9296727975c206a3
		 * dated 2016-02-07 23:45:40 (UTC)
		 */
		if (cs != MCS8)
			mcs_dec_to_single_block(&cs, &need_padding);
	}

	spb = get_egprs_dl_spb(index);

	LOGPTBFDL(this, LOGL_DEBUG, "need_padding %d spb_status %d spb %d (BSN1 %d BSN2 %d)\n",
		  need_padding, spb_status, spb, index, index2);

	gprs_rlc_data_info_init_dl(&rlc, cs, need_padding, spb);

	rlc.usf = 7; /* will be set at scheduler */
	rlc.pr = 0; /* FIXME: power reduction */
	rlc.tfi = m_tfi; /* TFI */

	/* return data block(s) as message */
	msg_len = mcs_size_dl(cs);
	dl_msg = msgb_alloc(msg_len, "rlcmac_dl_data");
	if (!dl_msg)
		return NULL;

	msg_data = msgb_put(dl_msg, msg_len);

	OSMO_ASSERT(rlc.num_data_blocks <= ARRAY_SIZE(rlc.block_info));
	OSMO_ASSERT(rlc.num_data_blocks > 0);

	LOGPTBFDL(this, LOGL_DEBUG, "Copying %u RLC blocks, %u BSNs\n", rlc.num_data_blocks, num_bsns);

	/* Copy block(s) to RLC message: the num_data_blocks cannot be more than 2 - see assert above */
	for (data_block_idx = 0; data_block_idx < OSMO_MIN(rlc.num_data_blocks, 2);
		data_block_idx++)
	{
		int bsn;
		uint8_t *block_data;
		gprs_rlc_data_block_info *rdbi, *block_info;
		enum egprs_rlc_dl_reseg_bsn_state reseg_status;

		/* Check if there are more blocks than BSNs */
		if (data_block_idx < num_bsns)
			bsn = bsns[data_block_idx];
		else
			bsn = bsns[0];

		/* Get current puncturing scheme from block */

		m_rlc.block(bsn)->next_ps = gprs_get_punct_scheme(
			m_rlc.block(bsn)->next_ps,
			m_rlc.block(bsn)->cs_last, cs, spb);

		if (mcs_is_edge(cs)) {
			OSMO_ASSERT(m_rlc.block(bsn)->next_ps >= EGPRS_PS_1);
			OSMO_ASSERT(m_rlc.block(bsn)->next_ps <= EGPRS_PS_3);
		}

		punct[data_block_idx] = m_rlc.block(bsn)->next_ps;

		rdbi = &rlc.block_info[data_block_idx];
		block_info = &m_rlc.block(bsn)->block_info;

		/*
		 * get data and header from current block
		 * function returns the reseg status
		 */
		reseg_status = egprs_dl_get_data(bsn, &block_data);
		m_rlc.block(bsn)->spb_status.block_status_dl = reseg_status;

		/*
		 * If it is first segment of the split block set the state of
		 * bsn to nacked. If it is the first segment dont update the
		 * next ps value of bsn. since next segment also needs same cps
		 */
		if (spb == EGPRS_RLCMAC_DL_FIRST_SEG)
			m_window.m_v_b.mark_nacked(bsn);
		else {
			/*
			 * TODO: Need to handle 2 same bsns
			 * in header type 1
			 */
			gprs_update_punct_scheme(&m_rlc.block(bsn)->next_ps,
						cs);
		}

		m_rlc.block(bsn)->cs_last = cs;
		rdbi->e   = block_info->e;
		rdbi->cv  = block_info->cv;
		rdbi->bsn = bsn;
		is_final = is_final || rdbi->cv == 0;

		LOGPTBFDL(this, LOGL_DEBUG, "Copying data unit %d (BSN %d)\n",
			  data_block_idx, bsn);

		Encoding::rlc_copy_from_aligned_buffer(&rlc, data_block_idx,
			msg_data, block_data);
	}

	/* Calculate CPS only for EGPRS case */
	if (mcs_is_edge(cs))
		rlc.cps = gprs_rlc_mcs_cps(cs, punct[0], punct[1], need_padding);

	/* If the TBF has just started, relate frames_since_last_poll to the
	 * current fn */
	if (m_last_dl_poll_fn < 0)
		m_last_dl_poll_fn = fn;

	/* poll after POLL_ACK_AFTER_FRAMES frames, or when final block is tx or
	 * when last polled DL ACK/NACK was lost. Always do so in the control TS. */
	if (tbf_is_control_ts(dl_tbf_as_tbf(this), pdch) &&
	    need_poll_for_dl_ack_nack()) {
		if (m_dl_ack_requested) {
			LOGPTBFDL(this, LOGL_DEBUG,
				  "Scheduling Ack/Nack polling, because it was requested explicitly "
				  "(e.g. first final block sent).\n");
		} else if (m_last_dl_poll_ack_lost) {
			LOGPTBFDL(this, LOGL_DEBUG,
				  "Scheduling Ack/Nack polling, because polling timed out.\n");
		} else {
			LOGPTBFDL(this, LOGL_DEBUG,
				  "Scheduling Ack/Nack polling, because %d blocks sent.\n",
				  POLL_ACK_AFTER_FRAMES);
		}

		rc = tbf_check_polling(this, pdch, fn, &new_poll_fn, &rrbp);
		if (rc >= 0) {
			tbf_set_polling(this, pdch, new_poll_fn, PDCH_ULC_POLL_DL_ACK);
			LOGPTBFDL(this, LOGL_DEBUG,
				  "Scheduled DL Acknowledgement polling on PACCH (FN=%d, TS=%d)\n",
				  new_poll_fn, pdch->ts_no);

			m_tx_counter = 0;
			/* start timer whenever we send the final block */
			if (is_final)
				T_START(this, T3191, 3191, "final block (DL-TBF)", true);

			/* Clear request flag */
			m_dl_ack_requested = false;
			/* clear poll timeout flag */
			m_last_dl_poll_ack_lost = false;

			/* set polling in header */
			rlc.rrbp = rrbp;
			rlc.es_p = 1; /* Polling */

			m_last_dl_poll_fn = new_poll_fn;

			LOGPTBFDL(this, LOGL_INFO,
				  "Scheduled Ack/Nack polling on FN=%d, TS=%d\n",
				  new_poll_fn, pdch->ts_no);
		}
	}

	Encoding::rlc_write_dl_data_header(&rlc, msg_data);

	LOGPTBFDL(this, LOGL_DEBUG, "msg block (BSN %d, %s%s): %s\n",
		  index, mcs_name(cs),
		  need_padding ? ", padded" : "",
		  msgb_hexdump(dl_msg));

	/* Increment TX-counter */
	m_tx_counter++;

	return dl_msg;
}

static uint16_t bitnum_to_bsn(int bitnum, uint16_t ssn)
{
	return ssn - 1 - bitnum;
}

int gprs_rlcmac_dl_tbf::analyse_errors(char *show_rbb, uint8_t ssn,
	ana_result *res)
{
	gprs_rlc_data *rlc_data;
	uint16_t lost = 0, received = 0, skipped = 0;
	char info[RLC_MAX_WS + 1];
	memset(info, '.', m_window.ws());
	info[m_window.ws()] = 0;
	uint16_t bsn = 0;
	unsigned received_bytes = 0, lost_bytes = 0;
	unsigned received_packets = 0, lost_packets = 0;
	unsigned num_blocks = strlen(show_rbb);

	unsigned distance = m_window.distance();

	num_blocks = num_blocks > distance
				? distance : num_blocks;

	/* SSN - 1 is in range V(A)..V(S)-1 */
	for (unsigned int bitpos = 0; bitpos < num_blocks; bitpos++) {
		bool is_received;
		int index = num_blocks - 1 - bitpos;

		is_received = (index >= 0 && show_rbb[index] == 'R');

		bsn = m_window.mod_sns(bitnum_to_bsn(bitpos, ssn));

		if (bsn == m_window.mod_sns(m_window.v_a() - 1)) {
			info[bitpos] = '$';
			break;
		}

		rlc_data = m_rlc.block(bsn);
		if (!rlc_data) {
			info[bitpos] = '0';
			continue;
		}

		/* Get general statistics */
		if (is_received && !m_window.m_v_b.is_acked(bsn)) {
			received_packets += 1;
			received_bytes += rlc_data->len;
		} else if (!is_received && !m_window.m_v_b.is_nacked(bsn)) {
			lost_packets += 1;
			lost_bytes += rlc_data->len;
		}

		/* Get statistics for current CS */

		if (rlc_data->cs_last != current_cs()) {
			/* This block has already been encoded with a different
			 * CS, so it doesn't help us to decide, whether the
			 * current CS is ok. Ignore it. */
			info[bitpos] = 'x';
			skipped += 1;
			continue;
		}

		if (is_received) {
			if (!m_window.m_v_b.is_acked(bsn)) {
				received += 1;
				info[bitpos] = 'R';
			} else {
				info[bitpos] = 'r';
			}
		} else {
			info[bitpos] = 'L';
			lost += 1;
		}
	}

	LOGPTBFDL(this, LOGL_DEBUG,
		  "DL analysis, range=%d:%d, lost=%d, recv=%d, skipped=%d, bsn=%d, info='%s'\n",
		  m_window.v_a(), m_window.v_s(), lost, received, skipped, bsn, info);

	res->received_packets = received_packets;
	res->lost_packets = lost_packets;
	res->received_bytes = received_bytes;
	res->lost_bytes = lost_bytes;

	if (lost + received <= 1)
		return -1;

	return lost * 100 / (lost + received);
}

gprs_rlc_window *gprs_rlcmac_dl_tbf::window()
{
	return &m_window;
}

int gprs_rlcmac_dl_tbf::update_window(unsigned first_bsn,
	const struct bitvec *rbb)
{
	unsigned dist;
	uint16_t lost = 0, received = 0;
	char show_v_b[RLC_MAX_SNS + 1];
	char show_rbb[RLC_MAX_SNS + 1];
	int error_rate;
	struct ana_result ana_res;
	dist = m_window.distance();
	unsigned num_blocks = rbb->cur_bit > dist
				? dist : rbb->cur_bit;
	unsigned behind_last_bsn = m_window.mod_sns(first_bsn + num_blocks);

	Decoding::extract_rbb(rbb, show_rbb);
	/* show received array in debug */
	LOGPTBFDL(this, LOGL_DEBUG,
		  "ack:  (BSN=%d)\"%s\"(BSN=%d)  R=ACK I=NACK\n",
		  first_bsn, show_rbb, m_window.mod_sns(behind_last_bsn - 1));

	error_rate = analyse_errors(show_rbb, behind_last_bsn, &ana_res);

	if (the_pcu->vty.cs_adj_enabled && ms())
		ms_update_error_rate(ms(), this, error_rate);

	m_window.update(bts, rbb, first_bsn, &lost, &received);
	rate_ctr_add(rate_ctr_group_get_ctr(m_ctrs, TBF_CTR_RLC_NACKED), lost);

	/* report lost and received packets */
	gprs_rlcmac_received_lost(this, received, lost);

	/* Used to measure the leak rate */
	gprs_bssgp_update_bytes_received(ana_res.received_bytes,
		ana_res.received_packets + ana_res.lost_packets);

	/* raise V(A), if possible */
	m_window.raise(m_window.move_window());

	/* show receive state array in debug (V(A)..V(S)-1) */
	m_window.show_state(show_v_b);
	LOGPTBFDL(this, LOGL_DEBUG,
		  "V(B): (V(A)=%d)\"%s\"(V(S)-1=%d)  A=Acked N=Nacked U=Unacked X=Resend-Unacked I=Invalid\n",
		  m_window.v_a(), show_v_b, m_window.v_s_mod(-1));
	return 0;
}

int gprs_rlcmac_dl_tbf::rcvd_dl_final_ack()
{
	uint16_t received;
	int rc;

	/* range V(A)..V(S)-1 */
	received = m_window.count_unacked();
	/* report all outstanding packets as received */
	gprs_rlcmac_received_lost(this, received, 0);
	m_tx_counter = 0;
	m_window.reset();

	rc = osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_FINAL_ACK_RECVD, NULL);

	return rc;
}

int gprs_rlcmac_dl_tbf::rcvd_dl_ack(bool final_ack, unsigned first_bsn,
	struct bitvec *rbb)
{
	int rc;
	LOGPTBFDL(this, LOGL_DEBUG, "downlink acknowledge\n");

	if (m_first_dl_ack_rcvd == false) {
		/* MS is there, free temporarily stored transmitted LLC PDUs */
		struct gprs_dl_llc_llist_item *llc_it;
		while ((llc_it = llist_first_entry_or_null(&this->tx_llc_until_first_dl_ack_rcvd, struct gprs_dl_llc_llist_item, list))) {
			llist_del(&llc_it->list);
			talloc_free(llc_it);
		}
		m_first_dl_ack_rcvd = true;
	}
	m_last_dl_poll_ack_lost = false;

	/* reset N3105 */
	n_reset(N3105);
	t_stop(T3191, "ACK/NACK received");

	rc = update_window(first_bsn, rbb);

	if (final_ack) {
		LOGPTBFDL(this, LOGL_DEBUG, "Final ACK received.\n");
		rc = rcvd_dl_final_ack();
	} else if (state_is(TBF_ST_FINISHED) && m_window.window_empty()) {
		LOGPTBFDL(this, LOGL_NOTICE,
			  "Received acknowledge of all blocks, but without final ack indication (don't worry)\n");
	}

	return rc;
}

bool gprs_rlcmac_dl_tbf::dl_window_stalled() const
{
	return m_window.window_stalled();
}

void gprs_rlcmac_dl_tbf::request_dl_ack()
{
	m_dl_ack_requested = true;
}

void dl_tbf_request_dl_ack(struct gprs_rlcmac_dl_tbf *dl_tbf) {
	dl_tbf->request_dl_ack();
}

bool dl_tbf_first_dl_ack_rcvd(const struct gprs_rlcmac_dl_tbf *tbf)
{
	return tbf->m_first_dl_ack_rcvd;
}

/* Copy back to GprsMs' llc_queue the LLC PDUs previously dequeued and never
 * fully ACKED at the MS side.
 * FIXME: For now, only blocks transmitted and without first ever DL ACK are
 * copied, because we have no way yet to track LLC PDUs once they are converted
 * to RLC blocks. This is however enough to cover the case where a DL TBF is
 * assigned over PCH and the MS never answers.
 */
void dl_tbf_copy_unacked_pdus_to_llc_queue(struct gprs_rlcmac_dl_tbf *tbf)
{
	struct GprsMs *ms = tbf_ms(dl_tbf_as_tbf(tbf));
	struct gprs_dl_llc_llist_item *llc_it;

	/* If we have LLC PDU still being transmitted, prepend it first to the queue: */
	if (llc_frame_length(&tbf->m_llc) > 0)
		llc_queue_merge_prepend(&ms->llc_queue, &tbf->m_llc);

	/* Iterate over the list of totally transmitted LLC PDUs and merge them
	 * into the queue. The items in the list are in inverse order of
	 * transmission, hence when popping from here and enqueueing (prepending)
	 * back to the llc_queue it ends up in the exact same initial order. */
	while ((llc_it = llist_first_entry_or_null(&tbf->tx_llc_until_first_dl_ack_rcvd, struct gprs_dl_llc_llist_item, list))) {
		llist_del(&llc_it->list);
		llc_queue_merge_prepend(&ms->llc_queue, &llc_it->llc);
		talloc_free(llc_it);
	}
}

/* Does this DL TBF require to poll the MS for DL ACK/NACK? */
bool gprs_rlcmac_dl_tbf::need_poll_for_dl_ack_nack() const
{
	/* poll after POLL_ACK_AFTER_FRAMES frames, or when final block is tx or
	 * when last polled DL ACK/NACK was lost. */
	return m_last_dl_poll_ack_lost ||
		m_tx_counter >= POLL_ACK_AFTER_FRAMES ||
		m_dl_ack_requested;
}

bool gprs_rlcmac_dl_tbf::have_data() const
{
	return llc_chunk_size(&m_llc) > 0 ||
		(llc_queue_size(llc_queue()) > 0);
}

static inline int frames_since_last(int32_t last, unsigned fn)
{
	unsigned wrapped = (fn + GSM_MAX_FN - last) % GSM_MAX_FN;

	if (last < 0)
		return -1;

	if (wrapped < GSM_MAX_FN/2)
		return wrapped;

	return wrapped - GSM_MAX_FN;
}

int gprs_rlcmac_dl_tbf::frames_since_last_poll(unsigned fn) const
{
	return frames_since_last(m_last_dl_poll_fn, fn);
}

int gprs_rlcmac_dl_tbf::frames_since_last_drain(unsigned fn) const
{
	return frames_since_last(m_last_dl_drained_fn, fn);
}

bool gprs_rlcmac_dl_tbf::keep_open(unsigned fn) const
{
	int keep_time_frames;
	unsigned long dl_tbf_idle_msec;
	int since_last_drain;
	bool keep;

	dl_tbf_idle_msec = osmo_tdef_get(the_pcu->T_defs, -2031, OSMO_TDEF_MS, -1);
	if (dl_tbf_idle_msec == 0)
		return false;

	keep_time_frames = msecs_to_frames(dl_tbf_idle_msec);
	since_last_drain = frames_since_last_drain(fn);
	keep = since_last_drain <= keep_time_frames;

	if (since_last_drain >= 0)
		LOGPTBFDL(this, LOGL_DEBUG, "Keep idle TBF open: %d/%d -> %s\n",
			  since_last_drain, keep_time_frames, keep ? "yes" : "no");
	return keep;
}

/*
 * This function returns the pointer to data which needs
 * to be copied. Also updates the status of the block related to
 * Split block handling in the RLC/MAC block.
 */
enum egprs_rlc_dl_reseg_bsn_state
	gprs_rlcmac_dl_tbf::egprs_dl_get_data(int bsn, uint8_t **block_data)
{
	gprs_rlc_data *rlc_data = m_rlc.block(bsn);
	egprs_rlc_dl_reseg_bsn_state *block_status_dl =
				&rlc_data->spb_status.block_status_dl;

	enum CodingScheme cs_init = rlc_data->cs_init;
	enum CodingScheme cs_current_trans = rlc_data->cs_current_trans;

	enum HeaderType ht_cs_init = mcs_header_type(rlc_data->cs_init);
	enum HeaderType ht_cs_current_trans = mcs_header_type(rlc_data->cs_current_trans);

	*block_data = &rlc_data->block[0];

	/*
	 * Table 10.3a.0.1 of 44.060
	 * MCS6,9: second segment starts at 74/2 = 37
	 * MCS5,7: second segment starts at 56/2 = 28
	 * MCS8: second segment starts at 31
	 * MCS4: second segment starts at 44/2 = 22
	 */
	if (ht_cs_current_trans == HEADER_EGPRS_DATA_TYPE_3) {
		if (*block_status_dl == EGPRS_RESEG_FIRST_SEG_SENT) {
			switch (cs_init) {
			case MCS6 :
			case MCS9 :
				*block_data = &rlc_data->block[37];
				break;
			case MCS7 :
			case MCS5 :
				*block_data = &rlc_data->block[28];
				break;
			case MCS8 :
				*block_data = &rlc_data->block[31];
				break;
			case MCS4 :
				*block_data = &rlc_data->block[22];
				break;
			default:
				LOGPTBFDL(this, LOGL_ERROR,
					  "FIXME: Software error: hit invalid condition. "
					  "headerType(%d) blockstatus(%d) cs(%s) PLEASE FIX!\n",
					  ht_cs_current_trans,
					  *block_status_dl, mcs_name(cs_init));
				break;

			}
			return EGPRS_RESEG_SECOND_SEG_SENT;
		} else if ((ht_cs_init == HEADER_EGPRS_DATA_TYPE_1) ||
			   (ht_cs_init == HEADER_EGPRS_DATA_TYPE_2)) {
			return EGPRS_RESEG_FIRST_SEG_SENT;
		} else if ((cs_init == MCS4) &&
			   (cs_current_trans == MCS1)) {
			return EGPRS_RESEG_FIRST_SEG_SENT;
		}
	}
	return EGPRS_RESEG_DL_DEFAULT;
}

/*
 * This function returns the status of split block
 * for RLC/MAC block.
 */
unsigned int gprs_rlcmac_dl_tbf::get_egprs_dl_spb_status(const int bsn)
{
	const gprs_rlc_data *rlc_data = m_rlc.block(bsn);

	return rlc_data->spb_status.block_status_dl;
}

/*
 * This function returns the spb value to be sent OTA
 * for RLC/MAC block.
 */
enum egprs_rlcmac_dl_spb gprs_rlcmac_dl_tbf::get_egprs_dl_spb(const int bsn)
{
	struct gprs_rlc_data *rlc_data = m_rlc.block(bsn);
	egprs_rlc_dl_reseg_bsn_state block_status_dl = rlc_data->spb_status.block_status_dl;

	enum CodingScheme cs_init = rlc_data->cs_init;
	enum CodingScheme cs_current_trans = rlc_data->cs_current_trans;

	enum HeaderType ht_cs_init = mcs_header_type(rlc_data->cs_init);
	enum HeaderType ht_cs_current_trans = mcs_header_type(rlc_data->cs_current_trans);

	/* Table 10.4.8b.1 of 44.060 */
	if (ht_cs_current_trans == HEADER_EGPRS_DATA_TYPE_3) {
		/*
		 * if we are sending the second segment the spb should be 3
		 * otherwise it should be 2
		 */
		if (block_status_dl == EGPRS_RESEG_FIRST_SEG_SENT) {
			/* statistics */
			bts_do_rate_ctr_inc(bts, CTR_SPB_DL_SECOND_SEGMENT);
			return EGPRS_RLCMAC_DL_SEC_SEG;
		} else if ((ht_cs_init == HEADER_EGPRS_DATA_TYPE_1) ||
			   (ht_cs_init == HEADER_EGPRS_DATA_TYPE_2)) {
			bts_do_rate_ctr_inc(bts, CTR_SPB_DL_FIRST_SEGMENT);
			return EGPRS_RLCMAC_DL_FIRST_SEG;
		} else if ((cs_init == MCS4) &&
			   (cs_current_trans == MCS1)) {
			bts_do_rate_ctr_inc(bts, CTR_SPB_DL_FIRST_SEGMENT);
			return EGPRS_RLCMAC_DL_FIRST_SEG;
		}
	}
	/* Non SPB cases 0 is reurned */
	return EGPRS_RLCMAC_DL_NO_RETX;
}

void gprs_rlcmac_dl_tbf::set_window_size()
{
	const struct gprs_rlcmac_bts *b = bts;
	uint16_t ws = egprs_window_size(b, dl_slots());

	LOGPTBFDL(this, LOGL_INFO, "setting EGPRS DL window size to %u, base(%u) slots(%u) ws_pdch(%u)\n",
		  ws, bts->pcu->vty.ws_base, pcu_bitcount(dl_slots()), bts->pcu->vty.ws_pdch);
	m_window.set_ws(ws);
}

void gprs_rlcmac_dl_tbf::update_coding_scheme_counter_dl(enum CodingScheme cs)
{
	switch (cs) {
	case CS1:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_DL_CS1);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_gprs_ctrs, TBF_CTR_GPRS_DL_CS1));
		break;
	case CS2:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_DL_CS2);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_gprs_ctrs, TBF_CTR_GPRS_DL_CS2));
		break;
	case CS3:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_DL_CS3);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_gprs_ctrs, TBF_CTR_GPRS_DL_CS3));
		break;
	case CS4:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_DL_CS4);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_gprs_ctrs, TBF_CTR_GPRS_DL_CS4));
		break;
	case MCS1:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS1);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS1));
		break;
	case MCS2:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS2);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS2));
		break;
	case MCS3:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS3);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS3));
		break;
	case MCS4:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS4);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS4));
		break;
	case MCS5:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS5);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS5));
		break;
	case MCS6:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS6);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS6));
		break;
	case MCS7:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS7);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS7));
		break;
	case MCS8:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS8);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS8));
		break;
	case MCS9:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_DL_MCS9);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_dl_egprs_ctrs, TBF_CTR_EGPRS_DL_MCS9));
		break;
	default:
		LOGPTBFDL(this, LOGL_ERROR, "attempting to update rate counters for unsupported (M)CS %s\n",
			  mcs_name(cs));
	}
}

struct gprs_rlcmac_dl_tbf *tbf_as_dl_tbf(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_DL_TBF)
		return static_cast<gprs_rlcmac_dl_tbf *>(tbf);
	else
		return NULL;
}

const struct gprs_rlcmac_dl_tbf *tbf_as_dl_tbf_const(const struct gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_DL_TBF)
		return static_cast<const gprs_rlcmac_dl_tbf *>(tbf);
	else
		return NULL;
}
