/* PDCH scheduler
 *
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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

#include <gprs_bssgp_pcu.h>
#include <gprs_rlcmac.h>
#include <pcu_l1_if.h>
#include <bts.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <rlc.h>
#include <sba.h>
#include <pdch.h>
#include "pcu_utils.h"

extern "C" {
	#include <osmocom/core/gsmtap.h>
}

struct tbf_sched_candidates {
	struct gprs_rlcmac_tbf *ul_ass;
	struct gprs_rlcmac_tbf *dl_ass;
	struct gprs_rlcmac_tbf *nacc;
	struct gprs_rlcmac_ul_tbf *ul_ack;
};

static void get_ctrl_msg_tbf_candidates(const struct gprs_rlcmac_pdch *pdch,
					struct tbf_sched_candidates *tbf_cand)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct llist_item *pos;

	llist_for_each_entry(pos, &pdch->trx->ul_tbfs, list) {
		ul_tbf = as_ul_tbf((struct gprs_rlcmac_tbf *)pos->entry);
		OSMO_ASSERT(ul_tbf);
		/* this trx, this ts */
		if (!ul_tbf->is_control_ts(pdch->ts_no))
			continue;
		if (ul_tbf->ul_ack_state_is(GPRS_RLCMAC_UL_ACK_SEND_ACK))
			tbf_cand->ul_ack = ul_tbf;
		if (tbf_dl_ass_rts(ul_tbf))
			tbf_cand->dl_ass = ul_tbf;
		if (tbf_ul_ass_rts(ul_tbf))
			tbf_cand->ul_ass = ul_tbf;
		/* NACC ready to send. TFI assigned is needed to send messages */
		if (ul_tbf->is_tfi_assigned() && ms_nacc_rts(ul_tbf->ms()))
			tbf_cand->nacc = ul_tbf;
/* FIXME: Is this supposed to be fair? The last TBF for each wins? Maybe use llist_add_tail and skip once we have all
states? */
	}
	llist_for_each_entry(pos, &pdch->trx->dl_tbfs, list) {
		dl_tbf = as_dl_tbf((struct gprs_rlcmac_tbf *)pos->entry);
		OSMO_ASSERT(dl_tbf);
		/* this trx, this ts */
		if (!dl_tbf->is_control_ts(pdch->ts_no))
			continue;
		if (tbf_dl_ass_rts(dl_tbf))
			tbf_cand->dl_ass = dl_tbf;
		if (tbf_ul_ass_rts(dl_tbf))
			tbf_cand->ul_ass = dl_tbf;
		/* NACC ready to send. TFI assigned is needed to send messages */
		if (dl_tbf->is_tfi_assigned() && ms_nacc_rts(dl_tbf->ms()))
			tbf_cand->nacc = dl_tbf;
	}
}

static struct gprs_rlcmac_ul_tbf *sched_select_uplink(struct gprs_rlcmac_pdch *pdch, bool require_gprs_only)
{
	struct gprs_rlcmac_ul_tbf *tbf;
	uint8_t i, tfi;

	/* select uplink resource */
	for (i = 0, tfi = pdch->next_ul_tfi; i < 32;
	     i++, tfi = (tfi + 1) & 31) {
		tbf = pdch->ul_tbf_by_tfi(tfi);
		/* no TBF for this tfi, go next */
		if (!tbf)
			continue;
		/* no UL resources needed, go next */
		/* we don't need to give resources in FINISHED state,
		 * because we have received all blocks and only poll
		 * for packet control ack. */
		if (tbf->state_is_not(TBF_ST_FLOW))
			continue;

		if (require_gprs_only && tbf->is_egprs_enabled())
			continue;

		/* use this USF (tbf) */
		/* next TBF to handle resource is the next one */
		pdch->next_ul_tfi = (tfi + 1) & 31;
		return tbf;
	}

	return NULL;
}

struct msgb *sched_app_info(struct gprs_rlcmac_tbf *tbf) {
	struct gprs_rlcmac_bts *bts;
	struct msgb *msg = NULL;

	if (!tbf || !tbf->ms()->app_info_pending)
		return NULL;

	bts = tbf->bts;

	if (bts->app_info) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Sending Packet Application Information message\n");
		msg = msgb_copy(bts->app_info, "app_info_msg_sched");
	} else
		LOGP(DRLCMACSCHED, LOGL_ERROR, "MS has app_info_pending flag set, but no Packet Application Information"
		     " message stored in BTS!\n");

	tbf->ms()->app_info_pending = false;
	bts->app_info_pending--;

	if (!bts->app_info_pending) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Packet Application Information successfully sent to all MS with active"
		     " TBF\n");
		msgb_free(bts->app_info);
		bts->app_info = NULL;
	}
	return msg;
}

static struct msgb *sched_select_ctrl_msg(struct gprs_rlcmac_pdch *pdch, uint32_t fn,
					  uint8_t block_nr, struct tbf_sched_candidates *tbfs)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_tbf *tbf = NULL;
	struct gprs_rlcmac_tbf *next_list[] = { tbfs->ul_ass,
						tbfs->dl_ass,
						tbfs->ul_ack,
						tbfs->nacc };
	uint8_t ts = pdch->ts_no;

	/* Send Packet Application Information first (ETWS primary notifications) */
	msg = sched_app_info(tbfs->dl_ass);

	if (!msg) {
		for (size_t i = 0; i < ARRAY_SIZE(next_list); ++i) {
			tbf = next_list[(pdch->next_ctrl_prio + i) % ARRAY_SIZE(next_list)];
			if (!tbf)
				continue;

			/*
			 * Assignments for the same direction have lower precedence,
			 * because they may kill the TBF when the CONTROL ACK is
			 * received, thus preventing the others from being processed.
			 */
			if (tbf == tbfs->ul_ass && tbf->ul_ass_state_is(TBF_UL_ASS_SEND_ASS_REJ))
				msg = tbf_ul_ass_create_rlcmac_msg(tbfs->ul_ass, fn, ts);
			else if (tbf == tbfs->ul_ass && tbf->direction == GPRS_RLCMAC_DL_TBF)
				msg = tbf_ul_ass_create_rlcmac_msg(tbfs->ul_ass, fn, ts);
			else if (tbf == tbfs->dl_ass && tbf->direction == GPRS_RLCMAC_UL_TBF)
				msg = tbf_dl_ass_create_rlcmac_msg(tbfs->dl_ass, fn, ts);
			else if (tbf == tbfs->ul_ack)
				msg = tbfs->ul_ack->create_ul_ack(fn, ts);
			else if (tbf == tbfs->nacc) {
				msg = ms_nacc_create_rlcmac_msg(tbf->ms(), tbf, fn, ts);
			}

			if (!msg) {
				tbf = NULL;
				continue;
			}

			pdch->next_ctrl_prio = (pdch->next_ctrl_prio + 1) % ARRAY_SIZE(next_list);
			break;
		}
	}

	if (!msg) {
		/*
		 * If one of these is left, the response (CONTROL ACK) from the
		 * MS will kill the current TBF, only one of them can be
		 * non-NULL
		 */
		if (tbfs->dl_ass) {
			tbf = tbfs->dl_ass;
			msg = tbf_dl_ass_create_rlcmac_msg(tbfs->dl_ass, fn, ts);
		} else if (tbfs->ul_ass) {
			tbf = tbfs->ul_ass;
			msg = tbf_ul_ass_create_rlcmac_msg(tbfs->ul_ass, fn, ts);
		}
	}

	/* any message */
	if (msg) {
		if (!tbf) {
			LOGPDCH(pdch, DRLCMACSCHED, LOGL_ERROR, "FN=%" PRIu32
				" Control message to be scheduled, but no TBF\n", fn);
			msgb_free(msg);
			return NULL;
		}
		tbf->rotate_in_list();
		LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "FN=%" PRIu32
			" Scheduling control message at RTS for %s\n",
			fn, tbf_name(tbf));
		rate_ctr_inc(rate_ctr_group_get_ctr(tbf->ms()->ctrs, MS_CTR_DL_CTRL_MSG_SCHED));
		return msg;
	}

	/* schedule PACKET PAGING REQUEST, if any are pending */
	msg = pdch->packet_paging_request();
	if (msg) {
		LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "FN=%" PRIu32
			" Scheduling paging request message at RTS\n", fn);
		return msg;
	}

	return NULL;
}

static inline enum tbf_dl_prio tbf_compute_priority(const struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_dl_tbf *tbf,
						    uint8_t ts, uint32_t fn, int age)
{
	const gprs_rlc_dl_window *w = static_cast<gprs_rlc_dl_window *>(tbf->window());
	unsigned long msecs_t3190 = osmo_tdef_get(the_pcu->T_defs, 3190, OSMO_TDEF_MS, -1);
	unsigned long dl_tbf_idle_msec = osmo_tdef_get(the_pcu->T_defs, -2031, OSMO_TDEF_MS, -1);
	int age_thresh1 = msecs_to_frames(200);
	int age_thresh2 = msecs_to_frames(OSMO_MIN(msecs_t3190/2, dl_tbf_idle_msec));

	if (tbf->is_control_ts(ts) && tbf->need_control_ts())
		return DL_PRIO_CONTROL;

	if (tbf->is_control_ts(ts) && age > age_thresh2 && age_thresh2 > 0)
		return DL_PRIO_HIGH_AGE;

	if ((tbf->state_is(TBF_ST_FLOW) && tbf->have_data()) || w->resend_needed() >= 0)
		return DL_PRIO_NEW_DATA;

	if (tbf->is_control_ts(ts) && age > age_thresh1 && tbf->keep_open(fn))
		return DL_PRIO_LOW_AGE;

	if (!w->window_empty())
		return DL_PRIO_SENT_DATA;

	return DL_PRIO_NONE;
}

/* Check if next data block of a TBF can be encoded in GMSK [(M)CS1-4]. */
static bool can_produce_gmsk_data_block_next(struct gprs_rlcmac_dl_tbf *tbf, enum tbf_dl_prio prio)
{
	const gprs_rlc_dl_window *w;

	/* GPRS TBFs can always send GMSK */
	if (!tbf->is_egprs_enabled())
		return true;

	switch (prio) {
	case DL_PRIO_CONTROL:
		/* Control blocks are always CS-1 */
		return true;
	case DL_PRIO_NEW_DATA:
		/* We can send any new data (no block generated yet) using any
		 * MCS. However, we don't (yet) support resegmenting already
		 * sent blocks (NACKed blocks in this case) into lower MCS of
		 * the same family. See OS#4966 */
		w = static_cast<gprs_rlc_dl_window *>(tbf->window());
		return w->resend_needed() < 0;
	default:
		return false;
	}
}

static struct msgb *sched_select_downlink(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_pdch *pdch, uint32_t fn,
		    uint8_t block_nr, enum mcs_kind req_mcs_kind, bool *is_egprs)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_dl_tbf *tbf, *prio_tbf = NULL;
	enum tbf_dl_prio prio, max_prio = DL_PRIO_NONE;
	uint8_t ts = pdch->ts_no;

	uint8_t i, tfi, prio_tfi;
	int age;

	/* select downlink resource */
	for (i = 0, tfi = pdch->next_dl_tfi; i < 32;
	     i++, tfi = (tfi + 1) & 31) {
		tbf = pdch->dl_tbf_by_tfi(tfi);
		/* no TBF for this tfi, go next */
		if (!tbf)
			continue;
		/* no DL TBF, go next */
		if (tbf->direction != GPRS_RLCMAC_DL_TBF)
			continue;
		/* no DL resources needed, go next */
		if (tbf->state_is_not(TBF_ST_FLOW)
		 && tbf->state_is_not(TBF_ST_FINISHED))
			continue;

		/* waiting for CCCH IMM.ASS confirm */
		if (tbf->m_wait_confirm)
			continue;

		/* If a GPRS (CS1-4) Dl block is required, skip EGPRS(_GSMK) tbfs: */
		if (req_mcs_kind == GPRS && tbf->is_egprs_enabled())
			continue;

		age = tbf->frames_since_last_poll(fn);

		/* compute priority */
		prio = tbf_compute_priority(bts, tbf, ts, fn, age);
		if (prio == DL_PRIO_NONE)
			continue;

		/* If a GPRS (CS1-4/MCS1-4) Dl block is required, downgrade MCS
		 * below instead of skipping. However, downgrade can only be
		 * done on new data BSNs (not yet sent) and control blocks. */
		if (req_mcs_kind == EGPRS_GMSK && !can_produce_gmsk_data_block_next(tbf, prio)) {
			LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "FN=%" PRIu32
				" Cannot downgrade EGPRS TBF with prio %d for %s\n",
				fn, prio, tbf_name(tbf));
			continue;
		}

		/* get the TBF with the highest priority */
		if (prio > max_prio) {
			prio_tfi = tfi;
			prio_tbf = tbf;
			max_prio = prio;
		}
	}

	if (prio_tbf) {
		LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "FN=%" PRIu32
			" Scheduling data message at RTS for DL TFI=%d prio=%d mcs_mode_restrict=%s\n",
			fn, prio_tfi, max_prio, mode_name(req_mcs_kind));
		/* next TBF to handle resource is the next one */
		pdch->next_dl_tfi = (prio_tfi + 1) & 31;
		/* generate DL data block */
		msg = prio_tbf->create_dl_acked_block(fn, ts, req_mcs_kind);
		*is_egprs = prio_tbf->is_egprs_enabled();
	}

	return msg;
}

static const uint8_t rlcmac_dl_idle[23] = {
	0x47, /* control without optional header octets, no polling, USF=111 */
	0x94, /* dummy downlink control message, paging mode 00 */
	0x2b, /* no persistance level, 7 bits spare pattern */
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
};

static struct msgb *sched_dummy(void)
{
	struct msgb *msg;

	msg = msgb_alloc(23, "rlcmac_dl_idle");
	if (!msg)
		return NULL;
	memcpy(msgb_put(msg, 23), rlcmac_dl_idle, 23);

	return msg;
}

static inline void tap_n_acc(const struct msgb *msg, struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
			     uint32_t fn, enum pcu_gsmtap_category cat)
{
	if (!msg)
		return;

	switch(cat) {
	case PCU_GSMTAP_C_DL_CTRL:
		bts_do_rate_ctr_inc(bts, CTR_RLC_SENT_CONTROL);
		bts_send_gsmtap(bts, PCU_GSMTAP_C_DL_CTRL, false, trx, ts, GSMTAP_CHANNEL_PACCH, fn, msg->data,
				      msg->len);
		break;
	case PCU_GSMTAP_C_DL_DATA_GPRS:
	case PCU_GSMTAP_C_DL_DATA_EGPRS:
		bts_do_rate_ctr_inc(bts, CTR_RLC_SENT);
		bts_send_gsmtap(bts, cat, false, trx, ts, GSMTAP_CHANNEL_PDTCH, fn, msg->data,
				      msg->len);
		break;
	case PCU_GSMTAP_C_DL_DUMMY:
		bts_do_rate_ctr_inc(bts, CTR_RLC_SENT_DUMMY);
		bts_send_gsmtap(bts, PCU_GSMTAP_C_DL_DUMMY, false, trx, ts, GSMTAP_CHANNEL_PACCH, fn, msg->data,
				      msg->len);
		break;
	default:
		break;
	}
}

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts,
        uint32_t fn, uint8_t block_nr)
{
	struct gprs_rlcmac_pdch *pdch;
	struct tbf_sched_candidates tbf_cand = {0};
	struct gprs_rlcmac_tbf *poll_tbf;
	struct gprs_rlcmac_ul_tbf *usf_tbf = NULL;
	struct gprs_rlcmac_sba *sba;
	uint8_t usf;
	struct msgb *msg = NULL;
	uint32_t poll_fn;
	enum pcu_gsmtap_category gsmtap_cat;
	bool tx_is_egprs = false;
	bool require_gprs_only;
	enum mcs_kind req_mcs_kind; /* Restrict CS/MCS if DL Data block is to be sent */

	if (trx >= 8 || ts >= 8)
		return -EINVAL;
	pdch = &bts->trx[trx].pdch[ts];

	if (!pdch->is_enabled()) {
		LOGP(DRLCMACSCHED, LOGL_ERROR, "Received RTS on disabled PDCH: "
			"TRX=%d TS=%d\n", trx, ts);
		return -EIO;
	}

	/* store last frame number of RTS */
	pdch->last_rts_fn = fn;

	/* require_gprs_only: Prioritize USF for GPRS-only MS here,
	 * since anyway we'll need to tx a Dl block with CS1-4 due to
	 * synchronization requirements. See 3GPP TS 03.64 version
	 * 8.12.0
	 */
	require_gprs_only = (pdch->fn_without_cs14 == MS_RESYNC_NUM_FRAMES - 1);
	if (require_gprs_only) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "TRX=%d TS=%d FN=%d "
		     "synchronization frame (every 18 frames), only CS1-4 allowed",
		     trx, ts, fn);
		req_mcs_kind = GPRS; /* only GPRS CS1-4 allowed, all MS need to be able to decode it */
	} else {
		req_mcs_kind = EGPRS; /* all kinds are fine */
	}

	/* polling for next uplink block */
	poll_fn = rts_next_fn(fn, block_nr);
	/* check for sba */
	if ((sba = pdch_ulc_get_sba(pdch->ulc, poll_fn))) {
		LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: "
			"FN=%d block_nr=%d scheduling free USF for "
			"single block allocation at FN=%d\n", fn, block_nr, sba->fn);
	/* else, check uplink resource for polling */
	} else if ((poll_tbf = pdch_ulc_get_tbf_poll(pdch->ulc, poll_fn))) {
		LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: FN=%d "
			"block_nr=%d scheduling free USF for polling at FN=%d of %s\n",
			fn, block_nr, poll_fn, tbf_name(poll_tbf));
		/* If POLL TBF is UL and already has a USF assigned on this TS,
		 * let's set its USF in the DL msg. This is not really needed,
		 * but it helps understand better the flow when looking at
		 * pcaps. */
		if (poll_tbf->direction == GPRS_RLCMAC_UL_TBF && as_ul_tbf(poll_tbf)->m_usf[ts] != USF_INVALID)
			usf_tbf = as_ul_tbf(poll_tbf);
	/* else, search for uplink tbf */
	} else if ((usf_tbf = sched_select_uplink(pdch, require_gprs_only))) {
		LOGPDCH(pdch, DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: FN=%d "
			"block_nr=%d scheduling USF=%d for %s, expect answer on UL FN=%d\n",
			fn, block_nr, usf_tbf->m_usf[pdch->ts_no], tbf_name(usf_tbf), poll_fn);
		pdch_ulc_reserve_tbf_usf(pdch->ulc, poll_fn, usf_tbf);
	}
	/* If MS selected for USF is GPRS-only, then it will only be
	 * able to read USF if dl block uses GMSK * (CS1-4, MCS1-4) */
	if (usf_tbf && req_mcs_kind == EGPRS && ms_mode(usf_tbf->ms()) != EGPRS)
		req_mcs_kind = EGPRS_GMSK;

	get_ctrl_msg_tbf_candidates(pdch, &tbf_cand);

	/* Prio 1: select control message */
	if ((msg = sched_select_ctrl_msg(pdch, fn, block_nr, &tbf_cand))) {
			gsmtap_cat = PCU_GSMTAP_C_DL_CTRL;
	}
	/* Prio 2: select data message for downlink */
	else if((msg = sched_select_downlink(bts, pdch, fn, block_nr, req_mcs_kind, &tx_is_egprs))) {
		gsmtap_cat = tx_is_egprs ? PCU_GSMTAP_C_DL_DATA_EGPRS :
					   PCU_GSMTAP_C_DL_DATA_GPRS;
	}
	/* Prio 3: send dummy contol message */
	else if ((msg = sched_dummy())) {
		/* increase counter */
		gsmtap_cat = PCU_GSMTAP_C_DL_DUMMY;
	} else {
		return -ENOMEM;
	}

	if (tx_is_egprs && pdch->has_gprs_only_tbf_attached()) {
		pdch->fn_without_cs14 += 1;
	} else {
		pdch->fn_without_cs14 = 0;
	}

	/* msg is now available */
	bts_do_rate_ctr_add(bts, CTR_RLC_DL_BYTES, msgb_length(msg));

	/* set USF */
	OSMO_ASSERT(msgb_length(msg) > 0);
	usf = usf_tbf ? usf_tbf->m_usf[ts] : USF_UNUSED;
	msg->data[0] = (msg->data[0] & 0xf8) | usf;

	/* Used to measure the leak rate, count all blocks */
	gprs_bssgp_update_frames_sent();

	/* Send to GSMTAP */
	tap_n_acc(msg, bts, trx, ts, fn, gsmtap_cat);

	/* send PDTCH/PACCH to L1 */
	pcu_l1if_tx_pdtch(msg, bts, trx, ts, bts->trx[trx].arfcn, fn, block_nr);

	return 0;
}
