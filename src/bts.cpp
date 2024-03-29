/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <bts.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <encoding.h>
#include <decoding.h>
#include <rlc.h>
#include <pcu_l1_if.h>
#include <gprs_ms.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <cxx_linuxlist.h>
#include <pdch.h>
#include <sba.h>
#include <bts_pch_timer.h>

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/msgb.h>
	#include <osmocom/core/stats.h>
	#include <osmocom/gsm/protocol/gsm_04_08.h>
	#include <osmocom/gsm/gsm_utils.h>
	#include <osmocom/gsm/gsm0502.h>
	#include <osmocom/gsm/gsm48.h>
	#include <osmocom/core/gsmtap_util.h>
	#include <osmocom/core/application.h>
	#include <osmocom/core/bitvec.h>
	#include <osmocom/core/gsmtap.h>
	#include <osmocom/core/logging.h>
	#include <osmocom/core/utils.h>
}

#include <errno.h>
#include <string.h>

#define RFN_THRESHOLD RFN_MODULUS / 2

extern void *tall_pcu_ctx;

extern "C" {
	/* e must make sure to initialize logging before the BTS static
	 * constructors are executed below, as those call libosmocore APIs that
	 * require logging already to be initialized. */
	__attribute__((constructor (101))) static void early_init(void)
	{
		if (!tall_pcu_ctx) {
			tall_pcu_ctx = talloc_named_const(NULL, 1, "Osmo-PCU context");
			osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
		}
	}
}

void bts_trx_free_all_tbf(struct gprs_rlcmac_trx *trx)
{
	for (uint8_t ts = 0; ts < 8; ts++)
		pdch_free_all_tbf(&trx->pdch[ts]);
}

static struct osmo_tdef T_defs_bts[] = {
	{ .T=3142, .default_val=20,  .unit=OSMO_TDEF_S,  .desc="Wait Indication used in Imm Ass Reject during TBF Establishment (CCCH)", .val=0, .min_val = 0, .max_val = 255 }, /* TS 44.018 10.5.2.43, TS 44.060 7.1.3.2.1 (T3172) */
	{ .T=3168, .default_val=4000, .unit=OSMO_TDEF_MS,  .desc="Time MS waits for PACKET UPLINK ACK when establishing a UL TBF", .val=0 },
	{ .T=3169, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of USF and TFI(s) after the MS uplink TBF assignment is invalid", .val=0 },
	{ .T=3191, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of TFI(s) after sending (1) last RLC Data Block on TBF(s), or (2) PACKET TBF RELEASE for an MBMS radio bearer", .val=0 },
	{ .T=3192, .default_val=1500, .unit=OSMO_TDEF_MS, .desc="Time MS stays monitoring the PDCH after transmitting DL ACK/NACK for last DL block (FBI=1). Configured at the BSC (SI13).", .val=0 },
	{ .T=3193, .default_val=1600, .unit=OSMO_TDEF_MS, .desc="Reuse of TFI(s) after reception of final PACKET DOWNLINK ACK/NACK from MS for TBF", .val=0 },
	{ .T=3195, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of TFI(s) upon no response from the MS (radio failure or cell change) for TBF/MBMS radio bearer", .val=0 },
	{ .T = -16, .default_val = 1000, .unit = OSMO_TDEF_MS,
		.desc = "Granularity for *:all_allocated rate counters: amount of milliseconds that one counter increment"
			" represents. See also X17, X18" },
	{ .T = -17, .default_val = 0, .unit = OSMO_TDEF_MS,
		.desc = "Rounding threshold for *:all_allocated rate counters: round up to the next counter increment"
			" after this many milliseconds. If set to half of X16 (or 0), employ the usual round() behavior:"
			" round up after half of a granularity period. If set to 1, behave like ceil(): already"
			" increment the counter immediately when all channels are allocated. If set >= X16, behave like"
			" floor(): only increment after a full X16 period of all channels being occupied."
			" See also X16, X18" },
	{ .T = -18, .default_val = 60000, .unit = OSMO_TDEF_MS,
		.desc = "Forget-sum period for *:all_allocated rate counters:"
			" after this amount of idle time, forget internally cumulated time remainders. Zero to always"
			" keep remainders. See also X16, X17." },
	{ .T=0, .default_val=0, .unit=OSMO_TDEF_S, .desc=NULL, .val=0 } /* empty item at the end */
};

/**
 * For gcc-4.4 compat do not use extended initializer list but keep the
 * order from the enum here. Once we support GCC4.7 and up we can change
 * the code below.
 */
static const struct rate_ctr_desc bts_ctr_description[] = {
	{ "pdch:all_allocated",		"Cumulative counter of seconds where all enabled PDCH resources were allocated"},
	{ "tbf:dl:alloc",		"TBF DL Allocated     "},
	{ "tbf:dl:freed",		"TBF DL Freed         "},
	{ "tbf:dl:aborted",		"TBF DL Aborted       "},
	{ "tbf:ul:alloc",		"TBF UL Allocated     "},
	{ "tbf:ul:freed",		"TBF UL Freed         "},
	{ "tbf:ul:aborted",		"TBF UL Aborted       "},
	{ "tbf:reused",			"TBF Reused           "},
	{ "tbf:alloc:algo-a",		"TBF Alloc Algo A     "},
	{ "tbf:alloc:algo-b",		"TBF Alloc Algo B     "},
	{ "tbf:alloc:failed",		"TBF Alloc Failure (any reason)"},
	{ "tbf:alloc:failed:no_tfi",	"TBF Alloc Failure (TFIs exhausted)"},
	{ "tbf:alloc:failed:no_usf",	"TBF Alloc Failure (USFs exhausted)"},
	{ "tbf:alloc:failed:no_slot_combi", "TBF Alloc Failure (No valid UL/DL slot combination found)"},
	{ "tbf:alloc:failed:no_slot_avail", "TBF Alloc Failure (No slot available)"},
	{ "rlc:sent",			"RLC Sent             "},
	{ "rlc:resent",			"RLC Resent           "},
	{ "rlc:restarted",		"RLC Restarted        "},
	{ "rlc:stalled",		"RLC Stalled          "},
	{ "rlc:nacked",			"RLC Nacked           "},
	{ "rlc:final_block_resent",	"RLC Final Blk resent "},
	{ "rlc:ass:timedout",		"RLC Assign Timeout   "},
	{ "rlc:ass:failed",		"RLC Assign Failed    "},
	{ "rlc:ack:timedout",		"RLC Ack Timeout      "},
	{ "rlc:ack:failed",		"RLC Ack Failed       "},
	{ "rlc:rel:timedout",		"RLC Release Timeout  "},
	{ "rlc:late-block",		"RLC Late Block       "},
	{ "rlc:sent-dummy",		"RLC Sent Dummy       "},
	{ "rlc:sent-control",		"RLC Sent Control     "},
	{ "rlc:dl_bytes",		"RLC DL Bytes         "},
	{ "rlc:dl_payload_bytes",	"RLC DL Payload Bytes "},
	{ "rlc:ul_bytes",		"RLC UL Bytes         "},
	{ "rlc:ul_payload_bytes",	"RLC UL Payload Bytes "},
	{ "decode:errors",		"Decode Errors        "},
	{ "sba:allocated",		"SBA Allocated        "},
	{ "sba:freed",			"SBA Freed            "},
	{ "sba:timedout",		"SBA Timeout          "},
	{ "llc:timeout",		"Timedout Frames      "},
	{ "llc:dropped",		"Dropped Frames       "},
	{ "llc:scheduled",		"Scheduled Frames     "},
	{ "llc:dl_bytes",               "RLC encapsulated PDUs"},
	{ "llc:ul_bytes",               "full PDUs received   "},
	{ "pch:requests",		"PCH requests sent    "},
	{ "pch:requests:already",	"PCH requests on subscriber already being paged"},
	{ "pch:requests:timeout",	"PCH requests timeout "},
	{ "rach:requests",		"RACH requests received"},
	{ "rach:requests:11bit",	"11BIT_RACH requests received"},
	{ "rach:requests:one_phase",	"One phase packet access with request for single TS UL"}, /* TS 52.402 B.2.1.49 */
	{ "rach:requests:two_phase",	"Single block packet request for two phase packet access"}, /* TS 52.402 B.2.1.49 */
	{ "rach:requests:unexpected",	"RACH Request with unexpected content received"},
	{ "spb:uplink_first_segment",   "First seg of UL SPB  "},
	{ "spb:uplink_second_segment",  "Second seg of UL SPB "},
	{ "spb:downlink_first_segment", "First seg of DL SPB  "},
	{ "spb:downlink_second_segment","Second seg of DL SPB "},
	{ "immediate:assignment_UL",	"Immediate Assign UL  "},
	{ "immediate:assignment_ul:one_phase",	"Immediate Assign UL (one phase packet access)"}, /* TS 52.402 B.2.1.50 */
	{ "immediate:assignment_ul:two_phase",	"Immediate Assign UL (two phase packet access)"}, /* TS 52.402 B.2.1.50 */
	{ "immediate:assignment_ul:contention_resolution_success", "First RLC Block (PDU) on the PDTCH from the MS received"}, /* TS 52.402 B.2.1.51 */
	{ "immediate:assignment_rej",   "Immediate Assign Rej "},
	{ "immediate:assignment_DL",	"Immediate Assign DL  "},
	{ "channel:request_description","Channel Request Desc "},
	{ "pkt:ul_assignment",		"Packet UL Assignment "},
	{ "pkt:access_reject",          "Packet Access Reject "},
	{ "pkt:dl_assignment",		"Packet DL Assignment "},
	{ "pkt:cell_chg_notification",	"Packet Cell Change Notification"},
	{ "pkt:cell_chg_continue",	"Packet Cell Change Continue"},
	{ "pkt:neigh_cell_data",	"Packet Neighbour Cell Data"},
	{ "ul:control",			"UL control Block     "},
	{ "ul:assignment_poll_timeout",	"UL Assign Timeout    "},
	{ "ul:assignment_failed",	"UL Assign Failed     "},
	{ "dl:assignment_timeout",	"DL Assign Timeout    "},
	{ "dl:assignment_failed",	"DL Assign Failed     "},
	{ "pkt:ul_ack_nack_timeout",	"PUAN Poll Timeout    "},
	{ "pkt:ul_ack_nack_failed",	"PUAN poll Failed     "},
	{ "pkt:dl_ack_nack_timeout",	"PDAN poll Timeout    "},
	{ "pkt:dl_ack_nack_failed",	"PDAN poll Failed     "},
	{ "gprs:downlink_cs1",		"CS1 downlink         "},
	{ "gprs:downlink_cs2",		"CS2 downlink         "},
	{ "gprs:downlink_cs3",		"CS3 downlink         "},
	{ "gprs:downlink_cs4",		"CS4 downlink         "},
	{ "egprs:downlink_mcs1",	"MCS1 downlink        "},
	{ "egprs:downlink_mcs2",	"MCS2 downlink        "},
	{ "egprs:downlink_mcs3",	"MCS3 downlink        "},
	{ "egprs:downlink_mcs4",	"MCS4 downlink        "},
	{ "egprs:downlink_mcs5",	"MCS5 downlink        "},
	{ "egprs:downlink_mcs6",	"MCS6 downlink        "},
	{ "egprs:downlink_mcs7",	"MCS7 downlink        "},
	{ "egprs:downlink_mcs8",	"MCS8 downlink        "},
	{ "egprs:downlink_mcs9",	"MCS9 downlink        "},
	{ "gprs:uplink_cs1",		"CS1 Uplink           "},
	{ "gprs:uplink_cs2",		"CS2 Uplink           "},
	{ "gprs:uplink_cs3",		"CS3 Uplink           "},
	{ "gprs:uplink_cs4",		"CS4 Uplink           "},
	{ "egprs:uplink_mcs1",		"MCS1 Uplink          "},
	{ "egprs:uplink_mcs2",		"MCS2 Uplink          "},
	{ "egprs:uplink_mcs3",		"MCS3 Uplink          "},
	{ "egprs:uplink_mcs4",		"MCS4 Uplink          "},
	{ "egprs:uplink_mcs5",		"MCS5 Uplink          "},
	{ "egprs:uplink_mcs6",		"MCS6 Uplink          "},
	{ "egprs:uplink_mcs7",		"MCS7 Uplink          "},
	{ "egprs:uplink_mcs8",		"MCS8 Uplink          "},
	{ "egprs:uplink_mcs9",		"MCS9 Uplink          "},
};

static const struct rate_ctr_group_desc bts_ctrg_desc = {
	"bts",
	"BTS Statistics",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bts_ctr_description),
	bts_ctr_description,
};

static const struct osmo_stat_item_desc bts_stat_item_description[] = {
	{ "ms.present",		"MS Present           ",
		OSMO_STAT_ITEM_NO_UNIT, 4, 0},
	{ "pdch.available",	"PDCH available       ",
		OSMO_STAT_ITEM_NO_UNIT, 50, 0},
	{ "pdch.occupied",	"PDCH occupied (all)  ",
		OSMO_STAT_ITEM_NO_UNIT, 50, 0},
	{ "pdch.occupied.gprs",	"PDCH occupied (GPRS) ",
		OSMO_STAT_ITEM_NO_UNIT, 50, 0},
	{ "pdch.occupied.egprs","PDCH occupied (EGPRS)",
		OSMO_STAT_ITEM_NO_UNIT, 50, 0},
};

static const struct osmo_stat_item_group_desc bts_statg_desc = {
	"bts",
	"BTS Statistics",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bts_stat_item_description),
	bts_stat_item_description,
};

static int bts_talloc_destructor(struct gprs_rlcmac_bts* bts)
{
	struct GprsMs *ms;
	while ((ms = llist_first_entry_or_null(&bts->ms_list, struct GprsMs, list)))
		talloc_free(ms);

	gprs_bssgp_destroy(bts);

	osmo_time_cc_cleanup(&bts->all_allocated_pdch);

	if (bts->ratectrs) {
		rate_ctr_group_free(bts->ratectrs);
		bts->ratectrs = NULL;
	}

	if (bts->statg) {
		osmo_stat_item_group_free(bts->statg);
		bts->statg = NULL;
	}

	if (bts->app_info) {
		msgb_free(bts->app_info);
		bts->app_info = NULL;
	}

	bts_pch_timer_stop_all(bts);

	llist_del(&bts->list);
	return 0;
}

struct gprs_rlcmac_bts* bts_alloc(struct gprs_pcu *pcu, uint8_t bts_nr)
{
	struct gprs_rlcmac_bts* bts;
	bts = talloc_zero(pcu, struct gprs_rlcmac_bts);
	if (!bts)
		return bts;
	talloc_set_destructor(bts, bts_talloc_destructor);

	bts->pcu = pcu;
	bts->nr = bts_nr;

	bts->cur_fn = FN_UNSET;
	bts->cur_blk_fn = -1;
	bts->max_cs_dl = MAX_GPRS_CS;
	bts->max_cs_ul = MAX_GPRS_CS;
	bts->max_mcs_dl = MAX_EDGE_MCS;
	bts->max_mcs_ul = MAX_EDGE_MCS;
	bts->initial_cs_dl = bts->initial_cs_ul = 1;
	bts->initial_mcs_dl = bts->initial_mcs_ul = 1;
	bts->cs_mask = 1 << 0;  /* CS-1 always enabled by default */
	bts->n3101 = 10;
	bts->n3103 = 4;
	bts->n3105 = 8;
	bts->si13_is_set = false;

	bts->app_info = NULL;
	bts->T_defs_bts = T_defs_bts;
	osmo_tdefs_reset(bts->T_defs_bts);

	/* initialize back pointers */
	for (size_t trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); ++trx_no)
		bts_trx_init(&bts->trx[trx_no], bts, trx_no);

	/* The static allocator might have already registered the counter group.
	   If this happens and we still called explicitly (in tests/ for example)
	   than just allocate the group with different index.
	   This shall be removed once weget rid of BTS singleton */
	if (rate_ctr_get_group_by_name_idx(bts_ctrg_desc.group_name_prefix, 0))
		bts->ratectrs = rate_ctr_group_alloc(tall_pcu_ctx, &bts_ctrg_desc, 1);
	else
		bts->ratectrs = rate_ctr_group_alloc(tall_pcu_ctx, &bts_ctrg_desc, 0);
	OSMO_ASSERT(bts->ratectrs);

	bts->statg = osmo_stat_item_group_alloc(tall_pcu_ctx, &bts_statg_desc, 0);
	OSMO_ASSERT(bts->statg);

	osmo_time_cc_init(&bts->all_allocated_pdch);
	struct osmo_time_cc_cfg *cc_cfg = &bts->all_allocated_pdch.cfg;
	cc_cfg->gran_usec = 1*1000000,
	cc_cfg->forget_sum_usec = 60*1000000,
	cc_cfg->rate_ctr = rate_ctr_group_get_ctr(bts->ratectrs, CTR_PDCH_ALL_ALLOCATED),
	cc_cfg->T_gran = -16,
	cc_cfg->T_round_threshold = -17,
	cc_cfg->T_forget_sum = -18,
	cc_cfg->T_defs = T_defs_bts,

	llist_add_tail(&bts->list, &pcu->bts_list);

	INIT_LLIST_HEAD(&bts->pch_timer);
	INIT_LLIST_HEAD(&bts->ms_list);

	return bts;
}

void bts_set_current_frame_number(struct gprs_rlcmac_bts *bts, uint32_t fn)
{
	/* See also 3GPP TS 45.002, section 4.3.3 */
	OSMO_ASSERT(fn < GSM_TDMA_HYPERFRAME);

	/* The UL frame numbers lag 3 behind the DL frames and the data
	 * indication is only sent after all 4 frames of the block have been
	 * received. Sometimes there is an idle frame between the end of one
	 * and start of another frame (every 3 blocks). */
	if (fn != bts->cur_fn && bts->cur_fn != FN_UNSET && fn != fn_next_block(bts->cur_fn)) {
		LOGP(DRLCMAC, LOGL_NOTICE,
		     "Detected FN jump! %u -> %u (expected %u, delta %u)\n",
		     bts->cur_fn, fn, fn_next_block(bts->cur_fn), GSM_TDMA_FN_DIFF(bts->cur_fn, fn));
	}
	bts->cur_fn = fn;
}

static inline int delta_fn(int fn, int to)
{
	return (fn + GSM_MAX_FN * 3 / 2 - to) % GSM_MAX_FN - GSM_MAX_FN/2;
}

void bts_set_current_block_frame_number(struct gprs_rlcmac_bts *bts, int fn)
{
	int delay = 0;
	const int late_block_delay_thresh = 13;
	const int fn_update_ok_min_delay = -500;
	const int fn_update_ok_max_delay = 0;

	/* frame numbers in the received blocks are assumed to be strongly
	 * monotonic. */
	if (bts->cur_blk_fn >= 0) {
		int delta = delta_fn(fn, bts->cur_blk_fn);
		if (delta <= 0)
			return;
	}

	/* Check block delay vs. the current frame number */
	if (bts_current_frame_number(bts) != 0)
		delay = delta_fn(fn, bts_current_frame_number(bts));
	if (delay <= -late_block_delay_thresh) {
		LOGP(DRLCMAC, LOGL_NOTICE,
			"Late RLC block, FN delta: %d FN: %d curFN: %d\n",
			delay, fn, bts_current_frame_number(bts));
		bts_do_rate_ctr_inc(bts, CTR_RLC_LATE_BLOCK);
	}

	bts->cur_blk_fn = fn;
	if (delay < fn_update_ok_min_delay || delay > fn_update_ok_max_delay ||
	    bts_current_frame_number(bts) == FN_UNSET)
		bts_set_current_frame_number(bts, fn);
}

/* Helper used by bts_add_paging() whenever the target MS is known */
static void bts_add_paging_known_ms(struct GprsMs *ms, const struct osmo_mobile_identity *mi, uint8_t chan_needed)
{
	uint8_t ts;

	if (ms->ul_tbf) {
		for (ts = 0; ts < ARRAY_SIZE(ms->ul_tbf->pdch); ts++) {
			if (ms->ul_tbf->pdch[ts]) {
				LOGPDCH(ms->ul_tbf->pdch[ts], DRLCMAC, LOGL_INFO,
					"Paging on PACCH for %s\n", tbf_name(ms->ul_tbf));
				if (!ms->ul_tbf->pdch[ts]->add_paging(chan_needed, mi))
					continue;
				return;
			}
		}
	}
	if (ms->dl_tbf) {
		for (ts = 0; ts < ARRAY_SIZE(ms->dl_tbf->pdch); ts++) {
			if (ms->dl_tbf->pdch[ts]) {
				LOGPDCH(ms->dl_tbf->pdch[ts], DRLCMAC, LOGL_INFO,
					"Paging on PACCH for %s\n", tbf_name(ms->ul_tbf));
				if (!ms->dl_tbf->pdch[ts]->add_paging(chan_needed, mi))
					continue;
				return;
			}
		}
	}
	LOGPMS(ms, DRLCMAC, LOGL_INFO, "Unable to page on PACCH, no available TBFs\n");
	return;
}

/* ms is NULL if no specific taget was found */
int bts_add_paging(struct gprs_rlcmac_bts *bts, const struct paging_req_cs *req, struct GprsMs *ms)
{
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct llist_head *tmp;
	const struct osmo_mobile_identity *mi;
	uint8_t slot_mask[ARRAY_SIZE(bts->trx)];
	int8_t first_ts; /* must be signed */

	/* First, build the MI used to page on PDCH from available subscriber info: */
	if (req->mi_tmsi_present) {
		mi = &req->mi_tmsi;
	} else if (req->mi_imsi_present) {
		mi = &req->mi_imsi;
	} else {
		LOGPMS(ms, DRLCMAC, LOGL_ERROR, "Unable to page on PACCH, no TMSI nor IMSI in request\n");
		return -EINVAL;
	}

	if (log_check_level(DRLCMAC, LOGL_INFO)) {
		char str[64];
		osmo_mobile_identity_to_str_buf(str, sizeof(str), mi);
		LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n", req->chan_needed, str);
	}

	/* We known the target MS for the paging req, send the req only on PDCH
	 * were that target MS is listening (first slot is enough), and we are done. */
	if (ms) {
		bts_add_paging_known_ms(ms, mi, req->chan_needed);
		return 0;
	}

	/* We don't know the target MS.
	 * collect slots to page
	 * Mark up to one slot attached to each of the TBF of the MS.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));

	llist_for_each(tmp, &bts->ms_list) {
		ms = llist_entry(tmp, typeof(*ms), list);
		struct gprs_rlcmac_tbf *tbfs[] = { ms->ul_tbf, ms->dl_tbf };
		for (l = 0; l < ARRAY_SIZE(tbfs); l++) {
			tbf = tbfs[l];
			if (!tbf)
				continue;
			first_ts = -1;
			for (ts = 0; ts < 8; ts++) {
				if (tbf->pdch[ts]) {
					/* remember the first slot found */
					if (first_ts < 0)
						first_ts = ts;
					/* break, if we already marked a slot */
					if ((slot_mask[tbf->trx->trx_no] & (1 << ts)))
						break;
				}
			}
			/* mark first slot found, if none is marked already */
			if (ts == 8 && first_ts >= 0) {
				LOGPTBF(tbf, LOGL_DEBUG, "uses "
					"TRX=%d TS=%d, so we mark\n",
					tbf->trx->trx_no, first_ts);
				slot_mask[tbf->trx->trx_no] |= (1 << first_ts);
			} else
				LOGPTBF(tbf, LOGL_DEBUG, "uses "
					"already marked TRX=%d TS=%d\n",
					tbf->trx->trx_no, ts);
		}
	}

	/* Now we have a list of marked slots. Every TBF uses at least one
	 * of these slots. */

	/* schedule paging to all marked slots */
	for (trx = 0; trx < 8; trx++) {
		if (slot_mask[trx] == 0)
			continue;
		for (ts = 0; ts < 8; ts++) {
			if ((slot_mask[trx] & (1 << ts))) {
				/* schedule */
				if (!bts->trx[trx].pdch[ts].add_paging(req->chan_needed, mi))
					return -ENOMEM;

				LOGPDCH(&bts->trx[trx].pdch[ts], DRLCMAC, LOGL_INFO, "Paging on PACCH\n");
				any_tbf = 1;
			}
		}
	}

	if (!any_tbf)
		LOGP(DRLCMAC, LOGL_INFO, "No paging, because no TBF\n");

	return 0;
}

void bts_send_gsmtap_rach(struct gprs_rlcmac_bts *bts,
			  enum pcu_gsmtap_category categ, uint8_t channel,
			  const struct rach_ind_params *rip)
{
	struct pcu_l1_meas meas = { 0 };
	uint8_t ra_buf[2];

	/* 3GPP TS 44.004 defines 11 bit RA as follows: xxxx xxxx  .... .yyy
	 * On the PCUIF, we get 16 bit machne dependent number (LE/BE)
	 * Over GSMTAP we send the following:           xxxx xxxx  yyy. ....
	 * This simplifies parsing in Wireshark using its CSN.1 codec. */
	if (rip->is_11bit) {
		ra_buf[0] = (uint8_t) ((rip->ra >> 3) & 0xff);
		ra_buf[1] = (uint8_t) ((rip->ra << 5) & 0xff);
	} else {
		ra_buf[0] = (uint8_t) (rip->ra & 0xff);
	}

	bts_send_gsmtap_meas(bts, categ, true, rip->trx_nr, rip->ts_nr, channel,
			 rip->fn, ra_buf,
			 rip->is_11bit ? 2 : 1, &meas);
}

void bts_send_gsmtap(struct gprs_rlcmac_bts *bts,
		     enum pcu_gsmtap_category categ, bool uplink, uint8_t trx_no,
		     uint8_t ts_no, uint8_t channel, uint32_t fn,
		     const uint8_t *data, unsigned int len)
{
	struct pcu_l1_meas meas = { 0 };
	bts_send_gsmtap_meas(bts, categ, uplink, trx_no, ts_no, channel, fn, data, len, &meas);
}

void bts_send_gsmtap_meas(struct gprs_rlcmac_bts *bts,
			  enum pcu_gsmtap_category categ, bool uplink, uint8_t trx_no,
			  uint8_t ts_no, uint8_t channel, uint32_t fn,
			  const uint8_t *data, unsigned int len, struct pcu_l1_meas *meas)
{
	uint16_t arfcn;

	/* check if category is activated at all */
	if (!(bts->pcu->gsmtap_categ_mask & (1 << categ)))
		return;

	arfcn = bts->trx[trx_no].arfcn;
	if (uplink)
		arfcn |= GSMTAP_ARFCN_F_UPLINK;

	/* GSMTAP needs the SNR here, but we only have C/I (meas->link_qual).
	   Those are not the same, but there is no known way to convert them,
	   let's pass C/I instead of nothing */
	gsmtap_send(bts->pcu->gsmtap, arfcn, ts_no, channel, 0, fn,
		    meas->rssi, meas->link_qual, data, len);
}

/* lookup downlink TBF Entity (by TFI) */
struct gprs_rlcmac_dl_tbf *bts_dl_tbf_by_tfi(struct gprs_rlcmac_bts *bts, uint8_t tfi, uint8_t trx, uint8_t ts)
{
	if (trx >= 8 || ts >= 8)
		return NULL;

	return bts->trx[trx].pdch[ts].dl_tbf_by_tfi(tfi);
}

/* lookup uplink TBF Entity (by TFI) */
struct gprs_rlcmac_ul_tbf *bts_ul_tbf_by_tfi(struct gprs_rlcmac_bts *bts, uint8_t tfi, uint8_t trx, uint8_t ts)
{
	if (trx >= 8 || ts >= 8)
		return NULL;

	return bts->trx[trx].pdch[ts].ul_tbf_by_tfi(tfi);
}

static unsigned int trx_count_free_tfi(const struct gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction dir, uint8_t *first_free_tfi)
{
	const struct gprs_rlcmac_pdch *pdch;
	uint8_t ts;
	unsigned int i;
	unsigned int free_tfi_cnt = 0;
	bool has_pdch = false;
	uint32_t mask = NO_FREE_TFI;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		pdch = &trx->pdch[ts];
		if (!pdch->is_enabled())
			continue;
		has_pdch = true;
		mask &= ~pdch->assigned_tfi(dir);
	}

	if (!has_pdch || !mask) {
		*first_free_tfi = (uint8_t)-1;
		return 0;
	}

	/* Count free tfis and return */
	for (i = 0; i < sizeof(mask) * 8 ; i++) {
		if (mask & 1) {
			if (free_tfi_cnt == 0)
				*first_free_tfi = i;
			free_tfi_cnt++;
		}
		mask >>= 1;
	}
	return free_tfi_cnt;
}

/*
 * Search for free TFI and return TFI, TRX. This method returns the first TFI
 * that is currently not used in any PDCH of a the TRX with least TFIs currently
 * assigned. Negative values indicate errors.
 */
int bts_tfi_find_free(const struct gprs_rlcmac_bts *bts, enum gprs_rlcmac_tbf_direction dir,
		      uint8_t *_trx, int8_t use_trx)
{
	uint8_t trx_from, trx_to, trx;
	uint8_t best_trx_nr = 0xff;
	unsigned int best_cnt = 0;
	uint8_t best_first_tfi = 0;

	if (use_trx >= 0 && use_trx < (int8_t)ARRAY_SIZE(bts->trx))
		trx_from = trx_to = use_trx;
	else {
		trx_from = 0;
		trx_to = 7;
	}

	/* find a TFI that is unused on all PDCH */
	for (trx = trx_from; trx <= trx_to; trx++) {
		uint8_t tmp_first_tfi = 0xff; /* make gcc happy */
		unsigned int tmp_cnt;
		tmp_cnt = trx_count_free_tfi(&bts->trx[trx], dir, &tmp_first_tfi);
		if (tmp_cnt > best_cnt) {
			best_cnt = tmp_cnt;
			best_first_tfi = tmp_first_tfi;
			best_trx_nr = trx;
		}
	}

	if (best_trx_nr == 0xff || best_cnt == 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available (suggested TRX: %d).\n", use_trx);
		bts_do_rate_ctr_inc(bts, CTR_TBF_ALLOC_FAIL_NO_TFI);
		return -EBUSY;
	}

	OSMO_ASSERT(best_first_tfi < 32);

	LOGP(DRLCMAC, LOGL_DEBUG, "Found first unallocated TRX=%d TFI=%d\n",
	     best_trx_nr, best_first_tfi);
	*_trx = best_trx_nr;
	return best_first_tfi;
}

static int tlli_from_imm_ass(uint32_t *tlli, const uint8_t *data)
{
	const struct gsm48_imm_ass *imm_ass = (struct gsm48_imm_ass *)data;
	uint8_t plen;

	/* Move to IA Rest Octets: TS 44.018 9.1.18 "The L2 pseudo length of
	 * this message is the sum of lengths of all information elements
	 * present in the message except the IA Rest Octets and L2 Pseudo Length
	 * information elements." */
	/* TS 44.018 10.5.2.19 l2_plen byte lowest 2 bits are '01'B */
	plen = imm_ass->l2_plen >> 2;
	data += 1 + plen;

	if ((*data & 0xf0) != 0xd0) {
		LOGP(DTBFDL, LOGL_ERROR, "Got IMM.ASS confirm, but rest "
			"octets do not start with bit sequence 'HH01' "
			"(Packet Downlink Assignment)\n");
		return -EINVAL;
	}

	/* get TLLI from downlink assignment */
	*tlli = (uint32_t)((*data++) & 0xf) << 28;
	*tlli |= (*data++) << 20;
	*tlli |= (*data++) << 12;
	*tlli |= (*data++) << 4;
	*tlli |= (*data++) >> 4;

	return 0;
}

int bts_rcv_imm_ass_cnf(struct gprs_rlcmac_bts *bts, const uint8_t *data, uint32_t tlli)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	GprsMs *ms;
	int rc;

	/* NOTE: A confirmation for a downlink IMMEDIATE ASSIGNMENT can be received using two different methods.
	 * One way is to send the whole IMMEDIATE ASSIGNMENT back to the PCU and the TLLI, which we use as
	 * reference is extracted from the rest octets of this message. Alternatively the TLLI may be sent as
	 * confirmation directly. */

	/* Extract TLLI from the presented IMMEDIATE ASSIGNMENT
	 * (if present and only when TLLI that is supplied as function parameter is valid.) */
	if (data && tlli == GSM_RESERVED_TMSI) {
		rc = tlli_from_imm_ass(&tlli, data);
		if (rc != 0)
			return -EINVAL;
	}

	/* Make sure TLLI is valid */
	if (tlli == GSM_RESERVED_TMSI) {
		LOGP(DTBFDL, LOGL_ERROR, "Got IMM.ASS confirm, but TLLI is invalid!\n");
		return -EINVAL;
	}

	/* Find related TBF and send confirmation signal to FSM */
	ms = bts_get_ms_by_tlli(bts, tlli, GSM_RESERVED_TMSI);
	if (!ms) {
		LOGP(DTBFDL, LOGL_ERROR, "Got IMM.ASS confirm for unknown MS with TLLI=%08x\n", tlli);
		return -EINVAL;
	}
	dl_tbf = ms_dl_tbf(ms);
	if (!dl_tbf) {
		LOGPMS(ms, DTBFDL, LOGL_ERROR, "Got IMM.ASS confirm, but MS has no DL TBF!\n");
		return -EINVAL;
	}

	LOGPTBFDL(dl_tbf, LOGL_DEBUG, "Got IMM.ASS confirm\n");
	osmo_fsm_inst_dispatch(dl_tbf->state_fi, TBF_EV_ASSIGN_PCUIF_CNF, NULL);

	return 0;
}

/* Determine the full frame number from a relative frame number */
uint32_t bts_rfn_to_fn(const struct gprs_rlcmac_bts *bts, uint32_t rfn)
{
	uint32_t m_cur_fn, m_cur_rfn;
	uint32_t fn_rounded;

	/* Ensure that all following calculations are performed with the
	 * relative frame number */
	OSMO_ASSERT(rfn < RFN_MODULUS);

	m_cur_fn = bts_current_frame_number(bts);
	if (OSMO_UNLIKELY(m_cur_fn == FN_UNSET)) {
		LOGP(DRLCMAC, LOGL_ERROR, "Unable to calculate full FN from RFN %u: Current FN not known!\n",
		     rfn);
		return rfn;
	}

	/* Compute an internal relative frame number from the full internal
	   frame number */
	m_cur_rfn = fn2rfn(m_cur_fn);

	/* Compute a "rounded" version of the internal frame number, which
	 * exactly fits in the RFN_MODULUS raster */
	fn_rounded = GSM_TDMA_FN_SUB(m_cur_fn, m_cur_rfn);

	/* If the delta between the internal and the external relative frame
	 * number exceeds a certain limit, we need to assume that the incoming
	 * rach request belongs to a the previous rfn period. To correct this,
	 * we roll back the rounded frame number by one RFN_MODULUS */
	if (GSM_TDMA_FN_DIFF(rfn, m_cur_rfn) > RFN_THRESHOLD) {
		LOGP(DRLCMAC, LOGL_DEBUG,
		     "Race condition between rfn (%u) and m_cur_fn (%u) detected: rfn belongs to the previous modulus %u cycle, wrapping...\n",
		     rfn, m_cur_fn, RFN_MODULUS);
		if (fn_rounded < RFN_MODULUS) {
			LOGP(DRLCMAC, LOGL_DEBUG,
			"Cornercase detected: wrapping crosses %u border\n",
			GSM_MAX_FN);
			fn_rounded = GSM_TDMA_FN_SUB(GSM_MAX_FN, (GSM_TDMA_FN_SUB(RFN_MODULUS, fn_rounded)));
		}
		else
			fn_rounded = GSM_TDMA_FN_SUB(fn_rounded, RFN_MODULUS);
	}

	/* The real frame number is the sum of the rounded frame number and the
	 * relative framenumber computed via RACH */
	return GSM_TDMA_FN_SUM(fn_rounded, rfn);
}

/* 3GPP TS 44.060:
 *   Table 11.2.5.2: PACKET CHANNEL REQUEST
 *   Table 11.2.5a.2: EGPRS PACKET CHANNEL REQUEST
 * Both GPRS and EGPRS use same MultislotClass coding, but since PRACH is
 * deprecated, no PACKET CHANNEL REQUEST exists, which means for GPRS we will
 * receive CCCH RACH which doesn't contain any mslot class. Hence in the end we
 * can only receive EGPRS mslot class through 11-bit EGPRS PACKET CHANNEL REQUEST. */
static int parse_egprs_pkt_ch_req(uint16_t ra11, struct chan_req_params *chan_req)
{
	EGPRS_PacketChannelRequest_t req;
	int rc;

	rc = decode_egprs_pkt_ch_req(ra11, &req);
	if (rc) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Failed to decode "
		     "EGPRS Packet Channel Request: rc=%d\n", rc);
		return rc;
	}

	LOGP(DRLCMAC, LOGL_INFO, "Rx EGPRS Packet Channel Request: %s\n",
	     get_value_string(egprs_pkt_ch_req_type_names, req.Type));

	switch (req.Type) {
	case EGPRS_PKT_CHAN_REQ_ONE_PHASE:
		chan_req->egprs_mslot_class = req.Content.MultislotClass + 1;
		chan_req->priority = req.Content.Priority + 1;
		break;
	case EGPRS_PKT_CHAN_REQ_SHORT:
		chan_req->priority = req.Content.Priority + 1;
		if (req.Content.NumberOfBlocks == 0)
			chan_req->single_block = true;
		break;
	case EGPRS_PKT_CHAN_REQ_ONE_PHASE_RED_LATENCY:
		chan_req->priority = req.Content.Priority + 1;
		break;
	/* Two phase access => single block is needed */
	case EGPRS_PKT_CHAN_REQ_TWO_PHASE:
	case EGPRS_PKT_CHAN_REQ_TWO_PHASE_IPA:
		chan_req->priority = req.Content.Priority + 1;
		chan_req->single_block = true;
		break;
	/* Signalling => single block is needed */
	case EGPRS_PKT_CHAN_REQ_SIGNALLING:
	case EGPRS_PKT_CHAN_REQ_SIGNALLING_IPA:
		chan_req->single_block = true;
		break;

	/* Neither unacknowledged RLC mode, nor emergency calls are supported */
	case EGPRS_PKT_CHAN_REQ_ONE_PHASE_UNACK:
	case EGPRS_PKT_CHAN_REQ_EMERGENCY_CALL:
	case EGPRS_PKT_CHAN_REQ_DEDICATED_CHANNEL:
		LOGP(DRLCMAC, LOGL_NOTICE, "%s is not supported, rejecting\n",
		     get_value_string(egprs_pkt_ch_req_type_names, req.Type));
		return -ENOTSUP;

	default:
		LOGP(DRLCMAC, LOGL_ERROR, "Unknown EGPRS Packet Channel Request "
		     "type=0x%02x, probably a bug in CSN.1 codec\n", req.Type);
		return -EINVAL;
	}

	return 0;
}

/* NOTE: chan_req needs to be zero-initialized by the caller */
static int parse_rach_ind(const struct rach_ind_params *rip,
			  struct chan_req_params *chan_req)
{
	int rc;

	switch (rip->burst_type) {
	case GSM_L1_BURST_TYPE_NONE:
		LOGP(DRLCMAC, LOGL_ERROR, "RACH.ind contains no burst type, assuming TS0\n");
		/* fall-through */
	case GSM_L1_BURST_TYPE_ACCESS_0:
		if (rip->is_11bit) { /* 11 bit Access Burst with TS0 => Packet Channel Request */
			LOGP(DRLCMAC, LOGL_ERROR, "11 bit Packet Channel Request "
			     "is not supported (PBCCH is deprecated)\n");
			return -ENOTSUP;
		}

		/* 3GPP TS 44.018, table 9.1.8.1: 8 bit CHANNEL REQUEST.
		 * Mask 01110xxx indicates single block packet access. */
		chan_req->single_block = ((rip->ra & 0xf8) == 0x70);
		break;
	case GSM_L1_BURST_TYPE_ACCESS_1:
	case GSM_L1_BURST_TYPE_ACCESS_2:
		if (!rip->is_11bit) { /* TS1/TS2 => EGPRS Packet Channel Request (always 11 bit) */
			LOGP(DRLCMAC, LOGL_ERROR, "11 bit Packet Channel Request "
			     "is not supported (PBCCH is deprecated)\n");
			return -ENOTSUP;
		}

		rc = parse_egprs_pkt_ch_req(rip->ra, chan_req);
		if (rc)
			return rc;
		break;
	default:
		LOGP(DRLCMAC, LOGL_ERROR, "RACH.ind contains unknown burst type 0x%02x "
		     "(%u bit)\n", rip->burst_type, rip->is_11bit ? 11 : 8);
		return -EINVAL;
	}

	return 0;
}

struct gprs_rlcmac_sba *bts_alloc_sba(struct gprs_rlcmac_bts *bts, uint8_t ta)
{
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_sba *sba = NULL;
	int8_t trx, ts;

	if (!gsm48_ta_is_valid(ta))
		return NULL;

	for (trx = 0; trx < 8; trx++) {
		for (ts = 7; ts >= 0; ts--) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->is_enabled())
				continue;
			break;
		}
		if (ts >= 0)
			break;
	}
	if (trx == 8) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		return NULL;
	}

	sba = sba_alloc(bts, pdch, ta);
	if (!sba)
		return NULL;

	bts_do_rate_ctr_inc(bts, CTR_SBA_ALLOCATED);
	return sba;
}

int bts_rcv_rach(struct gprs_rlcmac_bts *bts, const struct rach_ind_params *rip)
{
	struct chan_req_params chan_req = { 0 };
	struct gprs_rlcmac_ul_tbf *tbf = NULL;
	struct gprs_rlcmac_sba *sba;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_trx *trx;
	uint32_t sb_fn = 0;
	uint8_t usf = 7;
	int plen, rc;

	/* Allocate a bit-vector for RR Immediate Assignment [Reject] */
	struct bitvec *bv = bitvec_alloc(22, tall_pcu_ctx); /* without plen */
	bitvec_unhex(bv, DUMMY_VEC); /* standard '2B'O padding */

	bts_do_rate_ctr_inc(bts, CTR_RACH_REQUESTS);

	if (rip->is_11bit)
		bts_do_rate_ctr_inc(bts, CTR_RACH_REQUESTS_11BIT);

	uint8_t ta = qta2ta(rip->qta);

	bts_send_gsmtap_rach(bts, PCU_GSMTAP_C_UL_RACH, GSMTAP_CHANNEL_RACH, rip);

	LOGP(DRLCMAC, LOGL_DEBUG, "MS requests Uplink resource on CCCH/RACH: "
	     "ra=0x%02x (%d bit) Fn=%u qta=%d\n", rip->ra,
	     rip->is_11bit ? 11 : 8, rip->fn, rip->qta);

	/* Parse [EGPRS Packet] Channel Request from RACH.ind */
	rc = parse_rach_ind(rip, &chan_req);
	if (rc) {
		bts_do_rate_ctr_inc(bts, CTR_RACH_REQUESTS_UNEXPECTED);
		/* Send RR Immediate Assignment Reject */
		goto send_imm_ass_rej;
	}

	if (chan_req.single_block) {
		bts_do_rate_ctr_inc(bts, CTR_RACH_REQUESTS_TWO_PHASE);
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single block allocation "
		     "(two phase packet access)\n");
	} else {
		bts_do_rate_ctr_inc(bts, CTR_RACH_REQUESTS_ONE_PHASE);
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single TS uplink transmission "
		     "(one phase packet access)\n");
		if (bts->pcu->vty.force_two_phase) {
			/* 3GPP TS 44.018 3.5.2.1.3.1: "If the establishment cause in the
			 * CHANNEL REQUEST message indicates a request for one phase packet access,
			 * the network may grant either a one phase packet access or a single block
			 * packet access for the mobile station. If a single block packet access is
			 * granted, it forces the mobile station to perform a two phase packet access."
			 */
			LOGP(DRLCMAC, LOGL_DEBUG, "Forcing two phase access\n");
			chan_req.single_block = true;
		}
	}

	/* TODO: handle Radio Priority (see 3GPP TS 44.060, table 11.2.5a.5) */
	if (chan_req.priority > 0)
		LOGP(DRLCMAC, LOGL_NOTICE, "EGPRS Packet Channel Request indicates "
		     "Radio Priority %u, however we ignore it\n", chan_req.priority);

	/* Should we allocate a single block or an Uplink TBF? */
	if (chan_req.single_block) {
		sba = bts_alloc_sba(bts, ta);
		if (!sba) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource for "
			     "single block allocation\n");
			rc = -EBUSY;
			/* Send RR Immediate Assignment Reject */
			goto send_imm_ass_rej;
		}

		pdch = sba->pdch;
		sb_fn = sba->fn;
		LOGP(DRLCMAC, LOGL_DEBUG, "Allocated a single block at "
		     "SBFn=%u TRX=%u TS=%u\n", sb_fn, pdch->trx->trx_no, pdch->ts_no);
		bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_UL_TBF_TWO_PHASE);
	} else {
		GprsMs *ms = ms_alloc(bts, __func__);
		ms_set_egprs_ms_class(ms, chan_req.egprs_mslot_class);
		tbf = ms_new_ul_tbf_assigned_agch(ms);
		/* Here either tbf was created and it holds a ref to MS, or tbf
		 * creation failed and MS will end up without references and being
		 * freed: */
		ms_unref(ms, __func__);
		if (!tbf) {
			/* Send RR Immediate Assignment Reject */
			rc = -EBUSY;
			goto send_imm_ass_rej;
		}
		tbf->set_ta(ta);
		/* Only single TS can be allocated through AGCH, hence first TS is the only one: */
		pdch = tbf_get_first_ts(tbf);
		usf = tbf->m_usf[pdch->ts_no];
		bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_UL_TBF_ONE_PHASE);
	}
	trx = pdch->trx;

	LOGP(DRLCMAC, LOGL_DEBUG, "Tx Immediate Assignment on AGCH: "
	     "TRX=%u (ARFCN %u) TS=%u TA=%u TSC=%u TFI=%d USF=%d\n",
	     trx->trx_no, trx->arfcn & ~ARFCN_FLAG_MASK,
	     pdch->ts_no, ta, pdch->tsc, tbf ? tbf->tfi() : -1, usf);
	plen = Encoding::write_immediate_assignment(pdch, tbf, bv,
		false, rip->ra, rip->rfn, ta, usf, false, fn2rfn(sb_fn),
		bts_get_ms_pwr_alpha(bts), bts->pcu->vty.gamma, -1,
		rip->burst_type);
	bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_UL_TBF);
	if (plen >= 0) {
		pcu_l1if_tx_agch2(bts, bv, plen, false, GSM_RESERVED_TMSI);
		rc = 0;
	} else {
		rc = plen;
	}
	bitvec_free(bv);
	return rc;

send_imm_ass_rej:
	LOGP(DRLCMAC, LOGL_DEBUG, "Tx Immediate Assignment Reject on AGCH\n");
	plen = Encoding::write_immediate_assignment_reject(
		bv, rip->ra, rip->rfn, rip->burst_type,
		(uint8_t)osmo_tdef_get(bts->T_defs_bts, 3142, OSMO_TDEF_S, -1));
	bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_REJ);
	if (plen >= 0)
		pcu_l1if_tx_agch2(bts, bv, plen, false, GSM_RESERVED_TMSI);
	bitvec_free(bv);
	/* rc was already properly set before goto */
	return rc;
}

/* PTCCH/U sub-slot / frame-number mapping (see 3GPP TS 45.002, table 6) */
static uint32_t ptcch_slot_map[PTCCH_TAI_NUM] = {
	 12,  38,  64,  90,
	116, 142, 168, 194,
	220, 246, 272, 298,
	324, 350, 376, 402,
};

int bts_rcv_ptcch_rach(struct gprs_rlcmac_bts *bts, const struct rach_ind_params *rip)
{
	uint16_t fn416 = rip->rfn % 416;
	struct gprs_rlcmac_pdch *pdch;
	uint8_t ss;

	bts_send_gsmtap_rach(bts, PCU_GSMTAP_C_UL_PTCCH, GSMTAP_CHANNEL_PTCCH, rip);

	/* Prevent buffer overflow */
	if (rip->trx_nr >= ARRAY_SIZE(bts->trx) || rip->ts_nr >= 8) {
		LOGP(DRLCMAC, LOGL_ERROR, "(TRX=%u TS=%u RFN=%u) Rx malformed "
		     "RACH.ind (PTCCH/U)\n", rip->trx_nr, rip->ts_nr, rip->rfn);
		return -EINVAL;
	}

	/* Make sure PDCH time-slot is enabled */
	pdch = &bts->trx[rip->trx_nr].pdch[rip->ts_nr];
	if (!pdch->is_enabled()) {
		LOGP(DRLCMAC, LOGL_NOTICE, "(TRX=%u TS=%u RFN=%u) Rx RACH.ind (PTCCH/U) "
		     "for inactive PDCH\n", rip->trx_nr, rip->ts_nr, rip->rfn);
		return -EAGAIN;
	}

	/* Convert TDMA frame-number to PTCCH/U sub-slot number */
	for (ss = 0; ss < PTCCH_TAI_NUM; ss++)
		if (ptcch_slot_map[ss] == fn416)
			break;
	if (ss == PTCCH_TAI_NUM) {
		LOGP(DRLCMAC, LOGL_ERROR, "(TRX=%u TS=%u RFN=%u) Failed to map "
		     "PTCCH/U sub-slot\n", rip->trx_nr, rip->ts_nr, rip->rfn);
		return -ENODEV;
	}

	/* Apply the new Timing Advance value */
	LOGP(DRLCMAC, LOGL_INFO, "Continuous Timing Advance update "
	     "for TAI %u, new TA is %u\n", ss, qta2ta(rip->qta));
	pdch->update_ta(ss, qta2ta(rip->qta));

	return 0;
}

void bts_snd_dl_ass(struct gprs_rlcmac_bts *bts, const struct gprs_rlcmac_dl_tbf *tbf)
{
	int plen;

	/* Only one TS can be assigned through PCH, hence the first one is the only one: */
	const struct gprs_rlcmac_pdch *pdch = tbf_get_first_ts_const(tbf);
	OSMO_ASSERT(pdch);

	LOGPTBFDL(tbf, LOGL_INFO, "Tx CCCH (PCH) Immediate Assignment [PktDlAss=%s] TA=%d\n", pdch_name(pdch), tbf->ta());

	bitvec *immediate_assignment = bitvec_alloc(22, tall_pcu_ctx); /* without plen */
	bitvec_unhex(immediate_assignment, DUMMY_VEC); /* standard '2B'O padding */
	/* 3GPP TS 44.018, section 9.1.18.0d states that the network shall code the
	 * Request Reference IE, e.g. by using a suitably offset frame number, such
	 * that the resource reference cannot be confused with any CHANNEL REQUEST
	 * message sent by a mobile station.  Use last_rts_fn + 21216 (16 TDMA
	 * super-frame periods, or ~21.3 seconds) to achieve a decent distance. */
	plen = Encoding::write_immediate_assignment(pdch,
						    tbf, immediate_assignment, true, 125,
						    fn2rfn(GSM_TDMA_FN_SUM(pdch->last_rts_fn, 21216)),
						    tbf->ta(), 7, false, 0,
						    bts_get_ms_pwr_alpha(bts), bts->pcu->vty.gamma, -1,
						    GSM_L1_BURST_TYPE_ACCESS_0);
	if (plen >= 0) {
		bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_DL_TBF);

		if (ms_imsi_is_valid(tbf->ms())) {
			pcu_l1if_tx_pch2(bts, immediate_assignment, plen, true, tbf->imsi(), tbf->tlli());
		} else {
			/* During GMM ATTACH REQUEST, the IMSI is not yet known to the PCU or SGSN. (It is
			 * requested after the GMM ATTACH REQUEST with the GMM IDENTITY REQUEST.) When the PCU
			 * has to assign a DL TBF but the IMSI is not known, then the IMMEDIATE ASSIGNMENT is
			 * sent on the AGCH. The reason for this is that without an IMSI we can not calculate
			 * the paging group, which would be necessary for transmission on PCH. Since the IMSI
			 * is usually only unknown during the GMM ATTACH REQUEST, we may assume that the MS
			 * is in non-DRX mode and hence it is listening on all CCCH blocks, including AGCH.
			 *
			 * See also: 3gpp TS 44.060, section 5.5.1.5
			 *           3gpp TS 45.002, section 6.5.3, 6.5.6 */
			pcu_l1if_tx_agch2(bts, immediate_assignment, plen, true, tbf->tlli());
		}
	}

	bitvec_free(immediate_assignment);
}

/* return maximum DL CS supported by BTS and allowed by VTY */
uint8_t bts_max_cs_dl(const struct gprs_rlcmac_bts* bts)
{
	return bts->max_cs_dl;
}

/* return maximum UL CS supported by BTS and allowed by VTY */
uint8_t bts_max_cs_ul(const struct gprs_rlcmac_bts* bts)
{
	return bts->max_cs_ul;
}

/* return maximum DL MCS supported by BTS and allowed by VTY */
uint8_t bts_max_mcs_dl(const struct gprs_rlcmac_bts* bts)
{
	return bts->max_mcs_dl;
}

/* return maximum UL MCS supported by BTS and allowed by VTY */
uint8_t bts_max_mcs_ul(const struct gprs_rlcmac_bts* bts)
{
	return bts->max_mcs_ul;
}

/* Set maximum DL CS supported by BTS and allowed by VTY */
void bts_set_max_cs_dl(struct gprs_rlcmac_bts* bts, uint8_t cs_dl)
{
	bts->max_cs_dl = cs_dl;
}

/* Set maximum UL CS supported by BTS and allowed by VTY */
void bts_set_max_cs_ul(struct gprs_rlcmac_bts* bts, uint8_t cs_ul)
{
	bts->max_cs_ul = cs_ul;
}

/* Set maximum DL MCS supported by BTS and allowed by VTY */
void bts_set_max_mcs_dl(struct gprs_rlcmac_bts* bts, uint8_t mcs_dl)
{
	bts->max_mcs_dl = mcs_dl;
}

/* Set maximum UL MCS supported by BTS and allowed by VTY */
void bts_set_max_mcs_ul(struct gprs_rlcmac_bts* bts, uint8_t mcs_ul)
{
	bts->max_mcs_ul = mcs_ul;
}

bool bts_cs_dl_is_supported(const struct gprs_rlcmac_bts* bts, CodingScheme cs)
{
	OSMO_ASSERT(mcs_is_valid(cs));
	uint8_t num = mcs_chan_code(cs);
	if (mcs_is_gprs(cs)) {
		return (bts_max_cs_dl(bts) >= num) && (bts->cs_mask & (1U << num));
	} else {
		return (bts_max_mcs_dl(bts) >= num) && (bts->mcs_mask & (1U << num));
	}
}

struct GprsMs *bts_get_ms(const struct gprs_rlcmac_bts *bts, uint32_t tlli, uint32_t old_tlli,
			  const char *imsi)
{
	struct llist_head *tmp;

	if (tlli != GSM_RESERVED_TMSI || old_tlli != GSM_RESERVED_TMSI) {
		llist_for_each(tmp, &bts->ms_list) {
			struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
			if (ms_check_tlli(ms, tlli))
				return ms;
			if (ms_check_tlli(ms, old_tlli))
				return ms;
		}
	}

	/* not found by TLLI */

	if (imsi && imsi[0] != '\0') {
		llist_for_each(tmp, &bts->ms_list) {
			struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
			if (ms_imsi_is_valid(ms) && strcmp(imsi, ms_imsi(ms)) == 0)
				return ms;
		}
	}

	return NULL;
}

struct GprsMs *bts_get_ms_by_tlli(const struct gprs_rlcmac_bts *bts, uint32_t tlli, uint32_t old_tlli)
{
	return bts_get_ms(bts, tlli, old_tlli, NULL);
}

struct GprsMs *bts_get_ms_by_imsi(const struct gprs_rlcmac_bts *bts, const char *imsi)
{
	return bts_get_ms(bts, GSM_RESERVED_TMSI, GSM_RESERVED_TMSI, imsi);
}

/* update TA based on TA provided by PH-DATA-IND */
void update_tbf_ta(struct gprs_rlcmac_ul_tbf *tbf, int8_t ta_delta)
{
	int16_t ta_adj;
	uint8_t ta_target;

	if (ta_delta) {
		/* adjust TA based on TA provided by PH-DATA-IND */
		ta_adj = tbf->ta() + ta_delta;

		/* limit target TA in range 0..63 bits */
		ta_target = ta_limit(ta_adj);

		LOGP(DL1IF, LOGL_INFO, "PH-DATA-IND is updating %s: TA %u -> %u on "
		     "TRX = %d\n", tbf_name(tbf), tbf->ta(), ta_target, tbf->trx->trx_no);
		tbf->set_ta(ta_target);
	}
}

/* set TA based on TA provided by PH-RA-IND */
void set_tbf_ta(struct gprs_rlcmac_ul_tbf *tbf, uint8_t ta)
{
	uint8_t ta_target;

	if (tbf->ta() != ta) {
		/* limit target TA in range 0..63 bits */
		ta_target = ta_limit(ta);

		LOGP(DL1IF, LOGL_INFO, "PH-RA-IND is updating %s: TA %u -> %u on "
		     "TRX = %d\n", tbf_name(tbf), tbf->ta(), ta_target, tbf->trx->trx_no);
		tbf->set_ta(ta_target);
	}
}

void bts_update_tbf_ta(struct gprs_rlcmac_bts *bts, const char *p, uint32_t fn,
		       uint8_t trx_no, uint8_t ts, int8_t ta, bool is_rach)
{
	struct gprs_rlcmac_pdch *pdch = &bts->trx[trx_no].pdch[ts];
	struct pdch_ulc_node *poll;
	struct gprs_rlcmac_ul_tbf *tbf;
	if (!pdch->is_enabled())
		goto no_tbf;

	poll = pdch_ulc_get_node(pdch->ulc, fn);
	if (!poll || poll->type != PDCH_ULC_NODE_TBF_POLL ||
	    poll->tbf_poll.poll_tbf->direction != GPRS_RLCMAC_UL_TBF)
		goto no_tbf;

	tbf = tbf_as_ul_tbf(poll->tbf_poll.poll_tbf);
	/* we need to distinguish TA information provided by L1
	 * from PH-DATA-IND and PHY-RA-IND so that we can properly
	 * update TA for given TBF
	 */
	if (is_rach)
		set_tbf_ta(tbf, (uint8_t)ta);
	else
		update_tbf_ta(tbf, ta);
	return;

no_tbf:
	LOGP(DL1IF, LOGL_DEBUG, "[%s] update TA = %u ignored due to "
	     "unknown UL TBF on TRX = %d, TS = %d, FN = %d\n",
	     p, ta, trx_no, ts, fn);
}

void bts_trx_init(struct gprs_rlcmac_trx *trx, struct gprs_rlcmac_bts *bts, uint8_t trx_no)
{
	trx->trx_no = trx_no;
	trx->bts = bts;

	INIT_LLIST_HEAD(&trx->ul_tbfs);
	INIT_LLIST_HEAD(&trx->dl_tbfs);

	for (size_t ts_no = 0; ts_no < ARRAY_SIZE(trx->pdch); ts_no++)
		pdch_init(&trx->pdch[ts_no], trx, ts_no);
}

void bts_trx_reserve_slots(struct gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction dir,
	uint8_t slots)
{
	unsigned i;
	for (i = 0; i < ARRAY_SIZE(trx->pdch); i += 1)
		if (slots & (1 << i))
			trx->pdch[i].reserve(dir);
}

void bts_trx_unreserve_slots(struct gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction dir,
	uint8_t slots)
{
	unsigned i;
	for (i = 0; i < ARRAY_SIZE(trx->pdch); i += 1)
		if (slots & (1 << i))
			trx->pdch[i].unreserve(dir);
}

void bts_recalc_initial_cs(struct gprs_rlcmac_bts *bts)
{
	uint8_t max_cs_dl, max_cs_ul;

	if (the_pcu->vty.force_initial_cs) {
		bts->initial_cs_dl = the_pcu->vty.initial_cs_dl;
		bts->initial_cs_ul = the_pcu->vty.initial_cs_ul;
		return;
	}

	max_cs_dl = bts_max_cs_dl(bts);
	if (bts->pcuif_info_ind.initial_cs > max_cs_dl) {
		LOGP(DL1IF, LOGL_DEBUG, " downgrading initial_cs_dl to %d\n", max_cs_dl);
		bts->initial_cs_dl = max_cs_dl;
	} else {
		bts->initial_cs_dl = bts->pcuif_info_ind.initial_cs;
	}
	if (bts->initial_cs_dl == 0)
		bts->initial_cs_dl = 1; /* CS1 Must always be supported */

	max_cs_ul = bts_max_cs_ul(bts);
	if (bts->pcuif_info_ind.initial_cs > max_cs_ul) {
		LOGP(DL1IF, LOGL_DEBUG, " downgrading initial_cs_ul to %d\n", max_cs_ul);
		bts->initial_cs_ul = max_cs_ul;
	} else {
		bts->initial_cs_ul = bts->pcuif_info_ind.initial_cs;
	}
	if (bts->initial_cs_ul == 0)
		bts->initial_cs_ul = 1; /* CS1 Must always be supported */
}
void bts_recalc_initial_mcs(struct gprs_rlcmac_bts *bts)
{
	uint8_t max_mcs_dl, max_mcs_ul;

	if (the_pcu->vty.force_initial_mcs) {
		bts->initial_mcs_dl = the_pcu->vty.initial_mcs_dl;
		bts->initial_mcs_ul = the_pcu->vty.initial_mcs_ul;
		return;
	}

	max_mcs_dl = bts_max_mcs_dl(bts);
	if (bts->pcuif_info_ind.initial_mcs > max_mcs_dl) {
		LOGP(DL1IF, LOGL_DEBUG, " downgrading initial_mcs_dl to %d\n", max_mcs_dl);
		bts->initial_mcs_dl = max_mcs_dl;
	} else {
		bts->initial_mcs_dl = bts->pcuif_info_ind.initial_mcs;
	}
	max_mcs_ul = bts_max_mcs_ul(bts);
	if (bts->pcuif_info_ind.initial_mcs > max_mcs_ul) {
		LOGP(DL1IF, LOGL_DEBUG, " downgrading initial_mcs_ul to %d\n", max_mcs_ul);
		bts->initial_mcs_ul = max_mcs_ul;
	} else {
		bts->initial_mcs_ul = bts->pcuif_info_ind.initial_mcs;
	}
}

void bts_recalc_max_cs(struct gprs_rlcmac_bts *bts)
{
	int i;
	uint8_t cs_dl, cs_ul;
	struct gprs_pcu *pcu = bts->pcu;

	cs_dl = 0;
	for (i = pcu->vty.max_cs_dl - 1; i >= 0; i--) {
		if (bts->cs_mask & (1 << i)) {
			cs_dl = i + 1;
			break;
		}
	}

	cs_ul = 0;
	for (i = pcu->vty.max_cs_ul - 1; i >= 0; i--) {
		if (bts->cs_mask & (1 << i)) {
			cs_ul = i + 1;
			break;
		}
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "New max CS: DL=%u UL=%u\n", cs_dl, cs_ul);
	bts_set_max_cs_dl(bts, cs_dl);
	bts_set_max_cs_ul(bts, cs_ul);
}

void bts_recalc_max_mcs(struct gprs_rlcmac_bts *bts)
{
	int i;
	uint8_t mcs_dl, mcs_ul;
	struct gprs_pcu *pcu = bts->pcu;

	mcs_dl = 0;
	for (i = pcu->vty.max_mcs_dl - 1; i >= 0; i--) {
		if (bts->mcs_mask & (1 << i)) {
			mcs_dl = i + 1;
			break;
		}
	}

	mcs_ul = 0;
	for (i = pcu->vty.max_mcs_ul - 1; i >= 0; i--) {
		if (bts->mcs_mask & (1 << i)) {
			mcs_ul = i + 1;
			break;
		}
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "New max MCS: DL=%u UL=%u\n", mcs_dl, mcs_ul);
	bts_set_max_mcs_dl(bts, mcs_dl);
	bts_set_max_mcs_ul(bts, mcs_ul);
}

uint8_t bts_get_ms_pwr_alpha(const struct gprs_rlcmac_bts *bts)
{
	if (bts->pcu->vty.force_alpha != (uint8_t)-1)
		return bts->pcu->vty.force_alpha;
	if (bts->si13_is_set)
		return bts->si13_ro_decoded.pwr_ctrl_pars.alpha;
	/* default if no SI13 is received yet: closed loop control, TS 44.060
	 * B.2 Closed loop control */
	return 0;
}

/* Used by counter availablePDCHAllocatedTime, TS 52.402 B.2.1.45 "All available PDCH allocated time" */
bool bts_all_pdch_allocated(const struct gprs_rlcmac_bts *bts)
{
	unsigned trx_no, ts_no;
	for (trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); trx_no++) {
		const struct gprs_rlcmac_trx *trx = &bts->trx[trx_no];
		for (ts_no = 0; ts_no < ARRAY_SIZE(trx->pdch); ts_no++) {
			const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];
			if (!pdch_is_enabled(pdch))
				continue;
			if(!pdch_is_full(pdch))
				return false;
		}
	}
	return true;
}
