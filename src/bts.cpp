/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <bts.h>
#include <poll_controller.h>
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
#include <gprs_ms_storage.h>
#include <sba.h>

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/msgb.h>
	#include <osmocom/core/stats.h>
	#include <osmocom/gsm/protocol/gsm_04_08.h>
	#include <osmocom/gsm/gsm_utils.h>
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

#define RFN_MODULUS 42432
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

static struct osmo_tdef T_defs_bts[] = {
	{ .T=3142, .default_val=20,  .unit=OSMO_TDEF_S,  .desc="timer (s)", .val=0 },
	{ .T=3169, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of USF and TFI(s) after the MS uplink TBF assignment is invalid (s)", .val=0 },
	{ .T=3191, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of TFI(s) after sending (1) last RLC Data Block on TBF(s), or (2) PACKET TBF RELEASE for an MBMS radio bearer (s)", .val=0 },
	{ .T=3193, .default_val=100, .unit=OSMO_TDEF_MS, .desc="Reuse of TFI(s) after reception of final PACKET DOWNLINK ACK/NACK from MS for TBF (ms)", .val=0 },
	{ .T=3195, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of TFI(s) upon no response from the MS (radio failure or cell change) for TBF/MBMS radio bearer (s)", .val=0 },
	{ .T=0, .default_val=0, .unit=OSMO_TDEF_S, .desc=NULL, .val=0 } /* empty item at the end */
};

/**
 * For gcc-4.4 compat do not use extended initializer list but keep the
 * order from the enum here. Once we support GCC4.7 and up we can change
 * the code below.
 */
static const struct rate_ctr_desc bts_ctr_description[] = {
	{ "tbf:dl:alloc",		"TBF DL Allocated     "},
	{ "tbf:dl:freed",		"TBF DL Freed         "},
	{ "tbf:dl:aborted",		"TBF DL Aborted       "},
	{ "tbf:ul:alloc",		"TBF UL Allocated     "},
	{ "tbf:ul:freed",		"TBF UL Freed         "},
	{ "tbf:ul:aborted",		"TBF UL Aborted       "},
	{ "tbf:reused",			"TBF Reused           "},
	{ "tbf:alloc:algo-a",		"TBF Alloc Algo A     "},
	{ "tbf:alloc:algo-b",		"TBF Alloc Algo B     "},
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
	{ "rach:requests",		"RACH requests        "},
	{ "11bit_rach:requests",	"11BIT_RACH requests  "},
	{ "spb:uplink_first_segment",   "First seg of UL SPB  "},
	{ "spb:uplink_second_segment",  "Second seg of UL SPB "},
	{ "spb:downlink_first_segment", "First seg of DL SPB  "},
	{ "spb:downlink_second_segment","Second seg of DL SPB "},
	{ "immediate:assignment_UL",	"Immediate Assign UL  "},
	{ "immediate:assignment_rej",   "Immediate Assign Rej "},
	{ "immediate:assignment_DL",	"Immediate Assign DL  "},
	{ "channel:request_description","Channel Request Desc "},
	{ "pkt:ul_assignment",		"Packet UL Assignment "},
	{ "pkt:access_reject",          "Packet Access Reject "},
	{ "pkt:dl_assignment",		"Packet DL Assignment "},
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
};

static const struct osmo_stat_item_group_desc bts_statg_desc = {
	"bts",
	"BTS Statistics",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bts_stat_item_description),
	bts_stat_item_description,
};

static void bts_init(struct gprs_rlcmac_bts *bts, struct gprs_pcu *pcu)
{
	bts->pcu = pcu;

	bts->pollController = new PollController(*bts);
	bts->sba = new SBAController(*bts);
	bts->ms_store = new GprsMsStorage(bts);

	bts->cur_fn = 0;
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

	INIT_LLIST_HEAD(&bts->ul_tbfs);
	INIT_LLIST_HEAD(&bts->dl_tbfs);

	/* initialize back pointers */
	for (size_t trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); ++trx_no) {
		struct gprs_rlcmac_trx *trx = &bts->trx[trx_no];
		trx->trx_no = trx_no;
		trx->bts = bts;

		for (size_t ts_no = 0; ts_no < ARRAY_SIZE(trx->pdch); ++ts_no) {
			struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];
			pdch->init_ptcch_msg();
			pdch->ts_no = ts_no;
			pdch->trx = trx;
		}
	}

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
}

struct gprs_rlcmac_bts *bts_main_data()
{
	return the_pcu->bts;
}

struct rate_ctr_group *bts_main_data_stats()
{
	return bts_rate_counters(the_pcu->bts);
}

static void bts_cleanup(gprs_rlcmac_bts *bts)
{
	/* this can cause counter updates and must not be left to the
	 * m_ms_store's destructor */
	bts->ms_store->cleanup();
	delete bts->ms_store;
	delete bts->sba;
	delete bts->pollController;

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
}

void bts_set_current_frame_number(struct gprs_rlcmac_bts *bts, int fn)
{
	/* The UL frame numbers lag 3 behind the DL frames and the data
	 * indication is only sent after all 4 frames of the block have been
	 * received. Sometimes there is an idle frame between the end of one
	 * and start of another frame (every 3 blocks).  So the timeout should
	 * definitely be there if we're more than 8 frames past poll_fn. Let's
	 * stay on the safe side and say 13 or more. An additional delay can
	 * happen due to the block processing time in the DSP, so the delay of
	 * decoded blocks relative to the timing clock can be much larger.
	 * Values up to 50 frames have been observed under load. */
	const static int max_delay = 60;

	bts->cur_fn = fn;
	bts->pollController->expireTimedout(bts->cur_fn, max_delay);
}

static inline int delta_fn(int fn, int to)
{
	return (fn + GSM_MAX_FN * 3 / 2 - to) % GSM_MAX_FN - GSM_MAX_FN/2;
}

void bts_set_current_block_frame_number(struct gprs_rlcmac_bts *bts, int fn, unsigned max_delay)
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
		bts_current_frame_number(bts) == 0)
		bts->cur_fn = fn;

	bts->pollController->expireTimedout(fn, max_delay);
}

int bts_add_paging(struct gprs_rlcmac_bts *bts, uint8_t chan_needed, const struct osmo_mobile_identity *mi)
{
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct llist_item *pos;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	struct llist_head *tbfs_lists[] = {
		&bts->ul_tbfs,
		&bts->dl_tbfs,
		NULL
	};

	if (log_check_level(DRLCMAC, LOGL_INFO)) {
		char str[64];
		osmo_mobile_identity_to_str_buf(str, sizeof(str), mi);
		LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n", chan_needed, str);
	}

	/* collect slots to page
	 * Mark slots for every TBF, but only mark one of it.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));
	for (l = 0; tbfs_lists[l]; l++) {
		llist_for_each_entry(pos, tbfs_lists[l], list) {
			tbf = (struct gprs_rlcmac_tbf *)pos->entry;
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
				if (!bts->trx[trx].pdch[ts].add_paging(chan_needed, mi))
					return -ENOMEM;

				LOGP(DRLCMAC, LOGL_INFO, "Paging on PACCH of TRX=%d TS=%d\n", trx, ts);
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
			 bts_rfn_to_fn(bts, rip->rfn), ra_buf,
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

static inline bool tbf_check(gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t trx_no, uint8_t ts)
{
	if (tbf->state_is_not(GPRS_RLCMAC_RELEASING) && tbf->poll_scheduled()
	    && tbf->poll_fn == fn && tbf->trx->trx_no == trx_no && tbf->poll_ts == ts)
		return true;

	return false;
}

struct gprs_rlcmac_dl_tbf *bts_dl_tbf_by_poll_fn(struct gprs_rlcmac_bts *bts, uint32_t fn, uint8_t trx, uint8_t ts)
{
	struct llist_item *pos;
	struct gprs_rlcmac_tbf *tbf;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each_entry(pos, &bts->dl_tbfs, list) {
		tbf = (struct gprs_rlcmac_tbf *)pos->entry;
		if (tbf_check(tbf, fn, trx, ts))
			return as_dl_tbf(tbf);
	}
	return NULL;
}

struct gprs_rlcmac_ul_tbf *bts_ul_tbf_by_poll_fn(struct gprs_rlcmac_bts *bts, uint32_t fn, uint8_t trx, uint8_t ts)
{
	struct llist_item *pos;
	struct gprs_rlcmac_tbf *tbf;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each_entry(pos, &bts->ul_tbfs, list) {
		tbf = (struct gprs_rlcmac_tbf *)pos->entry;
		if (tbf_check(tbf, fn, trx, ts))
			return as_ul_tbf(tbf);
	}
	return NULL;
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

	if (use_trx >= 0 && use_trx < 8)
		trx_from = trx_to = use_trx;
	else {
		trx_from = 0;
		trx_to = 7;
	}

	/* find a TFI that is unused on all PDCH */
	for (trx = trx_from; trx <= trx_to; trx++) {
		uint8_t tmp_first_tfi;
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
		return -EBUSY;
	}

	OSMO_ASSERT(best_first_tfi < 32);

	LOGP(DRLCMAC, LOGL_DEBUG, "Found first unallocated TRX=%d TFI=%d\n",
	     best_trx_nr, best_first_tfi);
	*_trx = best_trx_nr;
	return best_first_tfi;
}

int bts_rcv_imm_ass_cnf(struct gprs_rlcmac_bts *bts, const uint8_t *data, uint32_t fn)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;
	uint8_t plen;
	uint32_t tlli;
	GprsMs *ms;

	/* move to IA Rest Octets */
	plen = data[0] >> 2;
	data += 1 + plen;

	if ((*data & 0xf0) != 0xd0) {
		LOGP(DRLCMAC, LOGL_ERROR, "Got IMM.ASS confirm, but rest "
			"octets do not start with bit sequence 'HH01' "
			"(Packet Downlink Assignment)\n");
		return -EINVAL;
	}

	/* get TLLI from downlink assignment */
	tlli = (uint32_t)((*data++) & 0xf) << 28;
	tlli |= (*data++) << 20;
	tlli |= (*data++) << 12;
	tlli |= (*data++) << 4;
	tlli |= (*data++) >> 4;

	ms = bts_ms_by_tlli(bts, tlli, GSM_RESERVED_TMSI);
	if (ms)
		dl_tbf = ms_dl_tbf(ms);
	if (!dl_tbf) {
		LOGP(DRLCMAC, LOGL_ERROR, "Got IMM.ASS confirm, but TLLI=%08x "
			"does not exit\n", tlli);
		return -EINVAL;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "Got IMM.ASS confirm for TLLI=%08x\n", tlli);

	if (dl_tbf->m_wait_confirm)
		T_START(dl_tbf, T0, -2002, "assignment (AGCH)", true);

	return 0;
}

/* Determine the full frame number from a relative frame number */
uint32_t bts_rfn_to_fn(const struct gprs_rlcmac_bts *bts, int32_t rfn)
{
	int32_t m_cur_rfn;
	int32_t fn;
	int32_t fn_rounded;

	/* double-check that relative FN is not negative and fits into int32_t */
	OSMO_ASSERT(rfn < GSM_MAX_FN);
	OSMO_ASSERT(rfn >= 0);

	/* Note: If a BTS is sending in a rach request it will be fully aware
	 * of the frame number. If the PCU is used in a BSC-co-located setup.
	 * The BSC will forward the incoming RACH request. The RACH request
	 * only contains the relative frame number (Fn % 42432) in its request
	 * reference. This PCU implementation has to fit both scenarios, so
	 * we need to assume that Fn is a relative frame number. */

	/* Ensure that all following calculations are performed with the
	 * relative frame number */
	if (rfn >= RFN_MODULUS)
		return rfn;

	/* Compute an internal relative frame number from the full internal
	   frame number */
	m_cur_rfn = bts->cur_fn % RFN_MODULUS;

	/* Compute a "rounded" version of the internal frame number, which
	 * exactly fits in the RFN_MODULUS raster */
	fn_rounded = bts->cur_fn - m_cur_rfn;

	/* If the delta between the internal and the external relative frame
	 * number exceeds a certain limit, we need to assume that the incoming
	 * rach request belongs to a the previous rfn period. To correct this,
	 * we roll back the rounded frame number by one RFN_MODULUS */
	if (abs(rfn - m_cur_rfn) > RFN_THRESHOLD) {
		LOGP(DRLCMAC, LOGL_DEBUG,
		     "Race condition between rfn (%u) and m_cur_fn (%u) detected: rfn belongs to the previous modulus %u cycle, wrapping...\n",
		     rfn, bts->cur_fn, RFN_MODULUS);
		if (fn_rounded < RFN_MODULUS) {
			LOGP(DRLCMAC, LOGL_DEBUG,
			"Cornercase detected: wrapping crosses %u border\n",
			GSM_MAX_FN);
			fn_rounded = GSM_MAX_FN - (RFN_MODULUS - fn_rounded);
		}
		else
			fn_rounded -= RFN_MODULUS;
	}

	/* The real frame number is the sum of the rounded frame number and the
	 * relative framenumber computed via RACH */
	fn = fn_rounded + rfn;

	return fn;
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

int bts_rcv_rach(struct gprs_rlcmac_bts *bts, const struct rach_ind_params *rip)
{
	struct chan_req_params chan_req = { 0 };
	struct gprs_rlcmac_ul_tbf *tbf = NULL;
	uint8_t trx_no, ts_no;
	uint32_t sb_fn = 0;
	uint8_t usf = 7;
	uint8_t tsc = 0;
	int plen, rc;

	bts_do_rate_ctr_inc(bts, CTR_RACH_REQUESTS);

	if (rip->is_11bit)
		bts_do_rate_ctr_inc(bts, CTR_11BIT_RACH_REQUESTS);

	/* Determine full frame number */
	uint32_t Fn = bts_rfn_to_fn(bts, rip->rfn);
	uint8_t ta = qta2ta(rip->qta);

	bts_send_gsmtap_rach(bts, PCU_GSMTAP_C_UL_RACH, GSMTAP_CHANNEL_RACH, rip);

	LOGP(DRLCMAC, LOGL_DEBUG, "MS requests Uplink resource on CCCH/RACH: "
	     "ra=0x%02x (%d bit) Fn=%u qta=%d\n", rip->ra,
	     rip->is_11bit ? 11 : 8, Fn, rip->qta);

	/* Parse [EGPRS Packet] Channel Request from RACH.ind */
	rc = parse_rach_ind(rip, &chan_req);
	if (rc) /* Send RR Immediate Assignment Reject */
		goto send_imm_ass_rej;

	if (chan_req.single_block)
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single block allocation\n");
	else if (bts->pcu->vty.force_two_phase) {
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single block allocation, "
		     "but we force two phase access\n");
		chan_req.single_block = true;
	}

	/* TODO: handle Radio Priority (see 3GPP TS 44.060, table 11.2.5a.5) */
	if (chan_req.priority > 0)
		LOGP(DRLCMAC, LOGL_NOTICE, "EGPRS Packet Channel Request indicates "
		     "Radio Priority %u, however we ignore it\n", chan_req.priority);

	/* Should we allocate a single block or an Uplink TBF? */
	if (chan_req.single_block) {
		rc = bts_sba(bts)->alloc(&trx_no, &ts_no, &sb_fn, ta);
		if (rc < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource for "
			     "single block allocation: rc=%d\n", rc);
			/* Send RR Immediate Assignment Reject */
			goto send_imm_ass_rej;
		}

		tsc = bts->trx[trx_no].pdch[ts_no].tsc;
		LOGP(DRLCMAC, LOGL_DEBUG, "Allocated a single block at "
		     "SBFn=%u TRX=%u TS=%u\n", sb_fn, trx_no, ts_no);
	} else {
		GprsMs *ms = bts_alloc_ms(bts, 0, chan_req.egprs_mslot_class);
		tbf = tbf_alloc_ul_tbf(bts, ms, -1, true);
		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource for Uplink TBF\n");
			/* Send RR Immediate Assignment Reject */
			rc = -EBUSY;
			goto send_imm_ass_rej;
		}

		/* FIXME: Copy and paste with other routines.. */
		tbf->set_ta(ta);
		TBF_SET_STATE(tbf, GPRS_RLCMAC_FLOW);
		TBF_ASS_TYPE_SET(tbf, GPRS_RLCMAC_FLAG_CCCH);
		T_START(tbf, T3169, 3169, "RACH (new UL-TBF)", true);
		trx_no = tbf->trx->trx_no;
		ts_no = tbf->first_ts;
		usf = tbf->m_usf[ts_no];
		tsc = tbf->tsc();
	}

send_imm_ass_rej:
	/* Allocate a bit-vector for RR Immediate Assignment [Reject] */
	struct bitvec *bv = bitvec_alloc(22, tall_pcu_ctx); /* without plen */
	bitvec_unhex(bv, DUMMY_VEC); /* standard '2B'O padding */

	if (rc != 0) {
		LOGP(DRLCMAC, LOGL_DEBUG, "Tx Immediate Assignment Reject on AGCH\n");
		plen = Encoding::write_immediate_assignment_reject(
			bv, rip->ra, Fn, rip->burst_type);
		bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_REJ);
	} else {
		LOGP(DRLCMAC, LOGL_DEBUG, "Tx Immediate Assignment on AGCH: "
		     "TRX=%u (ARFCN %u) TS=%u TA=%u TSC=%u TFI=%d USF=%d\n",
		     trx_no, bts->trx[trx_no].arfcn & ~ARFCN_FLAG_MASK,
		     ts_no, ta, tsc, tbf ? tbf->tfi() : -1, usf);
		plen = Encoding::write_immediate_assignment(
			&bts->trx[trx_no].pdch[ts_no], tbf, bv,
			false, rip->ra, Fn, ta, usf, false, sb_fn,
			bts->pcu->vty.alpha, bts->pcu->vty.gamma, -1,
			rip->burst_type);
		bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_UL_TBF);
	}

	if (plen >= 0)
		pcu_l1if_tx_agch(bv, plen);
	else
		rc = plen;

	bitvec_free(bv);

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
	uint32_t fn416 = bts_rfn_to_fn(bts, rip->rfn) % 416;
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
	if (!pdch->m_is_enabled) {
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

void bts_snd_dl_ass(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf, bool poll, uint16_t pgroup)
{
	uint8_t trx_no = tbf->trx->trx_no;
	uint8_t ts_no = tbf->first_ts;
	int plen;

	LOGPTBF(tbf, LOGL_INFO, "TX: START Immediate Assignment Downlink (PCH)\n");
	bitvec *immediate_assignment = bitvec_alloc(22, tall_pcu_ctx); /* without plen */
	bitvec_unhex(immediate_assignment, DUMMY_VEC); /* standard '2B'O padding */
	/* use request reference that has maximum distance to current time,
	 * so the assignment will not conflict with possible RACH requests. */
	LOGP(DRLCMAC, LOGL_DEBUG, " - TRX=%d (%d) TS=%d TA=%d pollFN=%d\n",
		trx_no, tbf->trx->arfcn, ts_no, tbf->ta(), poll ? tbf->poll_fn : -1);
	plen = Encoding::write_immediate_assignment(&bts->trx[trx_no].pdch[ts_no],
						    tbf, immediate_assignment, true, 125,
						    (tbf->pdch[ts_no]->last_rts_fn + 21216) % GSM_MAX_FN,
						    tbf->ta(), 7, poll, tbf->poll_fn,
						    bts->pcu->vty.alpha, bts->pcu->vty.gamma, -1,
						    GSM_L1_BURST_TYPE_ACCESS_0);
	if (plen >= 0) {
		bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_DL_TBF);
		pcu_l1if_tx_pch(immediate_assignment, plen, pgroup);
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

GprsMs *bts_alloc_ms(struct gprs_rlcmac_bts* bts, uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	ms = bts_ms_store(bts)->create_ms();

	ms_set_timeout(ms, osmo_tdef_get(bts->pcu->T_defs, -2030, OSMO_TDEF_S, -1));
	ms_set_ms_class(ms, ms_class);
	ms_set_egprs_ms_class(ms, egprs_ms_class);

	return ms;
}


static int bts_talloc_destructor(struct gprs_rlcmac_bts* bts)
{
	bts_cleanup(bts);
	return 0;
}

struct gprs_rlcmac_bts* bts_alloc(struct gprs_pcu *pcu)
{
	struct gprs_rlcmac_bts* bts;
	bts = talloc_zero(pcu, struct gprs_rlcmac_bts);
	if (!bts)
		return bts;
	talloc_set_destructor(bts, bts_talloc_destructor);
	bts_init(bts, pcu);
	return bts;
}

struct SBAController *bts_sba(struct gprs_rlcmac_bts *bts)
{
	return bts->sba;
}

struct GprsMsStorage *bts_ms_store(struct gprs_rlcmac_bts *bts)
{
	return bts->ms_store;
}

struct GprsMs *bts_ms_by_tlli(struct gprs_rlcmac_bts *bts, uint32_t tlli, uint32_t old_tlli)
{
	return bts_ms_store(bts)->get_ms(tlli, old_tlli);
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

		LOGP(DL1IF, LOGL_INFO, "PH-DATA-IND is updating TLLI=0x%08x: TA %u -> %u on "
				"TRX = %d, TS = %d, FN = %d\n",
				tbf->tlli(), tbf->ta(), ta_target,
				tbf->trx->trx_no , tbf->poll_ts, tbf->poll_fn);
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

		LOGP(DL1IF, LOGL_INFO, "PH-RA-IND is updating TLLI=0x%08x: TA %u -> %u on "
				"TRX = %d, TS = %d, FN = %d\n",
				tbf->tlli(), tbf->ta(), ta_target,
				tbf->trx->trx_no , tbf->poll_ts, tbf->poll_fn);
		tbf->set_ta(ta_target);
	}
}

void bts_update_tbf_ta(const char *p, uint32_t fn, uint8_t trx_no, uint8_t ts, int8_t ta, bool is_rach)
{
	struct gprs_rlcmac_ul_tbf *tbf =
		bts_ul_tbf_by_poll_fn(the_pcu->bts, fn, trx_no, ts);
	if (!tbf)
		LOGP(DL1IF, LOGL_DEBUG, "[%s] update TA = %u ignored due to "
		     "unknown UL TBF on TRX = %d, TS = %d, FN = %d\n",
		     p, ta, trx_no, ts, fn);
	else {
		/* we need to distinguish TA information provided by L1
		 * from PH-DATA-IND and PHY-RA-IND so that we can properly
		 * update TA for given TBF
		 */
		if (is_rach)
			set_tbf_ta(tbf, (uint8_t)ta);
		else
			update_tbf_ta(tbf, ta);

	}
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

struct GprsMs *bts_ms_by_imsi(struct gprs_rlcmac_bts *bts, const char *imsi)
{
	return bts_ms_store(bts)->get_ms(0, 0, imsi);
}
