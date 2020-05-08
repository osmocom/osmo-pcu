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
	__attribute__((constructor)) static void early_init(void)
	{
		if (!tall_pcu_ctx) {
			tall_pcu_ctx = talloc_named_const(NULL, 1, "Osmo-PCU context");
			osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
		}
	}
}

static BTS s_bts;

static struct osmo_tdef T_defs_bts[] = {
	{ .T=3142, .default_val=20,  .unit=OSMO_TDEF_S,  .desc="timer (s)", .val=0 },
	{ .T=3169, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of USF and TFI(s) after the MS uplink TBF assignment is invalid (s)", .val=0 },
	{ .T=3191, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of TFI(s) after sending (1) last RLC Data Block on TBF(s), or (2) PACKET TBF RELEASE for an MBMS radio bearer (s)", .val=0 },
	{ .T=3193, .default_val=100, .unit=OSMO_TDEF_MS, .desc="Reuse of TFI(s) after reception of final PACKET DOWNLINK ACK/NACK from MS for TBF (ms)", .val=0 },
	{ .T=3195, .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Reuse of TFI(s) upon no response from the MS (radio failure or cell change) for TBF/MBMS radio bearer (s)", .val=0 },
	{ .T=0, .default_val=0, .unit=OSMO_TDEF_S, .desc=NULL, .val=0 } /* empty item at the end */
};
static struct osmo_tdef T_defs_pcu[] = {
	{ .T=1,     .default_val=30,  .unit=OSMO_TDEF_S,  .desc="BSSGP (un)blocking procedures timer (s)",  .val=0 },
	{ .T=2,     .default_val=30,  .unit=OSMO_TDEF_S,  .desc="BSSGP reset procedure timer (s)",          .val=0 },
	{ .T=3190,  .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Return to packet idle mode after Packet DL Assignment on CCCH (s)", .val=0},
	{ .T=-2000, .default_val=2,   .unit=OSMO_TDEF_MS, .desc="Tbf reject for PRR timer (ms)",            .val=0 },
	{ .T=-2001, .default_val=2,   .unit=OSMO_TDEF_S,  .desc="PACCH assignment timer (s)",               .val=0 },
	{ .T=-2002, .default_val=200, .unit=OSMO_TDEF_MS, .desc="Waiting after IMM.ASS confirm timer (ms)", .val=0 },
	{ .T=-2030, .default_val=60,  .unit=OSMO_TDEF_S,  .desc="Time to keep an idle MS object alive (s)", .val=0 }, /* slightly above T3314 (default 44s, 24.008, 11.2.2) */
	{ .T=-2031, .default_val=2000, .unit=OSMO_TDEF_MS, .desc="Time to keep an idle DL TBF alive (ms)",  .val=0 },
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
	{ "tbf:failed:egprs-only",	"TBF Failed EGPRS-only"},
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

BTS* BTS::main_bts()
{
	return &s_bts;
}

struct gprs_rlcmac_bts *BTS::bts_data()
{
	return &m_bts;
}

struct gprs_rlcmac_bts *bts_main_data()
{
	return BTS::main_bts()->bts_data();
}

void bts_cleanup()
{
	return BTS::main_bts()->cleanup();
}

struct rate_ctr_group *bts_main_data_stats()
{
	return BTS::main_bts()->rate_counters();
}

BTS::BTS()
	: m_cur_fn(0)
	, m_cur_blk_fn(-1)
	, m_pollController(*this)
	, m_sba(*this)
	, m_ms_store(this)
{
	memset(&m_bts, 0, sizeof(m_bts));
	m_bts.bts = this;
	m_bts.app_info = NULL;
	m_bts.dl_tbf_preemptive_retransmission = true;
	m_bts.T_defs_bts = T_defs_bts;
	m_bts.T_defs_pcu = T_defs_pcu;
	osmo_tdefs_reset(m_bts.T_defs_bts);
	osmo_tdefs_reset(m_bts.T_defs_pcu);

	/* initialize back pointers */
	for (size_t trx_no = 0; trx_no < ARRAY_SIZE(m_bts.trx); ++trx_no) {
		struct gprs_rlcmac_trx *trx = &m_bts.trx[trx_no];
		trx->trx_no = trx_no;
		trx->bts = this;

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
		m_ratectrs = rate_ctr_group_alloc(tall_pcu_ctx, &bts_ctrg_desc, 1);
	else
		m_ratectrs = rate_ctr_group_alloc(tall_pcu_ctx, &bts_ctrg_desc, 0);
	OSMO_ASSERT(m_ratectrs);

	m_statg = osmo_stat_item_group_alloc(tall_pcu_ctx, &bts_statg_desc, 0);
	OSMO_ASSERT(m_statg);
}

void BTS::cleanup()
{
	/* this can cause counter updates and must not be left to the
	 * m_ms_store's destructor */
	m_ms_store.cleanup();

	if (m_ratectrs) {
		rate_ctr_group_free(m_ratectrs);
		m_ratectrs = NULL;
	}

	if (m_statg) {
		osmo_stat_item_group_free(m_statg);
		m_statg = NULL;
	}

	if (m_bts.app_info) {
		msgb_free(m_bts.app_info);
		m_bts.app_info = NULL;
	}
}

BTS::~BTS()
{
	cleanup();
}

void BTS::set_current_frame_number(int fn)
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

	m_cur_fn = fn;
	m_pollController.expireTimedout(m_cur_fn, max_delay);
}

static inline int delta_fn(int fn, int to)
{
	return (fn + GSM_MAX_FN * 3 / 2 - to) % GSM_MAX_FN - GSM_MAX_FN/2;
}

void BTS::set_current_block_frame_number(int fn, unsigned max_delay)
{
	int delay = 0;
	const int late_block_delay_thresh = 13;
	const int fn_update_ok_min_delay = -500;
	const int fn_update_ok_max_delay = 0;

	/* frame numbers in the received blocks are assumed to be strongly
	 * monotonic. */
	if (m_cur_blk_fn >= 0) {
		int delta = delta_fn(fn, m_cur_blk_fn);
		if (delta <= 0)
			return;
	}

	/* Check block delay vs. the current frame number */
	if (current_frame_number() != 0)
		delay = delta_fn(fn, current_frame_number());
	if (delay <= -late_block_delay_thresh) {
		LOGP(DRLCMAC, LOGL_NOTICE,
			"Late RLC block, FN delta: %d FN: %d curFN: %d\n",
			delay, fn, current_frame_number());
		rlc_late_block();
	}

	m_cur_blk_fn = fn;
	if (delay < fn_update_ok_min_delay || delay > fn_update_ok_max_delay ||
		current_frame_number() == 0)
		m_cur_fn = fn;

	m_pollController.expireTimedout(fn, max_delay);
}

int BTS::add_paging(uint8_t chan_needed, const uint8_t *mi, uint8_t mi_len)
{
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	LListHead<gprs_rlcmac_tbf> *pos;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	LListHead<gprs_rlcmac_tbf> *tbfs_lists[] = {
		&m_ul_tbfs,
		&m_dl_tbfs,
		NULL
	};


	LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n",
		chan_needed, osmo_mi_name(mi, mi_len));

	/* collect slots to page
	 * Mark slots for every TBF, but only mark one of it.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));
	for (l = 0; tbfs_lists[l]; l++) {
		llist_for_each(pos, tbfs_lists[l]) {
			tbf = pos->entry();
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
				if (!m_bts.trx[trx].pdch[ts].add_paging(chan_needed, mi, mi_len))
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

void BTS::send_gsmtap(enum pcu_gsmtap_category categ, bool uplink, uint8_t trx_no,
		      uint8_t ts_no, uint8_t channel, uint32_t fn,
		      const uint8_t *data, unsigned int len)
{
	uint16_t arfcn;

	/* check if category is activated at all */
	if (!(m_bts.gsmtap_categ_mask & (1 << categ)))
		return;

	arfcn = m_bts.trx[trx_no].arfcn;
	if (uplink)
		arfcn |= GSMTAP_ARFCN_F_UPLINK;

	gsmtap_send(m_bts.gsmtap, arfcn, ts_no, channel, 0, fn, 0, 0, data, len);
}

static inline bool tbf_check(gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t trx_no, uint8_t ts)
{
	if (tbf->state_is_not(GPRS_RLCMAC_RELEASING) && tbf->poll_scheduled()
	    && tbf->poll_fn == fn && tbf->trx->trx_no == trx_no && tbf->poll_ts == ts)
		return true;

	return false;
}

gprs_rlcmac_dl_tbf *BTS::dl_tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts)
{
	LListHead<gprs_rlcmac_tbf> *pos;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each(pos, &m_dl_tbfs) {
		if (tbf_check(pos->entry(), fn, trx, ts))
			return as_dl_tbf(pos->entry());
	}
	return NULL;
}

gprs_rlcmac_ul_tbf *BTS::ul_tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts)
{
	LListHead<gprs_rlcmac_tbf> *pos;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each(pos, &m_ul_tbfs) {
		if (tbf_check(pos->entry(), fn, trx, ts))
			return as_ul_tbf(pos->entry());
	}
	return NULL;
}

/* lookup downlink TBF Entity (by TFI) */
gprs_rlcmac_dl_tbf *BTS::dl_tbf_by_tfi(uint8_t tfi, uint8_t trx, uint8_t ts)
{
	if (trx >= 8 || ts >= 8)
		return NULL;

	return m_bts.trx[trx].pdch[ts].dl_tbf_by_tfi(tfi);
}

/* lookup uplink TBF Entity (by TFI) */
gprs_rlcmac_ul_tbf *BTS::ul_tbf_by_tfi(uint8_t tfi, uint8_t trx, uint8_t ts)
{
	if (trx >= 8 || ts >= 8)
		return NULL;

	return m_bts.trx[trx].pdch[ts].ul_tbf_by_tfi(tfi);
}

/*
 * Search for free TFI and return TFI, TRX.
 * This method returns the first TFI that is currently not used in any PDCH of
 * a TRX. The first TRX that contains such an TFI is returned. Negative values
 * indicate errors.
 */
int BTS::tfi_find_free(enum gprs_rlcmac_tbf_direction dir, uint8_t *_trx, int8_t use_trx) const
{
	const struct gprs_rlcmac_pdch *pdch;
	uint32_t free_tfis;
	bool has_pdch = false;
	uint8_t trx_from, trx_to, trx, ts, tfi;

	if (use_trx >= 0 && use_trx < 8)
		trx_from = trx_to = use_trx;
	else {
		trx_from = 0;
		trx_to = 7;
	}

	/* find a TFI that is unused on all PDCH */
	for (trx = trx_from; trx <= trx_to; trx++) {
		bool trx_has_pdch = false;

		free_tfis = NO_FREE_TFI;

		for (ts = 0; ts < 8; ts++) {
			pdch = &m_bts.trx[trx].pdch[ts];
			if (!pdch->is_enabled())
				continue;
			free_tfis &= ~pdch->assigned_tfi(dir);
			trx_has_pdch = true;
			has_pdch = true;
		}
		if (trx_has_pdch && free_tfis)
			break;

		free_tfis = 0;
	}
	if (!has_pdch) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		return -EINVAL;
	}

	if (!free_tfis) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available (suggested TRX: %d).\n", use_trx);
		return -EBUSY;
	}


	LOGP(DRLCMAC, LOGL_DEBUG,
		"Searching for first unallocated TFI: TRX=%d\n", trx);

	/* find the first */
	for (tfi = 0; tfi < 32; tfi++) {
		if (free_tfis & 1 << tfi)
			break;
	}

	OSMO_ASSERT(tfi < 32);

	LOGP(DRLCMAC, LOGL_DEBUG, " Found TFI=%d.\n", tfi);
	*_trx = trx;
	return tfi;
}

int BTS::rcv_imm_ass_cnf(const uint8_t *data, uint32_t fn)
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

	ms = ms_by_tlli(tlli);
	if (ms)
		dl_tbf = ms->dl_tbf();
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
uint32_t BTS::rfn_to_fn(int32_t rfn)
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
	m_cur_rfn = m_cur_fn % RFN_MODULUS;

	/* Compute a "rounded" version of the internal frame number, which
	 * exactly fits in the RFN_MODULUS raster */
	fn_rounded = m_cur_fn - m_cur_rfn;

	/* If the delta between the internal and the external relative frame
	 * number exceeds a certain limit, we need to assume that the incoming
	 * rach request belongs to a the previous rfn period. To correct this,
	 * we roll back the rounded frame number by one RFN_MODULUS */
	if (abs(rfn - m_cur_rfn) > RFN_THRESHOLD) {
		LOGP(DRLCMAC, LOGL_DEBUG,
		     "Race condition between rfn (%u) and m_cur_fn (%u) detected: rfn belongs to the previous modulus %u cycle, wrapping...\n",
		     rfn, m_cur_fn, RFN_MODULUS);
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
 *   Table 11.2.5.3: PACKET CHANNEL REQUEST
 *   Table 11.2.5a.3: EGPRS PACKET CHANNEL REQUEST
 * Both GPRS and EGPRS use same MultislotClass coding, but since use of PCCCH is
 * deprecated, no PACKET CHANNEL REQUEST exists, which means for GPRS we will
 * receive CCCH RACH which doesn't contain any mslot class. Hence in the end we
 * can only receive EGPRS mslot class through 11-bit EGPRS PACKET CHANNEL
 * REQUEST.
 */
static inline uint16_t egprs_mslot_class_from_ra(uint16_t ra, bool is_11bit)
{
	if (is_11bit)
		return ((ra & 0x3e0) >> 5) + 1;

	/* set EGPRS multislot class to 0 for 8-bit RACH, since we don't know it yet */
	return 0;
}

static inline uint16_t priority_from_ra(uint16_t ra, bool is_11bit)
{
	if (is_11bit)
		return (ra & 0x18) >> 3;

	return 0;
}

static inline bool is_single_block(bool force_two_phase, uint16_t ra, enum ph_burst_type burst_type, bool is_11bit)
{
	bool sb = false;

	if ((ra & 0xf8) == 0x70)
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single block allocation\n");
	else if (force_two_phase)
		LOGP(DRLCMAC, LOGL_DEBUG,
		     "MS requests single phase access, but we force two phase access [RACH is %s bit]\n",
		     is_11bit ? "11" : "8");

	switch(burst_type) {
	case GSM_L1_BURST_TYPE_ACCESS_0:
		if (is_11bit) {
			LOGP(DRLCMAC, LOGL_ERROR, "Error: GPRS 11 bit RACH not supported\n");
			return false;
		}

		if ((ra & 0xf8) == 0x70)
			return true;

		if (force_two_phase)
			return true;
		break;
	case GSM_L1_BURST_TYPE_ACCESS_1: /* deliberate fall-through */
	case GSM_L1_BURST_TYPE_ACCESS_2:
		if (is_11bit) {
			if (!(ra & (1 << 10))) {
				if (force_two_phase)
					return true;

				return false;
			}

			return true;
		}
		LOGP(DRLCMAC, LOGL_ERROR, "Unexpected RACH burst type %u for 8-bit RACH\n", burst_type);
		break;
	case GSM_L1_BURST_TYPE_NONE:
		LOGP(DRLCMAC, LOGL_ERROR, "PCU has not received burst type from BTS\n");
		break;
	default:
		LOGP(DRLCMAC, LOGL_ERROR, "Unexpected RACH burst type %u for %s-bit RACH\n",
		     burst_type, is_11bit ? "11" : "8");
	}

	return sb;
}

int BTS::rcv_rach(uint16_t ra, uint32_t Fn, int16_t qta, bool is_11bit,
		enum ph_burst_type burst_type)
{
	struct gprs_rlcmac_ul_tbf *tbf = NULL;
	uint8_t trx_no, ts_no = 0;
	uint8_t sb = 0;
	uint32_t sb_fn = 0;
	int rc = 0;
	int plen;
	uint8_t usf = 7;
	uint8_t tsc = 0, ta = qta2ta(qta);
	uint16_t egprs_ms_class = egprs_mslot_class_from_ra(ra, is_11bit);
	bool failure = false;

	rach_frame();

	if (is_11bit)
		rach_frame_11bit();

	/* Determine full frame number */
	Fn = rfn_to_fn(Fn);

	send_gsmtap(PCU_GSMTAP_C_UL_RACH, true, 0, ts_no, GSMTAP_CHANNEL_RACH,
		    Fn, (uint8_t*)&ra, is_11bit ? 2 : 1);

	LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF on RACH, "
		"so we provide one: ra=0x%02x Fn=%u qta=%d is_11bit=%d:\n",
		ra, Fn, qta, is_11bit);

	sb = is_single_block(m_bts.force_two_phase, ra, burst_type, is_11bit);

	if (sb) {
		rc = sba()->alloc(&trx_no, &ts_no, &sb_fn, ta);
		if (rc < 0) {
			failure = true;
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource for "
					"single block allocation."
					"sending Immediate "
					"Assignment Uplink (AGCH) reject\n");
		} else {
			tsc = m_bts.trx[trx_no].pdch[ts_no].tsc;

			LOGP(DRLCMAC, LOGL_DEBUG, "RX: [PCU <- BTS] RACH "
				" qbit-ta=%d ra=0x%02x, Fn=%d (%d,%d,%d),"
				" SBFn=%d\n",
				qta, ra,
				Fn, (Fn / (26 * 51)) % 32, Fn % 51, Fn % 26,
				sb_fn);
			LOGP(DRLCMAC, LOGL_INFO, "TX: Immediate Assignment "
				"Uplink (AGCH)\n");
		}
	} else {
		// Create new TBF
		/* FIXME: Copy and paste with other routines.. */
		tbf = tbf_alloc_ul_tbf(&m_bts, NULL, -1, 0, egprs_ms_class, true);

		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource sending "
					"Immediate Assignment Uplink (AGCH) "
					"reject\n");
			rc = -EBUSY;
			failure = true;
		} else {
			tbf->set_ta(ta);
			TBF_SET_STATE(tbf, GPRS_RLCMAC_FLOW);
			TBF_ASS_TYPE_SET(tbf, GPRS_RLCMAC_FLAG_CCCH);
			T_START(tbf, T3169, 3169, "RACH (new UL-TBF)", true);
			LOGPTBF(tbf, LOGL_DEBUG, "[UPLINK] START\n");
			LOGPTBF(tbf, LOGL_DEBUG, "RX: [PCU <- BTS] RACH "
					"qbit-ta=%d ra=0x%02x, Fn=%d "
					" (%d,%d,%d)\n",
					qta, ra, Fn, (Fn / (26 * 51)) % 32,
					Fn % 51, Fn % 26);
			LOGPTBF(tbf, LOGL_INFO, "TX: START Immediate Assignment Uplink (AGCH)\n");
			trx_no = tbf->trx->trx_no;
			ts_no = tbf->first_ts;
			usf = tbf->m_usf[ts_no];
			tsc = tbf->tsc();
		}
	}
	bitvec *immediate_assignment = bitvec_alloc(22, tall_pcu_ctx) /* without plen */;
	bitvec_unhex(immediate_assignment,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");


	if (failure) {
		plen = Encoding::write_immediate_assignment_reject(
			immediate_assignment, ra, Fn,
			burst_type);
		immediate_assignment_reject();
	}
	else {
		LOGP(DRLCMAC, LOGL_DEBUG,
			" - TRX=%d (%d) TS=%d TA=%d TSC=%d TFI=%d USF=%d\n",
			trx_no, m_bts.trx[trx_no].arfcn, ts_no, ta, tsc,
			tbf ? tbf->tfi() : -1, usf);
		// N. B: if tbf == NULL then SBA is used for Imm. Ass. below
		plen = Encoding::write_immediate_assignment(tbf, immediate_assignment, false, ra, Fn, ta,
							    m_bts.trx[trx_no].arfcn, ts_no, tsc, usf, false, sb_fn,
							    m_bts.alpha, m_bts.gamma, -1, burst_type);
	}

	if (plen >= 0) {
		immediate_assignment_ul_tbf();
		pcu_l1if_tx_agch(immediate_assignment, plen);
	}

	bitvec_free(immediate_assignment);

	return rc;
}

/* PTCCH/U sub-slot / frame-number mapping (see 3GPP TS 45.002, table 6) */
static uint32_t ptcch_slot_map[PTCCH_TAI_NUM] = {
	 12,  38,  64,  90,
	116, 142, 168, 194,
	220, 246, 272, 298,
	324, 350, 376, 402,
};

int BTS::rcv_ptcch_rach(uint8_t trx_nr, uint8_t ts_nr, uint32_t fn, int16_t qta)
{
	struct gprs_rlcmac_bts *bts = bts_data();
	struct gprs_rlcmac_pdch *pdch;
	uint32_t fn416 = fn % 416;
	uint8_t ss;

	/* Prevent buffer overflow */
	if (trx_nr >= ARRAY_SIZE(bts->trx) || ts_nr >= 8) {
		LOGP(DRLCMAC, LOGL_ERROR, "Malformed RACH.ind message "
		     "(TRX=%u TS=%u FN=%u)\n", trx_nr, ts_nr, fn);
		return -EINVAL;
	}

	/* Make sure PDCH time-slot is enabled */
	pdch = &bts->trx[trx_nr].pdch[ts_nr];
	if (!pdch->m_is_enabled) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Rx PTCCH RACH.ind for inactive PDCH "
		     "(TRX=%u TS=%u FN=%u)\n", trx_nr, ts_nr, fn);
		return -EAGAIN;
	}

	/* Convert TDMA frame-number to PTCCH/U sub-slot number */
	for (ss = 0; ss < PTCCH_TAI_NUM; ss++)
		if (ptcch_slot_map[ss] == fn416)
			break;
	if (ss == PTCCH_TAI_NUM) {
		LOGP(DRLCMAC, LOGL_ERROR, "Failed to map PTCCH/U sub-slot for fn=%u\n", fn);
		return -ENODEV;
	}

	/* Apply the new Timing Advance value */
	LOGP(DRLCMAC, LOGL_INFO, "Continuous Timing Advance update "
	     "for TAI %u, new TA is %u\n", ss, qta2ta(qta));
	pdch->update_ta(ss, qta2ta(qta));

	return 0;
}

void BTS::snd_dl_ass(gprs_rlcmac_tbf *tbf, bool poll, uint16_t pgroup)
{
	int plen;
	unsigned int ts = tbf->first_ts;

	LOGPTBF(tbf, LOGL_INFO, "TX: START Immediate Assignment Downlink (PCH)\n");
	bitvec *immediate_assignment = bitvec_alloc(22, tall_pcu_ctx); /* without plen */
	bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	/* use request reference that has maximum distance to current time,
	 * so the assignment will not conflict with possible RACH requests. */
	LOGP(DRLCMAC, LOGL_DEBUG, " - TRX=%d (%d) TS=%d TA=%d pollFN=%d\n",
		tbf->trx->trx_no, tbf->trx->arfcn,
		ts, tbf->ta(), poll ? tbf->poll_fn : -1);
	plen = Encoding::write_immediate_assignment(tbf, immediate_assignment, true, 125,
						    (tbf->pdch[ts]->last_rts_fn + 21216) % GSM_MAX_FN, tbf->ta(),
						    tbf->trx->arfcn, ts, tbf->tsc(), 7, poll,
						    tbf->poll_fn, m_bts.alpha, m_bts.gamma, -1,
						    GSM_L1_BURST_TYPE_ACCESS_0);
	if (plen >= 0) {
		immediate_assignment_dl_tbf();
		pcu_l1if_tx_pch(immediate_assignment, plen, pgroup);
	}

	bitvec_free(immediate_assignment);
}


GprsMs *BTS::ms_alloc(uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	ms = ms_store().create_ms();

	ms->set_timeout(osmo_tdef_get(m_bts.T_defs_pcu, -2030, OSMO_TDEF_S, -1));
	ms->set_ms_class(ms_class);
	ms->set_egprs_ms_class(egprs_ms_class);

	return ms;
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
		bts_main_data()->bts->ul_tbf_by_poll_fn(fn, trx_no, ts);
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

void gprs_rlcmac_trx::reserve_slots(enum gprs_rlcmac_tbf_direction dir,
	uint8_t slots)
{
	unsigned i;
	for (i = 0; i < ARRAY_SIZE(pdch); i += 1)
		if (slots & (1 << i))
			pdch[i].reserve(dir);
}

void gprs_rlcmac_trx::unreserve_slots(enum gprs_rlcmac_tbf_direction dir,
	uint8_t slots)
{
	unsigned i;
	for (i = 0; i < ARRAY_SIZE(pdch); i += 1)
		if (slots & (1 << i))
			pdch[i].unreserve(dir);
}
