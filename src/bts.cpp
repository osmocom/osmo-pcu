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
#include <encoding.h>
#include <decoding.h>
#include <rlc.h>
#include <pcu_l1_if.h>

#include <gprs_rlcmac.h>
#include <gprs_debug.h>

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/msgb.h>
	#include <osmocom/core/stats.h>
	#include <osmocom/gsm/protocol/gsm_04_08.h>
	#include <osmocom/gsm/gsm_utils.h>
	#include <osmocom/core/gsmtap_util.h>
	#include <osmocom/core/application.h>
}

#include <arpa/inet.h>

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
		osmo_init_logging(&gprs_log_info);
	}
}

static BTS s_bts;

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

	/* initialize back pointers */
	for (size_t trx_no = 0; trx_no < ARRAY_SIZE(m_bts.trx); ++trx_no) {
		struct gprs_rlcmac_trx *trx = &m_bts.trx[trx_no];
		trx->trx_no = trx_no;
		trx->bts = this;

		for (size_t ts_no = 0; ts_no < ARRAY_SIZE(trx->pdch); ++ts_no) {
			struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];
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

BTS::~BTS()
{
	/* this can cause counter updates and must not be left to the
	 * m_ms_store's destructor */
	m_ms_store.cleanup();

	rate_ctr_group_free(m_ratectrs);
	osmo_stat_item_group_free(m_statg);
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

int BTS::add_paging(uint8_t chan_needed, uint8_t *identity_lv)
{
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	LListHead<gprs_rlcmac_tbf> *pos;
	struct gprs_rlcmac_paging *pag;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	LListHead<gprs_rlcmac_tbf> *tbfs_lists[] = {
		&m_ul_tbfs,
		&m_dl_tbfs,
		NULL
	};


	LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n",
		chan_needed, osmo_hexdump(identity_lv + 1, identity_lv[0]));

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
				pag = talloc_zero(tall_pcu_ctx,
					struct gprs_rlcmac_paging);
				if (!pag)
					return -ENOMEM;
				pag->chan_needed = chan_needed;
				memcpy(pag->identity_lv, identity_lv,
					identity_lv[0] + 1);
				m_bts.trx[trx].pdch[ts].add_paging(pag);
				LOGP(DRLCMAC, LOGL_INFO, "Paging on PACCH of "
					"TRX=%d TS=%d\n", trx, ts);
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
int BTS::tfi_find_free(enum gprs_rlcmac_tbf_direction dir,
		uint8_t *_trx, int8_t use_trx)
{
	struct gprs_rlcmac_pdch *pdch;
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

		free_tfis = 0xffffffff;

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
		LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available.\n");
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
	tlli = (*data++) << 28;
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
		T_START(dl_tbf, T0, 0, T_ASS_AGCH_USEC, "assignment (AGCH)", true);

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
		     "Race condition between rfn (%u) and m_cur_fn (%u) detected: rfn belongs to the previos modulus %u cycle, wrappng...\n",
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

static inline uint16_t mslot_class_from_ra(uint16_t ra, bool is_11bit)
{
	if (is_11bit)
		return (ra & 0x3e0) >> 5;

	/* set multislot class to 0 for 8-bit RACH, since we don't know it yet */
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

	if (!is_11bit && (burst_type == GSM_L1_BURST_TYPE_ACCESS_0)) {

		if ((ra & 0xf8) == 0x70)
			sb = true;
		else if (force_two_phase) {
			LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single "
				"phase access, but we force two phase "
				"access\n");
			sb = true;
		}

	} else if (is_11bit &&
		((burst_type == GSM_L1_BURST_TYPE_ACCESS_1) ||
		(burst_type == GSM_L1_BURST_TYPE_ACCESS_2))) {

		if (!(ra & (1 << 10))) {
			if (force_two_phase) {
				LOGP(DRLCMAC, LOGL_DEBUG, "EGPRS 11 bit RACH "
					"received. MS requests single phase "
					"access but we force two phase "
					"access\n");
				sb = true;
			} else
				sb = false;
		} else {
			LOGP(DRLCMAC, LOGL_DEBUG, "EGPRS 11 bit RACH received."
				"MS requests single block allocation\n");
			sb = true;
		}

	} else if (is_11bit &&
		(burst_type == GSM_L1_BURST_TYPE_ACCESS_0)) {
		LOGP(DRLCMAC, LOGL_ERROR,
			"Error: GPRS 11 bit RACH not supported\n");

	} else if (burst_type == GSM_L1_BURST_TYPE_NONE) {
		LOGP(DRLCMAC, LOGL_DEBUG, "pcu has not received burst type "
			"from bts \n");

		if ((ra & 0xf8) == 0x70) {
			LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single block "
				"allocation\n");
			sb = true;
		} else if (force_two_phase) {
			LOGP(DRLCMAC, LOGL_DEBUG, "MS requests single "
				"phase access, but we force two phase "
				"access\n");
			sb = true;
		}
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
	uint16_t ms_class = mslot_class_from_ra(ra, is_11bit);
	bool failure = false;

	rach_frame();

	if (is_11bit)
		rach_frame_11bit();

	/* Determine full frame number */
	Fn = rfn_to_fn(Fn);

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

		tbf = tbf_alloc_ul_tbf(&m_bts, NULL, -1, 0, ms_class, 1);

		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource sending "
					"Immediate Assignment Uplink (AGCH) "
					"reject\n");
			rc = -EBUSY;
			failure = true;
		} else {
			tbf->set_ta(ta);
			TBF_SET_STATE(tbf, GPRS_RLCMAC_FLOW);
			tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_CCCH);
			T_START(tbf, T3169, m_bts.t3169, 0, "RACH (new UL-TBF)", true);
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

		plen = Encoding::write_immediate_assignment(
			tbf, immediate_assignment, 0, ra, Fn, ta,
			m_bts.trx[trx_no].arfcn, ts_no, tsc, usf, 0, sb_fn,
			m_bts.alpha, m_bts.gamma, -1, burst_type, sb);
	}

	if (plen >= 0) {
		immediate_assignment_ul_tbf();
		pcu_l1if_tx_agch(immediate_assignment, plen);
	}

	bitvec_free(immediate_assignment);

	return rc;
}

void BTS::snd_dl_ass(gprs_rlcmac_tbf *tbf, uint8_t poll, const char *imsi)
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
	plen = Encoding::write_immediate_assignment(tbf, immediate_assignment, 1, 125,
		(tbf->pdch[ts]->last_rts_fn + 21216) % GSM_MAX_FN, tbf->ta(),
		tbf->trx->arfcn, ts, tbf->tsc(), 7, poll,
		tbf->poll_fn, m_bts.alpha, m_bts.gamma, -1);
	if (plen >= 0) {
		immediate_assignment_dl_tbf();
		pcu_l1if_tx_pch(immediate_assignment, plen, imsi);
	}

	bitvec_free(immediate_assignment);
}


GprsMs *BTS::ms_alloc(uint8_t ms_class, uint8_t egprs_ms_class)
{
	GprsMs *ms;
	ms = ms_store().create_ms();

	ms->set_timeout(m_bts.ms_idle_sec);
	ms->set_ms_class(ms_class);
	ms->set_egprs_ms_class(egprs_ms_class);

	return ms;
}

/*
 * PDCH code below. TODO: move to a separate file
 */

void gprs_rlcmac_pdch::enable()
{
	/* TODO: Check if there are still allocated resources.. */
	INIT_LLIST_HEAD(&paging_list);
	m_is_enabled = 1;
}

void gprs_rlcmac_pdch::disable()
{
	/* TODO.. kick free_resources once we know the TRX/TS we are on */
	m_is_enabled = 0;
}

void gprs_rlcmac_pdch::free_resources()
{
	struct gprs_rlcmac_paging *pag;

	/* we are not enabled. there should be no resources */
	if (!is_enabled())
		return;

	/* kick all TBF on slot */
	gprs_rlcmac_tbf::free_all(this);

	/* flush all pending paging messages */
	while ((pag = dequeue_paging()))
		talloc_free(pag);

	trx->bts->sba()->free_resources(this);
}

struct gprs_rlcmac_paging *gprs_rlcmac_pdch::dequeue_paging()
{
	struct gprs_rlcmac_paging *pag;

	if (llist_empty(&paging_list))
		return NULL;
	pag = llist_entry(paging_list.next, struct gprs_rlcmac_paging, list);
	llist_del(&pag->list);

	return pag;
}

struct msgb *gprs_rlcmac_pdch::packet_paging_request()
{
	struct gprs_rlcmac_paging *pag;
	struct msgb *msg;
	unsigned wp = 0, len;

	/* no paging, no message */
	pag = dequeue_paging();
	if (!pag)
		return NULL;

	LOGP(DRLCMAC, LOGL_DEBUG, "Scheduling paging\n");

	/* alloc message */
	msg = msgb_alloc(23, "pag ctrl block");
	if (!msg) {
		talloc_free(pag);
		return NULL;
	}
	bitvec *pag_vec = bitvec_alloc(23, tall_pcu_ctx);
	if (!pag_vec) {
		msgb_free(msg);
		talloc_free(pag);
		return NULL;
	}
	wp = Encoding::write_packet_paging_request(pag_vec);

	/* loop until message is full */
	while (pag) {
		/* try to add paging */
		if ((pag->identity_lv[1] & 0x07) == 4) {
			/* TMSI */
			LOGP(DRLCMAC, LOGL_DEBUG, "- TMSI=0x%08x\n",
				ntohl(*((uint32_t *)(pag->identity_lv + 1))));
			len = 1 + 1 + 1 + 32 + 2 + 1;
			if (pag->identity_lv[0] != 5) {
				LOGP(DRLCMAC, LOGL_ERROR, "TMSI paging with "
					"MI != 5 octets!\n");
				goto continue_next;
			}
		} else {
			/* MI */
			LOGP(DRLCMAC, LOGL_DEBUG, "- MI=%s\n",
				osmo_hexdump(pag->identity_lv + 1,
					pag->identity_lv[0]));
			len = 1 + 1 + 1 + 4 + (pag->identity_lv[0]<<3) + 2 + 1;
			if (pag->identity_lv[0] > 8) {
				LOGP(DRLCMAC, LOGL_ERROR, "Paging with "
					"MI > 8 octets!\n");
				goto continue_next;
			}
		}
		if (wp + len > 184) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Does not fit, so schedule "
				"next time\n");
			/* put back paging record, because does not fit */
			llist_add_tail(&pag->list, &paging_list);
			break;
		}
		Encoding::write_repeated_page_info(pag_vec, wp, pag->identity_lv[0],
			pag->identity_lv + 1, pag->chan_needed);

continue_next:
		talloc_free(pag);
		pag = dequeue_paging();
	}

	bitvec_pack(pag_vec, msgb_put(msg, 23));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Paging Request +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(pag_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Paging Request -------------------------\n");
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);

	return msg;
}

void gprs_rlcmac_pdch::add_paging(struct gprs_rlcmac_paging *pag)
{
	llist_add(&pag->list, &paging_list);
}

void gprs_rlcmac_pdch::rcv_control_ack(Packet_Control_Acknowledgement_t *packet, uint32_t fn)
{
	struct gprs_rlcmac_tbf *tbf, *new_tbf;
	uint32_t tlli = packet->TLLI;
	GprsMs *ms = bts()->ms_by_tlli(tlli);
	gprs_rlcmac_ul_tbf *ul_tbf;

	tbf = bts()->ul_tbf_by_poll_fn(fn, trx_no(), ts_no);
	if (!tbf)
		tbf = bts()->dl_tbf_by_poll_fn(fn, trx_no(), ts_no);

	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
			"unknown FN=%u TLLI=0x%08x (TRX %d TS %d)\n",
			fn, tlli, trx_no(), ts_no);
		if (ms)
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
			     "unknown TBF corresponds to MS with IMSI %s, TA %d, "
			     "uTBF (TFI=%d, state=%s), dTBF (TFI=%d, state=%s)\n",
			     ms->imsi(), ms->ta(),
			     ms->ul_tbf() ? ms->ul_tbf()->tfi() : 0,
			     ms->ul_tbf() ? ms->ul_tbf()->state_name() : "None",
			     ms->dl_tbf() ? ms->dl_tbf()->tfi() : 0,
			     ms->dl_tbf() ? ms->dl_tbf()->state_name() : "None");
		return;
	}

	/* Reset N3101 counter: */
	tbf->m_n3101 = 0;

	tbf->update_ms(tlli, GPRS_RLCMAC_UL_TBF);

	LOGPTBF(tbf, LOGL_DEBUG, "RX: [PCU <- BTS] Packet Control Ack\n");
	TBF_POLL_SCHED_UNSET(tbf);

	/* check if this control ack belongs to packet uplink ack */
	ul_tbf = as_ul_tbf(tbf);
	if (ul_tbf && ul_tbf->handle_ctrl_ack()) {
		LOGPTBF(tbf, LOGL_DEBUG, "[UPLINK] END\n");
		if (ul_tbf->ctrl_ack_to_toggle())
			LOGPTBF(tbf, LOGL_NOTICE, "Recovered uplink ack for UL\n");

		tbf_free(tbf);
		return;
	}
	if (tbf->dl_ass_state_is(GPRS_RLCMAC_DL_ASS_WAIT_ACK)) {
		LOGPTBF(tbf, LOGL_DEBUG, "[UPLINK] DOWNLINK ASSIGNED\n");
		/* reset N3105 */
		tbf->n3105 = 0;
		TBF_SET_ASS_STATE_DL(tbf, GPRS_RLCMAC_DL_ASS_NONE);

		new_tbf = tbf->ms() ? tbf->ms()->dl_tbf() : NULL;
		if (!new_tbf) {
			LOGP(DRLCMAC, LOGL_ERROR, "Got ACK, but DL "
				"TBF is gone TLLI=0x%08x\n", tlli);
			return;
		}
		if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE) &&
				tbf->direction == new_tbf->direction)
			tbf_free(tbf);

		if (new_tbf->check_n_clear(GPRS_RLCMAC_FLAG_CCCH)) {
			/* We now know that the PACCH really existed */
			LOGPTBF(new_tbf, LOGL_INFO,
				"The TBF has been confirmed on the PACCH, "
				"changed type from CCCH to PACCH\n");
			new_tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_PACCH);
		}
		TBF_SET_STATE(new_tbf, GPRS_RLCMAC_FLOW);
		/* stop pending assignment timer */
		new_tbf->t_stop(T0, "control acked (DL-TBF)");
		if (new_tbf->check_n_clear(GPRS_RLCMAC_FLAG_TO_DL_ASS))
			LOGPTBF(new_tbf, LOGL_NOTICE, "Recovered downlink assignment\n");

		tbf_assign_control_ts(new_tbf);
		return;
	}
	if (tbf->ul_ass_state_is(GPRS_RLCMAC_UL_ASS_WAIT_ACK)) {
		LOGPTBF(tbf, LOGL_DEBUG, "[DOWNLINK] UPLINK ASSIGNED\n");
		/* reset N3105 */
		tbf->n3105 = 0;
		TBF_SET_ASS_STATE_UL(tbf, GPRS_RLCMAC_UL_ASS_NONE);

		new_tbf = tbf->ms() ? tbf->ms()->ul_tbf() : NULL;
		if (!new_tbf) {
			LOGP(DRLCMAC, LOGL_ERROR, "Got ACK, but UL "
				"TBF is gone TLLI=0x%08x\n", tlli);
			return;
		}
		if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE) &&
				tbf->direction == new_tbf->direction)
			tbf_free(tbf);

		TBF_SET_STATE(new_tbf, GPRS_RLCMAC_FLOW);
		if (new_tbf->check_n_clear(GPRS_RLCMAC_FLAG_TO_UL_ASS))
			LOGPTBF(new_tbf, LOGL_NOTICE, "Recovered uplink assignment for UL\n");

		tbf_assign_control_ts(new_tbf);
		/* there might be LLC packets waiting in the queue, but the DL
		 * TBF might have been released while the UL TBF has been
		 * established */
		if (new_tbf->ms()->need_dl_tbf())
			new_tbf->establish_dl_tbf_on_pacch();

		return;
	}
	LOGP(DRLCMAC, LOGL_ERROR, "Error: received PACET CONTROL ACK "
		"at no request\n");
}

static void get_rx_qual_meas(struct pcu_l1_meas *meas, uint8_t rx_qual_enc)
{
	static const int16_t rx_qual_map[] = {
		0, /* 0,14 % */
		0, /* 0,28 % */
		1, /* 0,57 % */
		1, /* 1,13 % */
		2, /* 2,26 % */
		5, /* 4,53 % */
		9, /* 9,05 % */
		18, /* 18,10 % */
	};

	meas->set_ms_rx_qual(rx_qual_map[
		OSMO_MIN(rx_qual_enc, ARRAY_SIZE(rx_qual_map)-1)
		]);
}

static void get_meas(struct pcu_l1_meas *meas,
	const Packet_Resource_Request_t *qr)
{
	unsigned i;

	meas->set_ms_c_value(qr->C_VALUE);
	if (qr->Exist_SIGN_VAR)
		meas->set_ms_sign_var((qr->SIGN_VAR + 2) / 4); /* SIGN_VAR * 0.25 dB */

	for (i = 0; i < OSMO_MIN(ARRAY_SIZE(qr->Slot), ARRAY_SIZE(meas->ts)); i++)
	{
		if (qr->Slot[i].Exist) {
			LOGP(DRLCMAC, LOGL_INFO,
				"Packet resource request: i_level[%d] = %d\n",
				i, qr->Slot[i].I_LEVEL);
			meas->set_ms_i_level(i, -2 * qr->Slot[i].I_LEVEL);
		}
	}
}

static void get_meas(struct pcu_l1_meas *meas,
	const Channel_Quality_Report_t *qr)
{
	unsigned i;

	get_rx_qual_meas(meas, qr->RXQUAL);
	meas->set_ms_c_value(qr->C_VALUE);
	meas->set_ms_sign_var((qr->SIGN_VAR + 2) / 4); /* SIGN_VAR * 0.25 dB */

	for (i = 0; i < OSMO_MIN(ARRAY_SIZE(qr->Slot), ARRAY_SIZE(meas->ts)); i++)
	{
		if (qr->Slot[i].Exist) {
			LOGP(DRLCMAC, LOGL_DEBUG,
				"Channel quality report: i_level[%d] = %d\n",
				i, qr->Slot[i].I_LEVEL_TN);
			meas->set_ms_i_level(i, -2 * qr->Slot[i].I_LEVEL_TN);
		}
	}
}

static inline void sched_ul_ass_or_rej(BTS *bts, gprs_rlcmac_bts *bts_data, struct gprs_rlcmac_dl_tbf *tbf)
{
	bts->channel_request_description();

	/* This call will register the new TBF with the MS on success */
	gprs_rlcmac_ul_tbf *ul_tbf = tbf_alloc_ul(bts_data, tbf->trx->trx_no, tbf->ms_class(),
						  tbf->ms()->egprs_ms_class(), tbf->tlli(), tbf->ta(), tbf->ms());

	/* schedule uplink assignment or reject */
	if (ul_tbf) {
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF in ack message, so we provide one:\n");
		TBF_SET_ASS_STATE_UL(tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS);
	} else {
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF in ack message, so we packet access reject:\n");
		TBF_SET_ASS_STATE_UL(tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ);
	}
}

void gprs_rlcmac_pdch::rcv_control_dl_ack_nack(Packet_Downlink_Ack_Nack_t *ack_nack, uint32_t fn)
{
	int8_t tfi = 0; /* must be signed */
	struct gprs_rlcmac_dl_tbf *tbf;
	int rc;
	struct pcu_l1_meas meas;
	int num_blocks;
	uint8_t bits_data[RLC_GPRS_WS/8];
	bitvec bits;
	int bsn_begin, bsn_end;
	char show_bits[RLC_GPRS_WS + 1];

	tfi = ack_nack->DOWNLINK_TFI;
	tbf = bts()->dl_tbf_by_poll_fn(fn, trx_no(), ts_no);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
			"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
			fn, tfi, trx_no(), ts_no);
		return;
	}
	if (tbf->tfi() != tfi) {
		LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
			"wrong TFI=%d, ignoring!\n", tfi);
		return;
	}

	/* Reset N3101 counter: */
	tbf->m_n3101 = 0;

	if (tbf->handle_ack_nack())
		LOGPTBF(tbf, LOGL_NOTICE, "Recovered downlink ack\n");

	LOGPTBF(tbf, LOGL_DEBUG, "RX: [PCU <- BTS] Packet Downlink Ack/Nack\n");

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	num_blocks = Decoding::decode_gprs_acknack_bits(
		&ack_nack->Ack_Nack_Description, &bits,
		&bsn_begin, &bsn_end, tbf->window());

	LOGP(DRLCMAC, LOGL_DEBUG,
		"Got GPRS DL ACK bitmap: SSN: %d, BSN %d to %d - 1 (%d blocks), "
		"\"%s\"\n",
		ack_nack->Ack_Nack_Description.STARTING_SEQUENCE_NUMBER,
		bsn_begin, bsn_end, num_blocks,
		(Decoding::extract_rbb(&bits, show_bits), show_bits));

	rc = tbf->rcvd_dl_ack(
		ack_nack->Ack_Nack_Description.FINAL_ACK_INDICATION,
		bsn_begin, &bits);
	if (rc == 1) {
		tbf_free(tbf);
		return;
	}
	/* check for channel request */
	if (ack_nack->Exist_Channel_Request_Description)
		sched_ul_ass_or_rej(bts(), bts_data(), tbf);

	/* get measurements */
	if (tbf->ms()) {
		get_meas(&meas, &ack_nack->Channel_Quality_Report);
		tbf->ms()->update_l1_meas(&meas);
	}
}

void gprs_rlcmac_pdch::rcv_control_egprs_dl_ack_nack(EGPRS_PD_AckNack_t *ack_nack, uint32_t fn)
{
	int8_t tfi = 0; /* must be signed */
	struct gprs_rlcmac_dl_tbf *tbf;
	struct pcu_l1_meas meas;
	int rc;
	int num_blocks;
	uint8_t bits_data[RLC_EGPRS_MAX_WS/8];
	char show_bits[RLC_EGPRS_MAX_WS + 1];
	bitvec bits;
	int bsn_begin, bsn_end;

	tfi = ack_nack->DOWNLINK_TFI;
	tbf = bts()->dl_tbf_by_poll_fn(fn, trx_no(), ts_no);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "EGPRS PACKET DOWNLINK ACK with "
			"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
			fn, tfi, trx_no(), ts_no);
		return;
	}
	if (tbf->tfi() != tfi) {
		LOGP(DRLCMAC, LOGL_NOTICE, "EGPRS PACKET DOWNLINK ACK with "
			"wrong TFI=%d, ignoring!\n", tfi);
		return;
	}

	/* Reset N3101 counter: */
	tbf->m_n3101 = 0;

	if (tbf->handle_ack_nack())
		LOGPTBF(tbf, LOGL_NOTICE, "Recovered EGPRS downlink ack\n");

	LOGPTBF(tbf, LOGL_DEBUG,
		"RX: [PCU <- BTS] EGPRS Packet Downlink Ack/Nack\n");

	LOGP(DRLCMAC, LOGL_DEBUG, "EGPRS ACK/NACK: "
		"ut: %d, final: %d, bow: %d, eow: %d, ssn: %d, have_crbb: %d, "
		"urbb_len:%d, %p, %p, %d, %d, win: %d-%d, urbb: %s\n",
		(int)ack_nack->EGPRS_AckNack.UnionType,
		(int)ack_nack->EGPRS_AckNack.Desc.FINAL_ACK_INDICATION,
		(int)ack_nack->EGPRS_AckNack.Desc.BEGINNING_OF_WINDOW,
		(int)ack_nack->EGPRS_AckNack.Desc.END_OF_WINDOW,
		(int)ack_nack->EGPRS_AckNack.Desc.STARTING_SEQUENCE_NUMBER,
		(int)ack_nack->EGPRS_AckNack.Desc.Exist_CRBB,
		(int)ack_nack->EGPRS_AckNack.Desc.URBB_LENGTH,
		(void *)&ack_nack->EGPRS_AckNack.UnionType,
		(void *)&ack_nack->EGPRS_AckNack.Desc,
		(int)offsetof(EGPRS_AckNack_t, Desc),
		(int)offsetof(EGPRS_AckNack_w_len_t, Desc),
		tbf->window()->v_a(),
		tbf->window()->v_s(),
		osmo_hexdump((const uint8_t *)&ack_nack->EGPRS_AckNack.Desc.URBB,
			sizeof(ack_nack->EGPRS_AckNack.Desc.URBB)));

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	num_blocks = Decoding::decode_egprs_acknack_bits(
		&ack_nack->EGPRS_AckNack.Desc, &bits,
		&bsn_begin, &bsn_end, tbf->window());

	LOGP(DRLCMAC, LOGL_DEBUG,
		"Got EGPRS DL ACK bitmap: SSN: %d, BSN %d to %d - 1 (%d blocks), "
		"\"%s\"\n",
		ack_nack->EGPRS_AckNack.Desc.STARTING_SEQUENCE_NUMBER,
		bsn_begin, bsn_end, num_blocks,
		(Decoding::extract_rbb(&bits, show_bits), show_bits)
	    );

	rc = tbf->rcvd_dl_ack(
		ack_nack->EGPRS_AckNack.Desc.FINAL_ACK_INDICATION,
		bsn_begin, &bits);
	if (rc == 1) {
		tbf_free(tbf);
		return;
	}

	/* check for channel request */
	if (ack_nack->Exist_ChannelRequestDescription)
		sched_ul_ass_or_rej(bts(), bts_data(), tbf);

	/* get measurements */
	if (tbf->ms()) {
		/* TODO: Implement Measurements parsing for EGPRS */
		/*
		get_meas(&meas, &ack_nack->Channel_Quality_Report);
		tbf->ms()->update_l1_meas(&meas);
		*/
	}
}

void gprs_rlcmac_pdch::rcv_resource_request(Packet_Resource_Request_t *request, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	if (request->ID.UnionType) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = NULL;
		struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;
		uint32_t tlli = request->ID.u.TLLI;
		uint8_t ms_class = 0;
		uint8_t egprs_ms_class = 0;
		uint8_t ta = GSM48_TA_INVALID;
		struct pcu_l1_meas meas;

		GprsMs *ms = bts()->ms_by_tlli(tlli);
		/* Keep the ms, even if it gets idle temporarily */
		GprsMs::Guard guard(ms);

		if (ms) {
			ul_tbf = ms->ul_tbf();
			dl_tbf = ms->dl_tbf();
			ta = ms->ta();
		}

		/* We got a RACH so the MS was in packet idle mode and thus
		 * didn't have any active TBFs */
		if (ul_tbf) {
			LOGPTBFUL(ul_tbf, LOGL_NOTICE,
				  "Got RACH from TLLI=0x%08x while TBF still exists. Killing pending UL TBF\n",
				  tlli);
			tbf_free(ul_tbf);
			ul_tbf = NULL;
		}

		if (dl_tbf) {
			LOGPTBFUL(dl_tbf, LOGL_NOTICE,
				  "Got RACH from TLLI=0x%08x while TBF still exists. Release pending DL TBF\n",
				  tlli);
			tbf_free(dl_tbf);
			dl_tbf = NULL;
		}
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF "
			"in packet resource request of single "
			"block, so we provide one:\n");
		sba = bts()->sba()->find(this, fn);
		if (!sba) {
			LOGP(DRLCMAC, LOGL_NOTICE, "MS requests UL TBF "
				"in packet resource request of single "
				"block, but there is no resource request "
				"scheduled!\n");
		} else {
			ta = sba->ta;
			bts()->sba()->free_sba(sba);
		}
		if (request->Exist_MS_Radio_Access_capability) {
			ms_class = Decoding::get_ms_class_by_capability(
				&request->MS_Radio_Access_capability);
			egprs_ms_class =
				Decoding::get_egprs_ms_class_by_capability(
					&request->MS_Radio_Access_capability);
		}
		if (!ms_class)
			LOGP(DRLCMAC, LOGL_NOTICE, "MS does not give us a class.\n");
		if (egprs_ms_class)
			LOGP(DRLCMAC, LOGL_NOTICE,
				"MS supports EGPRS multislot class %d.\n",
				egprs_ms_class);
		ul_tbf = tbf_alloc_ul(bts_data(), trx_no(), ms_class,
			egprs_ms_class, tlli, ta, ms);

		if (!ul_tbf) {
			handle_tbf_reject(bts_data(), ms, tlli,
				trx_no(), ts_no);
			return;
		}

		/* set control ts to current MS's TS, until assignment complete */
		LOGPTBF(ul_tbf, LOGL_DEBUG, "change control TS %d -> %d until assinment is complete.\n",
			ul_tbf->control_ts, ts_no);

		ul_tbf->control_ts = ts_no;
		/* schedule uplink assignment */
		TBF_SET_ASS_STATE_UL(ul_tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS);

		/* get capabilities */
		if (ul_tbf->ms())
			ul_tbf->ms()->set_egprs_ms_class(egprs_ms_class);

		/* get measurements */
		if (ul_tbf->ms()) {
			get_meas(&meas, request);
			ul_tbf->ms()->update_l1_meas(&meas);
		}
		return;
	}

	if (request->ID.u.Global_TFI.UnionType) {
		struct gprs_rlcmac_dl_tbf *dl_tbf;
		int8_t tfi = request->ID.u.Global_TFI.u.DOWNLINK_TFI;
		dl_tbf = bts()->dl_tbf_by_tfi(tfi, trx_no(), ts_no);
		if (!dl_tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown downlink TFI=%d\n", tfi);
			return;
		}
		LOGPTBFDL(dl_tbf, LOGL_ERROR,
			"RX: [PCU <- BTS] FIXME: Packet resource request\n");

		/* Reset N3101 counter: */
		dl_tbf->m_n3101 = 0;
	} else {
		struct gprs_rlcmac_ul_tbf *ul_tbf;
		int8_t tfi = request->ID.u.Global_TFI.u.UPLINK_TFI;
		ul_tbf = bts()->ul_tbf_by_tfi(tfi, trx_no(), ts_no);
		if (!ul_tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown uplink TFI=%d\n", tfi);
			return;
		}
		LOGPTBFUL(ul_tbf, LOGL_ERROR,
			"RX: [PCU <- BTS] FIXME: Packet resource request\n");

		/* Reset N3101 counter: */
		ul_tbf->m_n3101 = 0;
	}
}

void gprs_rlcmac_pdch::rcv_measurement_report(Packet_Measurement_Report_t *report, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	sba = bts()->sba()->find(this, fn);
	if (!sba) {
		LOGP(DRLCMAC, LOGL_NOTICE, "MS send measurement "
			"in packet resource request of single "
			"block, but there is no resource request "
			"scheduled! TLLI=0x%08x\n", report->TLLI);
	} else {
		GprsMs *ms = bts()->ms_store().get_ms(report->TLLI);
		if (!ms)
			LOGP(DRLCMAC, LOGL_NOTICE, "MS send measurement "
				"but TLLI 0x%08x is unknown\n", report->TLLI);
		else
			ms->set_ta(sba->ta);

		bts()->sba()->free_sba(sba);
	}
	gprs_rlcmac_meas_rep(report);
}

/* Received Uplink RLC control block. */
int gprs_rlcmac_pdch::rcv_control_block(
	const uint8_t *data, uint8_t data_len, bitvec *rlc_block, uint32_t fn)
{
	RlcMacUplink_t * ul_control_block = (RlcMacUplink_t *)talloc_zero(tall_pcu_ctx, RlcMacUplink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- RX : Uplink Control Block -------------------------\n");

	if (ul_control_block->u.MESSAGE_TYPE == MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK)
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_DUMMY, true, trx_no(), ts_no, GSMTAP_CHANNEL_PACCH, fn, data, data_len);
	else
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_CTRL, true, trx_no(), ts_no, GSMTAP_CHANNEL_PACCH, fn, data, data_len);

	bts()->rlc_rcvd_control();
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		rcv_control_ack(&ul_control_block->u.Packet_Control_Acknowledgement, fn);
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		rcv_control_dl_ack_nack(&ul_control_block->u.Packet_Downlink_Ack_Nack, fn);
		break;
	case MT_EGPRS_PACKET_DOWNLINK_ACK_NACK:
		rcv_control_egprs_dl_ack_nack(&ul_control_block->u.Egprs_Packet_Downlink_Ack_Nack, fn);
		break;
	case MT_PACKET_RESOURCE_REQUEST:
		rcv_resource_request(&ul_control_block->u.Packet_Resource_Request, fn);
		break;
	case MT_PACKET_MEASUREMENT_REPORT:
		rcv_measurement_report(&ul_control_block->u.Packet_Measurement_Report, fn);
		break;
	case MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK:
		/* ignoring it. change the SI to not force sending these? */
		break;
	default:
		bts()->decode_error();
		LOGP(DRLCMAC, LOGL_NOTICE,
			"RX: [PCU <- BTS] unknown control block(%d) received\n",
			ul_control_block->u.MESSAGE_TYPE);
	}
	talloc_free(ul_control_block);
	return 1;
}


/* received RLC/MAC block from L1 */
int gprs_rlcmac_pdch::rcv_block(uint8_t *data, uint8_t len, uint32_t fn,
	struct pcu_l1_meas *meas)
{
	GprsCodingScheme cs = GprsCodingScheme::getBySizeUL(len);
	if (!cs) {
		bts()->decode_error();
		LOGP(DRLCMACUL, LOGL_ERROR, "Dropping data block with invalid"
			"length: %d)\n", len);
		return -EINVAL;
	}

	bts()->rlc_ul_bytes(len);

	LOGP(DRLCMACUL, LOGL_DEBUG, "Got RLC block, coding scheme: %s, "
		"length: %d (%d))\n", cs.name(), len, cs.usedSizeUL());

	if (cs.isGprs())
		return rcv_block_gprs(data, len, fn, meas, cs);

	if (cs.isEgprs())
		return rcv_data_block(data, len, fn, meas, cs);

	bts()->decode_error();
	LOGP(DRLCMACUL, LOGL_ERROR, "Unsupported coding scheme %s\n",
		cs.name());
	return -EINVAL;
}

/*! \brief process egprs and gprs data blocks */
int gprs_rlcmac_pdch::rcv_data_block(uint8_t *data, uint8_t data_len, uint32_t fn,
	struct pcu_l1_meas *meas, GprsCodingScheme cs)
{
	int rc;
	struct gprs_rlc_data_info rlc_dec;
	struct gprs_rlcmac_ul_tbf *tbf;
	unsigned len = cs.sizeUL();

	/* These are always data blocks, since EGPRS still uses CS-1 for
	 * control blocks (see 44.060, section 10.3, 1st par.)
	 */
	if (cs.isEgprs()) {
		if (!bts()->bts_data()->egprs_enabled) {
			LOGP(DRLCMACUL, LOGL_ERROR,
				"Got %s RLC block but EGPRS is not enabled\n",
				cs.name());
			return -EINVAL;
		}
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_DATA_EGPRS, true, trx_no(), ts_no, GSMTAP_CHANNEL_PDTCH, fn, data, data_len);
	} else {
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_DATA_GPRS, true, trx_no(), ts_no, GSMTAP_CHANNEL_PDTCH, fn, data, data_len);
	}

	LOGP(DRLCMACUL, LOGL_DEBUG, "  UL data: %s\n", osmo_hexdump(data, len));

	rc = Decoding::rlc_parse_ul_data_header(&rlc_dec, data, cs);
	if (rc < 0) {
		LOGP(DRLCMACUL, LOGL_ERROR,
			"Got %s RLC block but header parsing has failed\n",
			cs.name());
		bts()->decode_error();
		return rc;
	}

	LOGP(DRLCMACUL, LOGL_INFO,
		"Got %s RLC block: "
		"R=%d, SI=%d, TFI=%d, CPS=%d, RSB=%d, "
		"rc=%d\n",
		cs.name(),
		rlc_dec.r, rlc_dec.si, rlc_dec.tfi, rlc_dec.cps, rlc_dec.rsb,
		rc);

	/* find TBF inst from given TFI */
	tbf = ul_tbf_by_tfi(rlc_dec.tfi);
	if (!tbf) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA unknown TFI=%d\n",
			rlc_dec.tfi);
		return 0;
	}

	/* Reset N3101 counter: */
	tbf->m_n3101 = 0;

	return tbf->rcv_data_block_acknowledged(&rlc_dec, data, meas);
}

int gprs_rlcmac_pdch::rcv_block_gprs(uint8_t *data, uint8_t data_len, uint32_t fn,
	struct pcu_l1_meas *meas, GprsCodingScheme cs)
{
	unsigned payload = data[0] >> 6;
	bitvec *block;
	int rc = 0;
	unsigned len = cs.maxBytesUL();

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = rcv_data_block(data, data_len, fn, meas, cs);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		block = bitvec_alloc(len, tall_pcu_ctx);
		if (!block)
			return -ENOMEM;
		bitvec_unpack(block, data);
		rc = rcv_control_block(data, data_len, block, fn);
		bitvec_free(block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload(%u).\n", payload);
		rc = -EINVAL;
	}

	return rc;
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

gprs_rlcmac_tbf *gprs_rlcmac_pdch::tbf_from_list_by_tfi(
		LListHead<gprs_rlcmac_tbf> *tbf_list, uint8_t tfi,
		enum gprs_rlcmac_tbf_direction dir)
{
	gprs_rlcmac_tbf *tbf;
	LListHead<gprs_rlcmac_tbf> *pos;

	llist_for_each(pos, tbf_list) {
		tbf = pos->entry();
		if (tbf->tfi() != tfi)
			continue;
		if (!tbf->pdch[ts_no])
			continue;
		return tbf;
	}
	return NULL;
}

gprs_rlcmac_ul_tbf *gprs_rlcmac_pdch::ul_tbf_by_tfi(uint8_t tfi)
{
	return as_ul_tbf(tbf_by_tfi(tfi, GPRS_RLCMAC_UL_TBF));
}

gprs_rlcmac_dl_tbf *gprs_rlcmac_pdch::dl_tbf_by_tfi(uint8_t tfi)
{
	return as_dl_tbf(tbf_by_tfi(tfi, GPRS_RLCMAC_DL_TBF));
}

/* lookup TBF Entity (by TFI) */
gprs_rlcmac_tbf *gprs_rlcmac_pdch::tbf_by_tfi(uint8_t tfi,
	enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;

	if (tfi >= 32)
		return NULL;

	tbf = m_tbfs[dir][tfi];

	if (!tbf)
		return NULL;

	if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)) {
		return tbf;
	}

	return NULL;
}

void gprs_rlcmac_pdch::attach_tbf(gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	if (m_tbfs[tbf->direction][tbf->tfi()])
		LOGP(DRLCMAC, LOGL_ERROR, "PDCH(TS %d, TRX %d): "
			"%s has not been detached, overwriting it\n",
			ts_no, trx_no(),
			m_tbfs[tbf->direction][tbf->tfi()]->name());

	m_num_tbfs[tbf->direction] += 1;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		ul_tbf = as_ul_tbf(tbf);
		m_assigned_usf |= 1 << ul_tbf->m_usf[ts_no];
	}
	m_assigned_tfi[tbf->direction] |= 1UL << tbf->tfi();
	m_tbfs[tbf->direction][tbf->tfi()] = tbf;

	LOGP(DRLCMAC, LOGL_INFO, "PDCH(TS %d, TRX %d): Attaching %s, %d TBFs, "
		"USFs = %02x, TFIs = %08x.\n",
		ts_no, trx_no(), tbf->name(), m_num_tbfs[tbf->direction],
		m_assigned_usf, m_assigned_tfi[tbf->direction]);
}

void gprs_rlcmac_pdch::detach_tbf(gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	OSMO_ASSERT(m_num_tbfs[tbf->direction] > 0);

	m_num_tbfs[tbf->direction] -= 1;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		ul_tbf = as_ul_tbf(tbf);
		m_assigned_usf &= ~(1 << ul_tbf->m_usf[ts_no]);
	}
	m_assigned_tfi[tbf->direction] &= ~(1UL << tbf->tfi());
	m_tbfs[tbf->direction][tbf->tfi()] = NULL;

	LOGP(DRLCMAC, LOGL_INFO, "PDCH(TS %d, TRX %d): Detaching %s, %d TBFs, "
		"USFs = %02x, TFIs = %08x.\n",
		ts_no, trx_no(), tbf->name(), m_num_tbfs[tbf->direction],
		m_assigned_usf, m_assigned_tfi[tbf->direction]);
}

void gprs_rlcmac_pdch::reserve(enum gprs_rlcmac_tbf_direction dir)
{
	m_num_reserved[dir] += 1;
}

void gprs_rlcmac_pdch::unreserve(enum gprs_rlcmac_tbf_direction dir)
{
	OSMO_ASSERT(m_num_reserved[dir] > 0);
	m_num_reserved[dir] -= 1;
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
