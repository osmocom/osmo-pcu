/* gprs_rlcmac.cpp
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

#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <bts.h>
#include <tbf.h>
#include <gprs_ms.h>
#include <pcu_utils.h>

#include <errno.h>
#include <values.h>

extern "C" {
#include "mslot_class.h"
}

/* Consider a PDCH as idle if has at most this number of TBFs assigned to it */
#define PDCH_IDLE_TBF_THRESH	1

static char *set_flag_chars(char *buf, uint8_t val, char set_char, char unset_char = 0)
{
	int i;

	for (i = 0; i < 8; i += 1, val = val >> 1) {
		if (val & 1)
			buf[i] = set_char;
		else if (unset_char)
			buf[i] = unset_char;
	}

	return buf;
}

static bool test_and_set_bit(uint32_t *bits, size_t elem)
{
	bool was_set = bits[elem/32] & (1 << (elem % 32));
	bits[elem/32] |= (1 << (elem % 32));

	return was_set;
}

static inline int8_t find_free_usf(const struct gprs_rlcmac_pdch *pdch)
{
	uint8_t usf_map = 0;
	uint8_t usf;

	usf_map = pdch->assigned_usf();
	if (usf_map == (1 << 7) - 1)
		return -1;

	/* look for USF, don't use USF=7 */
	for (usf = 0; usf < 7; usf++) {
		if (!(usf_map & (1 << usf)))
			return usf;
	}

	return -1;
}

static inline int8_t find_free_tfi(const struct gprs_rlcmac_pdch *pdch, enum gprs_rlcmac_tbf_direction dir)
{
	uint32_t tfi_map = pdch->assigned_tfi(dir);
	int8_t tfi;

	if (tfi_map == NO_FREE_TFI)
		return -1;

	/* look for USF, don't use USF=7 */
	for (tfi = 0; tfi < 32; tfi++) {
		if (!(tfi_map & (1 << tfi)))
			return tfi;
	}

	return -1;
}

static int find_possible_pdchs(const struct gprs_rlcmac_trx *trx, size_t max_slots, uint8_t mask,
			       const char *mask_reason = NULL)
{
	unsigned ts;
	int valid_ts_set = 0;
	int8_t last_tsc = -1; /* must be signed */

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		const struct gprs_rlcmac_pdch *pdch;

		pdch = &trx->pdch[ts];
		if (!pdch->is_enabled()) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, because "
				"not enabled\n", ts);
			continue;
		}

		if (((1 << ts) & mask) == 0) {
			if (mask_reason)
				LOGP(DRLCMAC, LOGL_DEBUG,
					"- Skipping TS %d, because %s\n",
					ts, mask_reason);
			continue;
		}

		if (max_slots > 1) {
			/* check if TSC changes, see TS 45.002, 6.4.2 */
			if (last_tsc < 0)
				last_tsc = pdch->tsc;
			else if (last_tsc != pdch->tsc) {
				LOGP(DRLCMAC, LOGL_ERROR,
					"Skipping TS %d of TRX=%d, because it "
					"has different TSC than lower TS of TRX. "
					"In order to allow multislot, all "
					"slots must be configured with the same "
					"TSC!\n", ts, trx->trx_no);
				continue;
			}
		}

		valid_ts_set |= 1 << ts;
	}

	return valid_ts_set;
}

static int compute_usage_by_num_tbfs(const struct gprs_rlcmac_pdch *pdch, enum gprs_rlcmac_tbf_direction dir)
{
	return pdch->num_tbfs(dir);
}

static int compute_usage_by_reservation(const struct gprs_rlcmac_pdch *pdch, enum gprs_rlcmac_tbf_direction)
{
	return
		pdch->num_reserved(GPRS_RLCMAC_DL_TBF) +
		pdch->num_reserved(GPRS_RLCMAC_UL_TBF);
}

static int compute_usage_for_algo_a(const struct gprs_rlcmac_pdch *pdch, enum gprs_rlcmac_tbf_direction dir)
{
	int usage =
		pdch->num_tbfs(GPRS_RLCMAC_DL_TBF) +
		pdch->num_tbfs(GPRS_RLCMAC_UL_TBF) +
		compute_usage_by_reservation(pdch, dir);

	if (pdch->assigned_tfi(reverse(dir)) == NO_FREE_TFI)
		/* No TFI in the opposite direction, avoid it */
		usage += 32;

	return usage;

}

/*! Return the TS which corresponds to least busy PDCH
 *
 *  \param[in] trx Pointer to TRX object
 *  \param[in] dir TBF direction
 *  \param[in] mask set of available timeslots
 *  \param[in] fn Function pointer to function which computes number of associated TBFs
 *  \param[out] free_tfi Free TFI
 *  \param[out] free_usf Free USF
 *  \returns TS number or -1 if unable to find
 */
static int find_least_busy_pdch(const struct gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction dir, uint8_t mask,
				int (*fn)(const struct gprs_rlcmac_pdch *, enum gprs_rlcmac_tbf_direction dir),
				int *free_tfi = 0, int *free_usf = 0)
{
	unsigned ts;
	int min_used = INT_MAX;
	int min_ts = -1;
	int min_tfi = -1;
	int min_usf = -1;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
		int num_tbfs;
		int usf = -1; /* must be signed */
		int tfi = -1;

		if (((1 << ts) & mask) == 0)
			continue;

		num_tbfs = fn(pdch, dir);

		if (num_tbfs < min_used) {
			/* We have found a candidate */
			/* Make sure that a TFI is available */
			if (free_tfi) {
				tfi = find_free_tfi(pdch, dir);
				if (tfi < 0) {
					LOGP(DRLCMAC, LOGL_DEBUG,
						"- Skipping TS %d, because "
						"no TFI available\n", ts);
					continue;
				}
			}
			/* Make sure that an USF is available */
			if (dir == GPRS_RLCMAC_UL_TBF) {
				usf = find_free_usf(pdch);
				if (usf < 0) {
					LOGP(DRLCMAC, LOGL_DEBUG,
						"- Skipping TS %d, because "
						"no USF available\n", ts);
					continue;
				}
			}
			if (min_ts >= 0)
				LOGP(DRLCMAC, LOGL_DEBUG,
					"- Skipping TS %d, because "
					"num TBFs %d > %d\n",
					min_ts, min_used, num_tbfs);
			min_used = num_tbfs;
			min_ts = ts;
			min_tfi = tfi;
			min_usf = usf;
		} else {
			LOGP(DRLCMAC, LOGL_DEBUG,
				"- Skipping TS %d, because "
				"num TBFs %d >= %d\n",
				ts, num_tbfs, min_used);
		}
	}

	if (min_ts < 0)
		return -1;

	if (free_tfi)
		*free_tfi = min_tfi;
	if (free_usf)
		*free_usf = min_usf;

	return min_ts;
}

static void attach_tbf_to_pdch(struct gprs_rlcmac_pdch *pdch,
	struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->pdch[pdch->ts_no])
		tbf->pdch[pdch->ts_no]->detach_tbf(tbf);

	tbf->pdch[pdch->ts_no] = pdch;
	pdch->attach_tbf(tbf);
}

static void assign_uplink_tbf_usf(struct gprs_rlcmac_pdch *pdch, struct gprs_rlcmac_ul_tbf *tbf, uint8_t tfi, int8_t usf)
{
	tbf->m_tfi = tfi;
	tbf->m_usf[pdch->ts_no] = usf;
	attach_tbf_to_pdch(pdch, tbf);
}

static void assign_dlink_tbf(struct gprs_rlcmac_pdch *pdch, struct gprs_rlcmac_dl_tbf *tbf, uint8_t tfi)
{
	tbf->m_tfi = tfi;
	attach_tbf_to_pdch(pdch, tbf);
}

static int find_trx(const struct gprs_rlcmac_bts *bts_data, const GprsMs *ms, int8_t use_trx)
{
	unsigned trx_no;
	unsigned ts;

	/* We must use the TRX currently actively used by an MS */
	if (ms && ms->current_trx())
		return ms->current_trx()->trx_no;

	if (use_trx >= 0 && use_trx < 8)
		return use_trx;

	/* Find the first TRX that has a PDCH with a free UL and DL TFI */
	for (trx_no = 0; trx_no < ARRAY_SIZE(bts_data->trx); trx_no += 1) {
		const struct gprs_rlcmac_trx *trx = &bts_data->trx[trx_no];
		for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
			const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
			if (!pdch->is_enabled())
				continue;

			if (pdch->assigned_tfi(GPRS_RLCMAC_UL_TBF) == NO_FREE_TFI)
				continue;

			if (pdch->assigned_tfi(GPRS_RLCMAC_DL_TBF) == NO_FREE_TFI)
				continue;

			return trx_no;
		}
	}

	return -EBUSY;
}

static bool idle_pdch_avail(const struct gprs_rlcmac_bts *bts_data)
{
	unsigned trx_no;
	unsigned ts;

	/* Find the first PDCH with an unused DL TS */
	for (trx_no = 0; trx_no < ARRAY_SIZE(bts_data->trx); trx_no += 1) {
		const struct gprs_rlcmac_trx *trx = &bts_data->trx[trx_no];
		for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
			const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
			if (!pdch->is_enabled())
				continue;

			if (pdch->num_tbfs(GPRS_RLCMAC_DL_TBF) > PDCH_IDLE_TBF_THRESH)
				continue;

			return true;
		}
	}

	return false;
}

/*! Return free TFI
 *
 *  \param[in] bts Pointer to BTS struct
 *  \param[in] trx Pointer to TRX struct
 *  \param[in] ms Pointer to MS object
 *  \param[in] dir DL or UL direction
 *  \param[in] use_trx which TRX to use or -1 if it should be selected based on what MS uses
 *  \param[out] trx_no_ TRX number on which TFI was found
 *  \returns negative error code or 0 on success
 */
static int tfi_find_free(const BTS *bts, const gprs_rlcmac_trx *trx, const GprsMs *ms,
			 enum gprs_rlcmac_tbf_direction dir, int8_t use_trx, uint8_t *trx_no_)
{
	int tfi;
	uint8_t trx_no;

	if (use_trx == -1 && ms->current_trx())
		use_trx = ms->current_trx()->trx_no;

	tfi = bts->tfi_find_free(dir, &trx_no, use_trx);
	if (tfi < 0)
		return -EBUSY;

	if (trx_no_)
		*trx_no_ = trx_no;

	return tfi;
}

/*! Slot Allocation: Algorithm A
 *
 * Assign single slot for uplink and downlink
 *
 *  \param[in,out] bts Pointer to BTS struct
 *  \param[in,out] ms_ Pointer to MS object
 *  \param[in,out] tbf_ Pointer to TBF struct
 *  \param[in] single flag indicating if we should force single-slot allocation
 *  \param[in] use_trx which TRX to use or -1 if it should be selected during allocation
 *  \returns negative error code or 0 on success
 */
int alloc_algorithm_a(struct gprs_rlcmac_bts *bts, GprsMs *ms_, struct gprs_rlcmac_tbf *tbf_, bool single,
		      int8_t use_trx)
{
	struct gprs_rlcmac_pdch *pdch;
	int ts = -1;
	uint8_t ul_slots, dl_slots;
	int trx_no;
	int tfi = -1;
	int usf = -1;
	int mask = 0xff;
	const char *mask_reason = NULL;
	const GprsMs *ms = ms_;
	const gprs_rlcmac_tbf *tbf = tbf_;
	gprs_rlcmac_trx *trx = ms->current_trx();

	LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm A) for class "
		"%d\n", tbf->ms_class());

	trx_no = find_trx(bts, ms, use_trx);
	if (trx_no < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE,
			"- Failed to find a usable TRX (TFI exhausted)\n");
		return trx_no;
	}
	if (!trx)
		trx = &bts->trx[trx_no];

	dl_slots = ms->reserved_dl_slots();
	ul_slots = ms->reserved_ul_slots();

	ts = ms->first_common_ts();

	if (ts >= 0) {
		mask_reason = "need to reuse TS";
		mask = 1 << ts;
	} else if (dl_slots || ul_slots) {
		mask_reason = "need to use a reserved common TS";
		mask = dl_slots & ul_slots;
	}

	mask = find_possible_pdchs(trx, 1, mask, mask_reason);
	if (!mask)
		return -EINVAL;

	ts = find_least_busy_pdch(trx, tbf->direction, mask,
		compute_usage_for_algo_a,
		&tfi, &usf);

	if (tbf->direction == GPRS_RLCMAC_UL_TBF && usf < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
			"to allocate a TS, no USF available\n");
		return -EBUSY;
	}

	if (ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
			"to allocate a TS, no TFI available\n");
		return -EBUSY;
	}

	pdch = &trx->pdch[ts];

	/* The allocation will be successful, so the system state and tbf_/ms_
	 * may be modified from now on. */
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(tbf_);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign uplink TS=%d TFI=%d USF=%d\n",
			ts, tfi, usf);
		assign_uplink_tbf_usf(pdch, ul_tbf, tfi, usf);
	} else {
		struct gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf_);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign downlink TS=%d TFI=%d\n",
			ts, tfi);
		assign_dlink_tbf(pdch, dl_tbf, tfi);
	}

	tbf_->trx = trx;
	/* the only one TS is the common TS */
	tbf_->first_ts = tbf_->first_common_ts = ts;
	ms_->set_reserved_slots(trx, 1 << ts, 1 << ts);

	tbf_->upgrade_to_multislot = 0;
	bts->bts->tbf_alloc_algo_a();
	return 0;
}

/*! Find set of slots available for allocation while taking MS class into account
 *
 *  \param[in] trx Pointer to TRX object
 *  \param[in] mslot_class The multislot class
 *  \param[in,out] ul_slots set of UL timeslots
 *  \param[in,out] dl_slots set of DL timeslots
 *  \returns negative error code or 0 on success
 */
int find_multi_slots(struct gprs_rlcmac_trx *trx, uint8_t mslot_class, uint8_t *ul_slots, uint8_t *dl_slots)
{
	uint8_t Tx, Sum;	/* Maximum Number of Slots: RX, Tx, Sum Rx+Tx */
	uint8_t Tta, Ttb, Tra, Trb;	/* Minimum Number of Slots */
	uint8_t Type; /* Type of Mobile */
	int rx_window, tx_window, pdch_slots;
	static const char *digit[10] = { "0","1","2","3","4","5","6","7","8","9" };
	char slot_info[9] = {0};
	int max_capacity;
	uint8_t max_ul_slots;
	uint8_t max_dl_slots;
	unsigned max_slots;

	unsigned ul_ts, dl_ts;
	unsigned num_tx;
	enum {MASK_TT, MASK_TR};
	unsigned mask_sel;

	if (mslot_class)
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for class %d\n",
		     mslot_class);

	Tx = mslot_class_get_tx(mslot_class);
	Sum = mslot_class_get_sum(mslot_class);
	Tta = mslot_class_get_ta(mslot_class);
	Ttb = mslot_class_get_tb(mslot_class);

	/* FIXME: use actual TA offset for computation - make sure to adjust "1 + MS_TO" accordingly
	   see also "Offset required" bit in 3GPP TS 24.008 §10.5.1.7 */
	Tra = mslot_class_get_ra(mslot_class, 0);
	Trb = mslot_class_get_rb(mslot_class, 0);

	Type = mslot_class_get_type(mslot_class);

	if (Tx == MS_NA) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Multislot class %d not applicable.\n",
		     mslot_class);
		return -EINVAL;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "- Rx=%d Tx=%d Sum Rx+Tx=%s  Tta=%s Ttb=%d "
		" Tra=%d Trb=%d Type=%d\n", mslot_class_get_rx(mslot_class), Tx,
		(Sum == MS_NA) ? "N/A" : digit[Sum],
		(Tta == MS_NA) ? "N/A" : digit[Tta], Ttb, Tra, Trb, Type);

	max_slots = OSMO_MAX(mslot_class_get_rx(mslot_class), Tx);

	if (*dl_slots == 0)
		*dl_slots = 0xff;

	if (*ul_slots == 0)
		*ul_slots = 0xff;

	pdch_slots = find_possible_pdchs(trx, max_slots, 0xff);

	*dl_slots &= pdch_slots;
	*ul_slots &= pdch_slots;

	LOGP(DRLCMAC, LOGL_DEBUG, "- Possible DL/UL slots: (TS=0)\"%s\"(TS=7)\n",
		set_flag_chars(set_flag_chars(set_flag_chars(slot_info,
				*dl_slots, 'D', '.'),
				*ul_slots, 'U'),
				*ul_slots & *dl_slots, 'C'));

	/* Check for each UL (TX) slot */

	max_capacity = -1;
	max_ul_slots = 0;
	max_dl_slots = 0;

	/* Iterate through possible numbers of TX slots */
	for (num_tx = 1; num_tx <= mslot_class_get_tx(mslot_class); num_tx += 1) {
		uint16_t tx_valid_win = (1 << num_tx) - 1;

		uint8_t rx_mask[MASK_TR+1];
		if (Type == 1) {
			rx_mask[MASK_TT] = (0x100 >> OSMO_MAX(Ttb, Tta)) - 1;
			rx_mask[MASK_TT] &= ~((1 << (Trb + num_tx)) - 1);
			rx_mask[MASK_TR] = (0x100 >> Ttb) - 1;
			rx_mask[MASK_TR] &=
				~((1 << (OSMO_MAX(Trb, Tra) + num_tx)) - 1);
		} else {
			/* Class type 2 MS have independant RX and TX */
			rx_mask[MASK_TT] = 0xff;
			rx_mask[MASK_TR] = 0xff;
		}

		rx_mask[MASK_TT] = (rx_mask[MASK_TT] << 3) | (rx_mask[MASK_TT] >> 5);
		rx_mask[MASK_TR] = (rx_mask[MASK_TR] << 3) | (rx_mask[MASK_TR] >> 5);

	/* Rotate group of TX slots: UUU-----, -UUU----, ..., UU-----U */
	for (ul_ts = 0; ul_ts < 8; ul_ts += 1, tx_valid_win <<= 1) {
		unsigned tx_slot_count;
		int max_rx;
		uint16_t rx_valid_win;
		uint32_t checked_rx[256/32] = {0};

		/* Wrap valid window */
		tx_valid_win = (tx_valid_win | tx_valid_win >> 8) & 0xff;

		tx_window = tx_valid_win;

		/* Filter out unavailable slots */
		tx_window &= *ul_slots;

		/* Skip if the the first TS (ul_ts) is not in the set */
		if ((tx_window & (1 << ul_ts)) == 0)
			continue;

		/* Skip if the the last TS (ul_ts+num_tx-1) is not in the set */
		if ((tx_window & (1 << ((ul_ts+num_tx-1) % 8))) == 0)
			continue;

		tx_slot_count = pcu_bitcount(tx_window);

		max_rx = OSMO_MIN(mslot_class_get_rx(mslot_class), Sum - num_tx);
		rx_valid_win = (1 << max_rx) - 1;

	/* Rotate group of RX slots: DDD-----, -DDD----, ..., DD-----D */
	for (dl_ts = 0; dl_ts < 8; dl_ts += 1, rx_valid_win <<= 1) {
		/* Wrap valid window */
		rx_valid_win = (rx_valid_win | rx_valid_win >> 8) & 0xff;

	/* Validate with both Tta/Ttb/Trb and Ttb/Tra/Trb */
	for (mask_sel = MASK_TT; mask_sel <= MASK_TR; mask_sel += 1) {
		unsigned common_slot_count;
		unsigned req_common_slots;
		unsigned rx_slot_count;
		uint16_t rx_bad;
		uint8_t rx_good;
		unsigned ts;
		int capacity;

		/* Filter out bad slots */
		rx_bad = (uint16_t)(0xff & ~rx_mask[mask_sel]) << ul_ts;
		rx_bad = (rx_bad | (rx_bad >> 8)) & 0xff;
		rx_good = *dl_slots & ~rx_bad;

		/* TODO: CHECK this calculation -> separate function for unit
		 * testing */

		rx_window = rx_good & rx_valid_win;
		rx_slot_count = pcu_bitcount(rx_window);

#if 0
		LOGP(DRLCMAC, LOGL_DEBUG, "n_tx=%d, n_rx=%d, mask_sel=%d, "
			"tx=%02x, rx=%02x, mask=%02x, bad=%02x, good=%02x, "
			"ul=%02x, dl=%02x\n",
			tx_slot_count, rx_slot_count, mask_sel,
			tx_window, rx_window, rx_mask[mask_sel], rx_bad, rx_good,
			*ul_slots, *dl_slots);
#endif

		/* Check compliance with TS 45.002, table 6.4.2.2.1 */
		/* Whether to skip this round doesn not only depend on the bit
		 * sets but also on mask_sel. Therefore this check must be done
		 * before doing the test_and_set_bit shortcut. */
		if (Type == 1) {
			unsigned slot_sum = rx_slot_count + tx_slot_count;
			/* Assume down+up/dynamic.
			 * TODO: For ext-dynamic, down only, up only add more
			 *       cases.
			 */
			if (slot_sum <= 6 && tx_slot_count < 3) {
			       if (mask_sel != MASK_TR)
				       /* Skip Tta */
				       continue;
			} else if (slot_sum > 6 && tx_slot_count < 3) {
				if (mask_sel != MASK_TT)
					/* Skip Tra */
					continue;
			} else {
				/* No supported row in table 6.4.2.2.1. */
#ifdef ENABLE_TS_ALLOC_DEBUG
				LOGP(DRLCMAC, LOGL_DEBUG,
					"- Skipping DL/UL slots: (TS=0)\"%s\"(TS=7), "
					"combination not supported\n",
					set_flag_chars(set_flag_chars(set_flag_chars(
								slot_info,
								rx_bad, 'x', '.'),
							rx_window, 'D'),
						tx_window, 'U'));
#endif
				continue;
			}
		}

		/* Avoid repeated RX combination check */
		if (test_and_set_bit(checked_rx, rx_window))
			continue;

		if (!rx_good) {
#ifdef ENABLE_TS_ALLOC_DEBUG
			LOGP(DRLCMAC, LOGL_DEBUG,
				"- Skipping DL/UL slots: (TS=0)\"%s\"(TS=7), "
				"no DL slots available\n",
				set_flag_chars(set_flag_chars(slot_info,
						rx_bad, 'x', '.'),
						tx_window, 'U'));
#endif
			continue;
		}

		if (!rx_window)
			continue;

		/* Check number of common slots according to TS 54.002, 6.4.2.2 */
		common_slot_count = pcu_bitcount(tx_window & rx_window);
		req_common_slots = OSMO_MIN(tx_slot_count, rx_slot_count);
		if (Type == 1)
			req_common_slots = OSMO_MIN(req_common_slots, 2);

		if (req_common_slots != common_slot_count) {
#ifdef ENABLE_TS_ALLOC_DEBUG
			LOGP(DRLCMAC, LOGL_DEBUG,
				"- Skipping DL/UL slots: (TS=0)\"%s\"(TS=7), "
				"invalid number of common TS: %d (expected %d)\n",
				set_flag_chars(set_flag_chars(set_flag_chars(
							slot_info,
							rx_bad, 'x', '.'),
						rx_window, 'D'),
					tx_window, 'U'),
				common_slot_count,
				req_common_slots);
#endif
			continue;
		}

		/* Compute capacity */
		capacity = 0;

		for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
			int c;
			const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
			if (rx_window & (1 << ts)) {
				c = 32 - pdch->num_reserved(GPRS_RLCMAC_DL_TBF);
				c = OSMO_MAX(c, 1);
				capacity += c;
			}
			/* Only consider common slots for UL */
			if (tx_window & rx_window & (1 << ts)) {
				if (find_free_usf(pdch) >= 0) {
					c = 32 - pdch->num_reserved(GPRS_RLCMAC_UL_TBF);
					c = OSMO_MAX(c, 1);
					capacity += c;
				}
			}
		}

#ifdef ENABLE_TS_ALLOC_DEBUG
		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Considering DL/UL slots: (TS=0)\"%s\"(TS=7), "
			"capacity = %d\n",
			set_flag_chars(set_flag_chars(set_flag_chars(set_flag_chars(
					slot_info,
					rx_bad, 'x', '.'),
					rx_window, 'D'),
					tx_window, 'U'),
					rx_window & tx_window, 'C'),
			capacity);
#endif

		if (capacity <= max_capacity)
			continue;

		max_capacity = capacity;
		max_ul_slots = tx_window;
		max_dl_slots = rx_window;
	}}}}

	if (!max_ul_slots || !max_dl_slots) {
		LOGP(DRLCMAC, LOGL_NOTICE,
			"No valid UL/DL slot combination found\n");
		return -EINVAL;
	}

	*ul_slots = max_ul_slots;
	*dl_slots = max_dl_slots;

	return 0;
}

/*! Slot Allocation: Algorithm B
 *
 * Assign as many downlink slots as possible.
 * Assign one uplink slot. (With free USF)
 *
 *  \param[in,out] bts Pointer to BTS struct
 *  \param[in,out] ms_ Pointer to MS object
 *  \param[in,out] tbf_ Pointer to TBF struct
 *  \param[in] single flag indicating if we should force single-slot allocation
 *  \param[in] use_trx which TRX to use or -1 if it should be selected during allocation
 *  \returns negative error code or 0 on success
 */
int alloc_algorithm_b(struct gprs_rlcmac_bts *bts, GprsMs *ms_, struct gprs_rlcmac_tbf *tbf_, bool single,
		      int8_t use_trx)
{
	uint8_t dl_slots;
	uint8_t ul_slots;
	uint8_t reserved_dl_slots;
	uint8_t reserved_ul_slots;
	int8_t first_common_ts;
	uint8_t slotcount = 0;
	uint8_t avail_count = 0, trx_no;
	char slot_info[9] = {0};
	int ts;
	int first_ts = -1;
	int usf[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
	int rc;
	int tfi;
	const GprsMs *ms = ms_;
	const gprs_rlcmac_tbf *tbf = tbf_;
	gprs_rlcmac_trx *trx;

	/* Step 1: Get current state from the MS object */

	if (!ms) {
		LOGP(DRLCMAC, LOGL_ERROR, "MS not set\n");
		return -EINVAL;
	}

	dl_slots = ms->reserved_dl_slots();
	ul_slots = ms->reserved_ul_slots();
	first_common_ts = ms->first_common_ts();
	trx = ms->current_trx();

	if (trx) {
		if (use_trx >= 0 && use_trx != trx->trx_no) {
			LOGP(DRLCMAC, LOGL_ERROR,
				"- Requested incompatible TRX %d (current is %d)\n",
				use_trx, trx->trx_no);
			return -EINVAL;
		}
		use_trx = trx->trx_no;
	}

	/* Step 2a: Find usable TRX and TFI */
	tfi = tfi_find_free(bts->bts, trx, ms, tbf->direction, use_trx, &trx_no);
	if (tfi < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "- Failed to allocate a TFI\n");
		return tfi;
	}

	/* Step 2b: Reserve slots on the TRX for the MS */
	if (!trx)
		trx = &bts->trx[trx_no];

	if (!dl_slots || !ul_slots) {
		rc = find_multi_slots(trx, ms->ms_class(), &ul_slots, &dl_slots);
		if (rc < 0)
			return rc;
	}

	reserved_dl_slots = dl_slots;
	reserved_ul_slots = ul_slots;

	/* Step 3: Derive the slot set for the current TBF */
	if (single) {
		/* Make sure to consider the first common slot only */
		ul_slots = dl_slots = dl_slots & ul_slots;

		ts = first_common_ts;

		if (ts < 0)
			ts = find_least_busy_pdch(trx, tbf->direction,
				dl_slots & ul_slots, compute_usage_by_num_tbfs,
				NULL, NULL);
		if (ts < 0)
			ul_slots = dl_slots = pcu_lsb(dl_slots & ul_slots);
		else
			ul_slots = dl_slots = (dl_slots & ul_slots) & (1<<ts);
	}

	if (dl_slots == 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No downlink slots available\n");
		return -EINVAL;
	}

	if (ul_slots == 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No uplink slots available\n");
		return -EINVAL;
	}

	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Selected DL slots: (TS=0)\"%s\"(TS=7)%s\n",
			set_flag_chars(set_flag_chars(slot_info,
					reserved_dl_slots, 'd', '.'),
					dl_slots, 'D'),
			single ? ", single" : "");

		/* assign downlink */
		if (dl_slots == 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No downlink slots "
				"available\n");
			return -EINVAL;
		}
		slotcount = pcu_bitcount(dl_slots);
		first_ts = ffs(dl_slots) - 1;
		avail_count = pcu_bitcount(reserved_dl_slots);

	} else {
		int free_usf = -1;

		if (first_common_ts >= 0)
			ul_slots = 1 << first_common_ts;
		else
			ul_slots = ul_slots & dl_slots;

		ts = find_least_busy_pdch(trx, GPRS_RLCMAC_UL_TBF,
			ul_slots, compute_usage_by_num_tbfs,
			NULL, &free_usf);

		if (free_usf < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No USF available\n");
			return -EBUSY;
		}
		OSMO_ASSERT(ts >= 0 && ts <= 8);

		ul_slots = 1 << ts;
		usf[ts] = free_usf;

		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Selected UL slots: (TS=0)\"%s\"(TS=7)%s\n",
			set_flag_chars(set_flag_chars(slot_info,
					reserved_ul_slots, 'u', '.'),
					ul_slots, 'U'),
			single ? ", single" : "");

		slotcount++;
		first_ts = ts;

		/* We will stick to that single UL slot, unreserve the others */
		reserved_ul_slots = ul_slots;

		avail_count = pcu_bitcount(reserved_ul_slots);
	}

	first_common_ts = ffs(dl_slots & ul_slots) - 1;

	if (first_common_ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No first common slots available\n");
		return -EINVAL;
	}
	if (first_ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No first slot available\n");
		return -EINVAL;
	}

	if (single && slotcount) {
		tbf_->upgrade_to_multislot = (avail_count > slotcount);
		LOGP(DRLCMAC, LOGL_INFO, "Using single slot at TS %d for %s\n",
			first_ts,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	} else {
		tbf_->upgrade_to_multislot = 0;
		LOGP(DRLCMAC, LOGL_INFO, "Using %d slots for %s\n", slotcount,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	}

	/* The allocation will be successful, so the system state and tbf_/ms_
	 * may be modified from now on. */

	/* Step 4: Update MS and TBF and really allocate the resources */

	/* The reserved slots have changed, update the MS */
	if (reserved_ul_slots != ms->reserved_ul_slots() ||
		reserved_dl_slots != ms->reserved_dl_slots())
	{
		ms_->set_reserved_slots(trx,
			reserved_ul_slots, reserved_dl_slots);

		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Reserved DL/UL slots: (TS=0)\"%s\"(TS=7)\n",
			set_flag_chars(set_flag_chars(set_flag_chars(slot_info,
				dl_slots, 'D', '.'),
				ul_slots, 'U'),
				ul_slots & dl_slots, 'C'));
	}

	tbf_->trx = trx;
	tbf_->first_common_ts = first_common_ts;
	tbf_->first_ts = first_ts;

	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		struct gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf_);
		for (ts = 0; ts < 8; ts++) {
			if (!(dl_slots & (1 << ts)))
				continue;

			LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning DL TS "
				"%d\n", ts);
			assign_dlink_tbf(&trx->pdch[ts], dl_tbf, tfi);
		}
	} else {
		struct gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(tbf_);

		for (ts = 0; ts < 8; ts++) {
			if (!(ul_slots & (1 << ts)))
				continue;

			OSMO_ASSERT(usf[ts] >= 0);

			LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning UL TS "
				"%d\n", ts);
			assign_uplink_tbf_usf(&trx->pdch[ts], ul_tbf,
				tfi, usf[ts]);
		}
	}

	bts->bts->tbf_alloc_algo_b();

	return 0;
}

/*! Slot Allocation: Algorithm dynamic
 *
 * This meta algorithm automatically selects on of the other algorithms based
 * on the current system state.
 *
 * The goal is to support as many MS and TBF as possible. On low usage, the
 * goal is to provide the highest possible bandwidth per MS.
 *
 *  \param[in,out] bts Pointer to BTS struct
 *  \param[in,out] ms_ Pointer to MS object
 *  \param[in,out] tbf_ Pointer to TBF struct
 *  \param[in] single flag indicating if we should force single-slot allocation
 *  \param[in] use_trx which TRX to use or -1 if it should be selected during allocation
 *  \returns negative error code or 0 on success
 */
int alloc_algorithm_dynamic(struct gprs_rlcmac_bts *bts, GprsMs *ms_, struct gprs_rlcmac_tbf *tbf_, bool single,
			    int8_t use_trx)
{
	int rc;

	/* Reset load_is_high if there is at least one idle PDCH */
	if (bts->multislot_disabled) {
		bts->multislot_disabled = !idle_pdch_avail(bts);
		if (!bts->multislot_disabled)
			LOGP(DRLCMAC, LOGL_DEBUG, "Enabling algorithm B\n");
	}

	if (!bts->multislot_disabled) {
		rc = alloc_algorithm_b(bts, ms_, tbf_, single, use_trx);
		if (rc >= 0)
			return rc;

		if (!bts->multislot_disabled)
			LOGP(DRLCMAC, LOGL_DEBUG, "Disabling algorithm B\n");
		bts->multislot_disabled = 1;
	}

	return alloc_algorithm_a(bts, ms_, tbf_, single, use_trx);
}

int gprs_alloc_max_dl_slots_per_ms(struct gprs_rlcmac_bts *bts, uint8_t ms_class)
{
	int rx = mslot_class_get_rx(ms_class);

	if (rx == MS_NA)
		rx = 4;

	if (bts->alloc_algorithm == alloc_algorithm_a)
		return 1;

	if (bts->multislot_disabled)
		return 1;

	return rx;
}
