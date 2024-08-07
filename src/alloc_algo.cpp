/* alloc_algo.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <bts.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <pdch.h>
#include <gprs_ms.h>
#include <pcu_utils.h>

#include <errno.h>
#include <values.h>

extern "C" {
#include "mslot_class.h"
#include "alloc_algo.h"
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
}

/* Consider a PDCH as idle if has at most this number of TBFs assigned to it */
#define PDCH_IDLE_TBF_THRESH	1

#define LOGPSL(req, level, fmt, args...) LOGP(DRLCMAC, level, "[%s] " fmt, \
					      (req->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL", ## args)

#define LOGPAL(req, kind, level, fmt, args...) LOGPSL(req, level, \
								     "algo %s <%s> (suggested TRX: %d): " fmt, \
								     kind, req->single ? "single" : "multi", req->use_trx, ## args)

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

static uint8_t find_possible_pdchs(const struct gprs_rlcmac_trx *trx, uint8_t max_slots, uint8_t mask,
				   const char *mask_reason = NULL)
{
	unsigned ts;
	uint8_t valid_ts_set = 0;
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
				int *free_tfi = NULL, int *free_usf = NULL)
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
				tfi = find_free_tfi(pdch->assigned_tfi(dir));
				if (tfi < 0) {
					LOGP(DRLCMAC, LOGL_DEBUG,
						"- Skipping TS %d, because "
						"no TFI available\n", ts);
					continue;
				}
			}
			/* Make sure that an USF is available */
			if (dir == GPRS_RLCMAC_UL_TBF) {
				usf = find_free_usf(pdch->assigned_usf());
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

static int find_trx(const struct alloc_resources_req *req)
{
	unsigned trx_no;
	unsigned ts;

	/* We must use the TRX currently actively used by an MS */
	if (req->ms && ms_current_trx(req->ms))
		return ms_current_trx(req->ms)->trx_no;

	if (req->use_trx >= 0 && req->use_trx < 8)
		return req->use_trx;

	/* Find the first TRX that has a PDCH with a free UL and DL TFI */
	for (trx_no = 0; trx_no < ARRAY_SIZE(req->bts->trx); trx_no += 1) {
		const struct gprs_rlcmac_trx *trx = &req->bts->trx[trx_no];
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

static bool idle_pdch_avail(const struct gprs_rlcmac_bts *bts)
{
	unsigned trx_no;
	unsigned ts;

	/* Find the first PDCH with an unused DL TS */
	for (trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); trx_no += 1) {
		const struct gprs_rlcmac_trx *trx = &bts->trx[trx_no];
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
 *  \param[in] req Contains all the requested params
 *  \param[out] trx_no_ TRX number on which TFI was found
 *  \returns negative error code or 0 on success
 */
static int tfi_find_free(const struct alloc_resources_req *req, uint8_t *trx_no_)
{
	const struct gprs_rlcmac_trx *trx;
	int tfi;
	int8_t use_trx = req->use_trx;
	uint8_t trx_no;

	/* If MS is already doing stuff on a TRX, set use_trx to it: */
	if ((trx = ms_current_trx(req->ms))) {
		if (use_trx >= 0 && use_trx != trx->trx_no) {
			LOGP(DRLCMAC, LOGL_ERROR, "- Requested incompatible TRX %d (current is %d)\n",
			     req->use_trx, trx->trx_no);
			return -EINVAL;
		}
		use_trx = trx->trx_no;
	}

	tfi = bts_tfi_find_free(req->bts, req->direction, &trx_no, use_trx);
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
 *  \param[in] req Contains all the requested params
 *  \param[out] res The resolution/response for the allocation request
 *  \returns negative error code or 0 on success
 */
int alloc_algorithm_a(const struct alloc_resources_req *req,
		      struct alloc_resources_res *res)
{
	int ts = -1;
	uint8_t ul_slots, dl_slots;
	int trx_no;
	int tfi = -1;
	int usf = -1;
	uint8_t mask = 0xff;
	const char *mask_reason = NULL;
	gprs_rlcmac_trx *trx = ms_current_trx(req->ms);
	struct gprs_rlcmac_pdch *first_common_ts = ms_first_common_ts(req->ms);

	LOGPAL(req, "A", LOGL_DEBUG, "Alloc start\n");

	trx_no = find_trx(req);
	if (trx_no < 0) {
		LOGPAL(req, "A", LOGL_NOTICE,
		       "failed to find a usable TRX (TFI exhausted)\n");
		return trx_no;
	}
	if (!trx)
		trx = &req->bts->trx[trx_no];

	dl_slots = ms_reserved_dl_slots(req->ms);
	ul_slots = ms_reserved_ul_slots(req->ms);

	if (first_common_ts) {
		mask_reason = "need to reuse TS";
		mask = 1 << first_common_ts->ts_no;
	} else if (dl_slots || ul_slots) {
		mask_reason = "need to use a reserved common TS";
		mask = dl_slots & ul_slots;
	}

	mask = find_possible_pdchs(trx, 1, mask, mask_reason);
	if (!mask)
		return -EINVAL;

	ts = find_least_busy_pdch(trx, req->direction, mask,
		compute_usage_for_algo_a,
		&tfi, &usf);

	if (req->direction == GPRS_RLCMAC_UL_TBF && usf < 0) {
		LOGPAL(req, "A", LOGL_NOTICE,
		       "failed to allocate a TS, no USF available\n");
		return -EBUSY;
	}

	if (ts < 0) {
		LOGPAL(req, "A", LOGL_NOTICE,
		       "failed to allocate a TS, no TFI available\n");
		return -EBUSY;
	}

	res->trx = trx;
	res->first_common_ts = &trx->pdch[ts];
	res->reserved_ul_slots = 1 << ts;
	res->reserved_dl_slots = 1 << ts;
	res->ass_slots_mask = 1 << ts;
	res->upgrade_to_multislot = false;
	res->tfi = tfi;
	res->usf[ts] = usf;

	bts_do_rate_ctr_inc(req->bts, CTR_TBF_ALLOC_ALGO_A);
	return 0;
}

/*! Compute capacity of a given TRX
 *
 *  \param[in] trx Pointer to TRX object
 *  \param[in] rx_window Receive window
 *  \param[in] tx_window Transmit window
 *  \returns non-negative capacity
 */
static inline unsigned compute_capacity(const struct gprs_rlcmac_trx *trx, int rx_window, int tx_window)
{
	const struct gprs_rlcmac_pdch *pdch;
	unsigned ts, capacity = 0;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		pdch = &trx->pdch[ts];
		if (rx_window & (1 << ts))
			capacity += OSMO_MAX(32 - pdch->num_reserved(GPRS_RLCMAC_DL_TBF), 1);

		/* Only consider common slots for UL */
		if (tx_window & rx_window & (1 << ts)) {
			if (find_free_usf(pdch->assigned_usf()) >= 0)
				capacity += OSMO_MAX(32 - pdch->num_reserved(GPRS_RLCMAC_UL_TBF), 1);
		}
	}

	return capacity;
}

/*! Decide if a given slot should be skipped by multislot allocator
 *
 *  \param[in] ms_class Pointer to MS Class object
 *  \param[in] check_tr Flag indicating whether we should check for Tra or Tta parameters for a given MS class
 *  \param[in] rx_window Receive window
 *  \param[in] tx_window Transmit window
 *  \param[in,out] checked_rx array with already checked RX timeslots
 *  \returns true if the slot should be skipped, false otherwise
 */
static bool skip_slot(uint8_t mslot_class, bool check_tr,
		      int16_t rx_window, int16_t tx_window,
		      uint32_t *checked_rx)
{
	uint8_t common_slot_count, req_common_slots,
		rx_slot_count = pcu_bitcount(rx_window),
		tx_slot_count = pcu_bitcount(tx_window);

	/* Check compliance with TS 45.002, table 6.4.2.2.1 */
	/* Whether to skip this round doesn not only depend on the bit
	 * sets but also on check_tr. Therefore this check must be done
	 * before doing the mslot_test_and_set_bit shortcut. */
	if (mslot_class_get_type(mslot_class) == 1) {
		uint16_t slot_sum = rx_slot_count + tx_slot_count;
		/* Assume down + up / dynamic.
		 * TODO: For ext-dynamic, down only, up only add more cases.
		 */
		if (slot_sum <= 6 && tx_slot_count < 3) {
			if (!check_tr)
				return true; /* Skip Tta */
		} else if (slot_sum > 6 && tx_slot_count < 3) {
			if (check_tr)
				return true; /* Skip Tra */
		} else
			return true; /* No supported row in TS 45.002, table 6.4.2.2.1. */
	}

	/* Avoid repeated RX combination check */
	if (mslot_test_and_set_bit(checked_rx, rx_window))
		return true;

	/* Check number of common slots according to TS 45.002, §6.4.2.2 */
	common_slot_count = pcu_bitcount(tx_window & rx_window);
	req_common_slots = OSMO_MIN(tx_slot_count, rx_slot_count);
	if (mslot_class_get_type(mslot_class) == 1)
		req_common_slots = OSMO_MIN(req_common_slots, 2);

	if (req_common_slots != common_slot_count)
		return true;

	return false;
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
	const uint8_t Rx = mslot_class_get_rx(mslot_class),   /* Max number of Rx slots */
		      Tx = mslot_class_get_tx(mslot_class),   /* Max number of Tx slots */
		      Sum = mslot_class_get_sum(mslot_class), /* Max number of Tx + Rx slots */
		      Type = mslot_class_get_type(mslot_class);
	uint8_t max_slots, num_rx, num_tx, mask_sel, pdch_slots, ul_ts, dl_ts;
	int16_t rx_window, tx_window;
	char slot_info[9] = {0};
	int max_capacity = -1;
	uint8_t max_ul_slots = 0, max_dl_slots = 0;

	if (mslot_class)
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for class %d\n",
		     mslot_class);

	if (Tx == MS_NA) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Multislot class %d not applicable.\n",
		     mslot_class);
		return -EINVAL;
	}

	max_slots = OSMO_MAX(Rx, Tx);

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

	/* Iterate through possible numbers of TX slots */
	for (num_tx = 1; num_tx <= Tx; num_tx += 1) {
		uint16_t tx_valid_win = (1 << num_tx) - 1;
		uint8_t rx_mask[MASK_TR + 1];

		mslot_fill_rx_mask(mslot_class, num_tx, rx_mask);

		/* Rotate group of TX slots: UUU-----, -UUU----, ..., UU-----U */
		for (ul_ts = 0; ul_ts < 8; ul_ts += 1, tx_valid_win <<= 1) {
			uint16_t rx_valid_win;
			uint32_t checked_rx[256/32] = {0};

			/* Wrap valid window */
			tx_valid_win = mslot_wrap_window(tx_valid_win);

			/* for multislot type 1: don't split the window to wrap around.
			 * E.g. 'UU-----U' is invalid for a 4 TN window. Except 8 TN window.
			 * See 45.002 B.1 */
			if (Type == 1 && num_tx < 8 &&
					tx_valid_win & (1 << 0) && tx_valid_win & (1 << 7))
				continue;

			tx_window = tx_valid_win;

			/* Filter out unavailable slots */
			tx_window &= *ul_slots;

			/* Skip if the the first TS (ul_ts) is not in the set */
			if ((tx_window & (1 << ul_ts)) == 0)
				continue;

			/* Skip if the the last TS (ul_ts+num_tx-1) is not in the set */
			if ((tx_window & (1 << ((ul_ts+num_tx-1) % 8))) == 0)
				continue;

			num_rx = OSMO_MIN(Rx, Sum - num_tx);
			rx_valid_win = (1 << num_rx) - 1;

			/* Rotate group of RX slots: DDD-----, -DDD----, ..., DD-----D */
			for (dl_ts = 0; dl_ts < 8; dl_ts += 1, rx_valid_win <<= 1) {
				/* Wrap valid window */
				rx_valid_win = (rx_valid_win | rx_valid_win >> 8) & 0xff;

				/* for multislot type 1: don't split the window to wrap around.
				 * E.g. 'DD-----D' is invalid for a 4 TN window. Except 8 TN window.
				 * See 45.002 B.1 */
				if (Type == 1 && num_rx < 8 &&
						(rx_valid_win & (1 << 0)) && (rx_valid_win & (1 << 7)))
					continue;

				/* Validate with both Tta/Ttb/Trb and Ttb/Tra/Trb */
				for (mask_sel = MASK_TT; mask_sel <= MASK_TR; mask_sel += 1) {
					int capacity;

					rx_window = mslot_filter_bad(rx_mask[mask_sel], ul_ts, *dl_slots, rx_valid_win);
					if (rx_window < 0)
						continue;

					if (skip_slot(mslot_class, mask_sel != MASK_TT, rx_window, tx_window, checked_rx))
						continue;

					/* Compute capacity */
					capacity = compute_capacity(trx, rx_window, tx_window);

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
				}
			}
		}
	}

	if (!max_ul_slots || !max_dl_slots) {
		LOGP(DRLCMAC, LOGL_NOTICE,
			"No valid UL/DL slot combination found\n");
		bts_do_rate_ctr_inc(trx->bts, CTR_TBF_ALLOC_FAIL_NO_SLOT_COMBI);
		return -EINVAL;
	}

	*ul_slots = max_ul_slots;
	*dl_slots = max_dl_slots;

	return 0;
}

/*! Count used bits in slots and reserved_slots bitmasks
 *
 *  \param[in] slots Timeslots in use
 *  \param[in] reserved_slots Reserved timeslots
 *  \param[out] slotcount Number of TS in use
 *  \param[out] reserve_count Number of reserved TS
 */
static void count_slots(uint8_t slots, uint8_t reserved_slots, uint8_t *slotcount, uint8_t *reserve_count)
{
	(*slotcount) = pcu_bitcount(slots);
	(*reserve_count) = pcu_bitcount(reserved_slots);
}

/*! Return slot mask with single TS from a given UL/DL set according to TBF's direction, ts pointer is set to that TS
 * number or to negative value on error
 *
 *  \param[in] trx Pointer to TRX object
 *  \param[in] direction Direction of the TBF to allocate
 *  \param[in] dl_slots set of DL timeslots
 *  \param[in] ul_slots set of UL timeslots
 *  \param[in] ts corresponding TS or -1 for autoselection
 *  \returns slot mask with single UL or DL timeslot number if possible
 */
static uint8_t get_single_ts(const gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction direction, uint8_t dl_slots, uint8_t ul_slots,
			     int ts)
{
	uint8_t ret = dl_slots & ul_slots; /* Make sure to consider the first common slot only */

	if (ts < 0)
		ts = find_least_busy_pdch(trx, direction, ret, compute_usage_by_num_tbfs, NULL, NULL);

	if (ts < 0)
		return ffs(ret);

	return ret & (1 << ts);
}

/*! Find set of timeslots available for allocation
 *
 *  \param[in] req Contains all the requested params
 *  \param[in] trx Pointer to TRX object
 *  \param[in] ul_slots set of UL timeslots
 *  \param[in] dl_slots set of DL timeslots
 *  \param[in] reserved_ul_slots set of reserved UL timeslots
 *  \param[in] reserved_dl_slots set of reserved DL timeslots
 *  \param[in] first_common_ts First TS common for both UL and DL or -1 if unknown
 *  \returns negative error code or selected TS on success
 */
static int tbf_select_slot_set(const struct alloc_resources_req *req, const gprs_rlcmac_trx *trx,
			       uint8_t ul_slots, uint8_t dl_slots,
			       uint8_t reserved_ul_slots, uint8_t reserved_dl_slots,
			       int8_t first_common_ts)
{
	bool is_ul = req->direction == GPRS_RLCMAC_UL_TBF;
	uint8_t sl = is_ul ? ul_slots : dl_slots;
	char slot_info[9] = { 0 };

	if (req->single)
		sl = get_single_ts(trx, req->direction, dl_slots, ul_slots, first_common_ts);

	if (!sl) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No %s slots available\n",
		     is_ul ? "uplink" : "downlink");
		bts_do_rate_ctr_inc(trx->bts, CTR_TBF_ALLOC_FAIL_NO_SLOT_AVAIL);
		return -EINVAL;
	}

	if (is_ul) {
		snprintf(slot_info, 9, OSMO_BIT_SPEC, OSMO_BIT_PRINT_EX(reserved_ul_slots, 'u'));
		masked_override_with(slot_info, sl, 'U');
	} else {
		snprintf(slot_info, 9, OSMO_BIT_SPEC, OSMO_BIT_PRINT_EX(reserved_dl_slots, 'd'));
		masked_override_with(slot_info, sl, 'D');
	}

	LOGPC(DRLCMAC, LOGL_DEBUG, "Selected %s slots: (TS=0)\"%s\"(TS=7), %s\n",
	      is_ul ? "UL" : "DL",
	      slot_info, req->single ? "single" : "multi");

	return sl;
}

/*! Allocate USF according to a given UL TS mapping
 *
 *  \param[in] trx Pointer to TRX object
 *  \param[in] selected_ul_slots set of UL timeslots selected for allocation
 *  \param[in] dl_slots set of DL timeslots
 *  \param[out] usf array for allocated USF
 *  \returns updated UL TS mask or negative on error
 */
static int allocate_usf(const gprs_rlcmac_trx *trx, uint8_t selected_ul_slots, uint8_t dl_slots,
			int *usf_list)
{
	uint8_t ul_slots = selected_ul_slots & dl_slots;
	unsigned int ts;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
		int8_t free_usf;

		if (((1 << ts) & ul_slots) == 0)
			continue;

		free_usf = find_free_usf(pdch->assigned_usf());
		if (free_usf < 0) {
			LOGP(DRLCMAC, LOGL_DEBUG,
				"- Skipping TS %d, because "
				"no USF available\n", ts);
			ul_slots &= (~(1 << ts)) & 0xff;
			continue;
		}
		usf_list[ts] = free_usf;
	}

	if (!ul_slots) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No USF available\n");
		bts_do_rate_ctr_inc(trx->bts, CTR_TBF_ALLOC_FAIL_NO_USF);
		return -EBUSY;
	}

	return ul_slots;
}

/*! Slot Allocation: Algorithm B
 *
 * Assign as many downlink slots as possible.
 * Assign one uplink slot. (With free USF)
 *
 *  \param[in] req Contains all the requested params
 *  \param[out] res The resolution/response for the allocation request
 *  \returns negative error code or 0 on success
 */
int alloc_algorithm_b(const struct alloc_resources_req *req,
		      struct alloc_resources_res *res)
{
	uint8_t dl_slots;
	uint8_t ul_slots;
	uint8_t reserved_dl_slots;
	uint8_t reserved_ul_slots;
	int8_t first_common_tn;
	uint8_t slotcount = 0;
	uint8_t reserve_count = 0, trx_no;
	int first_ts;
	int rc;
	int tfi;
	unsigned int i;
	gprs_rlcmac_trx *trx;
	char slot_info[9] = { 0 };
	struct gprs_rlcmac_pdch *first_common_ts = ms_first_common_ts(req->ms);

	LOGPAL(req, "B", LOGL_DEBUG, "Alloc start\n");

	for (i = 0; i < ARRAY_SIZE(res->usf); i++)
		res->usf[i] = -1;

	/* Step 1: Get current state from the MS object */

	reserved_dl_slots = ms_reserved_dl_slots(req->ms);
	reserved_ul_slots = ms_reserved_ul_slots(req->ms);
	first_common_tn = first_common_ts ? first_common_ts->ts_no : -1;

	/* Step 2a: Find usable TRX and TFI */
	tfi = tfi_find_free(req, &trx_no);
	if (tfi < 0) {
		LOGPAL(req, "B", LOGL_NOTICE, "failed to allocate a TFI\n");
		return tfi;
	}

	/* Step 2b: Reserve slots on the TRX for the MS */
	trx = &req->bts->trx[trx_no];

	if (!reserved_dl_slots || !reserved_ul_slots) {
		rc = find_multi_slots(trx, ms_ms_class(req->ms), &reserved_ul_slots, &reserved_dl_slots);
		if (rc < 0)
			return rc;
	}
	dl_slots = reserved_dl_slots;
	ul_slots = reserved_ul_slots;

	/* Step 3a: Derive the slot set for the current TBF */
	rc = tbf_select_slot_set(req, trx, ul_slots, dl_slots, reserved_ul_slots, reserved_dl_slots,
				 first_common_tn);
	if (rc < 0)
		return -EINVAL;

	/* Step 3b: Derive the slot set for a given direction */
	if (req->direction == GPRS_RLCMAC_DL_TBF) {
		dl_slots = rc;
		count_slots(dl_slots, reserved_dl_slots, &slotcount, &reserve_count);
	} else {
		rc = allocate_usf(trx, rc, dl_slots, &res->usf[0]);
		if (rc < 0)
			return rc;

		ul_slots = rc;
		reserved_ul_slots = ul_slots;

		count_slots(ul_slots, reserved_ul_slots, &slotcount, &reserve_count);
	}

	first_ts = ffs(rc) - 1;
	if (first_ts < 0) {
		LOGPAL(req, "B", LOGL_NOTICE, "first slot unavailable\n");
		return -EINVAL;
	}

	first_common_tn = ffs(dl_slots & ul_slots) - 1;
	if (first_common_tn < 0) {
		LOGPAL(req, "B", LOGL_NOTICE, "first common slot unavailable\n");
		return -EINVAL;
	}
	first_common_ts = &trx->pdch[first_common_tn];

	res->trx = trx;
	res->first_common_ts = first_common_ts;
	res->reserved_ul_slots = reserved_ul_slots;
	res->reserved_dl_slots = reserved_dl_slots;
	res->tfi = tfi;
	/* res->usf is already filled in above */
	if (req->single && slotcount) {
		res->upgrade_to_multislot = (reserve_count > slotcount);
		LOGPAL(req, "B", LOGL_INFO, "using single slot at TS %d\n", first_ts);
	} else {
		res->upgrade_to_multislot = false;
		LOGPAL(req, "B", LOGL_INFO, "using %d slots\n", slotcount);
	}

	ts_format(slot_info, dl_slots, ul_slots);
	LOGP(DRLCMAC, LOGL_DEBUG, "- Available DL/UL slots: (TS=0)\"%s\"(TS=7)\n", slot_info);

	if (req->direction == GPRS_RLCMAC_DL_TBF)
		res->ass_slots_mask = dl_slots;
	else
		res->ass_slots_mask = ul_slots;

	bts_do_rate_ctr_inc(req->bts, CTR_TBF_ALLOC_ALGO_B);

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
 *  \param[in] req Contains all the requested params
 *  \param[out] res The resolution/response for the allocation request
 *  \returns negative error code or 0 on success
 */
int alloc_algorithm_dynamic(const struct alloc_resources_req *req,
			    struct alloc_resources_res *res)
{
	int rc;

	/* Reset load_is_high if there is at least one idle PDCH */
	if (req->bts->multislot_disabled) {
		req->bts->multislot_disabled = !idle_pdch_avail(req->bts);
		if (!req->bts->multislot_disabled)
			LOGP(DRLCMAC, LOGL_DEBUG, "Enabling algorithm B\n");
	}

	if (!req->bts->multislot_disabled) {
		rc = alloc_algorithm_b(req, res);
		if (rc >= 0)
			return rc;

		if (!req->bts->multislot_disabled)
			LOGP(DRLCMAC, LOGL_DEBUG, "Disabling algorithm B\n");
		req->bts->multislot_disabled = 1;
	}

	return alloc_algorithm_a(req, res);
}

int gprs_alloc_max_dl_slots_per_ms(const struct gprs_rlcmac_bts *bts, uint8_t ms_class)
{
	int rx = mslot_class_get_rx(ms_class);

	if (rx == MS_NA)
		rx = 4;

	if (the_pcu->alloc_algorithm == alloc_algorithm_a)
		return 1;

	if (bts->multislot_disabled)
		return 1;

	return rx;
}
