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

#include <errno.h>
#include <values.h>

/* 3GPP TS 05.02 Annex B.1 */

#define MS_NA	255 /* N/A */
#define MS_A	254 /* 1 with hopping, 0 without */
#define MS_B	253 /* 1 with hopping, 0 without (change Rx to Tx)*/
#define MS_C	252 /* 1 with hopping, 0 without (change Tx to Rx)*/

struct gprs_ms_multislot_class {
	uint8_t rx, tx, sum;	/* Maximum Number of Slots: RX, Tx, Sum Rx+Tx */
	uint8_t ta, tb, ra, rb;	/* Minimum Number of Slots */
	uint8_t type; /* Type of Mobile */
};

static const struct gprs_ms_multislot_class gprs_ms_multislot_class[32] = {
/* M-S Class	  Rx	Tx	Sum	Tta	Ttb	Tra	Trb	Type */
/* N/A */	{ MS_NA,MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA },
/* 1 */		{ 1,	1,	2,	3,	2,	4,	2,	1 },
/* 2 */		{ 2,	1,	3,	3,	2,	3,	1,	1 },
/* 3 */		{ 2,	2,	3,	3,	2,	3,	1,	1 },
/* 4 */		{ 3,	1,	4,	3,	1,	3,	1,	1 },
/* 5 */		{ 2,	2,	4,	3,	1,	3,	1,	1 },
/* 6 */		{ 3,	2,	4,	3,	1,	3,	1,	1 },
/* 7 */		{ 3,	3,	4,	3,	1,	3,	1,	1 },
/* 8 */		{ 4,	1,	5,	3,	1,	2,	1,	1 },
/* 9 */		{ 3,	2,	5,	3,	1,	2,	1,	1 },
/* 10 */	{ 4,	2,	5,	3,	1,	2,	1,	1 },
/* 11 */	{ 4,	3,	5,	3,	1,	2,	1,	1 },
/* 12 */	{ 4,	4,	5,	2,	1,	2,	1,	1 },
/* 13 */	{ 3,	3,	MS_NA,	MS_NA,	MS_A,	3,	MS_A,	2 },
/* 14 */	{ 4,	4,	MS_NA,	MS_NA,	MS_A,	3,	MS_A,	2 },
/* 15 */	{ 5,	5,	MS_NA,	MS_NA,	MS_A,	3,	MS_A,	2 },
/* 16 */	{ 6,	6,	MS_NA,	MS_NA,	MS_A,	2,	MS_A,	2 },
/* 17 */	{ 7,	7,	MS_NA,	MS_NA,	MS_A,	1,	0,	2 },
/* 18 */	{ 8,	8,	MS_NA,	MS_NA,	0,	0,	0,	2 },
/* 19 */	{ 6,	2,	MS_NA,	3,	MS_B,	2,	MS_C,	1 },
/* 20 */	{ 6,	3,	MS_NA,	3,	MS_B,	2,	MS_C,	1 },
/* 21 */	{ 6,	4,	MS_NA,	3,	MS_B,	2,	MS_C,	1 },
/* 22 */	{ 6,	4,	MS_NA,	2,	MS_B,	2,	MS_C,	1 },
/* 23 */	{ 6,	6,	MS_NA,	2,	MS_B,	2,	MS_C,	1 },
/* 24 */	{ 8,	2,	MS_NA,	3,	MS_B,	2,	MS_C,	1 },
/* 25 */	{ 8,	3,	MS_NA,	3,	MS_B,	2,	MS_C,	1 },
/* 26 */	{ 8,	4,	MS_NA,	3,	MS_B,	2,	MS_C,	1 },
/* 27 */	{ 8,	4,	MS_NA,	2,	MS_B,	2,	MS_C,	1 },
/* 28 */	{ 8,	6,	MS_NA,	2,	MS_B,	2,	MS_C,	1 },
/* 29 */	{ 8,	8,	MS_NA,	2,	MS_B,	2,	MS_C,	1 },
/* N/A */	{ MS_NA,MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA },
/* N/A */	{ MS_NA,MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA,	MS_NA },
};

static unsigned lsb(unsigned x)
{
	return x & -x;
}

static unsigned bitcount(unsigned x)
{
	unsigned count = 0;
	for (count = 0; x; count += 1)
		x &= x - 1;

	return count;
}

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

static inline int8_t find_free_usf(struct gprs_rlcmac_pdch *pdch)
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

static int find_possible_pdchs(struct gprs_rlcmac_trx *trx,
	size_t max_slots,
	uint8_t mask, const char *mask_reason = NULL)
{
	unsigned ts;
	int valid_ts_set = 0;
	int8_t last_tsc = -1; /* must be signed */

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		struct gprs_rlcmac_pdch *pdch;

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

static int find_least_busy_pdch(struct gprs_rlcmac_trx *trx,
	enum gprs_rlcmac_tbf_direction dir,
	uint8_t mask,
	int *free_usf = 0)
{
	unsigned ts;
	int min_used = INT_MAX;
	int min_ts = -1;
	int min_usf = -1;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
		int num_tbfs;
		int usf = -1; /* must be signed */

		if (((1 << ts) & mask) == 0)
			continue;

		num_tbfs = pdch->num_tbfs(dir);
		if (num_tbfs < min_used) {
			/* We have found a candidate */
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

	if (free_usf)
		*free_usf = min_usf;

	return min_ts;
}

static int find_least_reserved_pdch(struct gprs_rlcmac_trx *trx,
	enum gprs_rlcmac_tbf_direction dir,
	uint8_t mask,
	int *free_usf = 0)
{
	unsigned ts;
	int min_used = INT_MAX;
	int min_ts = -1;
	int min_usf = -1;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
		int num_tbfs;
		int usf = -1; /* must be signed */

		if (((1 << ts) & mask) == 0)
			continue;

		num_tbfs =
			pdch->num_reserved(GPRS_RLCMAC_DL_TBF) +
			pdch->num_reserved(GPRS_RLCMAC_UL_TBF);

		if (num_tbfs < min_used) {
			/* We have found a candidate */
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

static void assign_uplink_tbf_usf(
				struct gprs_rlcmac_pdch *pdch,
				struct gprs_rlcmac_ul_tbf *tbf, int8_t usf)
{
	tbf->trx->ul_tbf[tbf->tfi()] = tbf;
	tbf->m_usf[pdch->ts_no] = usf;
	attach_tbf_to_pdch(pdch, tbf);
}

static void assign_dlink_tbf(
				struct gprs_rlcmac_pdch *pdch,
				struct gprs_rlcmac_dl_tbf *tbf)
{
	tbf->trx->dl_tbf[tbf->tfi()] = tbf;
	attach_tbf_to_pdch(pdch, tbf);
}


/* Slot Allocation: Algorithm A
 *
 * Assign single slot for uplink and downlink
 */
int alloc_algorithm_a(struct gprs_rlcmac_bts *bts,
	GprsMs *ms,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single)
{
	struct gprs_rlcmac_pdch *pdch;
	int ts = -1;
	uint8_t ul_slots, dl_slots;
	int usf = -1;
	int mask = 0xff;
	const char *mask_reason = NULL;

	LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm A) for class "
		"%d\n", tbf->ms_class());

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

	mask = find_possible_pdchs(tbf->trx, 1, mask, mask_reason);
	if (!mask)
		return -EINVAL;

	ts = find_least_reserved_pdch(tbf->trx, tbf->direction, mask, &usf);

	if (ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
			"to allocate a TS, no USF available\n");
		return -EBUSY;
	}

	pdch = &tbf->trx->pdch[ts];
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = static_cast<gprs_rlcmac_ul_tbf *>(tbf);

		if (usf < 0)
			usf = find_free_usf(pdch);

		if (usf < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
				"allocating TS=%d, no USF available\n", ts);
			return -EBUSY;
		}

		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign uplink TS=%d USF=%d\n",
			ts, usf);
		assign_uplink_tbf_usf(pdch, ul_tbf, usf);
	} else {
		struct gprs_rlcmac_dl_tbf *dl_tbf = static_cast<gprs_rlcmac_dl_tbf *>(tbf);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign downlink TS=%d\n", ts);
		assign_dlink_tbf(pdch, dl_tbf);
	}
	/* the only one TS is the common TS */
	tbf->first_ts = tbf->first_common_ts = ts;
	ms->set_reserved_slots(tbf->trx, 1 << ts, 1 << ts);

	tbf->upgrade_to_multislot = 0;

	return 0;
}

static int find_multi_slots(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_trx *trx,
	GprsMs *ms, uint8_t *ul_slots, uint8_t *dl_slots)
{
	const struct gprs_ms_multislot_class *ms_class;
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

	uint32_t checked_tx[256/32] = {0};

	if (ms->ms_class() >= 32) {
		LOGP(DRLCMAC, LOGL_ERROR, "Multislot class %d out of range.\n",
			ms->ms_class());
		return -EINVAL;
	}

	if (ms->ms_class()) {
		ms_class = &gprs_ms_multislot_class[ms->ms_class()];
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for "
			"class %d\n", ms->ms_class());
	} else {
		ms_class = &gprs_ms_multislot_class[12];
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for "
			"unknown class (assuming 12)\n");
	}

	if (ms_class->tx == MS_NA) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Multislot class %d not "
			"applicable.\n", ms->ms_class());
		return -EINVAL;
	}

	Tx = ms_class->tx;
	Sum = ms_class->sum;
	Tta = ms_class->ta;
	Ttb = ms_class->tb;
	Tra = ms_class->ra;
	Trb = ms_class->rb;
	Type = ms_class->type;

	/* Tta and Ttb may depend on hopping or frequency change */
	/* TODO: Set them to 1  */
	if (Ttb == MS_A || Ttb == MS_B)
		Ttb = 0;
	if (Trb == MS_A || Trb == MS_C)
		Trb = 0;

	LOGP(DRLCMAC, LOGL_DEBUG, "- Rx=%d Tx=%d Sum Rx+Tx=%s  Tta=%s Ttb=%d "
		" Tra=%d Trb=%d Type=%d\n", ms_class->rx, Tx,
		(Sum == MS_NA) ? "N/A" : digit[Sum],
		(Tta == MS_NA) ? "N/A" : digit[Tta], Ttb, Tra, Trb, Type);

	max_slots = OSMO_MAX(ms_class->rx, ms_class->tx);

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
	for (num_tx = 1; num_tx <= ms_class->tx; num_tx += 1) {
		uint16_t tx_valid_win = (1 << num_tx) - 1;

		uint8_t rx_mask[2]; /* 0: Tt*, 1: Tr* */
		rx_mask[0] = (0x100 >> OSMO_MAX(Ttb, Tta)) - 1;
		rx_mask[0] &= ~((1 << (Trb + num_tx)) - 1);
		rx_mask[0] = rx_mask[0] << 3 | rx_mask[0] >> 5;
		rx_mask[1] = (0x100 >> Ttb) - 1;
		rx_mask[1] &= ~((1 << (OSMO_MAX(Trb, Tra) + num_tx)) - 1);
		rx_mask[1] = rx_mask[1] << 3 | rx_mask[1] >> 5;

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

		/* Avoid repeated TX combination check */
		if (test_and_set_bit(checked_tx, tx_window))
			continue;

		if (!tx_window)
			continue;

		tx_slot_count = bitcount(tx_window);

		max_rx = OSMO_MIN(ms_class->rx, ms_class->sum - num_tx);
		rx_valid_win = (1 << max_rx) - 1;

	/* Rotate group of RX slots: DDD-----, -DDD----, ..., DD-----D */
	for (dl_ts = 0; dl_ts < 8; dl_ts += 1, rx_valid_win <<= 1) {
		/* Wrap valid window */
		rx_valid_win = (rx_valid_win | rx_valid_win >> 8) & 0xff;

	/* Validate with both Tta/Ttb/Trb and Ttb/Tra/Trb */
	for (unsigned m_idx = 0; m_idx < ARRAY_SIZE(rx_mask); m_idx += 1) {
		unsigned common_slot_count;
		unsigned req_common_slots;
		unsigned rx_slot_count;
		uint16_t rx_bad;
		uint8_t rx_good;
		unsigned ts;
		int capacity;

		/* Filter out bad slots */
		rx_bad = (uint16_t)(0xff & ~rx_mask[m_idx]) << ul_ts;
		rx_bad = (rx_bad | (rx_bad >> 8)) & 0xff;
		rx_good = *dl_slots & ~rx_bad;

		/* TODO: CHECK this calculation -> separate function for unit
		 * testing */

		rx_window = rx_good & rx_valid_win;

		/* Avoid repeated RX combination check */
		if (test_and_set_bit(checked_rx, rx_window))
			continue;

		rx_slot_count = bitcount(rx_window);

#if 0
		LOGP(DRLCMAC, LOGL_DEBUG, "n_tx=%d, n_rx=%d, "
			"tx=%02x, rx=%02x, mask=%02x, bad=%02x, good=%02x, ul=%02x, dl=%02x\n",
			tx_slot_count, rx_slot_count,
			tx_window, rx_window, rx_mask[m_idx], rx_bad, rx_good, *ul_slots, *dl_slots);
#endif

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
		common_slot_count = bitcount(tx_window & rx_window);
		req_common_slots = OSMO_MIN(tx_slot_count, rx_slot_count);
		if (ms_class->type == 1)
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
			struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
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

/* Slot Allocation: Algorithm B
 *
 * Assign as many downlink slots as possible.
 * Assign one uplink slot. (With free USF)
 *
 */
int alloc_algorithm_b(struct gprs_rlcmac_bts *bts,
	GprsMs *ms,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single)
{
	uint8_t dl_slots = 0;
	uint8_t ul_slots = 0;
	int8_t first_common_ts;
	uint8_t slotcount = 0;
	uint8_t avail_count = 0;
	char slot_info[9] = {0};
	int ts;
	int rc;

	if (!ms) {
		LOGP(DRLCMAC, LOGL_ERROR, "MS not set\n");
		return -EINVAL;
	}

	dl_slots = ms->reserved_dl_slots();
	ul_slots = ms->reserved_ul_slots();

	if (!dl_slots || !ul_slots) {
		rc = find_multi_slots(bts, tbf->trx, ms, &ul_slots, &dl_slots);
		if (rc < 0)
			return rc;

		ms->set_reserved_slots(tbf->trx, ul_slots, dl_slots);

		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Reserved DL/UL slots: (TS=0)\"%s\"(TS=7)\n",
			set_flag_chars(set_flag_chars(set_flag_chars(slot_info,
				dl_slots, 'D', '.'),
				ul_slots, 'U'),
				ul_slots & dl_slots, 'C'));
	}

	first_common_ts = ms->first_common_ts();

	if (single) {
		/* Make sure to consider the first common slot only */
		ul_slots = dl_slots = dl_slots & ul_slots;

		ts = first_common_ts;

		if (ts < 0)
			ts = find_least_busy_pdch(tbf->trx, tbf->direction,
				dl_slots & ul_slots, NULL);
		if (ts < 0)
			ul_slots = dl_slots = lsb(dl_slots & ul_slots);
		else
			ul_slots = dl_slots = (dl_slots & ul_slots) & (1<<ts);
	} else if (first_common_ts > 0) {
		/* Make sure to keep the common TBF */
		uint8_t disable_dl_slots;

		/* Mark all slots below the common TBF, e.g. cTS=4 -> xxx----- */
		disable_dl_slots = (1 << (first_common_ts - 1)) - 1;

		/* Only disable common slots in that set */
		disable_dl_slots &= (dl_slots & ul_slots);

		/* Remove them from the uplink set */
		ul_slots &= ~disable_dl_slots;

		/* The disabled UL slots will not be used again for subsequent
		 * TBF, do not reserve them anymore */
		if (disable_dl_slots)
			ms->set_reserved_slots(tbf->trx, ul_slots, dl_slots);
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
		struct gprs_rlcmac_dl_tbf *dl_tbf = static_cast<gprs_rlcmac_dl_tbf *>(tbf);

		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Selected DL slots: (TS=0)\"%s\"(TS=7)%s\n",
			set_flag_chars(set_flag_chars(slot_info,
					ms->reserved_dl_slots(), 'd', '.'),
					dl_slots, 'D'),
			single ? ", single" : "");

		/* assign downlink */
		if (dl_slots == 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No downlink slots "
				"available\n");
			return -EINVAL;
		}
		for (ts = 0; ts < 8; ts++) {
			if (!(dl_slots & (1 << ts)))
				continue;

			LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning DL TS "
				"%d\n", ts);
			assign_dlink_tbf(&tbf->trx->pdch[ts], dl_tbf);
			slotcount++;
			if (slotcount == 1)
				dl_tbf->first_ts = ts;
		}
		avail_count = bitcount(ms->reserved_dl_slots());

	} else {
		struct gprs_rlcmac_ul_tbf *ul_tbf = static_cast<gprs_rlcmac_ul_tbf *>(tbf);
		int free_usf = -1;

		if (first_common_ts >= 0)
			ul_slots = 1 << first_common_ts;
		else
			ul_slots = ul_slots & dl_slots;

		ts = find_least_busy_pdch(tbf->trx, GPRS_RLCMAC_UL_TBF,
			ul_slots, &free_usf);

		if (free_usf < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No USF available\n");
			return -EBUSY;
		}
		ul_slots = 1 << ts;

		LOGP(DRLCMAC, LOGL_DEBUG,
			"- Selected UL slots: (TS=0)\"%s\"(TS=7)%s\n",
			set_flag_chars(set_flag_chars(slot_info,
					ms->reserved_ul_slots(), 'u', '.'),
					ul_slots, 'U'),
			single ? ", single" : "");

		assign_uplink_tbf_usf(&tbf->trx->pdch[ts], ul_tbf, free_usf);
		slotcount++;
		ul_tbf->first_ts = ts;

		/* We will stick to that single UL slot, unreserve the others */
		if (ul_slots != ms->reserved_ul_slots())
			ms->set_reserved_slots(tbf->trx,
				ul_slots, ms->reserved_dl_slots());

		avail_count = bitcount(ms->reserved_ul_slots());
#if 0 /* This code assigns multiple slots for UL (and wastes USFs that way) */
		for (ts = 0; ts < 8; ts++) {
			if (!(ul_slots & (1 << ts)))
				continue;

			free_usf = find_free_usf(&tbf->trx->pdch[ts]);
			if (free_usf < 0) {
				LOGP(DRLCMAC, LOGL_DEBUG,
					"- Skipping TS %d, because "
					"no USF available\n", ts);
				continue;
			}

			LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning UL TS "
				"%d\n", ts);
			assign_uplink_tbf_usf(&tbf->trx->pdch[ts], ul_tbf, free_usf);
			slotcount++;
			if (slotcount == 1)
				ul_tbf->first_ts = ts;
		}
#endif
	}

	if (single && slotcount) {
		tbf->upgrade_to_multislot = (avail_count > slotcount);
		LOGP(DRLCMAC, LOGL_INFO, "Using single slot at TS %d for %s\n",
			tbf->first_ts,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	} else {
		tbf->upgrade_to_multislot = 0;
		LOGP(DRLCMAC, LOGL_INFO, "Using %d slots for %s\n", slotcount,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	}

	first_common_ts = ffs(dl_slots & ul_slots) - 1;

	if (first_common_ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No first common slots available\n");
		return -EINVAL;
	}

	tbf->first_common_ts = first_common_ts;

	return 0;
}
