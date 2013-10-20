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

#include <errno.h>

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

static inline int8_t find_free_usf(struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_tbf *tbf;
	uint8_t usf_map = 0;
	uint8_t tfi, usf;

	/* make map of used USF */
	for (tfi = 0; tfi < 32; tfi++) {
		tbf = pdch->ul_tbf[tfi];
		if (!tbf)
			continue;
		usf_map |= (1 << tbf->dir.ul.usf[pdch->ts_no]);
	}

	/* look for USF, don't use USF=7 */
	for (usf = 0; usf < 7; usf++) {
		if (!(usf_map & (1 << usf)))
			return usf;
	}

	return -1;
}

static int find_enabled_pdch(struct gprs_rlcmac_trx *trx, const uint8_t start_ts)
{
	int ts;
	for (ts = start_ts; ts < 8; ts++) {
		struct gprs_rlcmac_pdch *pdch;

		pdch = &trx->pdch[ts];
		if (!pdch->is_enabled()) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, because "
				"not enabled\n", ts);
			continue;
		}
		return ts;
	}

	return 8;
}

static void assign_uplink_tbf_usf(
				struct gprs_rlcmac_pdch *pdch,
				struct gprs_rlcmac_tbf *tbf, int8_t usf)
{
	tbf->trx->ul_tbf[tbf->tfi] = tbf;
	pdch->ul_tbf[tbf->tfi] = tbf;
	tbf->pdch[pdch->ts_no] = pdch;
	tbf->dir.ul.usf[pdch->ts_no] = usf;
}

static void assign_dlink_tbf(
				struct gprs_rlcmac_pdch *pdch,
				struct gprs_rlcmac_tbf *tbf)
{
	tbf->trx->dl_tbf[tbf->tfi] = tbf;
	pdch->dl_tbf[tbf->tfi] = tbf;
	tbf->pdch[pdch->ts_no] = pdch;
}


/* Slot Allocation: Algorithm A
 *
 * Assign single slot for uplink and downlink
 */
int alloc_algorithm_a(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single)
{
	struct gprs_rlcmac_pdch *pdch;
	uint8_t ts;

	LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm A) for class "
		"%d\n", tbf->ms_class);

	ts = find_enabled_pdch(tbf->trx, 0);
	if (ts == 8)
		return -EINVAL;

	pdch = &tbf->trx->pdch[ts];
	tbf->tsc = pdch->tsc;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		int8_t usf; /* must be signed */

		/* if USF available */
		usf = find_free_usf(pdch);
		if (usf < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
				"allocating TS=%d, no USF available\n", ts);
			return -EBUSY;
		}
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign uplink "
			"TS=%d USF=%d\n", ts, usf);
		assign_uplink_tbf_usf(pdch, tbf, usf);
	} else {
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign downlink TS=%d\n", ts);
		assign_dlink_tbf(pdch, tbf);
	}
	/* the only one TS is the common TS */
	tbf->first_ts = tbf->first_common_ts = ts;

	return 0;
}

/* Slot Allocation: Algorithm B
 *
 * Assign as many downlink slots as possible.
 * Assign one uplink slot. (With free USF)
 *
 */
int alloc_algorithm_b(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single)
{
	struct gprs_rlcmac_pdch *pdch;
	const struct gprs_ms_multislot_class *ms_class;
	uint8_t Rx, Tx, Sum;	/* Maximum Number of Slots: RX, Tx, Sum Rx+Tx */
	uint8_t Tta, Ttb, Tra, Trb, Tt, Tr;	/* Minimum Number of Slots */
	uint8_t Type; /* Type of Mobile */
	uint8_t rx_win_min = 0, rx_win_max = 7;
	uint8_t tx_win_min, tx_win_max, tx_range;
	uint8_t rx_window = 0, tx_window = 0;
	static const char *digit[10] = { "0","1","2","3","4","5","6","7","8","9" };
	int8_t usf[8] = { -1, -1, -1, -1, -1, -1, -1, -1 }; /* must be signed */
	int8_t tsc = -1; /* must be signed */
	int8_t first_common_ts = -1;
	uint8_t i, ts;
	uint8_t slotcount = 0;


	if (tbf->ms_class >= 32) {
		LOGP(DRLCMAC, LOGL_ERROR, "Multislot class %d out of range.\n",
			tbf->ms_class);
		return -EINVAL;
	}

	if (tbf->ms_class) {
		ms_class = &gprs_ms_multislot_class[tbf->ms_class];
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for "
			"class %d\n", tbf->ms_class);
	} else {
		ms_class = &gprs_ms_multislot_class[12];
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for "
			"unknow class (assuming 12)\n");
	}

	if (ms_class->tx == MS_NA) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Multislot class %d not "
			"applicable.\n", tbf->ms_class);
		return -EINVAL;
	}

	Rx = ms_class->rx;
	Tx = ms_class->tx;
	Sum = ms_class->sum;
	Tta = ms_class->ta;
	Ttb = ms_class->tb;
	Tra = ms_class->ra;
	Trb = ms_class->rb;
	Type = ms_class->type;

	/* Tta and Ttb may depend on hopping or frequency change */
	if (Ttb == MS_A)
		Ttb = 0;
	if (Trb == MS_A)
		Trb = 0;
	if (Ttb == MS_B)
		Ttb = 0;
	if (Trb == MS_C)
		Trb = 0;

	LOGP(DRLCMAC, LOGL_DEBUG, "- Rx=%d Tx=%d Sum Rx+Tx=%s  Tta=%s Ttb=%d "
		" Tra=%d Trb=%d Type=%d\n", Rx, Tx,
		(Sum == MS_NA) ? "N/A" : digit[Sum],
		(Tta == MS_NA) ? "N/A" : digit[Tta], Ttb, Tra, Trb, Type);

	/* select the values for time contraints */
	/* applicable to type 1 and type 2 */
	Tt = Ttb;
	Tr = Trb;

	/* select a window of Rx slots if available
	 * The maximum allowed slots depend on RX or the window of available
	 * slots.
	 * This must be done for uplink TBF also, because it is the basis
	 * for calculating control slot and uplink slot(s). */
	for (ts = 0, i = 0; ts < 8; ts++) {
		pdch = &tbf->trx->pdch[ts];
		/* check if enabled */
		if (!pdch->is_enabled()) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, because "
				"not enabled\n", ts);
			/* increase window for Type 1 */
			if (Type == 1 && rx_window)
				i++;
			continue;
		}
		/* check if TSC changes */
		if (tsc < 0)
			tbf->tsc = tsc = pdch->tsc;
		else if (tsc != pdch->tsc) {
			LOGP(DRLCMAC, LOGL_ERROR, "Skipping TS %d of TRX=%d, "
				"because it has different TSC than lower TS "
				"of TRX. In order to allow multislot, all "
				"slots must be configured with the same "
				"TSC!\n", ts, tbf->trx_no);
			/* increase window for Type 1 */
			if (Type == 1 && rx_window)
				i++;
			continue;
		}

		if (!rx_window)
			rx_win_min = ts;

		rx_window |= (1 << ts);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Selected DL TS %d\n", ts);

		/* range of window (required for Type 1) */
		rx_win_max = ts;

		if (++i == Rx) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because slots / "
				"window reached maximum alowed Rx size\n");
			break;
		}
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "- Selected slots for RX: "
		"(TS=0)\"%c%c%c%c%c%c%c%c\"(TS=7)\n",
		((rx_window & 0x01)) ? 'D' : '.',
		((rx_window & 0x02)) ? 'D' : '.',
		((rx_window & 0x04)) ? 'D' : '.',
		((rx_window & 0x08)) ? 'D' : '.',
		((rx_window & 0x10)) ? 'D' : '.',
		((rx_window & 0x20)) ? 'D' : '.',
		((rx_window & 0x40)) ? 'D' : '.',
		((rx_window & 0x80)) ? 'D' : '.');

	/* reduce window, if existing uplink slots collide RX window */
	if (Type == 1 && old_tbf && old_tbf->direction == GPRS_RLCMAC_UL_TBF) {
		uint8_t collide = 0, ul_usage = 0;
		int j;

		/* calculate mask of colliding slots */
		for (ts = 0; ts < 8; ts++) {
			if (old_tbf->pdch[ts]) {
				ul_usage |= (1 << ts);
				/* mark bits from TS-t .. TS+r */
				for (j = ts - Tt; j != ((ts + Tr + 1) & 7);
				     j = (j + 1) & 7)
					collide |= (1 << j);
			}
		}
		LOGP(DRLCMAC, LOGL_DEBUG, "- Not allowed slots due to existing "
			"UL allocation: (TS=0)\"%c%c%c%c%c%c%c%c\"(TS=7) "
			" D=downlink  x=not usable\n",
			((ul_usage & 0x01)) ? 'D' : ((collide & 0x01))?'x':'.',
			((ul_usage & 0x02)) ? 'D' : ((collide & 0x02))?'x':'.',
			((ul_usage & 0x04)) ? 'D' : ((collide & 0x04))?'x':'.',
			((ul_usage & 0x08)) ? 'D' : ((collide & 0x08))?'x':'.',
			((ul_usage & 0x10)) ? 'D' : ((collide & 0x10))?'x':'.',
			((ul_usage & 0x20)) ? 'D' : ((collide & 0x20))?'x':'.',
			((ul_usage & 0x40)) ? 'D' : ((collide & 0x40))?'x':'.',
			((ul_usage & 0x80)) ? 'D' : ((collide & 0x80))?'x':'.');

		/* apply mask to reduce tx_window (shifted by 3 slots) */
		rx_window &= ~(collide << 3);
		rx_window &= ~(collide >> 5);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Remaining slots for RX: "
			"(TS=0)\"%c%c%c%c%c%c%c%c\"(TS=7)\n",
			((rx_window & 0x01)) ? 'D' : '.',
			((rx_window & 0x02)) ? 'D' : '.',
			((rx_window & 0x04)) ? 'D' : '.',
			((rx_window & 0x08)) ? 'D' : '.',
			((rx_window & 0x10)) ? 'D' : '.',
			((rx_window & 0x20)) ? 'D' : '.',
			((rx_window & 0x40)) ? 'D' : '.',
			((rx_window & 0x80)) ? 'D' : '.');
		if (!rx_window) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No suitable downlink slots "
				"available with current uplink assignment\n");
			return -EBUSY;
		}

		/* calculate new min/max */
		for (ts = rx_win_min; ts <= rx_win_max; ts++) {
			if ((rx_window & (1 << ts)))
				break;
			rx_win_min = ts + 1;
			LOGP(DRLCMAC, LOGL_DEBUG, "- TS has been deleted, so "
				"raising start of DL window to %d\n",
				rx_win_min);
		}
		for (ts = rx_win_max; ts >= rx_win_min; ts--) {
			if ((rx_window & (1 << ts)))
				break;
			rx_win_max = ts - 1;
			LOGP(DRLCMAC, LOGL_DEBUG, "- TS has been deleted, so "
				"lowering end of DL window to %d\n",
				rx_win_max);
		}
	}

	/* reduce window, to allow at least one uplink TX slot
	 * this is only required for Type 1 */
	if (Type == 1 && rx_win_max - rx_win_min + 1 + Tt + 1 + Tr > 8) {
		rx_win_max = rx_win_min + 7 - Tt - 1 - Tr;
		LOGP(DRLCMAC, LOGL_DEBUG, "- Reduce RX window due to time "
			"contraints to %d slots\n",
			rx_win_max - rx_win_min + 1);
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "- RX-Window is: %d..%d\n", rx_win_min,
		rx_win_max);

	/* calculate TX window */
	if (Type == 1) {
		/* calculate TX window (shifted by 3 timeslots)
		 * it uses the space between tx_win_max and tx_win_min */
		tx_win_min = (rx_win_max - 2 + Tt) & 7;
		tx_win_max = (rx_win_min + 4 - Tr) & 7;
		/* calculate the TX window size (might be larger than Tx) */
		tx_range = (tx_win_max - tx_win_min + 1) & 7;
	} else {
		/* TX and RX simultaniously */
		tx_win_min = rx_win_min;
		tx_win_max = 7;
		/* TX window size (might be larger than Tx) */
		tx_range = tx_win_max - tx_win_min + 1;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "- TX-Window is: %d..%d\n", tx_win_min,
		tx_win_max);

	/* select a window of Tx slots if available
	 * The maximum allowed slots depend on TX or the window of available
	 * slots.
	 *
	 * also assign the first common ts, which is used for control or single
	 * slot. */
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		for (ts = tx_win_min, i = 0; i < tx_range; ts = (ts + 1) & 7) {
			pdch = &tbf->trx->pdch[ts];
			/* check if enabled */
			if (!pdch->is_enabled()) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
					"because not enabled\n", ts);
				continue;
			}
			/* check if TSC changes */
			if (tsc < 0)
				tbf->tsc = tsc = pdch->tsc;
			else if (tsc != pdch->tsc) {
				LOGP(DRLCMAC, LOGL_ERROR, "Skipping TS %d of "
					"TRX=%d, because it has different TSC "
					"than lower TS of TRX. In order to "
					"allow multislot, all slots must be "
					"configured with the same TSC!\n",
					ts, tbf->trx_no);
				/* increase window for Type 1 */
				if (Type == 1)
					i++;
				continue;
			}
			/* check for free usf */
			usf[ts] = find_free_usf(pdch);
			if (usf[ts] < 0) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
					"because no USF available\n", ts);
				/* increase window for Type 1 */
				if (Type == 1)
					i++;
				continue;
			}

			if (!tx_window)
				first_common_ts = ts;

			tx_window |= (1 << ts);
			LOGP(DRLCMAC, LOGL_DEBUG, "- Selected UL TS %d\n", ts);

			if (1 && Type == 1) { /* FIXME: multislot UL assignment */
				LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because "
					"1 slot assigned\n");
				break;
			}
			if (++i == Tx) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because "
					"slots / window reached maximum "
					"allowed Tx size\n");
				break;
			}
		}

		LOGP(DRLCMAC, LOGL_DEBUG, "- Selected TX window: "
			"(TS=0)\"%c%c%c%c%c%c%c%c\"(TS=7)\n",
			((tx_window & 0x01)) ? 'U' : '.',
			((tx_window & 0x02)) ? 'U' : '.',
			((tx_window & 0x04)) ? 'U' : '.',
			((tx_window & 0x08)) ? 'U' : '.',
			((tx_window & 0x10)) ? 'U' : '.',
			((tx_window & 0x20)) ? 'U' : '.',
			((tx_window & 0x40)) ? 'U' : '.',
			((tx_window & 0x80)) ? 'U' : '.');

		if (!tx_window) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No suitable uplink slots "
				"available\n");
			return -EBUSY;
		}
	} else {
		/* assign the first common ts, which is used for control or
		 * single slot. */
		for (ts = tx_win_min, i = 0; i < tx_range; ts = (ts + 1) & 7) {
			pdch = &tbf->trx->pdch[ts];
			/* check if enabled */
			if (!pdch->is_enabled()) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
					"because not enabled\n", ts);
				continue;
			}
			first_common_ts = ts;
			break;
		}
	}

	if (first_common_ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No first common slots available\n");
		return -EINVAL;
	}

	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		/* assign downlink */
		if (rx_window == 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No downlink slots "
				"available\n");
			return -EINVAL;
		}
		for (ts = 0; ts < 8; ts++) {
			if ((rx_window & (1 << ts))) {
				/* be sure to select a single downlink slots
				 * that can be used for uplink, if multiple
				 * slots are assigned later. */
				if (single && first_common_ts != ts)
					continue;
				LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning DL TS "
					"%d\n", ts);
				pdch = &tbf->trx->pdch[ts];
				assign_dlink_tbf(pdch, tbf);
				slotcount++;
				if (slotcount == 1)
					tbf->first_ts = ts;
				if (single)
					break;
			}
		}
	} else {
		/* assign uplink */
		if (tx_window == 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No uplink slots "
				"available\n");
			return -EINVAL;
		}
		for (ts = 0; ts < 8; ts++) {
			if ((tx_window & (1 << ts))) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning UL TS "
					"%d\n", ts);
				pdch = &tbf->trx->pdch[ts];
				assign_uplink_tbf_usf(pdch, tbf, usf[ts]);
				slotcount++;
				if (slotcount == 1)
					tbf->first_ts = ts;
				if (single)
					break;
			}
		}
	}
	if (single && slotcount) {
		LOGP(DRLCMAC, LOGL_INFO, "Using single slot at TS %d for %s\n",
			tbf->first_ts,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	} else {
		LOGP(DRLCMAC, LOGL_INFO, "Using %d slots for %s\n", slotcount,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	}
	if (slotcount == 0)
		return -EBUSY;

	tbf->first_common_ts = first_common_ts;

	return 0;
}
