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
	struct gprs_rlcmac_ul_tbf *tbf;
	uint8_t usf_map = 0;
	uint8_t tfi, usf;

	/* make map of used USF */
	for (tfi = 0; tfi < 32; tfi++) {
		tbf = pdch->ul_tbf_by_tfi(tfi);
		if (!tbf)
			continue;
		usf_map |= (1 << tbf->m_usf[pdch->ts_no]);
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
	attach_tbf_to_pdch(pdch, tbf);
	tbf->m_usf[pdch->ts_no] = usf;
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
	uint8_t ts;

	LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm A) for class "
		"%d\n", tbf->ms_class());

	ts = find_enabled_pdch(tbf->trx, 0);
	if (ts == 8)
		return -EINVAL;

	pdch = &tbf->trx->pdch[ts];
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		int8_t usf; /* must be signed */
		struct gprs_rlcmac_ul_tbf *ul_tbf = static_cast<gprs_rlcmac_ul_tbf *>(tbf);

		/* if USF available */
		usf = find_free_usf(pdch);
		if (usf < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
				"allocating TS=%d, no USF available\n", ts);
			return -EBUSY;
		}
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign uplink "
			"TS=%d USF=%d\n", ts, usf);
		assign_uplink_tbf_usf(pdch, ul_tbf, usf);
	} else {
		struct gprs_rlcmac_dl_tbf *dl_tbf = static_cast<gprs_rlcmac_dl_tbf *>(tbf);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Assign downlink TS=%d\n", ts);
		assign_dlink_tbf(pdch, dl_tbf);
	}
	/* the only one TS is the common TS */
	tbf->first_ts = tbf->first_common_ts = ts;

	tbf->upgrade_to_multislot = 0;

	return 0;
}

/*
 * Select a window of Rx slots if available.
 * The maximum allowed slots depend on RX or the window of available
 * slots. This must be done for uplink TBF also, because it is the basis
 * for calculating control slot and uplink slot(s).
 */
static uint8_t select_dl_slots(struct gprs_rlcmac_trx *trx,
			const int ms_type, const int ms_max_rxslots,
			uint8_t *out_rx_win_min, uint8_t *out_rx_win_max)

{
	uint8_t rx_window = 0;
	int rx_window_size = 0;
	int8_t last_tsc = -1; /* must be signed */
	uint8_t rx_win_min = 0, rx_win_max = 0;

	for (int ts_no = 0; ts_no < 8; ts_no++) {
		struct gprs_rlcmac_pdch *pdch;
		pdch = &trx->pdch[ts_no];

		/* check if enabled */
		if (!pdch->is_enabled()) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, because "
				"not enabled\n", ts_no);
			if (ms_type == 1 && rx_window)
				goto inc_window;
			continue;
		}
		/* check if TSC changes */
		if (last_tsc < 0)
			last_tsc = pdch->tsc;
		else if (last_tsc != pdch->tsc) {
			LOGP(DRLCMAC, LOGL_ERROR, "Skipping TS %d of TRX=%d, "
				"because it has different TSC than lower TS "
				"of TRX. In order to allow multislot, all "
				"slots must be configured with the same "
				"TSC!\n", ts_no, trx->trx_no);
			if (ms_type == 1 && rx_window)
				goto inc_window;
			continue;
		}

		if (!rx_window)
			rx_win_min = ts_no;

		rx_window |= (1 << ts_no);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Selected DL TS %d\n", ts_no);

		/* range of window (required for Type 1) */
		rx_win_max = ts_no;

inc_window:
		if (++rx_window_size == ms_max_rxslots) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because slots / "
				"window reached maximum alowed Rx size\n");
			break;
		}
		if (ms_type == 1 && rx_window_size == 5) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because slots / "
				"window reached maximum supported Rx size of "
				"this algorithm\n");
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

	*out_rx_win_min = rx_win_min;
	*out_rx_win_max = rx_win_max;
	return rx_window;
}

static int reduce_rx_window(const int ms_type, const GprsMs *ms,
				const int Tt, const int Tr,
				int *rx_window,
				uint8_t *rx_win_min, uint8_t *rx_win_max)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	if (ms_type != 1)
		return 0;
	if (!ms)
		return 0;

	ul_tbf = ms->ul_tbf();

	if (!ul_tbf)
		return 0;

	uint8_t collide = 0, ul_usage = 0;

	/* calculate mask of colliding slots */
	for (uint8_t ts_no = 0; ts_no < 8; ts_no++) {
		int j;
		if (!ul_tbf->pdch[ts_no])
			continue;

		ul_usage |= (1 << ts_no);
		/* mark bits from TS-t .. TS+r */
		for (j = (ts_no - Tt) & 7; j != ((ts_no + Tr + 1) & 7); j = (j + 1) & 7)
			collide |= (1 << j);
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

	/*
	 * Uplink/Downlink in GSM is shifted by three timeslots. Make
	 * sure they don't collide.
	 */
	*rx_window &= ~(collide << 3);
	*rx_window &= ~(collide >> 5);
	LOGP(DRLCMAC, LOGL_DEBUG, "- Remaining slots for RX: "
		"(TS=0)\"%c%c%c%c%c%c%c%c\"(TS=7)\n",
		((*rx_window & 0x01)) ? 'D' : '.',
		((*rx_window & 0x02)) ? 'D' : '.',
		((*rx_window & 0x04)) ? 'D' : '.',
		((*rx_window & 0x08)) ? 'D' : '.',
		((*rx_window & 0x10)) ? 'D' : '.',
		((*rx_window & 0x20)) ? 'D' : '.',
		((*rx_window & 0x40)) ? 'D' : '.',
		((*rx_window & 0x80)) ? 'D' : '.');

	if (!*rx_window) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No suitable downlink slots "
			"available with current uplink assignment\n");
		return -EBUSY;
	}

	return 0;
}

/* shrink range of rx_win_min and rx_win_max */
static void shrink_rx_window(uint8_t *rx_win_min, uint8_t *rx_win_max, int rx_window)
{
	/* calculate new min/max */
	for (uint8_t ts_no = *rx_win_min; ts_no <= *rx_win_max; ts_no++) {
		if ((rx_window & (1 << ts_no)))
			break;
		*rx_win_min = ts_no + 1;
		LOGP(DRLCMAC, LOGL_DEBUG, "- TS is unused, so "
			"raising start of DL window to %d\n",
			*rx_win_min);
	}
	for (uint8_t ts_no = *rx_win_max; ts_no >= *rx_win_min; ts_no--) {
		if ((rx_window & (1 << ts_no)))
			break;
		*rx_win_max = ts_no - 1;
		LOGP(DRLCMAC, LOGL_DEBUG, "- TS is unused, so "
			"lowering end of DL window to %d\n",
			*rx_win_max);
	}
}

/*
 * reduce window, to allow at least one uplink TX slot
 * this is only required for Type 1
 */
static uint8_t update_rx_win_max(const int ms_type, const int Tt,
			const int Tr, uint8_t rx_win_min, uint8_t rx_win_max)
{
	if (ms_type != 1)
		return rx_win_max;

	if (rx_win_max - rx_win_min + 1 + Tt + 1 + Tr > 8) {
		rx_win_max = rx_win_min + 7 - Tt - 1 - Tr;
		LOGP(DRLCMAC, LOGL_DEBUG, "- Reduce RX window due to time "
			"contraints to %d slots\n", rx_win_max - rx_win_min + 1);
	}

	return rx_win_max;
}

static void tx_win_from_rx(const int ms_type,
				uint8_t rx_win_min, uint8_t rx_win_max,
				int Tt, int Tr,
				uint8_t *tx_win_min, uint8_t *tx_win_max,
				uint8_t *tx_range)
{
	if (ms_type == 1) {
		/* calculate TX window (shifted by 3 timeslots)
		 * it uses the space between tx_win_max and tx_win_min */
		*tx_win_min = (rx_win_max - 2 + Tt) & 7;
		*tx_win_max = (rx_win_min + 4 - Tr) & 7;
	} else {
		/* TX and RX simultaniously */
		*tx_win_min = rx_win_min;
		*tx_win_max = 7;
	}

	*tx_range = (*tx_win_max - *tx_win_min + 1) & 7;
	/* if TX window fills complete range */
	if (*tx_range == 0)
		*tx_range = 8;
	LOGP(DRLCMAC, LOGL_DEBUG, "- TX-Window is: %d..%d\n", *tx_win_min,
		*tx_win_max);
}

/*
 * Select a window of Tx slots if available.
 * The maximum allowed slots depend on TX or the window of available
 * slots.
 */
static int select_ul_slots(gprs_rlcmac_trx *trx,
		const int ms_type, const int ms_max_txslots,
		uint8_t tx_win_min, uint8_t tx_range,
		int8_t *usf, int8_t *first_common_ts, uint8_t rx_window)
{
	int tsc = -1;
	uint8_t tx_window = 0;
	int i;
	uint8_t ts_no;

	for (ts_no = tx_win_min, i = 0; i < tx_range; ts_no = (ts_no + 1) & 7, i++) {
		gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];

		/* check if enabled */
		if (!pdch->is_enabled()) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
				"because not enabled\n", ts_no);
			if (ms_type == 1 && tx_window)
				goto inc_window;
			continue;
		}
		/* check if used as downlink */
		if (!(rx_window & (1 << ts_no))) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
				"because not a downlink slot\n", ts_no);
			if (ms_type == 1 && tx_window)
				goto inc_window;
			continue;
		}
		/* check if TSC changes */
		if (tsc < 0)
			tsc = pdch->tsc;
		else if (tsc != pdch->tsc) {
			LOGP(DRLCMAC, LOGL_ERROR, "Skipping TS %d of "
				"TRX=%d, because it has different TSC "
				"than lower TS of TRX. In order to "
				"allow multislot, all slots must be "
				"configured with the same TSC!\n",
				ts_no, trx->trx_no);
			if (ms_type == 1)
				goto inc_window;
			continue;
		}
		/* check for free usf */
		usf[ts_no] = find_free_usf(pdch);
		if (usf[ts_no] < 0) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
			"because no USF available\n", ts_no);
			if (ms_type == 1)
				goto inc_window;
			continue;
		}

		if (!tx_window)
			*first_common_ts = ts_no;

		tx_window |= (1 << ts_no);
		LOGP(DRLCMAC, LOGL_DEBUG, "- Selected UL TS %d\n", ts_no);

inc_window:
		if (1 && ms_type == 1) { /* FIXME: multislot UL assignment */
			LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because "
				"1 slot assigned\n");
			break;
		}
		if (i+1 == ms_max_txslots) {
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

	return tx_window;
}

/*
 * Assign the first common ts, which is used for control or
 * single slot.
 */
static int select_first_ts(gprs_rlcmac_trx *trx, uint8_t tx_win_min,
	uint8_t tx_range, uint8_t rx_window)
{
	uint8_t ts_no;
	int i;
	for (ts_no = tx_win_min, i = 0; i < tx_range; ts_no = (ts_no + 1) & 7, i++) {
		gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];
		/* check if enabled */
		if (!pdch->is_enabled()) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
					"because not enabled\n", ts_no);
			continue;
		}
		/* check if used as downlink */
		if (!(rx_window & (1 << ts_no))) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
				"because not a downlink slot\n", ts_no);
			continue;
		}
		return ts_no;
	}

	return -1;
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
	const struct gprs_ms_multislot_class *ms_class;
	uint8_t Tx, Sum;	/* Maximum Number of Slots: RX, Tx, Sum Rx+Tx */
	uint8_t Tta, Ttb, Tra, Trb, Tt, Tr;	/* Minimum Number of Slots */
	uint8_t Type; /* Type of Mobile */
	int rx_window;
	static const char *digit[10] = { "0","1","2","3","4","5","6","7","8","9" };
	int8_t usf[8] = { -1, -1, -1, -1, -1, -1, -1, -1 }; /* must be signed */
	int8_t first_common_ts = -1;
	uint8_t ts;
	uint8_t slotcount = 0;


	if (tbf->ms_class() >= 32) {
		LOGP(DRLCMAC, LOGL_ERROR, "Multislot class %d out of range.\n",
			tbf->ms_class());
		return -EINVAL;
	}

	if (tbf->ms_class()) {
		ms_class = &gprs_ms_multislot_class[tbf->ms_class()];
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for "
			"class %d\n", tbf->ms_class());
	} else {
		ms_class = &gprs_ms_multislot_class[12];
		LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for "
			"unknow class (assuming 12)\n");
	}

	if (ms_class->tx == MS_NA) {
		LOGP(DRLCMAC, LOGL_NOTICE, "Multislot class %d not "
			"applicable.\n", tbf->ms_class());
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
	if (Ttb == MS_A || Ttb == MS_B)
		Ttb = 0;
	if (Trb == MS_A || Trb == MS_C)
		Trb = 0;

	LOGP(DRLCMAC, LOGL_DEBUG, "- Rx=%d Tx=%d Sum Rx+Tx=%s  Tta=%s Ttb=%d "
		" Tra=%d Trb=%d Type=%d\n", ms_class->rx, Tx,
		(Sum == MS_NA) ? "N/A" : digit[Sum],
		(Tta == MS_NA) ? "N/A" : digit[Tta], Ttb, Tra, Trb, Type);

	/* select the values for time contraints */
	/* applicable to type 1 and type 2 */
	Tt = Ttb;
	Tr = Trb;

	uint8_t rx_win_min, rx_win_max;
	rx_window = select_dl_slots(tbf->trx, ms_class->type, ms_class->rx,
				&rx_win_min, &rx_win_max);


	/* reduce window, if existing uplink slots collide RX window */
	int rc = reduce_rx_window(ms_class->type, ms, Tt, Tr,
				&rx_window, &rx_win_min, &rx_win_max);
	if (rc < 0)
		return rc;
	shrink_rx_window(&rx_win_min, &rx_win_max, rx_window);
	rx_win_max = update_rx_win_max(ms_class->type, Tt, Tr,
				rx_win_min, rx_win_max);
	shrink_rx_window(&rx_win_min, &rx_win_max, rx_window);
	LOGP(DRLCMAC, LOGL_DEBUG, "- RX-Window is: %d..%d\n", rx_win_min,
		rx_win_max);

	/* calculate TX window */
	uint8_t tx_win_min, tx_win_max, tx_range;
	tx_win_from_rx(ms_class->type, rx_win_min, rx_win_max, Tt, Tr,
				&tx_win_min, &tx_win_max, &tx_range);

	/* select UL slots but in both cases assign first_common_ts */
	uint8_t tx_window = 0;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		rc = select_ul_slots(tbf->trx, ms_class->type, ms_class->tx,
					tx_win_min, tx_range, usf,
					&first_common_ts, rx_window);
		if (rc < 0)
			return rc;
		tx_window = rc;
	} else {
		first_common_ts = select_first_ts(tbf->trx, tx_win_min,
					tx_range, rx_window);
	}
	#warning "first_common_ts might be different if there was no free USF for the new uplink assignment"

	if (first_common_ts < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No first common slots available\n");
		return -EINVAL;
	}

	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		struct gprs_rlcmac_dl_tbf *dl_tbf = static_cast<gprs_rlcmac_dl_tbf *>(tbf);
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
				assign_dlink_tbf(&tbf->trx->pdch[ts], dl_tbf);
				slotcount++;
				if (slotcount == 1)
					dl_tbf->first_ts = ts;
				if (single)
					break;
			}
		}
	} else {
		struct gprs_rlcmac_ul_tbf *ul_tbf = static_cast<gprs_rlcmac_ul_tbf *>(tbf);
		for (ts = 0; ts < 8; ts++) {
			if ((tx_window & (1 << ts))) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning UL TS "
					"%d\n", ts);
				assign_uplink_tbf_usf(&tbf->trx->pdch[ts], ul_tbf, usf[ts]);
				slotcount++;
				if (slotcount == 1)
					ul_tbf->first_ts = ts;
				if (single)
					break;
			}
		}
	}
	if (single && slotcount) {
		uint8_t ts_count = 0;
		for (ts = 0; ts < 8; ts++)
			if ((tx_window & (1 << ts)))
				ts_count++;

		tbf->upgrade_to_multislot = (ts_count > 1);
		LOGP(DRLCMAC, LOGL_INFO, "Using single slot at TS %d for %s\n",
			tbf->first_ts,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	} else {
		tbf->upgrade_to_multislot = 0;
		LOGP(DRLCMAC, LOGL_INFO, "Using %d slots for %s\n", slotcount,
			(tbf->direction == GPRS_RLCMAC_DL_TBF) ? "DL" : "UL");
	}
	if (slotcount == 0)
		return -EBUSY;

	tbf->first_common_ts = first_common_ts;

	return 0;
}
