/* gprs_rlcmac.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>

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

struct gprs_ms_multislot_class gprs_ms_multislot_class[32] = {
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

LLIST_HEAD(gprs_rlcmac_ul_tbfs);
LLIST_HEAD(gprs_rlcmac_dl_tbfs);
llist_head *gprs_rlcmac_tbfs_lists[] = {
	&gprs_rlcmac_ul_tbfs,
	&gprs_rlcmac_dl_tbfs,
	NULL
};
extern void *tall_pcu_ctx;

/* FIXME: spread ressources over multiple TRX. Also add option to use same
 * TRX in case of existing TBF for TLLI in the other direction. */
/* search for free TFI and return TFI, TRX and first TS */
int tfi_alloc(enum gprs_rlcmac_tbf_direction dir, uint8_t *_trx, uint8_t *_ts,
	int8_t use_trx, int8_t first_ts)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf **tbfp;
	uint8_t trx_from, trx_to, trx, ts, tfi;

	if (use_trx >= 0 && use_trx < 8)
		trx_from = trx_to = use_trx;
	else {
		trx_from = 0;
		trx_to = 7;
	}
	if (first_ts < 0 || first_ts >= 8)
		first_ts = 0;

	/* on TRX find first enabled TS */
	for (trx = trx_from; trx <= trx_to; trx++) {
		for (ts = first_ts; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->enable)
				continue;
			break;
		}
		if (ts < 8)
			break;
	}
	if (trx > trx_to) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		return -EINVAL;
	}


	LOGP(DRLCMAC, LOGL_DEBUG, "Searching for first unallocated TFI: "
		"TRX=%d first TS=%d\n", trx, ts);
	if (dir == GPRS_RLCMAC_UL_TBF)
		tbfp = pdch->ul_tbf;
	else
		tbfp = pdch->dl_tbf;
	for (tfi = 0; tfi < 32; tfi++) {
		if (!tbfp[tfi])
			break;
	}
	
	if (tfi < 32) {
		LOGP(DRLCMAC, LOGL_DEBUG, " Found TFI=%d.\n", tfi);
		*_trx = trx;
		*_ts = ts;
		return tfi;
	}
	LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available.\n");

	return -1;
}

static inline int8_t find_free_usf(struct gprs_rlcmac_pdch *pdch, uint8_t ts)
{
	struct gprs_rlcmac_tbf *tbf;
	uint8_t usf_map = 0;
	uint8_t tfi, usf;

	/* make map of used USF */
	for (tfi = 0; tfi < 32; tfi++) {
		tbf = pdch->ul_tbf[tfi];
		if (!tbf)
			continue;
		usf_map |= (1 << tbf->dir.ul.usf[ts]);
	}

	/* look for USF, don't use USF=7 */
	for (usf = 0; usf < 7; usf++) {
		if (!(usf_map & (1 << usf)))
			return usf;
	}

	return -1;
}

/* lookup TBF Entity (by TFI) */
struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi, uint8_t trx, uint8_t ts,
	enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

	if (tfi >= 32 || trx >= 8 || ts >= 8)
		return NULL;

	if (dir == GPRS_RLCMAC_UL_TBF)
		tbf = bts->trx[trx].pdch[ts].ul_tbf[tfi];
	else
		tbf = bts->trx[trx].pdch[ts].dl_tbf[tfi];
	if (!tbf)
		return NULL;

	if (tbf->state != GPRS_RLCMAC_RELEASING)
			return tbf;

	return NULL;
}

/* search for active downlink or uplink tbf */
struct gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli,
	enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;
	if (dir == GPRS_RLCMAC_UL_TBF) {
		llist_for_each_entry(tbf, &gprs_rlcmac_ul_tbfs, list) {
			if (tbf->state != GPRS_RLCMAC_RELEASING
			 && tbf->tlli == tlli && tbf->tlli_valid)
				return tbf;
		}
	} else {
		llist_for_each_entry(tbf, &gprs_rlcmac_dl_tbfs, list) {
			if (tbf->state != GPRS_RLCMAC_RELEASING
			 && tbf->tlli == tlli)
				return tbf;
		}
	}
	return NULL;
}

struct gprs_rlcmac_tbf *tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_tbf *tbf;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each_entry(tbf, &gprs_rlcmac_ul_tbfs, list) {
		if (tbf->state != GPRS_RLCMAC_RELEASING
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn && tbf->trx == trx
		 && tbf->control_ts == ts)
			return tbf;
	}
	llist_for_each_entry(tbf, &gprs_rlcmac_dl_tbfs, list) {
		if (tbf->state != GPRS_RLCMAC_RELEASING
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn && tbf->trx == trx
		 && tbf->control_ts == ts)
			return tbf;
	}
	return NULL;
}

struct gprs_rlcmac_tbf *tbf_alloc(struct gprs_rlcmac_tbf *old_tbf,
	enum gprs_rlcmac_tbf_direction dir, uint8_t tfi, uint8_t trx,
	uint8_t first_ts, uint8_t ms_class, uint8_t single_slot)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_tbf *tbf;
	int rc;

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF starts here **********\n");
	LOGP(DRLCMAC, LOGL_INFO, "Allocating %s TBF: TFI=%d TRX=%d "
		"MS_CLASS=%d\n", (dir == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
		tfi, trx, ms_class);

	if (trx >= 8 || first_ts >= 8 || tfi >= 32)
		return NULL;

	tbf = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_tbf);
	if (!tbf)
		return NULL;

	tbf->direction = dir;
	tbf->tfi = tfi;
	tbf->trx = trx;
	tbf->arfcn = bts->trx[trx].arfcn;
	tbf->first_ts = first_ts;
	tbf->ms_class = ms_class;
	tbf->ws = 64;
	tbf->sns = 128;
	/* select algorithm A in case we don't have multislot class info */
	if (single_slot || ms_class == 0)
		rc = alloc_algorithm_a(old_tbf, tbf,
			bts->alloc_algorithm_curst);
	else
		rc = bts->alloc_algorithm(old_tbf, tbf,
			bts->alloc_algorithm_curst);
	/* if no ressource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}
	/* assign control ts */
	tbf->control_ts = 0xff;
	rc = tbf_assign_control_ts(tbf);
	/* if no ressource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}

	/* set timestamp */
	gettimeofday(&tbf->bw_tv, NULL);

	INIT_LLIST_HEAD(&tbf->llc_queue);
	if (dir == GPRS_RLCMAC_UL_TBF)
		llist_add(&tbf->list, &gprs_rlcmac_ul_tbfs);
	else
		llist_add(&tbf->list, &gprs_rlcmac_dl_tbfs);

	return tbf;
}

/* Slot Allocation: Algorithm A
 *
 * Assign single slot for uplink and downlink
 */
int alloc_algorithm_a(struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	uint8_t ts = tbf->first_ts;
	int8_t usf; /* must be signed */

	LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm A) for class "
		"%d\n", tbf->ms_class);

	pdch = &bts->trx[tbf->trx].pdch[ts];
	if (!pdch->enable) {
		LOGP(DRLCMAC, LOGL_ERROR, "TS=%d not enabled.", ts);
			return -EIO;
	}
	tbf->tsc = pdch->tsc;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		/* if TFI is free on TS */
		if (!pdch->ul_tbf[tbf->tfi]) {
			/* if USF available */
			usf = find_free_usf(pdch, ts);
			if (usf >= 0) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Assign uplink "
					"TS=%d USF=%d\n", ts, usf);
				pdch->ul_tbf[tbf->tfi] = tbf;
				tbf->pdch[ts] = pdch;
			} else {
				LOGP(DRLCMAC, LOGL_NOTICE, "- Failed "
					"allocating TS=%d, no USF available\n",
					ts);
				return -EBUSY;
			}
		} else {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Failed allocating "
				"TS=%d, TFI is not available\n", ts);
			return -EBUSY;
		}
	} else {
		/* if TFI is free on TS */
		if (!pdch->dl_tbf[tbf->tfi]) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Assign downlink TS=%d\n",
				ts);
			pdch->dl_tbf[tbf->tfi] = tbf;
			tbf->pdch[ts] = pdch;
		} else {
			LOGP(DRLCMAC, LOGL_NOTICE, "- Failed allocating "
				"TS=%d, TFI is not available\n", ts);
			return -EBUSY;
		}
	}
	/* the only one TS is the common TS */
	tbf->first_common_ts = ts;

	return 0;
}

/* Slot Allocation: Algorithm B
 *
 * Assign as many downlink slots as possible.
 * Assign one uplink slot. (With free USF)
 *
 */
int alloc_algorithm_b(struct gprs_rlcmac_tbf *old_tbf,
	struct gprs_rlcmac_tbf *tbf, uint32_t cust)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_ms_multislot_class *ms_class;
	uint8_t Rx, Tx, Sum;	/* Maximum Number of Slots: RX, Tx, Sum Rx+Tx */
	uint8_t Tta, Ttb, Tra, Trb, Tt, Tr;	/* Minimum Number of Slots */
	uint8_t Type; /* Type of Mobile */
	uint8_t rx_win_min, rx_win_max;
	uint8_t tx_win_min, tx_win_max, tx_range;
	uint8_t rx_window = 0, tx_window = 0;
	const char *digit[10] = { "0","1","2","3","4","5","6","7","8","9" };
	int8_t usf[8] = { -1, -1, -1, -1, -1, -1, -1, -1 }; /* must be signed */
	int8_t tsc = -1; /* must be signed */
	uint8_t i, ts;

	LOGP(DRLCMAC, LOGL_DEBUG, "Slot Allocation (Algorithm B) for class "
		"%d\n", tbf->ms_class);

	if (tbf->ms_class >= 32) {
		LOGP(DRLCMAC, LOGL_ERROR, "Multislot class %d out of range.\n",
			tbf->ms_class);
		return -EINVAL;
	}

	ms_class = &gprs_ms_multislot_class[tbf->ms_class];
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
	if (Ttb == MS_A) {
		if (/* FIXME: hopping*/ 0)
			Ttb = 1;
		else
			Ttb = 0;
	}
	if (Trb == MS_A) {
		if (/* FIXME: hopping*/ 0)
			Ttb = 1;
		else
			Ttb = 0;
	}
	if (Ttb == MS_B) {
		/* FIXME: or frequency change */
		if (/* FIXME: hopping*/ 0)
			Ttb = 1;
		else
			Ttb = 0;
	}
	if (Trb == MS_C) {
		/* FIXME: or frequency change */
		if (/* FIXME: hopping*/ 0)
			Ttb = 1;
		else
			Ttb = 0;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "- Rx=%d Tx=%d Sum Rx+Tx=%s  Tta=%s Ttb=%d "
		" Tra=%d Trb=%d Type=%d\n", Rx, Tx,
		(Sum == MS_NA) ? "N/A" : digit[Sum],
		(Tta == MS_NA) ? "N/A" : digit[Tta], Ttb, Tra, Trb, Type);

	/* select the values for time contraints */
	if (/* FIXME: monitoring */0) {	
		/* applicable to type 1 and type 2 */
		Tt = Ttb;
		Tr = Tra;
	} else {
		/* applicable to type 1 and type 2 */
		Tt = Ttb;
		Tr = Trb;
	}

	/* select a window of Rx slots if available
	 * The maximum allowed slots depend on RX or the window of available
	 * slots.
	 * This must be done for uplink TBF also, because it is the basis
	 * for calculating control slot and uplink slot(s). */
	rx_win_min = rx_win_max = tbf->first_ts;
	for (ts = tbf->first_ts, i = 0; ts < 8; ts++) {
		pdch = &bts->trx[tbf->trx].pdch[ts];
		/* check if enabled */
		if (!pdch->enable) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, because "
				"not enabled\n", ts);
			/* increase window for Type 1 */
			if (Type == 1)
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
				"TSC!\n", ts, tbf->trx);
			/* increase window for Type 1 */
			if (Type == 1)
				i++;
			continue;
		}
		/* check if TFI for slot is available
		 * This is only possible for downlink TFI. */
		if (tbf->direction == GPRS_RLCMAC_DL_TBF
		 && pdch->dl_tbf[tbf->tfi]) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, because "
				"already assigned to other DL TBF with "
				"TFI=%d\n", ts, tbf->tfi);
			/* increase window for Type 1 */
			if (Type == 1)
				i++;
			continue;
		}

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
		for (ts = old_tbf->first_ts; ts < 8; ts++) {
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

		/* apply massk to reduce tx_window (shifted by 3 slots) */
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
		rx_win_max = rx_win_min + 7 - Tr - 1 - Tr;
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
	 * slots. */
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		for (ts = tx_win_min, i = 0; i < tx_range; ts = (ts + 1) & 7) {
			pdch = &bts->trx[tbf->trx].pdch[ts];
			/* check if enabled */
			if (!pdch->enable) {
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
					ts, tbf->trx);
				/* increase window for Type 1 */
				if (Type == 1)
					i++;
				continue;
			}
			/* check if TFI for slot is available */
			if (pdch->ul_tbf[tbf->tfi]) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
					"because already assigned to other "
					"UL TBF with TFI=%d\n", ts, tbf->tfi);
				/* increase window for Type 1 */
				if (Type == 1)
					i++;
				continue;
			}
			/* check for free usf */
			usf[ts] = find_free_usf(pdch, ts);
			if (usf[ts] < 0) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Skipping TS %d, "
					"because no USF available\n", ts);
				/* increase window for Type 1 */
				if (Type == 1)
					i++;
				continue;
			}

			tx_window |= (1 << ts);
			LOGP(DRLCMAC, LOGL_DEBUG, "- Selected UL TS %d\n", ts);

			if (!(cust & 1)) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because "
					"1 slot assigned\n");
				break;
			}
			if (++i == Tx) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Done, because "
					"slots / window reached maximum alowed "
					"Tx size\n");
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
	}

	if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
		uint8_t slotcount = 0;

		/* assign downlink */
		if (rx_window == 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No downlink slots "
				"available\n");
			return -EINVAL;
		}
		for (ts = 0; ts < 8; ts++) {
			if ((rx_window & (1 << ts))) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- Assigning DL TS "
					"%d\n", ts);
				pdch = &bts->trx[tbf->trx].pdch[ts];
				pdch->dl_tbf[tbf->tfi] = tbf;
				tbf->pdch[ts] = pdch;
				slotcount++;
			}
		}
		if (slotcount)
			LOGP(DRLCMAC, LOGL_INFO, "Using Multislot with %d "
				"slots DL\n", slotcount);
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
				pdch = &bts->trx[tbf->trx].pdch[ts];
				pdch->ul_tbf[tbf->tfi] = tbf;
				tbf->pdch[ts] = pdch;
				tbf->dir.ul.usf[ts] = usf[ts];
			}
		}
	}

	/* the timeslot of the TX window start is always
	 * available in RX window */
	tbf->first_common_ts = tx_win_min;

	return 0;
}

static void tbf_unlink_pdch(struct gprs_rlcmac_tbf *tbf)
{
	struct gprs_rlcmac_pdch *pdch;
	int ts;

	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		for (ts = 0; ts < 8; ts++) {
			pdch = tbf->pdch[ts];
			if (pdch)
				pdch->ul_tbf[tbf->tfi] = NULL;
			tbf->pdch[ts] = NULL;
		}
	} else {
		for (ts = 0; ts < 8; ts++) {
			pdch = tbf->pdch[ts];
			if (pdch)
				pdch->dl_tbf[tbf->tfi] = NULL;
			tbf->pdch[ts] = NULL;
		}
	}
}

void tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	struct msgb *msg;

	LOGP(DRLCMAC, LOGL_INFO, "Free %s TBF=%d with TLLI=0x%08x.\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi,
		tbf->tlli);
	if (tbf->ul_ass_state != GPRS_RLCMAC_UL_ASS_NONE)
		LOGP(DRLCMAC, LOGL_ERROR, "Software error: Pending uplink "
			"assignment. This may not happen, because the "
			"assignment message never gets transmitted. Please "
			"be shure not to free in this state. PLEASE FIX!\n");
	if (tbf->dl_ass_state != GPRS_RLCMAC_DL_ASS_NONE)
		LOGP(DRLCMAC, LOGL_ERROR, "Software error: Pending downlink "
			"assignment. This may not happen, because the "
			"assignment message never gets transmitted. Please "
			"be shure not to free in this state. PLEASE FIX!\n");
	tbf_timer_stop(tbf);
	while ((msg = msgb_dequeue(&tbf->llc_queue)))
		msgb_free(msg);
	tbf_unlink_pdch(tbf);
	llist_del(&tbf->list);
	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF ends here **********\n");
	talloc_free(tbf);
}

int tbf_update(struct gprs_rlcmac_tbf *tbf)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_tbf *ul_tbf = NULL;
	int rc;

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF update **********\n");

	if (tbf->direction != GPRS_RLCMAC_DL_TBF)
		return -EINVAL;

	if (!tbf->ms_class) {
		LOGP(DRLCMAC, LOGL_DEBUG, "- Cannot update, no class\n");
		return -EINVAL;
	}

	ul_tbf = tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF);

	tbf_unlink_pdch(tbf);
	rc = bts->alloc_algorithm(ul_tbf, tbf, bts->alloc_algorithm_curst);
	/* if no ressource */
	if (rc < 0) {
		LOGP(DRLCMAC, LOGL_ERROR, "No ressource after update???\n");
		return -rc;
	}

	return 0;
}

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->control_ts == 0xff)
		LOGP(DRLCMAC, LOGL_DEBUG, "- Setting Control TS %d\n",
			tbf->first_common_ts);
	else if (tbf->control_ts != tbf->first_common_ts)
		LOGP(DRLCMAC, LOGL_DEBUG, "- Changing Control TS %d\n",
			tbf->first_common_ts);
	tbf->control_ts = tbf->first_common_ts;

	return 0;
}


const char *tbf_state_name[] = {
	"NULL",
	"ASSIGN",
	"FLOW",
	"FINISHED",
	"WAIT RELEASE",
	"RELEASING",
};

void tbf_new_state(struct gprs_rlcmac_tbf *tbf,
	enum gprs_rlcmac_tbf_state state)
{
	LOGP(DRLCMAC, LOGL_DEBUG, "%s TBF=%d changes state from %s to %s\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi,
		tbf_state_name[tbf->state], tbf_state_name[state]);
	tbf->state = state;
}

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
			unsigned int seconds, unsigned int microseconds)
{
	if (!osmo_timer_pending(&tbf->timer))
		LOGP(DRLCMAC, LOGL_DEBUG, "Starting %s TBF=%d timer %u.\n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			tbf->tfi, T);
	else
		LOGP(DRLCMAC, LOGL_DEBUG, "Restarting %s TBF=%d timer %u "
			"while old timer %u pending \n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			tbf->tfi, T, tbf->T);

	tbf->T = T;
	tbf->num_T_exp = 0;

	/* Tunning timers can be safely re-scheduled. */
	tbf->timer.data = tbf;
	tbf->timer.cb = &tbf_timer_cb;

	osmo_timer_schedule(&tbf->timer, seconds, microseconds);
}

void tbf_timer_stop(struct gprs_rlcmac_tbf *tbf)
{
	if (osmo_timer_pending(&tbf->timer)) {
		LOGP(DRLCMAC, LOGL_DEBUG, "Stopping %s TBF=%d timer %u.\n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			tbf->tfi, tbf->T);
		osmo_timer_del(&tbf->timer);
	}
}

/* starting time for assigning single slot
 * This offset must be a multiple of 13. */
#define AGCH_START_OFFSET 52

LLIST_HEAD(gprs_rlcmac_sbas);

int sba_alloc(uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta)
{

	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_sba *sba;
	uint8_t trx, ts;
	uint32_t fn;

	sba = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_sba);
	if (!sba)
		return -ENOMEM;

	for (trx = 0; trx < 8; trx++) {
		for (ts = 0; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->enable)
				continue;
			break;
		}
		if (ts < 8)
			break;
	}
	if (trx == 8) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		return -EINVAL;
	}

	fn = (pdch->last_rts_fn + AGCH_START_OFFSET) % 2715648;

	sba->trx = trx;
	sba->ts = ts;
	sba->fn = fn;
	sba->ta = ta;

	llist_add(&sba->list, &gprs_rlcmac_sbas);

	*_trx = trx;
	*_ts = ts;
	*_fn = fn;
	return 0;
}

struct gprs_rlcmac_sba *sba_find(uint8_t trx, uint8_t ts, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	llist_for_each_entry(sba, &gprs_rlcmac_sbas, list) {
		if (sba->trx == trx && sba->ts == ts && sba->fn == fn)
			return sba;
	}

	return NULL;
}

#if 0
static void tbf_gsm_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	tbf->num_fT_exp++;

	switch (tbf->fT) {
	case 0:
hier alles berdenken
		// This is timer for delay RLC/MAC data sending after Downlink Immediate Assignment on CCCH.
		gprs_rlcmac_segment_llc_pdu(tbf);
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] END TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
		tbf_free(tbf);
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Timer expired in unknown mode: %u \n", tbf->fT);
	}
}

static void tbf_gsm_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int fT,
				int frames)
{
	if (osmo_gsm_timer_pending(&tbf->gsm_timer))
		LOGP(DRLCMAC, LOGL_NOTICE, "Starting TBF timer %u while old timer %u pending \n", fT, tbf->fT);
	tbf->fT = fT;
	tbf->num_fT_exp = 0;

	/* FIXME: we should do this only once ? */
	tbf->gsm_timer.data = tbf;
	tbf->gsm_timer.cb = &tbf_gsm_timer_cb;

	osmo_gsm_timer_schedule(&tbf->gsm_timer, frames);
}

eine stop-funktion, auch im tbf_free aufrufen

#endif

#if 0
void gprs_rlcmac_enqueue_block(bitvec *block, int len)
{
	struct msgb *msg = msgb_alloc(len, "rlcmac_dl");
	bitvec_pack(block, msgb_put(msg, len));
	msgb_enqueue(&block_queue, msg);
}
#endif

/* received RLC/MAC block from L1 */
int gprs_rlcmac_rcv_block(uint8_t trx, uint8_t ts, uint8_t *data, uint8_t len,
	uint32_t fn)
{
	unsigned payload = data[0] >> 6;
	bitvec *block;
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = gprs_rlcmac_rcv_data_block_acknowledged(trx, ts, data,
			len);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		block = bitvec_alloc(len);
		if (!block)
			return -ENOMEM;
		bitvec_unpack(block, data);
		rc = gprs_rlcmac_rcv_control_block(block, trx, ts, fn);
		bitvec_free(block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload.\n");
		rc = -EINVAL;
	}

	return rc;
}

/* add paging to paging queue(s) */
int gprs_rlcmac_add_paging(uint8_t chan_needed, uint8_t *identity_lv)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_paging *pag;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n",
		chan_needed, osmo_hexdump(identity_lv + 1, identity_lv[0]));

	/* collect slots to page
	 * Mark slots for every TBF, but only mark one of it.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));
	for (l = 0; gprs_rlcmac_tbfs_lists[l]; l++) {
		llist_for_each_entry(tbf, gprs_rlcmac_tbfs_lists[l], list) {
			first_ts = -1;
			for (ts = 0; ts < 8; ts++) {
				if (tbf->pdch[ts]) {
					/* remember the first slot found */
					if (first_ts < 0)
						first_ts = ts;
					/* break, if we already marked a slot */
					if ((slot_mask[tbf->trx] & (1 << ts)))
						break;
				}
			}
			/* mark first slot found, if none is marked already */
			if (ts == 8 && first_ts >= 0) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- %s TBF=%d uses "
					"TRX=%d TS=%d, so we mark\n",
					(tbf->direction == GPRS_RLCMAC_UL_TBF)
						? "UL" : "DL",
					tbf->tfi, tbf->trx, first_ts);
				slot_mask[tbf->trx] |= (1 << first_ts);
			} else
				LOGP(DRLCMAC, LOGL_DEBUG, "- %s TBF=%d uses "
					"already marked TRX=%d TS=%d\n",
					(tbf->direction == GPRS_RLCMAC_UL_TBF)
						? "UL" : "DL",
					tbf->tfi, tbf->trx, ts);
		}
	}

	/* Now we have a list of marked slots. Every TBF uses at least one
	 * of these slots. */

	/* schedule paging to all marked slots */
	for (trx = 0; trx < 8; trx++) {
		if (slot_mask[trx] == 0)
			continue;
		any_tbf = 1;
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
				llist_add(&pag->list,
					&bts->trx[trx].pdch[ts].paging_list);
				LOGP(DRLCMAC, LOGL_INFO, "Paging on PACCH of "
					"TRX=%d TS=%d\n", trx, ts);
			}
		}
	}

	if (!any_tbf)
		LOGP(DRLCMAC, LOGL_INFO, "No paging, because no TBF\n");

	return 0;
}

struct gprs_rlcmac_paging *gprs_rlcmac_dequeue_paging(
	struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_paging *pag;

	if (llist_empty(&pdch->paging_list))
		return NULL;
	pag = llist_entry(pdch->paging_list.next,
		struct gprs_rlcmac_paging, list);
        llist_del(&pag->list);

	return pag;
}

struct msgb *gprs_rlcmac_send_packet_paging_request(
	struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_paging *pag;
	struct msgb *msg;
	unsigned wp = 0, len;

	/* no paging, no message */
	pag = gprs_rlcmac_dequeue_paging(pdch);
	if (!pag)
		return NULL;

	LOGP(DRLCMAC, LOGL_DEBUG, "Scheduling paging\n");

	/* alloc message */
	msg = msgb_alloc(23, "pag ctrl block");
	if (!msg)
		return NULL;
	bitvec *pag_vec = bitvec_alloc(23);
	if (!pag_vec) {
		msgb_free(msg);
		return NULL;
	}
	wp = write_packet_paging_request(pag_vec);

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
				break;
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
				break;
			}
		}
		if (wp + len > 184) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Does not fit, so schedule "
				"next time\n");
			/* put back paging record, because does not fit */
			llist_add_tail(&pag->list, &pdch->paging_list);
			break;
		}
		write_repeated_page_info(pag_vec, wp, pag->identity_lv[0],
			pag->identity_lv + 1, pag->chan_needed);

		pag = gprs_rlcmac_dequeue_paging(pdch);
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

// GSM 04.08 9.1.18 Immediate assignment
int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra,
	uint32_t ref_fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc,
	uint8_t tfi, uint8_t usf, uint32_t tlli,
	uint8_t polling, uint32_t fn, uint8_t single_block)
{
	unsigned wp = 0;
	uint8_t plen;

	bitvec_write_field(dest, wp,0x0,4);  // Skip Indicator
	bitvec_write_field(dest, wp,0x6,4);  // Protocol Discriminator
	bitvec_write_field(dest, wp,0x3F,8); // Immediate Assignment Message Type

	// 10.5.2.25b Dedicated mode or TBF
	bitvec_write_field(dest, wp,0x0,1);      // spare
	bitvec_write_field(dest, wp,0x0,1);      // TMA : Two-message assignment: No meaning
	bitvec_write_field(dest, wp,downlink,1); // Downlink : Downlink assignment to mobile in packet idle mode
	bitvec_write_field(dest, wp,0x1,1);      // T/D : TBF or dedicated mode: this message assigns a Temporary Block Flow (TBF).

	bitvec_write_field(dest, wp,0x0,4); // Page Mode

	// GSM 04.08 10.5.2.25a Packet Channel Description
	bitvec_write_field(dest, wp,0x1,5);                               // Channel type
	bitvec_write_field(dest, wp,ts,3);     // TN
	bitvec_write_field(dest, wp,tsc,3);    // TSC
	bitvec_write_field(dest, wp,0x0,3);                               // non-hopping RF channel configuraion
	bitvec_write_field(dest, wp,arfcn,10); // ARFCN

	//10.5.2.30 Request Reference
	bitvec_write_field(dest, wp,ra,8);                    // RA
	bitvec_write_field(dest, wp,(ref_fn / (26 * 51)) % 32,5); // T1'
	bitvec_write_field(dest, wp,ref_fn % 51,6);               // T3
	bitvec_write_field(dest, wp,ref_fn % 26,5);               // T2

	// 10.5.2.40 Timing Advance
	bitvec_write_field(dest, wp,0x0,2); // spare
	bitvec_write_field(dest, wp,ta,6);  // Timing Advance value

	// No mobile allocation in non-hopping systems.
	// A zero-length LV.  Just write L=0.
	bitvec_write_field(dest, wp,0,8);

	if ((wp % 8)) {
		LOGP(DRLCMACUL, LOGL_ERROR, "Length of IMM.ASS without rest "
			"octets is not multiple of 8 bits, PLEASE FIX!\n");
		exit (0);
	}
	plen = wp / 8;

	if (downlink)
	{
		// GSM 04.08 10.5.2.16 IA Rest Octets
		bitvec_write_field(dest, wp, 3, 2);   // "HH"
		bitvec_write_field(dest, wp, 1, 2);   // "01" Packet Downlink Assignment
		bitvec_write_field(dest, wp,tlli,32); // TLLI
		bitvec_write_field(dest, wp,0x1,1);   // switch TFI   : on
		bitvec_write_field(dest, wp,tfi,5);   // TFI
		bitvec_write_field(dest, wp,0x0,1);   // RLC acknowledged mode
		bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
		bitvec_write_field(dest, wp,0x0,5);   // GAMMA power control parameter
		bitvec_write_field(dest, wp,polling,1);   // Polling Bit
		bitvec_write_field(dest, wp,!polling,1);   // TA_VALID ???
		bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
		bitvec_write_field(dest, wp,0x0,4);   // TIMING_ADVANCE_INDEX
		if (polling) {
			bitvec_write_field(dest, wp,0x1,1);   // TBF Starting TIME present
			bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
			bitvec_write_field(dest, wp,fn % 51,6);               // T3
			bitvec_write_field(dest, wp,fn % 26,5);               // T2
		} else {
			bitvec_write_field(dest, wp,0x0,1);   // TBF Starting TIME present
		}
		bitvec_write_field(dest, wp,0x0,1);   // P0 not present
//		bitvec_write_field(dest, wp,0x1,1);   // P0 not present
//		bitvec_write_field(dest, wp,0xb,4);
	}
	else
	{
		struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
		// GMS 04.08 10.5.2.37b 10.5.2.16
		bitvec_write_field(dest, wp, 3, 2);    // "HH"
		bitvec_write_field(dest, wp, 0, 2);    // "0" Packet Uplink Assignment
		if (single_block) {
			bitvec_write_field(dest, wp, 0, 1);    // Block Allocation : Single Block Allocation
			bitvec_write_field(dest, wp, 1, 1);   // "1" Alpha : Present
			bitvec_write_field(dest, wp, 0, 4);    // Alpha
			bitvec_write_field(dest, wp, 0, 5);    // Gamma
			bitvec_write_field(dest, wp, 0, 1);    // TIMING_ADVANCE_INDEX_FLAG
			bitvec_write_field(dest, wp, 1, 1);    // TBF_STARTING_TIME_FLAG
			bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
			bitvec_write_field(dest, wp,fn % 51,6);               // T3
			bitvec_write_field(dest, wp,fn % 26,5);               // T2
		} else {
			bitvec_write_field(dest, wp, 1, 1);    // Block Allocation : Not Single Block Allocation
			bitvec_write_field(dest, wp, tfi, 5);  // TFI_ASSIGNMENT Temporary Flow Identity
			bitvec_write_field(dest, wp, 0, 1);    // POLLING
			bitvec_write_field(dest, wp, 0, 1);    // ALLOCATION_TYPE: dynamic
			bitvec_write_field(dest, wp, usf, 3);    // USF
			bitvec_write_field(dest, wp, 0, 1);    // USF_GRANULARITY
			bitvec_write_field(dest, wp, 0, 1);   // "0" power control: Not Present
			bitvec_write_field(dest, wp, bts->initial_cs-1, 2);    // CHANNEL_CODING_COMMAND 
			bitvec_write_field(dest, wp, 1, 1);    // TLLI_BLOCK_CHANNEL_CODING
			bitvec_write_field(dest, wp, 1, 1);   // "1" Alpha : Present
			bitvec_write_field(dest, wp, 0, 4);    // Alpha
			bitvec_write_field(dest, wp, 0, 5);    // Gamma
			bitvec_write_field(dest, wp, 0, 1);    // TIMING_ADVANCE_INDEX_FLAG
			bitvec_write_field(dest, wp, 0, 1);    // TBF_STARTING_TIME_FLAG
		}
	}

	return plen;
}

/* generate uplink assignment */
void write_packet_uplink_assignment(bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
	struct gprs_rlcmac_tbf *tbf, uint8_t poll)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	unsigned wp = 0;
	uint8_t ts;

	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber (N+13)
	bitvec_write_field(dest, wp,poll,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	bitvec_write_field(dest, wp,0xa,6);  // MESSAGE TYPE

	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1); // switch PERSIST_LEVEL: off
	if (use_tlli) {
		bitvec_write_field(dest, wp,0x2,2); // switch TLLI   : on
		bitvec_write_field(dest, wp,tlli,32); // TLLI
	} else {
		bitvec_write_field(dest, wp,0x0,1); // switch TFI : on
		bitvec_write_field(dest, wp,old_downlink,1); // 0=UPLINK TFI, 1=DL TFI
		bitvec_write_field(dest, wp,old_tfi,5); // TFI
	}

	bitvec_write_field(dest, wp,0x0,1); // Message escape
	bitvec_write_field(dest, wp,bts->initial_cs-1, 2); // CHANNEL_CODING_COMMAND 
	bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 

	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(dest, wp,tbf->ta,6); // TIMING_ADVANCE_VALUE
	bitvec_write_field(dest, wp,0x0,1); // switch TIMING_ADVANCE_INDEX = off

#if 1
	bitvec_write_field(dest, wp,0x1,1); // Frequency Parameters information elements = present
	bitvec_write_field(dest, wp,tbf->tsc,3); // Training Sequence Code (TSC)
	bitvec_write_field(dest, wp,0x0,2); // ARFCN = present
	bitvec_write_field(dest, wp,tbf->arfcn,10); // ARFCN
#else
	bitvec_write_field(dest, wp,0x0,1); // Frequency Parameters = off
#endif

	bitvec_write_field(dest, wp,0x1,2); // Dynamic Allocation
	
	bitvec_write_field(dest, wp,0x0,1); // Extended Dynamic Allocation = off
	bitvec_write_field(dest, wp,0x0,1); // P0 = off
	
	bitvec_write_field(dest, wp,0x0,1); // USF_GRANULARITY
	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,tbf->tfi,5);// TFI

	bitvec_write_field(dest, wp,0x0,1); //
	bitvec_write_field(dest, wp,0x0,1); // TBF Starting Time = off
	bitvec_write_field(dest, wp,0x0,1); // Timeslot Allocation
	
	for (ts = 0; ts < 8; ts++) {
		if (tbf->pdch[ts]) {
			bitvec_write_field(dest, wp,0x1,1); // USF_TN(i): on
			bitvec_write_field(dest, wp,tbf->dir.ul.usf[ts],3); // USF_TN(i)
		} else
			bitvec_write_field(dest, wp,0x0,1); // USF_TN(i): off
	}
//	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
}


/* generate downlink assignment */
void write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t old_tfi,
	uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll)
{
	// Packet downlink assignment TS 44.060 11.2.7

	uint8_t tn;

	block->PAYLOAD_TYPE = 0x1;  // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0;  // N+13
	block->SP           = poll; // RRBP field is valid
	block->USF          = 0x0;  // Uplink state flag

	block->u.Packet_Downlink_Assignment.MESSAGE_TYPE = 0x2;  // Packet Downlink Assignment
	block->u.Packet_Downlink_Assignment.PAGE_MODE    = 0x0;  // Normal Paging

	block->u.Packet_Downlink_Assignment.Exist_PERSISTENCE_LEVEL      = 0x0;          // PERSISTENCE_LEVEL: off

	block->u.Packet_Downlink_Assignment.ID.UnionType                 = 0x0;          // TFI = on
	block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.UnionType    = old_downlink; // 0=UPLINK TFI, 1=DL TFI
	block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.u.UPLINK_TFI = old_tfi;      // TFI

	block->u.Packet_Downlink_Assignment.MAC_MODE            = 0x0;          // Dynamic Allocation
	block->u.Packet_Downlink_Assignment.RLC_MODE            = 0x0;          // RLC acknowledged mode
	block->u.Packet_Downlink_Assignment.CONTROL_ACK         = old_downlink; // NW establishes no new DL TBF for the MS with running timer T3192
	block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION = 0;   // timeslot(s)
	for (tn = 0; tn < 8; tn++) {
		if (tbf->pdch[tn])
			block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION |= 0x80 >> tn;   // timeslot(s)
	}

	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_TIMING_ADVANCE_VALUE = 0x1; // TIMING_ADVANCE_VALUE = on
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_VALUE       = tbf->ta;  // TIMING_ADVANCE_VALUE
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x0; // TIMING_ADVANCE_INDEX = off

	block->u.Packet_Downlink_Assignment.Exist_P0_and_BTS_PWR_CTRL_MODE = 0x0;   // POWER CONTROL = off

	block->u.Packet_Downlink_Assignment.Exist_Frequency_Parameters     = 0x1;   // Frequency Parameters = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.TSC       = tbf->tsc;   // Training Sequence Code (TSC)
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.UnionType = 0x0;   // ARFCN = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.u.ARFCN   = tbf->arfcn; // ARFCN

	block->u.Packet_Downlink_Assignment.Exist_DOWNLINK_TFI_ASSIGNMENT  = 0x1;     // DOWNLINK TFI ASSIGNMENT = on
	block->u.Packet_Downlink_Assignment.DOWNLINK_TFI_ASSIGNMENT        = tbf->tfi; // TFI

	block->u.Packet_Downlink_Assignment.Exist_Power_Control_Parameters = 0x1;   // Power Control Parameters = on
	block->u.Packet_Downlink_Assignment.Power_Control_Parameters.ALPHA = 0x0;   // ALPHA

	for (tn = 0; tn < 8; tn++)
	{
		if (tbf->pdch[tn])
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].Exist    = 0x1; // Slot[i] = on
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].GAMMA_TN = 0x0; // GAMMA_TN
		}
		else
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].Exist    = 0x0; // Slot[i] = off
		}
	}

	block->u.Packet_Downlink_Assignment.Exist_TBF_Starting_Time   = 0x0; // TBF Starting TIME = off
	block->u.Packet_Downlink_Assignment.Exist_Measurement_Mapping = 0x0; // Measurement_Mapping = off
	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x0; // AdditionsR99 = off
}

/* generate uplink ack */
void write_packet_uplink_ack(RlcMacDownlink_t * block, struct gprs_rlcmac_tbf *tbf,
	uint8_t final)
{
	// Packet Uplink Ack/Nack  TS 44.060 11.2.28

	char show_v_n[65];

	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	uint8_t rbb = 0;
	uint16_t i, bbn;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	char bit;

	LOGP(DRLCMACUL, LOGL_DEBUG, "Sending Ack/Nack for TBF=%d "
		"(final=%d)\n", tbf->tfi, final);

	block->PAYLOAD_TYPE = 0x1;   // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0;   // N+13
	block->SP           = final; // RRBP field is valid, if it is final ack
	block->USF          = 0x0;   // Uplink state flag

	block->u.Packet_Uplink_Ack_Nack.MESSAGE_TYPE = 0x9;      // Packet Downlink Assignment
	block->u.Packet_Uplink_Ack_Nack.PAGE_MODE    = 0x0;      // Normal Paging
	block->u.Packet_Uplink_Ack_Nack.UPLINK_TFI   = tbf->tfi; // Uplink TFI

	block->u.Packet_Uplink_Ack_Nack.UnionType    = 0x0;      // PU_AckNack_GPRS = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.CHANNEL_CODING_COMMAND                        = bts->initial_cs - 1;             // CS1
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.FINAL_ACK_INDICATION     = final;           // FINAL ACK INDICATION
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER = tbf->dir.ul.v_r; // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	for (i = 0, bbn = (tbf->dir.ul.v_r - 64) & mod_sns_half; i < 64;
	     i++, bbn = (bbn + 1) & mod_sns_half) {
	     	bit = tbf->dir.ul.v_n[bbn];
		if (bit == 0)
			bit = ' ';
		show_v_n[i] = bit;
		if (bit == 'R')
			rbb = (rbb << 1)|1;
		else
			rbb = (rbb << 1);
		if((i%8) == 7)
		{
			block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP[i/8] = rbb;
			rbb = 0;
		}
	}
	show_v_n[64] = '\0';
	LOGP(DRLCMACUL, LOGL_DEBUG, "- V(N): \"%s\" R=Received "
		"N=Not-Received\n", show_v_n);

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.UnionType              = 0x0; // Fixed Allocation Dummy = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.u.FixedAllocationDummy = 0x0; // Fixed Allocation Dummy
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Exist_AdditionsR99     = 0x0; // AdditionsR99 = off

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI = 0x1;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI       = tbf->tlli;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance      = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits             = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters   = 0x0;
}

unsigned write_packet_paging_request(bitvec * dest)
{
	unsigned wp = 0;

	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,3);  // No polling
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	bitvec_write_field(dest, wp,0x22,6);  // MESSAGE TYPE

	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1);  // No PERSISTENCE_LEVEL
	bitvec_write_field(dest, wp,0x0,1);  // No NLN

	return wp;
}

unsigned write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
	uint8_t *identity, uint8_t chan_needed)
{
	bitvec_write_field(dest, wp,0x1,1);  // Repeated Page info exists

	bitvec_write_field(dest, wp,0x1,1);  // RR connection paging

	if ((identity[0] & 0x07) == 4) {
		bitvec_write_field(dest, wp,0x0,1);  // TMSI
		identity++;
		len--;
	} else {
		bitvec_write_field(dest, wp,0x0,1);  // MI
		bitvec_write_field(dest, wp,len,4);  // MI len
	}
	while (len) {
		bitvec_write_field(dest, wp,*identity++,8);  // MI data
		len--;
	}
	bitvec_write_field(dest, wp,chan_needed,2);  // CHANNEL_NEEDED
	bitvec_write_field(dest, wp,0x0,1);  // No eMLPP_PRIORITY

	return wp;
}

/* Send Uplink unit-data to SGSN. */
int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf)
{
	const uint8_t qos_profile = QOS_PROFILE;
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + tbf->llc_index;

	LOGP(DBSSGP, LOGL_INFO, "LLC [PCU -> SGSN] TFI: %u TLLI: 0x%08x len=%d\n", tbf->tfi, tbf->tlli, tbf->llc_index);
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	
	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	msgb_tvlv_push(llc_pdu, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*tbf->llc_index, tbf->llc_frame);
	bssgp_tx_ul_ud(bctx, tbf->tlli, &qos_profile, llc_pdu);

	return 0;
}
