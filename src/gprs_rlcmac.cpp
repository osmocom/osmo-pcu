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
	uint8_t use_trx, uint8_t first_ts)
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
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = gprs_rlcmac_rcv_data_block_acknowledged(trx, ts, data,
			len);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		rc = gprs_rlcmac_rcv_control_block(trx, ts, fn, data, len);
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
