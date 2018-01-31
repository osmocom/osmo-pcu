/* mslot_class.c
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <mslot_class.h>
#include <gprs_debug.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <errno.h>

/* 3GPP TS 45.002 Annex B Table B.1 */

struct gprs_ms_multislot_class {
	uint8_t rx, tx, sum;	/* Maximum Number of Slots: RX, Tx, Sum Rx+Tx */
	uint8_t ta, tb, ra, rb;	/* Minimum Number of Slots */
	uint8_t type; /* Type of Mobile */
};

static const struct gprs_ms_multislot_class gprs_ms_multislot_class[] = {
	/* M-S Class |  Max # of slots |       Min # of slots      | Type */
	/*           | Rx     Tx   Sum |  Tta    Ttb    Tra    Trb |      */
	/* N/A */ { MS_NA, MS_NA, MS_NA, MS_NA, MS_NA, MS_NA, MS_NA, MS_NA },
	/*  1 */  {   1,     1,     2,     3,     2,     4,     2,     1 },
	/*  2 */  {   2,     1,     3,     3,     2,     3,     1,     1 },
	/*  3 */  {   2,     2,     3,     3,     2,     3,     1,     1 },
	/*  4 */  {   3,     1,     4,     3,     1,     3,     1,     1 },
	/*  5 */  {   2,     2,     4,     3,     1,     3,     1,     1 },
	/*  6 */  {   3,     2,     4,     3,     1,     3,     1,     1 },
	/*  7 */  {   3,     3,     4,     3,     1,     3,     1,     1 },
	/*  8 */  {   4,     1,     5,     3,     1,     2,     1,     1 },
	/*  9 */  {   3,     2,     5,     3,     1,     2,     1,     1 },
	/* 10 */  {   4,     2,     5,     3,     1,     2,     1,     1 },
	/* 11 */  {   4,     3,     5,     3,     1,     2,     1,     1 },
	/* 12 */  {   4,     4,     5,     2,     1,     2,     1,     1 },
	/* 13 */  {   3,     3,   MS_NA, MS_NA, MS_A,    3,   MS_A,    2 },
	/* 14 */  {   4,     4,   MS_NA, MS_NA, MS_A,    3,   MS_A,    2 },
	/* 15 */  {   5,     5,   MS_NA, MS_NA, MS_A,    3,   MS_A,    2 },
	/* 16 */  {   6,     6,   MS_NA, MS_NA, MS_A,    2,   MS_A,    2 },
	/* 17 */  {   7,     7,   MS_NA, MS_NA, MS_A,    1,     0,     2 },
	/* 18 */  {   8,     8,   MS_NA, MS_NA,   0,     0,     0,     2 },
	/* 19 */  {   6,     2,   MS_NA,   3,   MS_B,    2,   MS_C,    1 },
	/* 20 */  {   6,     3,   MS_NA,   3,   MS_B,    2,   MS_C,    1 },
	/* 21 */  {   6,     4,   MS_NA,   3,   MS_B,    2,   MS_C,    1 },
	/* 22 */  {   6,     4,   MS_NA,   2,   MS_B,    2,   MS_C,    1 },
	/* 23 */  {   6,     6,   MS_NA,   2,   MS_B,    2,   MS_C,    1 },
	/* 24 */  {   8,     2,   MS_NA,   3,   MS_B,    2,   MS_C,    1 },
	/* 25 */  {   8,     3,   MS_NA,   3,   MS_B,    2,   MS_C,    1 },
	/* 26 */  {   8,     4,   MS_NA,   3,   MS_B,    2,   MS_C,    1 },
	/* 27 */  {   8,     4,   MS_NA,   2,   MS_B,    2,   MS_C,    1 },
	/* 28 */  {   8,     6,   MS_NA,   2,   MS_B,    2,   MS_C,    1 },
	/* 29 */  {   8,     8,   MS_NA,   2,   MS_B,    2,   MS_C,    1 },
	/* 30 */  {   5,     1,     6,     2,     1,     1,     1,     1 },
	/* 31 */  {   5,     2,     6,     2,     1,     1,     1,     1 },
	/* 32 */  {   5,     3,     6,     2,     1,     1,     1,     1 },
	/* 33 */  {   5,     4,     6,     2,     1,     1,     1,     1 },
	/* 34 */  {   5,     5,     6,     2,     1,     1,     1,     1 },
	/* 35 */  {   5,     1,     6,     2,     1,   MS_TO,   1,     1 },
	/* 36 */  {   5,     2,     6,     2,     1,   MS_TO,   1,     1 },
	/* 37 */  {   5,     3,     6,     2,     1,   MS_TO,   1,     1 },
	/* 38 */  {   5,     4,     6,     2,     1,   MS_TO,   1,     1 },
	/* 39 */  {   5,     5,     6,     2,     1,   MS_TO,   1,     1 },
	/* 40 */  {   6,     1,     7,     1,     1,     1,   MS_TO,   1 },
	/* 41 */  {   6,     2,     7,     1,     1,     1,   MS_TO,   1 },
	/* 42 */  {   6,     3,     7,     1,     1,     1,   MS_TO,   1 },
	/* 43 */  {   6,     4,     7,     1,     1,     1,   MS_TO,   1 },
	/* 44 */  {   6,     5,     7,     1,     1,     1,   MS_TO,   1 },
	/* 45 */  {   6,     6,     7,     1,     1,     1,   MS_TO,   1 },
};

static inline const struct gprs_ms_multislot_class *get_mslot_table(uint8_t ms_cl)
{
	uint8_t index = ms_cl ? ms_cl : DEFAULT_MSLOT_CLASS;

	if (ms_cl >= ARRAY_SIZE(gprs_ms_multislot_class))
		index = 0;

	return &gprs_ms_multislot_class[index];
}

uint8_t mslot_class_max()
{
	return ARRAY_SIZE(gprs_ms_multislot_class);
}

uint8_t mslot_class_get_ta(uint8_t ms_cl)
{
	return get_mslot_table(ms_cl)->ta;
}

/* TODO: Set it to 1 if FH is implemented and enabled
 * MS_A and MS_B are 0 iff FH is disabled and there is no Tx/Rx change.
 * This is never the case with the current implementation, so 1 will always be used. */
uint8_t mslot_class_get_tb(uint8_t ms_cl)
{
	const struct gprs_ms_multislot_class *t = get_mslot_table(ms_cl);

	switch (t->tb) {
	case MS_A:
		return 0;
	case MS_B:
		return 1;
	default:
		return t->tb;
	}
}

uint8_t mslot_class_get_ra(uint8_t ms_cl, uint8_t ta)
{
	const struct gprs_ms_multislot_class *t = get_mslot_table(ms_cl);

	switch (t->ra) {
	case MS_TO:
		return ta + 1;
	default:
		return t->ra;
	}
}

uint8_t mslot_class_get_rb(uint8_t ms_cl, uint8_t ta)
{
	const struct gprs_ms_multislot_class *t = get_mslot_table(ms_cl);

	switch (t->rb) {
	case MS_A:
		return 0;
	case MS_C:
		return 1;
	case MS_TO:
		return ta;
	default:
		return t->rb;
	}
}

uint8_t mslot_class_get_tx(uint8_t ms_cl)
{
	return get_mslot_table(ms_cl)->tx;
}

uint8_t mslot_class_get_rx(uint8_t ms_cl)
{
	return get_mslot_table(ms_cl)->rx;
}

uint8_t mslot_class_get_sum(uint8_t ms_cl)
{
	return get_mslot_table(ms_cl)->sum;
}

uint8_t mslot_class_get_type(uint8_t ms_cl)
{
	return get_mslot_table(ms_cl)->type;
}

/*! Fill in RX mask table for a given MS Class
 *
 *  \param[in] ms_cl MS Class pointer
 *  \param[in] num_tx Number of TX slots to consider
 *  \param[out] rx_mask RX mask table
 */
void mslot_fill_rx_mask(uint8_t mslot_class, uint8_t num_tx, uint8_t *rx_mask)
{
	static const char *digit[10] = { "0","1","2","3","4","5","6","7","8","9" };
	uint8_t Tx = mslot_class_get_tx(mslot_class),     /* Max number of Tx slots */
		Sum = mslot_class_get_sum(mslot_class),	  /* Max number of Tx + Rx slots */
		Type = mslot_class_get_type(mslot_class), /* Type of Mobile */
		Tta = mslot_class_get_ta(mslot_class),    /* Minimum number of slots */
		Ttb = mslot_class_get_tb(mslot_class),
		/* FIXME: use actual TA offset for computation - make sure to adjust "1 + MS_TO" accordingly
		   see also "Offset required" bit in 3GPP TS 24.008 §10.5.1.7 */
		Tra = mslot_class_get_ra(mslot_class, 0),
		Trb = mslot_class_get_rb(mslot_class, 0);

	if (num_tx == 1) /* it's enough to log this once per TX slot set iteration */
		LOGP(DRLCMAC, LOGL_DEBUG,
		     "Rx=%d Tx=%d Sum Rx+Tx=%s, Tta=%s Ttb=%d, Tra=%d Trb=%d, Type=%d\n",
		     mslot_class_get_rx(mslot_class), Tx,
		     (Sum == MS_NA) ? "N/A" : digit[Sum],
		     (Tta == MS_NA) ? "N/A" : digit[Tta], Ttb, Tra, Trb, Type);

	if (Type == 1) {
		rx_mask[MASK_TT] = (0x100 >> OSMO_MAX(Ttb, Tta)) - 1;
		rx_mask[MASK_TT] &= ~((1 << (Trb + num_tx)) - 1);
		rx_mask[MASK_TR] = (0x100 >> Ttb) - 1;
		rx_mask[MASK_TR] &= ~((1 << (OSMO_MAX(Trb, Tra) + num_tx)) - 1);
	} else {
		/* Class type 2 MS have independant RX and TX */
		rx_mask[MASK_TT] = 0xff;
		rx_mask[MASK_TR] = 0xff;
	}

	rx_mask[MASK_TT] = (rx_mask[MASK_TT] << 3) | (rx_mask[MASK_TT] >> 5);
	rx_mask[MASK_TR] = (rx_mask[MASK_TR] << 3) | (rx_mask[MASK_TR] >> 5);
}
