/* RLC Window (DL TBF), 3GPP TS 44.060
 *
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2023 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include "gprs_debug.h"
#include "bts.h"
#include "rlc_window_dl.h"

extern "C" {
#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>
}

static uint16_t bitnum_to_bsn(int bitnum, uint16_t ssn)
{
	return (ssn - 1 - bitnum);
}

void gprs_rlc_v_b::reset()
{
	for (size_t i = 0; i < ARRAY_SIZE(m_v_b); ++i)
		mark_invalid(i);
}

void gprs_rlc_dl_window::reset()
{
	m_v_s = 0;
	m_v_a = 0;
	m_v_b.reset();
}

int gprs_rlc_dl_window::resend_needed() const
{
	for (uint16_t bsn = v_a(); bsn != v_s(); bsn = mod_sns(bsn + 1)) {
		if (m_v_b.is_nacked(bsn) || m_v_b.is_resend(bsn))
			return bsn;
	}

	return -1;
}

int gprs_rlc_dl_window::mark_for_resend()
{
	int resend = 0;

	for (uint16_t bsn = v_a(); bsn != v_s(); bsn = mod_sns(bsn + 1)) {
		if (m_v_b.is_unacked(bsn)) {
			/* mark to be re-send */
			m_v_b.mark_resend(bsn);
			resend += 1;
		}
	}

	return resend;
}

int gprs_rlc_dl_window::count_unacked()
{
	uint16_t unacked = 0;
	uint16_t bsn;

	for (bsn = v_a(); bsn != v_s(); bsn = mod_sns(bsn + 1)) {
		if (!m_v_b.is_acked(bsn))
			unacked += 1;
	}

	return unacked;
}

void gprs_rlc_dl_window::update(struct gprs_rlcmac_bts *bts, const struct bitvec *rbb,
			uint16_t first_bsn, uint16_t *lost,
			uint16_t *received)
{
	unsigned dist = distance();
	unsigned num_blocks = rbb->cur_bit > dist
				? dist : rbb->cur_bit;
	unsigned bsn;

	/* first_bsn is in range V(A)..V(S) */

	for (unsigned int bitpos = 0; bitpos < num_blocks; bitpos++) {
		bool is_ack;
		bsn = mod_sns(first_bsn + bitpos);
		if (bsn == mod_sns(v_a() - 1))
			break;

		is_ack = bitvec_get_bit_pos(rbb, bitpos) == 1;

		if (is_ack) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- got ack for BSN=%d\n", bsn);
			if (!m_v_b.is_acked(bsn))
				*received += 1;
			m_v_b.mark_acked(bsn);
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- got NACK for BSN=%d\n", bsn);
			m_v_b.mark_nacked(bsn);
			bts_do_rate_ctr_inc(bts, CTR_RLC_NACKED);
			*lost += 1;
		}
	}
}

void gprs_rlc_dl_window::update(struct gprs_rlcmac_bts *bts, char *show_rbb, uint16_t ssn,
			uint16_t *lost, uint16_t *received)
{
	/* SSN - 1 is in range V(A)..V(S)-1 */
	for (int bitpos = 0; bitpos < ws(); bitpos++) {
		uint16_t bsn = mod_sns(bitnum_to_bsn(bitpos, ssn));

		if (bsn == mod_sns(v_a() - 1))
			break;

		if (show_rbb[ws() - 1 - bitpos] == 'R') {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- got ack for BSN=%d\n", bsn);
			if (!m_v_b.is_acked(bsn))
				*received += 1;
			m_v_b.mark_acked(bsn);
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- got NACK for BSN=%d\n", bsn);
			m_v_b.mark_nacked(bsn);
			bts_do_rate_ctr_inc(bts, CTR_RLC_NACKED);
			*lost += 1;
		}
	}
}

int gprs_rlc_dl_window::move_window()
{
	uint16_t bsn;
	int moved = 0;

	for (bsn = v_a(); bsn != v_s(); bsn = mod_sns(bsn + 1)) {
		if (m_v_b.is_acked(bsn)) {
			m_v_b.mark_invalid(bsn);
			moved += 1;
		} else
			break;
	}

	return moved;
}

void gprs_rlc_dl_window::show_state(char *show_v_b)
{
	int i;
	uint16_t bsn;

	for (i = 0, bsn = v_a(); bsn != v_s(); i++, bsn = mod_sns(bsn + 1)) {
		uint16_t index = bsn & mod_sns_half();
		switch(m_v_b.get_state(index)) {
		case GPRS_RLC_DL_BSN_INVALID:
			show_v_b[i] = 'I';
			break;
		case GPRS_RLC_DL_BSN_ACKED:
			show_v_b[i] = 'A';
			break;
		case GPRS_RLC_DL_BSN_RESEND:
			show_v_b[i] = 'X';
			break;
		case GPRS_RLC_DL_BSN_NACKED:
			show_v_b[i] = 'N';
			break;
		default:
			show_v_b[i] = '?';
		}
	}
	show_v_b[i] = '\0';
}
