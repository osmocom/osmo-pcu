/* RLC Window (UL TBF), 3GPP TS 44.060
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
#include "rlc_window_ul.h"

extern "C" {
#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>
}

void gprs_rlc_v_n::reset()
{
	for (size_t i = 0; i < ARRAY_SIZE(m_v_n); ++i)
		m_v_n[i] = GPRS_RLC_UL_BSN_INVALID;
}

/* Raise V(R) to highest received sequence number not received. */
void gprs_rlc_ul_window::raise_v_r(const uint16_t bsn)
{
	uint16_t offset_v_r;
	offset_v_r = mod_sns(bsn + 1 - v_r());
	/* Positive offset, so raise. */
	if (offset_v_r < (sns() >> 1)) {
		while (offset_v_r--) {
			if (offset_v_r) /* all except the received block */
				m_v_n.mark_missing(v_r());
			raise_v_r_to(1);
		}
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Raising V(R) to %d\n", v_r());
	}
}

/*
 * Raise V(Q) if possible. This is looped until there is a gap
 * (non received block) or the window is empty.
 */
uint16_t gprs_rlc_ul_window::raise_v_q()
{
	uint16_t count = 0;

	while (v_q() != v_r()) {
		if (!m_v_n.is_received(v_q()))
			break;
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Taking block %d out, raising "
			"V(Q) to %d\n", v_q(), mod_sns(v_q() + 1));
		raise_v_q(1);
		count += 1;
	}

	return count;
}

void gprs_rlc_ul_window::receive_bsn(const uint16_t bsn)
{
	m_v_n.mark_received(bsn);
	raise_v_r(bsn);
}

bool gprs_rlc_ul_window::invalidate_bsn(const uint16_t bsn)
{
	bool was_valid = m_v_n.is_received(bsn);
	m_v_n.mark_missing(bsn);

	return was_valid;
}


/* Update the receive block bitmap */
uint16_t gprs_rlc_ul_window::update_egprs_rbb(uint8_t *rbb)
{
	uint16_t i;
	uint16_t bsn;
	uint16_t bitmask = 0x80;
	int8_t pos = 0;
	int8_t bit_pos = 0;
	for (i = 0, bsn = (v_q()+1); ((bsn < (v_r())) && (i < ws())); i++,
					bsn = this->mod_sns(bsn + 1)) {
		if (m_v_n.is_received(bsn)) {
			rbb[pos] = rbb[pos] | bitmask;
		} else {
			rbb[pos] = rbb[pos] & (~bitmask);
		}
		bitmask = bitmask >> 1;
		bit_pos++;
		bit_pos = bit_pos % 8;
		if (bit_pos == 0) {
			pos++;
			bitmask = 0x80;
		}
	}
	return i;
}

/* Update the receive block bitmap */
void gprs_rlc_ul_window::update_rbb(char *rbb)
{
	int i;
	for (i=0; i < ws(); i++) {
		if (m_v_n.is_received((ssn()-1-i) & mod_sns()))
			rbb[ws()-1-i] = 'R';
		else
			rbb[ws()-1-i] = 'I';
	}
}