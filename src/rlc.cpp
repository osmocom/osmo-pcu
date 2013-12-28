/*
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

#include "tbf.h"
#include "bts.h"
#include "gprs_debug.h"

extern "C" {
#include <osmocom/core/utils.h>
}


uint8_t *gprs_rlc_data::prepare(size_t block_data_len)
{
	/* todo.. only set it once if it turns out to be a bottleneck */
	memset(block, 0x0, sizeof(block));
	memset(block, 0x2b, block_data_len);

	return block;
}

void gprs_rlc_data::put_data(const uint8_t *data, size_t data_len)
{
	memcpy(block, data, data_len);
	len = data_len;
}

void gprs_rlc_v_b::reset()
{
	for (size_t i = 0; i < ARRAY_SIZE(m_v_b); ++i)
		mark_invalid(i);
}

int gprs_rlc_v_b::resend_needed(const gprs_rlc_dl_window &w)
{
	for (uint16_t bsn = w.v_a(); bsn != w.v_s(); bsn = (bsn + 1) & w.mod_sns()) {
		if (is_nacked(bsn) || is_resend(bsn))
			return bsn;
	}

	return -1;
}

int gprs_rlc_v_b::mark_for_resend(const gprs_rlc_dl_window &w)
{
	int resend = 0;

	for (uint16_t bsn = w.v_a(); bsn != w.v_s(); bsn = (bsn + 1) & w.mod_sns()) {
		if (is_unacked(bsn)) {
			/* mark to be re-send */
			mark_resend(bsn);
			resend += 1;
		}
	}

	return resend;
}

int gprs_rlc_v_b::count_unacked(const gprs_rlc_dl_window &w)
{
	uint16_t unacked = 0;
	uint16_t bsn;

	for (bsn = w.v_a(); bsn != w.v_s(); bsn = (bsn + 1) & w.mod_sns()) {
		if (!is_acked(bsn))
			unacked += 1;
	}

	return unacked;
}

static uint16_t bitnum_to_bsn(int bitnum, uint16_t ssn, uint16_t mod_sns)
{
	return (ssn - 1 - bitnum) & mod_sns;
}

void gprs_rlc_v_b::update(BTS *bts, char *show_rbb, uint8_t ssn,
			const gprs_rlc_dl_window &w,
			uint16_t *lost, uint16_t *received)
{
	/* SSN - 1 is in range V(A)..V(S)-1 */
	for (int bitpos = 0; bitpos < w.ws(); bitpos++) {
		uint16_t bsn = bitnum_to_bsn(bitpos, ssn, w.mod_sns());

		if (bsn == ((w.v_a() - 1) & w.mod_sns()))
			break;

		if (show_rbb[w.ws() - 1 - bitpos] == 'R') {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- got ack for BSN=%d\n", bsn);
			if (!is_acked(bsn))
				*received += 1;
			mark_acked(bsn);
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- got NACK for BSN=%d\n", bsn);
			mark_nacked(bsn);
			bts->rlc_nacked();
			*lost += 1;
		}
	}
}

int gprs_rlc_v_b::move_window(const gprs_rlc_dl_window &w)
{
	int i;
	uint16_t bsn;
	int moved = 0;

	for (i = 0, bsn = w.v_a(); bsn != w.v_s(); i++, bsn = (bsn + 1) & w.mod_sns()) {
		if (is_acked(bsn)) {
			mark_invalid(bsn);
			moved += 1;
		} else
			break;
	}

	return moved;
}

void gprs_rlc_v_b::state(char *show_v_b, const gprs_rlc_dl_window &w)
{
	int i;
	uint16_t bsn;

	for (i = 0, bsn = w.v_a(); bsn != w.v_s(); i++, bsn = (bsn + 1) & w.mod_sns()) {
		uint16_t index = bsn & mod_sns_half();
		show_v_b[i] = m_v_b[index];
		if (show_v_b[i] == 0)
			show_v_b[i] = ' ';
	}
	show_v_b[i] = '\0';
}

void gprs_rlc_v_n::reset()
{
	memset(m_v_n, 0x0, sizeof(m_v_n));
}

/* Update the receive block bitmap */
void gprs_rlc_ul_window::update_rbb(char *rbb)
{
	int i;
	for (i=0; i < ws(); i++) {
		if (m_v_n.is_received(ssn()-1-i))
			rbb[ws()-1-i] = 'R';
		else
			rbb[ws()-1-i] = 'I';
	}
}

/* Raise V(R) to highest received sequence number not received. */
void gprs_rlc_ul_window::raise_v_r(const uint16_t bsn)
{
	uint16_t offset_v_r;
	offset_v_r = (bsn + 1 - v_r()) & mod_sns();
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
			"V(Q) to %d\n", v_q(), (v_q() + 1) & mod_sns());
		raise_v_q(1);
		count += 1;
	}

	return count;
}

uint16_t gprs_rlc_ul_window::receive_bsn(const uint16_t bsn)
{
	m_v_n.mark_received(bsn);
	raise_v_r(bsn);

	return raise_v_q();
}
