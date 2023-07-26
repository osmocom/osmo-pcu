/* RLC Window (UL TBF), 3GPP TS 44.060
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
#pragma once

#include "rlc.h"
#include "rlc_window.h"

/* The state of a BSN in the send/receive window */
enum gprs_rlc_ul_bsn_state {
	GPRS_RLC_UL_BSN_INVALID,
	GPRS_RLC_UL_BSN_RECEIVED,
	GPRS_RLC_UL_BSN_MISSING,
	GPRS_RLC_UL_BSN_MAX,
};

struct gprs_rlc_v_n {
	void reset(void);

	void mark_received(int bsn);
	void mark_missing(int bsn);

	bool is_received(int bsn) const;

	gprs_rlc_ul_bsn_state state(int bsn) const;
private:
	bool is_state(int bsn, const gprs_rlc_ul_bsn_state state) const;
	void mark(int bsn, const gprs_rlc_ul_bsn_state state);
	gprs_rlc_ul_bsn_state m_v_n[RLC_MAX_SNS/2]; /* receive state array */
};


inline void gprs_rlc_v_n::mark_received(int bsn)
{
	return mark(bsn, GPRS_RLC_UL_BSN_RECEIVED);
}

inline void gprs_rlc_v_n::mark_missing(int bsn)
{
	return mark(bsn, GPRS_RLC_UL_BSN_MISSING);
}

inline bool gprs_rlc_v_n::is_received(int bsn) const
{
	return is_state(bsn, GPRS_RLC_UL_BSN_RECEIVED);
}

inline bool gprs_rlc_v_n::is_state(int bsn, gprs_rlc_ul_bsn_state type) const
{
	return m_v_n[bsn & mod_sns_half()] == type;
}

inline void gprs_rlc_v_n::mark(int bsn, gprs_rlc_ul_bsn_state type)
{
	m_v_n[bsn & mod_sns_half()] = type;
}

inline gprs_rlc_ul_bsn_state gprs_rlc_v_n::state(int bsn) const
{
	return m_v_n[bsn & mod_sns_half()];
}

struct gprs_rlc_ul_window : public gprs_rlc_window {
	const uint16_t v_r(void) const;
	const uint16_t v_q(void) const;

	const void set_v_r(int v_r);
	const void set_v_q(int v_q);
	void reset_state(void);

	const uint16_t ssn(void) const;

	bool is_in_window(uint16_t bsn) const;
	bool is_received(uint16_t bsn) const;

	void update_rbb(char *rbb);
	uint16_t update_egprs_rbb(uint8_t *rbb);
	void raise_v_r_to(int moves);
	void raise_v_r(const uint16_t bsn);
	uint16_t raise_v_q(void);

	void raise_v_q(int incr);

	void receive_bsn(const uint16_t bsn);
	bool invalidate_bsn(const uint16_t bsn);

	uint16_t m_v_r;	/* receive state */
	uint16_t m_v_q;	/* receive window state */

	gprs_rlc_v_n m_v_n;

	gprs_rlc_ul_window(void);
};


inline gprs_rlc_ul_window::gprs_rlc_ul_window(void)
{
	reset_state();
}

inline bool gprs_rlc_ul_window::is_in_window(uint16_t bsn) const
{
	uint16_t offset_v_q;

	/* current block relative to lowest unreceived block */
	offset_v_q = (bsn - m_v_q) & mod_sns();
	/* If out of window (may happen if blocks below V(Q) are received
	 * again. */
	return offset_v_q < ws();
}

inline bool gprs_rlc_ul_window::is_received(uint16_t bsn) const
{
	uint16_t offset_v_r;

	/* Offset to the end of the received window */
	offset_v_r = (m_v_r - 1 - bsn) & mod_sns();
	return is_in_window(bsn) && m_v_n.is_received(bsn) && offset_v_r < ws();
}

inline void gprs_rlc_ul_window::reset_state(void)
{
	m_v_r = 0;
	m_v_q = 0;
	m_v_n.reset();
}

inline const void gprs_rlc_ul_window::set_v_r(int v_r)
{
	m_v_r = v_r;
}

inline const void gprs_rlc_ul_window::set_v_q(int v_q)
{
	m_v_q = v_q;
}

inline const uint16_t gprs_rlc_ul_window::v_r(void) const
{
	return m_v_r;
}

inline const uint16_t gprs_rlc_ul_window::v_q(void) const
{
	return m_v_q;
}

inline const uint16_t gprs_rlc_ul_window::ssn(void) const
{
	return m_v_r;
}

inline void gprs_rlc_ul_window::raise_v_r_to(int moves)
{
	m_v_r = mod_sns(m_v_r + moves);
}

inline void gprs_rlc_ul_window::raise_v_q(int incr)
{
	m_v_q = mod_sns(m_v_q + incr);
}
