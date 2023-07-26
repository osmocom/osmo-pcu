/* RLC Window (DL TBF), 3GPP TS 44.060
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

enum gprs_rlc_dl_bsn_state {
	GPRS_RLC_DL_BSN_INVALID,
	GPRS_RLC_DL_BSN_NACKED,
	GPRS_RLC_DL_BSN_ACKED,
	GPRS_RLC_DL_BSN_UNACKED,
	GPRS_RLC_DL_BSN_RESEND,
	GPRS_RLC_DL_BSN_MAX,
};

/**
 * TODO: for GPRS/EDGE maybe make sns a template parameter
 * so we create specialized versions...
 */
struct gprs_rlc_v_b {
	/* Check for an individual frame */
	bool is_unacked(int bsn) const;
	bool is_nacked(int bsn) const;
	bool is_acked(int bsn) const;
	bool is_resend(int bsn) const;
	bool is_invalid(int bsn) const;
	gprs_rlc_dl_bsn_state get_state(int bsn) const;

	/* Mark a RLC frame for something */
	void mark_unacked(int bsn);
	void mark_nacked(int bsn);
	void mark_acked(int bsn);
	void mark_resend(int bsn);
	void mark_invalid(int bsn);

	void reset(void);


private:
	bool is_state(int bsn, const gprs_rlc_dl_bsn_state state) const;
	void mark(int bsn, const gprs_rlc_dl_bsn_state state);

	gprs_rlc_dl_bsn_state m_v_b[RLC_MAX_SNS/2]; /* acknowledge state array */
};

inline bool gprs_rlc_v_b::is_state(int bsn, const gprs_rlc_dl_bsn_state type) const
{
	return m_v_b[bsn & mod_sns_half()] == type;
}

inline void gprs_rlc_v_b::mark(int bsn, const gprs_rlc_dl_bsn_state type)
{
	m_v_b[bsn & mod_sns_half()] = type;
}

inline bool gprs_rlc_v_b::is_nacked(int bsn) const
{
	return is_state(bsn, GPRS_RLC_DL_BSN_NACKED);
}

inline bool gprs_rlc_v_b::is_acked(int bsn) const
{
	return is_state(bsn, GPRS_RLC_DL_BSN_ACKED);
}

inline bool gprs_rlc_v_b::is_unacked(int bsn) const
{
	return is_state(bsn, GPRS_RLC_DL_BSN_UNACKED);
}

inline bool gprs_rlc_v_b::is_resend(int bsn) const
{
	return is_state(bsn, GPRS_RLC_DL_BSN_RESEND);
}

inline bool gprs_rlc_v_b::is_invalid(int bsn) const
{
	return is_state(bsn, GPRS_RLC_DL_BSN_INVALID);
}

inline gprs_rlc_dl_bsn_state gprs_rlc_v_b::get_state(int bsn) const
{
	return m_v_b[bsn & mod_sns_half()];
}

inline void gprs_rlc_v_b::mark_resend(int bsn)
{
	return mark(bsn, GPRS_RLC_DL_BSN_RESEND);
}

inline void gprs_rlc_v_b::mark_unacked(int bsn)
{
	return mark(bsn, GPRS_RLC_DL_BSN_UNACKED);
}

inline void gprs_rlc_v_b::mark_acked(int bsn)
{
	return mark(bsn, GPRS_RLC_DL_BSN_ACKED);
}

inline void gprs_rlc_v_b::mark_nacked(int bsn)
{
	return mark(bsn, GPRS_RLC_DL_BSN_NACKED);
}

inline void gprs_rlc_v_b::mark_invalid(int bsn)
{
	return mark(bsn, GPRS_RLC_DL_BSN_INVALID);
}

struct gprs_rlc_dl_window : public gprs_rlc_window {
	void reset(void);

	bool window_stalled(void) const;
	bool window_empty(void) const;

	void increment_send(void);
	void raise(int moves);

	const uint16_t v_s(void) const;
	const uint16_t v_s_mod(int offset) const;
	const uint16_t v_a(void) const;
	const uint16_t distance(void) const;

	/* Methods to manage reception */
	int resend_needed(void) const;
	int mark_for_resend(void);
	void update(struct gprs_rlcmac_bts *bts, char *show_rbb, uint16_t ssn,
			uint16_t *lost, uint16_t *received);
	void update(struct gprs_rlcmac_bts *bts, const struct bitvec *rbb,
			uint16_t first_bsn, uint16_t *lost,
			uint16_t *received);
	int move_window(void);
	void show_state(char *show_v_b);
	int count_unacked(void);

	uint16_t m_v_s;	/* send state */
	uint16_t m_v_a;	/* ack state */

	gprs_rlc_v_b m_v_b;

	gprs_rlc_dl_window(void);
};

inline gprs_rlc_dl_window::gprs_rlc_dl_window(void)
	: m_v_s(0)
	, m_v_a(0)
{
	reset();
}

inline const uint16_t gprs_rlc_dl_window::v_s(void) const
{
	return m_v_s;
}

inline const uint16_t gprs_rlc_dl_window::v_s_mod(int offset) const
{
	return mod_sns(m_v_s + offset);
}

inline const uint16_t gprs_rlc_dl_window::v_a(void) const
{
	return m_v_a;
}

inline bool gprs_rlc_dl_window::window_stalled(void) const
{
	return (mod_sns(m_v_s - m_v_a)) == ws();
}

inline bool gprs_rlc_dl_window::window_empty(void) const
{
	return m_v_s == m_v_a;
}

inline void gprs_rlc_dl_window::increment_send(void)
{
	m_v_s = (m_v_s + 1) & mod_sns();
}

inline void gprs_rlc_dl_window::raise(int moves)
{
	m_v_a = (m_v_a + moves) & mod_sns();
}

inline const uint16_t gprs_rlc_dl_window::distance(void) const
{
	return (m_v_s - m_v_a) & mod_sns();
}
