/* rlc header descriptions
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
#pragma once

#include <stdint.h>

#define RLC_MAX_SNS 128 /* GPRS, must be power of 2 */
#define RLC_MAX_WS  64 /* max window size */
#define RLC_MAX_LEN 54 /* CS-4 including spare bits */

class BTS;

struct gprs_rlc_data {
	uint8_t *prepare(size_t block_data_length);

	/* block history */
	uint8_t block[RLC_MAX_LEN];
	/* block len of history */
	uint8_t len;
};

/*
 * I hold the currently transferred blocks and will provide
 * the routines to manipulate these arrays.
 */
struct gprs_rlc {
	gprs_rlc_data blocks[RLC_MAX_SNS/2];
};

/**
 * TODO: for GPRS/EDGE maybe make sns a template parameter
 * so we create specialized versions...
 */
struct gprs_rlc_v_b {
	int resend_needed(const uint16_t acked, const uint16_t sent,
			const uint16_t mod_sns, const uint16_t mod_sns_half);
	int mark_for_resend(const uint16_t acked, const uint16_t sent,
			const uint16_t mod_sns, const uint16_t mod_sns_half);
	void update(BTS *bts, char *show_rbb, uint8_t ssn, const uint16_t v_a,
			const uint16_t mod_sns, const uint16_t mod_sns_half,
			uint16_t *lost, uint16_t *received);

	/* Check for an individual frame */
	bool is_unacked(int index) const;
	bool is_nacked(int index) const;
	bool is_acked(int index) const;
	bool is_resend(int index) const;
	bool is_invalid(int index) const;

	char state(int index) const;

	/* Mark a RLC frame for something */
	void mark_unacked(int index);
	void mark_nacked(int index);
	void mark_acked(int index);
	void mark_resend(int index);
	void mark_invalid(int index);

	void reset();

private:
	bool is_state(int index, const char state) const;
	void mark(int index, const char state);

	char m_v_b[RLC_MAX_SNS/2]; /* acknowledge state array */
};


extern "C" {
/* TS 04.60  10.2.2 */
struct rlc_ul_header {
	uint8_t	r:1,
		 si:1,
		 cv:4,
		 pt:2;
	uint8_t	ti:1,
		 tfi:5,
		 pi:1,
		 spare:1;
	uint8_t	e:1,
		 bsn:7;
} __attribute__ ((packed));

struct rlc_dl_header {
	uint8_t	usf:3,
		 s_p:1,
		 rrbp:2,
		 pt:2;
	uint8_t	fbi:1,
		 tfi:5,
		 pr:2;
	uint8_t	e:1,
		 bsn:7;
} __attribute__ ((packed));

struct rlc_li_field {
	uint8_t	e:1,
		 m:1,
		 li:6;
} __attribute__ ((packed));
}

inline bool gprs_rlc_v_b::is_state(int index, const char type) const
{
	return m_v_b[index] == type;
}

inline void gprs_rlc_v_b::mark(int index, const char type)
{
	m_v_b[index] = type;
}

inline char gprs_rlc_v_b::state(int index) const
{
	return m_v_b[index];
}

inline bool gprs_rlc_v_b::is_nacked(int index) const
{
	return is_state(index, 'N');
}

inline bool gprs_rlc_v_b::is_acked(int index) const
{
	return is_state(index, 'A');
}

inline bool gprs_rlc_v_b::is_unacked(int index) const
{
	return is_state(index, 'U');
}

inline bool gprs_rlc_v_b::is_resend(int index) const
{
	return is_state(index, 'X');
}

inline bool gprs_rlc_v_b::is_invalid(int index) const
{
	return is_state(index, 'I');
}

inline void gprs_rlc_v_b::mark_resend(int index)
{
	return mark(index, 'X');
}

inline void gprs_rlc_v_b::mark_unacked(int index)
{
	return mark(index, 'U');
}

inline void gprs_rlc_v_b::mark_acked(int index)
{
	return mark(index, 'A');
}

inline void gprs_rlc_v_b::mark_nacked(int index)
{
	return mark(index, 'N');
}

inline void gprs_rlc_v_b::mark_invalid(int index)
{
	return mark(index, 'I');
}
