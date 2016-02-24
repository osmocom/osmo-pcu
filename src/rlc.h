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

#include "gprs_coding_scheme.h"

#include <osmocom/core/endian.h>

#include <stdint.h>

#define RLC_GPRS_SNS 128 /* GPRS, must be power of 2 */
#define RLC_GPRS_WS  64 /* max window size */
#define RLC_EGPRS_SNS 2048 /* EGPRS, must be power of 2 */
#define RLC_EGPRS_MIN_WS 64 /* min window size */
#define RLC_EGPRS_MAX_WS 1024 /* min window size */
#define RLC_EGPRS_SNS 2048 /* EGPRS, must be power of 2 */
#define RLC_EGPRS_MAX_BSN_DELTA 512
#define RLC_MAX_SNS  RLC_EGPRS_SNS
#define RLC_MAX_WS   RLC_EGPRS_MAX_WS
#define RLC_MAX_LEN 74 /* MCS-9 data unit */

struct BTS;
struct gprs_rlc_v_n;

/* The state of a BSN in the send/receive window */
enum gprs_rlc_ul_bsn_state {
	GPRS_RLC_UL_BSN_INVALID,
	GPRS_RLC_UL_BSN_RECEIVED,
	GPRS_RLC_UL_BSN_MISSING,
	GPRS_RLC_UL_BSN_MAX,
};

enum gprs_rlc_dl_bsn_state {
	GPRS_RLC_DL_BSN_INVALID,
	GPRS_RLC_DL_BSN_NACKED,
	GPRS_RLC_DL_BSN_ACKED,
	GPRS_RLC_DL_BSN_UNACKED,
	GPRS_RLC_DL_BSN_RESEND,
	GPRS_RLC_DL_BSN_MAX,
};


static inline uint16_t mod_sns_half()
{
	return (RLC_MAX_SNS / 2) - 1;
}

struct gprs_rlc_data_block_info {
	unsigned int data_len; /* EGPRS: N2, GPRS: N2-2, N-2 */
	unsigned int bsn;
	unsigned int ti;
	unsigned int e;
	unsigned int cv; /* FBI == 1 <=> CV == 0 */
	unsigned int pi;
	unsigned int spb;
};

struct gprs_rlc_data_info {
	GprsCodingScheme cs;
	unsigned int r;
	unsigned int si;
	unsigned int tfi;
	unsigned int cps;
	unsigned int rsb;
	unsigned int usf;
	unsigned int es_p;
	unsigned int rrbp;
	unsigned int pr;
	unsigned int num_data_blocks;
	unsigned int with_padding;
	unsigned int data_offs_bits[2];
	struct gprs_rlc_data_block_info block_info[2];
};

struct gprs_rlc_data {
	uint8_t *prepare(size_t block_data_length);
	void put_data(const uint8_t *data, size_t len);

	/* block history */
	uint8_t block[RLC_MAX_LEN];
	/* block len of history */
	uint8_t len;

	struct gprs_rlc_data_block_info block_info;
	GprsCodingScheme cs;
};

void gprs_rlc_data_info_init_dl(struct gprs_rlc_data_info *rlc,
	GprsCodingScheme cs, bool with_padding);
void gprs_rlc_data_info_init_ul(struct gprs_rlc_data_info *rlc,
	GprsCodingScheme cs, bool with_padding);
void gprs_rlc_data_block_info_init(struct gprs_rlc_data_block_info *rdbi,
	GprsCodingScheme cs, bool with_padding);
unsigned int gprs_rlc_mcs_cps(GprsCodingScheme cs, int punct, int punct2,
	int with_padding);
void gprs_rlc_mcs_cps_decode(unsigned int cps, GprsCodingScheme cs,
	int *punct, int *punct2, int *with_padding);

/*
 * I hold the currently transferred blocks and will provide
 * the routines to manipulate these arrays.
 */
struct gprs_rlc {
	gprs_rlc_data *block(int bsn);
	gprs_rlc_data m_blocks[RLC_MAX_SNS/2];
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

	void reset();


private:
	bool is_state(int bsn, const gprs_rlc_dl_bsn_state state) const;
	void mark(int bsn, const gprs_rlc_dl_bsn_state state);

	gprs_rlc_dl_bsn_state m_v_b[RLC_MAX_SNS/2]; /* acknowledge state array */
};


/**
 * TODO: The UL/DL code could/should share a base class.
 */
class gprs_rlc_window {
public:
	gprs_rlc_window();

	const uint16_t mod_sns() const;
	const uint16_t mod_sns(uint16_t bsn) const;
	const uint16_t sns() const;
	const uint16_t ws() const;

	void set_sns(uint16_t sns);
	void set_ws(uint16_t ws);

protected:
	uint16_t m_sns;
	uint16_t m_ws;
};

struct gprs_rlc_dl_window: public gprs_rlc_window {
	void reset();

	bool window_stalled() const;
	bool window_empty() const;

	void increment_send();
	void raise(int moves);

	const uint16_t v_s() const;
	const uint16_t v_s_mod(int offset) const;
	const uint16_t v_a() const;
	const int16_t distance() const;

	/* Methods to manage reception */
	int resend_needed();
	int mark_for_resend();
	void update(BTS *bts, char *show_rbb, uint16_t ssn,
			uint16_t *lost, uint16_t *received);
	void update(BTS *bts, const struct bitvec *rbb,
			uint16_t first_bsn, uint16_t *lost,
			uint16_t *received);
	int move_window();
	void show_state(char *show_rbb);
	int count_unacked();

	uint16_t m_v_s;	/* send state */
	uint16_t m_v_a;	/* ack state */

	gprs_rlc_v_b m_v_b;

	gprs_rlc_dl_window();
};

struct gprs_rlc_v_n {
	void reset();

	void mark_received(int bsn);
	void mark_missing(int bsn);

	bool is_received(int bsn) const;

	gprs_rlc_ul_bsn_state state(int bsn) const;
private:
	bool is_state(int bsn, const gprs_rlc_ul_bsn_state state) const;
	void mark(int bsn, const gprs_rlc_ul_bsn_state state);
	gprs_rlc_ul_bsn_state m_v_n[RLC_MAX_SNS/2]; /* receive state array */
};

struct gprs_rlc_ul_window: public gprs_rlc_window {
	const uint16_t v_r() const;
	const uint16_t v_q() const;

	const uint16_t ssn() const;

	bool is_in_window(uint16_t bsn) const;
	bool is_received(uint16_t bsn) const;

	void update_rbb(char *rbb);
	void raise_v_r_to(int moves);
	void raise_v_r(const uint16_t bsn);
	uint16_t raise_v_q();

	void raise_v_q(int);

	void receive_bsn(const uint16_t bsn);
	bool invalidate_bsn(const uint16_t bsn);

	uint16_t m_v_r;	/* receive state */
	uint16_t m_v_q;	/* receive window state */

	gprs_rlc_v_n m_v_n;

	gprs_rlc_ul_window();
};

extern "C" {
/* TS 04.60  10.2.2 */
#if OSMO_IS_LITTLE_ENDIAN
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

struct rlc_li_field_egprs {
	uint8_t	e:1,
		 li:7;
} __attribute__ ((packed));

struct gprs_rlc_ul_header_egprs_3 {
	uint8_t r:1,
		si:1,
		cv:4,
		tfi_a:2;
	uint8_t tfi_b:3,
		bsn1_a:5;
	uint8_t bsn1_b:6,
		cps_a:2;
	uint8_t cps_b:2,
		spb:2,
		rsb:1,
		pi:1,
		spare:1,
		dummy:1;
} __attribute__ ((packed));

struct gprs_rlc_dl_header_egprs_1 {
	uint8_t usf:3,
		es_p:2,
		rrbp:2,
		tfi_a:1;
	uint8_t tfi_b:4,
		pr:2,
		bsn1_a:2;
	uint8_t bsn1_b:8;
	uint8_t bsn1_c:1,
		bsn2_a:7;
	uint8_t bsn2_b:3,
		cps:5;
} __attribute__ ((packed));

struct gprs_rlc_dl_header_egprs_2 {
	uint8_t usf:3,
		es_p:2,
		rrbp:2,
		tfi_a:1;
	uint8_t tfi_b:4,
		pr:2,
		bsn1_a:2;
	uint8_t bsn1_b:8;
	uint8_t bsn1_c:1,
		cps:3,
		dummy:4;
} __attribute__ ((packed));

struct gprs_rlc_dl_header_egprs_3 {
	uint8_t usf:3,
		es_p:2,
		rrbp:2,
		tfi_a:1;
	uint8_t tfi_b:4,
		pr:2,
		bsn1_a:2;
	uint8_t bsn1_b:8;
	uint8_t bsn1_c:1,
		cps:4,
		spb:2,
		dummy:1;
} __attribute__ ((packed));
#else
#  error "Only little endian headers are supported yet. TODO: add missing structs"
#endif
}

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

inline gprs_rlc_window::gprs_rlc_window()
	: m_sns(RLC_GPRS_SNS)
	, m_ws(RLC_GPRS_WS)
{
}

inline const uint16_t gprs_rlc_window::sns() const
{
	return m_sns;
}

inline const uint16_t gprs_rlc_window::ws() const
{
	return m_ws;
}

inline const uint16_t gprs_rlc_window::mod_sns() const
{
	return sns() - 1;
}

inline const uint16_t gprs_rlc_window::mod_sns(uint16_t bsn) const
{
	return bsn & mod_sns();
}

inline gprs_rlc_dl_window::gprs_rlc_dl_window()
	: m_v_s(0)
	, m_v_a(0)
{
	m_v_b.reset();
}

inline const uint16_t gprs_rlc_dl_window::v_s() const
{
	return m_v_s;
}

inline const uint16_t gprs_rlc_dl_window::v_s_mod(int offset) const
{
	return mod_sns(m_v_s + offset);
}

inline const uint16_t gprs_rlc_dl_window::v_a() const
{
	return m_v_a;
}

inline bool gprs_rlc_dl_window::window_stalled() const
{
	return (mod_sns(m_v_s - m_v_a)) == ws();
}

inline bool gprs_rlc_dl_window::window_empty() const
{
	return m_v_s == m_v_a;
}

inline void gprs_rlc_dl_window::increment_send()
{
	m_v_s = (m_v_s + 1) & mod_sns();
}

inline void gprs_rlc_dl_window::raise(int moves)
{
	m_v_a = (m_v_a + moves) & mod_sns();
}

inline const int16_t gprs_rlc_dl_window::distance() const
{
	return (m_v_s - m_v_a) & mod_sns();
}

inline gprs_rlc_ul_window::gprs_rlc_ul_window()
	: m_v_r(0)
	, m_v_q(0)
{
	m_v_n.reset();
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

inline const uint16_t gprs_rlc_ul_window::v_r() const
{
	return m_v_r;
}

inline const uint16_t gprs_rlc_ul_window::v_q() const
{
	return m_v_q;
}

inline const uint16_t gprs_rlc_ul_window::ssn() const
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

inline gprs_rlc_data *gprs_rlc::block(int bsn)
{
	return &m_blocks[bsn & mod_sns_half()];
}
