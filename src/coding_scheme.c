/* coding_scheme.c
 *
 * Copyright (C) 2019 by sysmocom s.f.m.c. GmbH
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

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>

#include "coding_scheme.h"

const struct value_string mcs_names[] = {
	{ UNKNOWN, "UNKNOWN" },
	{ CS1, "CS-1" },
	{ CS2, "CS-2" },
	{ CS3, "CS-3" },
	{ CS4, "CS-4" },
	{ MCS1, "MCS-1" },
	{ MCS2, "MCS-2" },
	{ MCS3, "MCS-3" },
	{ MCS4, "MCS-4" },
	{ MCS5, "MCS-5" },
	{ MCS6, "MCS-6" },
	{ MCS7, "MCS-7" },
	{ MCS8, "MCS-8" },
	{ MCS9, "MCS-9" },
	{ 0, NULL }
};

enum Family {
	FAMILY_INVALID,
	FAMILY_A,
	FAMILY_B,
	FAMILY_C,
};

static struct {
	struct {
		uint8_t bytes;
		uint8_t ext_bits;
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_bytes;
	uint8_t optional_padding_bits;
	enum HeaderType data_hdr;
	enum Family family;
} mcs_info[NUM_SCHEMES] = {
	{{0, 0},   {0, 0},    0,  0,
		HEADER_INVALID, FAMILY_INVALID},
	{{23, 0},  {23, 0},  20,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},
	{{33, 7},  {33, 7},  30,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},
	{{39, 3},  {39, 3},  36,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},
	{{53, 7},  {53, 7},  50,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},

	{{26, 1},  {26, 1},  22,  0,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_C},
	{{32, 1},  {32, 1},  28,  0,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_B},
	{{41, 1},  {41, 1},  37, 48,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_A},
	{{48, 1},  {48, 1},  44,  0,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_C},

	{{60, 7},  {59, 6},  56,  0,
		HEADER_EGPRS_DATA_TYPE_2, FAMILY_B},
	{{78, 7},  {77, 6},  74, 48,
		HEADER_EGPRS_DATA_TYPE_2, FAMILY_A},
	{{118, 2}, {117, 4}, 56,  0,
		HEADER_EGPRS_DATA_TYPE_1, FAMILY_B},
	{{142, 2}, {141, 4}, 68,  0,
		HEADER_EGPRS_DATA_TYPE_1, FAMILY_A},
	{{154, 2}, {153, 4}, 74,  0,
		HEADER_EGPRS_DATA_TYPE_1, FAMILY_A},
};

const char *mcs_name(enum CodingScheme val) {
	return get_value_string(mcs_names, val);
}

bool mcs_is_gprs(enum CodingScheme cs)
{
	return CS1 <= cs && cs <= CS4;
}

bool mcs_is_edge(enum CodingScheme cs)
{
	return MCS1 <= cs && cs <= MCS9;
}

bool mcs_is_edge_gmsk(enum CodingScheme cs)
{
	if (mcs_is_edge(cs))
		return cs <= MCS4;

	return false;
}

/* Return 3GPP TS 44.060 §12.10d (EDGE) or Table 11.2.28.2 (GPRS) Channel Coding Command value */
uint8_t mcs_chan_code(enum CodingScheme cs)
{
	if (mcs_is_gprs(cs))
		return cs - CS1;

	if (mcs_is_edge(cs))
		return cs - MCS1;

	/* Defaults to (M)CS1 */
	return 0;
}

enum CodingScheme mcs_get_by_size_ul(unsigned size)
{
	switch (size) {
		case 23: return CS1;
		case 27: return MCS1;
		case 33: return MCS2;
		case 34: return CS2;
		case 40: return CS3;
		case 42: return MCS3;
		case 49: return MCS4;
		case 54: return CS4;
		case 61: return MCS5;
		case 79: return MCS6;
		case 119: return MCS7;
		case 143: return MCS8;
		case 155: return MCS9;
		default: return UNKNOWN;
	}
}

enum CodingScheme mcs_get_gprs_by_num(unsigned num)
{
	if (num < 1 || num > 4)
		return UNKNOWN;
	return CS1 + (num - 1);
}

enum CodingScheme mcs_get_egprs_by_num(unsigned num)
{
	if (num < 1 || num > 9)
		return UNKNOWN;
	return MCS1 + (num - 1);
}

bool mcs_is_valid(enum CodingScheme cs)
{
	return UNKNOWN < cs && cs <= MCS9;
}

bool mcs_is_compat_kind(enum CodingScheme cs, enum mcs_kind mode)
{
	switch (mode) {
	case GPRS: return mcs_is_gprs(cs);
	case EGPRS_GMSK: return mcs_is_edge_gmsk(cs);
	case EGPRS: return mcs_is_edge(cs);
	}

	return false;
}

bool mcs_is_compat(enum CodingScheme cs, enum CodingScheme o)
{
	return (mcs_is_gprs(cs) && mcs_is_gprs(o)) || (mcs_is_edge(cs) && mcs_is_edge(o));
}

uint8_t mcs_size_ul(enum CodingScheme cs)
{
	return mcs_info[cs].uplink.bytes + (mcs_spare_bits_ul(cs) ? 1 : 0);
}

uint8_t mcs_size_dl(enum CodingScheme cs)
{
	return mcs_info[cs].downlink.bytes + (mcs_spare_bits_dl(cs) ? 1 : 0);
}

uint8_t mcs_used_size_ul(enum CodingScheme cs)
{
	if (mcs_info[cs].data_hdr == HEADER_GPRS_DATA)
		return mcs_info[cs].uplink.bytes;
	else
		return mcs_size_ul(cs);
}

uint8_t mcs_used_size_dl(enum CodingScheme cs)
{
	if (mcs_info[cs].data_hdr == HEADER_GPRS_DATA)
		return mcs_info[cs].downlink.bytes;
	else
		return mcs_size_dl(cs);
}

uint8_t mcs_max_bytes_ul(enum CodingScheme cs)
{
	return mcs_info[cs].uplink.bytes;
}

uint8_t mcs_max_bytes_dl(enum CodingScheme cs)
{
	return mcs_info[cs].downlink.bytes;
}

uint8_t mcs_spare_bits_ul(enum CodingScheme cs)
{
	return mcs_info[cs].uplink.ext_bits;
}

uint8_t mcs_spare_bits_dl(enum CodingScheme cs)
{
	return mcs_info[cs].downlink.ext_bits;
}

uint8_t mcs_max_data_block_bytes(enum CodingScheme cs)
{
	return mcs_info[cs].data_bytes;
}

uint8_t mcs_opt_padding_bits(enum CodingScheme cs)
{
	return mcs_info[cs].optional_padding_bits;
}

void mcs_inc_kind(enum CodingScheme *cs, enum mcs_kind mode)
{
	if (!mcs_is_compat_kind(*cs, mode))
		/* This should not happen. TODO: Use assert? */
		return;

	enum CodingScheme new_cs = *cs + 1;
	if (!mcs_is_compat_kind(new_cs, mode))
		/* Clipping, do not change the value */
		return;

	*cs = new_cs;
}

void mcs_dec_kind(enum CodingScheme *cs, enum mcs_kind mode)
{
	if (!mcs_is_compat_kind(*cs, mode))
		/* This should not happen. TODO: Use assert? */
		return;

	enum CodingScheme new_cs = *cs - 1;
	if (!mcs_is_compat_kind(new_cs, mode))
		/* Clipping, do not change the value */
		return;

	*cs = new_cs;
}

void mcs_inc(enum CodingScheme *cs)
{
	if (mcs_is_gprs(*cs) && *cs == CS4)
		return;

	if (mcs_is_edge(*cs) && *cs == MCS9)
		return;

	if (!mcs_is_valid(*cs))
		return;

	*cs = *cs + 1;
}

void mcs_dec(enum CodingScheme *cs)
{
	if (mcs_is_gprs(*cs) && *cs == CS1)
		return;

	if (mcs_is_edge(*cs) && *cs == MCS1)
		return;

	if (!mcs_is_valid(*cs))
		return;

	*cs = *cs - 1;
}

bool mcs_is_family_compat(enum CodingScheme cs, enum CodingScheme o)
{
	if (cs == o)
		return true;

	if (mcs_info[cs].family == FAMILY_INVALID)
		return false;

	return mcs_info[cs].family == mcs_info[o].family;
}

void mcs_dec_to_single_block(enum CodingScheme *cs, bool *need_stuffing)
{
	switch (*cs) {
	case MCS7: *need_stuffing = false; *cs = MCS5; break;
	case MCS8: *need_stuffing =  true; *cs = MCS6; break;
	case MCS9: *need_stuffing = false; *cs = MCS6; break;
	default:   *need_stuffing = false; break;
	}
}

static struct {
	struct {
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_block_header_bits;
	uint8_t num_blocks;
	const char *name;
} hdr_type_info[NUM_HEADER_TYPES] = {
	{ { 0 },         { 0 },         0, 0, "INVALID" },
	{ { 1 * 8 + 0 }, { 1 * 8 + 0 }, 0, 0, "CONTROL" },
	{ { 3 * 8 + 0 }, { 3 * 8 + 0 }, 0, 1, "GPRS_DATA" },
	{ { 5 * 8 + 6 }, { 5 * 8 + 0 }, 2, 2, "EGPRS_DATA_TYPE1" },
	{ { 4 * 8 + 5 }, { 3 * 8 + 4 }, 2, 1, "EGPRS_DATA_TYPE2" },
	{ { 3 * 8 + 7 }, { 3 * 8 + 7 }, 2, 1, "EGPRS_DATA_TYPE3" },
};

enum HeaderType mcs_header_type(enum CodingScheme mcs)
{
	return mcs_info[mcs].data_hdr;
}

uint8_t num_data_blocks(enum HeaderType ht)
{
	OSMO_ASSERT(ht < NUM_HEADER_TYPES);
	return hdr_type_info[ht].num_blocks;
}

uint8_t num_data_header_bits_UL(enum HeaderType ht)
{
	OSMO_ASSERT(ht < NUM_HEADER_TYPES);
	return hdr_type_info[ht].uplink.data_header_bits;
}

uint8_t num_data_header_bits_DL(enum HeaderType ht)
{
	OSMO_ASSERT(ht < NUM_HEADER_TYPES);
	return hdr_type_info[ht].downlink.data_header_bits;
}

uint8_t num_data_block_header_bits(enum HeaderType ht)
{
	OSMO_ASSERT(ht < NUM_HEADER_TYPES);
	return hdr_type_info[ht].data_block_header_bits;
}

const struct value_string mode_names[] = {
	{ GPRS, "GPRS" },
	{ EGPRS_GMSK, "EGPRS_GMSK-only"},
	{ EGPRS, "EGPRS"},
	{ 0, NULL }
};

const char *mode_name(enum mcs_kind val) {
	return get_value_string(mode_names, val);
}

/* FIXME: take into account padding and special cases of commanded MCS (MCS-6-9 and MCS-5-7) */
enum CodingScheme get_retx_mcs(enum CodingScheme initial_mcs, enum CodingScheme commanded_mcs, bool resegment_bit)
{
	OSMO_ASSERT(mcs_is_edge(initial_mcs));
	OSMO_ASSERT(mcs_is_edge(commanded_mcs));
	OSMO_ASSERT(NUM_SCHEMES - MCS1 == 9);

	if (resegment_bit) { /* 3GPP TS 44.060 Table 8.1.1.1, reflected over antidiagonal */
		enum CodingScheme egprs_reseg[NUM_SCHEMES - MCS1][NUM_SCHEMES - MCS1] = {
			{ MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1 },
			{ MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2 },
			{ MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3 },
			{ MCS1, MCS1, MCS1, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4 },
			{ MCS2, MCS2, MCS2, MCS2, MCS5, MCS5, MCS7, MCS7, MCS7 },
			{ MCS3, MCS3, MCS3, MCS3, MCS3, MCS6, MCS6, MCS6, MCS9 },
			{ MCS2, MCS2, MCS2, MCS2, MCS5, MCS5, MCS7, MCS7, MCS7 },
			{ MCS3, MCS3, MCS3, MCS3, MCS3, MCS6, MCS6, MCS8, MCS8 },
			{ MCS3, MCS3, MCS3, MCS3, MCS3, MCS6, MCS6, MCS6, MCS9 },
		};
		return egprs_reseg[mcs_chan_code(initial_mcs)][mcs_chan_code(commanded_mcs)];
	} else { /* 3GPP TS 44.060 Table 8.1.1.2, reflected over antidiagonal */
		enum CodingScheme egprs_no_reseg[NUM_SCHEMES - MCS1][NUM_SCHEMES - MCS1] = {
			{ MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1 },
			{ MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2 },
			{ MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3 },
			{ MCS4, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4 },
			{ MCS5, MCS5, MCS5, MCS5, MCS5, MCS5, MCS7, MCS7, MCS7 },
			{ MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS9 },
			{ MCS5, MCS5, MCS5, MCS5, MCS5, MCS5, MCS7, MCS7, MCS7 },
			{ MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS8, MCS8 },
			{ MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS9 },
		};
		return egprs_no_reseg[mcs_chan_code(initial_mcs)][mcs_chan_code(commanded_mcs)];
	}
}
