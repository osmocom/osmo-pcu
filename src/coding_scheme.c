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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
