/* coding_scheme.h
 *
 * Copyright (C) 2015-2019 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/core/utils.h>

#include <stdbool.h>

enum CodingScheme {
	UNKNOWN,
	/* GPRS Coding Schemes: */
	CS1, CS2, CS3, CS4,
	/* EDGE/EGPRS Modulation and Coding Schemes: */
	MCS1, MCS2, MCS3, MCS4, MCS5, MCS6, MCS7, MCS8, MCS9,
	NUM_SCHEMES
};

enum mcs_kind {
	GPRS,
	EGPRS_GMSK,
	EGPRS,
};

enum egprs_arq_type {
	EGPRS_ARQ1 = 0,
	EGPRS_ARQ2 = 1
};

extern const struct value_string mcs_names[];
const char *mcs_name(enum CodingScheme val);
enum CodingScheme get_retx_mcs(enum CodingScheme initial_mcs, enum CodingScheme commanded_mcs, bool resegment_bit);

bool mcs_is_gprs(enum CodingScheme cs);
bool mcs_is_edge(enum CodingScheme cs);
bool mcs_is_edge_gmsk(enum CodingScheme cs);

uint8_t mcs_chan_code(enum CodingScheme cs);

enum CodingScheme mcs_get_by_size_ul(unsigned size);
enum CodingScheme mcs_get_gprs_by_num(unsigned num);
enum CodingScheme mcs_get_egprs_by_num(unsigned num);
bool mcs_is_valid(enum CodingScheme cs);
bool mcs_is_compat(enum CodingScheme cs, enum CodingScheme o);
bool mcs_is_compat_kind(enum CodingScheme cs, enum mcs_kind mode);

uint8_t mcs_size_ul(enum CodingScheme cs);
uint8_t mcs_size_dl(enum CodingScheme cs);
uint8_t mcs_used_size_ul(enum CodingScheme cs);
uint8_t mcs_used_size_dl(enum CodingScheme cs);
uint8_t mcs_max_bytes_ul(enum CodingScheme cs);
uint8_t mcs_max_bytes_dl(enum CodingScheme cs);
uint8_t mcs_spare_bits_ul(enum CodingScheme cs);
uint8_t mcs_spare_bits_dl(enum CodingScheme cs);
uint8_t mcs_max_data_block_bytes(enum CodingScheme cs);
uint8_t mcs_opt_padding_bits(enum CodingScheme cs);

void mcs_inc_kind(enum CodingScheme *cs, enum mcs_kind mode);
void mcs_dec_kind(enum CodingScheme *cs, enum mcs_kind mode);
void mcs_inc(enum CodingScheme *cs);
void mcs_dec(enum CodingScheme *cs);

bool mcs_is_family_compat(enum CodingScheme cs, enum CodingScheme o);
void mcs_dec_to_single_block(enum CodingScheme *cs, bool *need_stuffing);

enum HeaderType {
	HEADER_INVALID,
	HEADER_GPRS_CONTROL,
	HEADER_GPRS_DATA,
	HEADER_EGPRS_DATA_TYPE_1,
	HEADER_EGPRS_DATA_TYPE_2,
	HEADER_EGPRS_DATA_TYPE_3,
	NUM_HEADER_TYPES
};

enum HeaderType mcs_header_type(enum CodingScheme mcs);

uint8_t num_data_blocks(enum HeaderType ht);
uint8_t num_data_header_bits_UL(enum HeaderType ht);
uint8_t num_data_header_bits_DL(enum HeaderType ht);
uint8_t num_data_block_header_bits(enum HeaderType ht);

const char *mode_name(enum mcs_kind val);
