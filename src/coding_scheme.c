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
