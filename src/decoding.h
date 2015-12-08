/* decoding
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

#include <gsm_rlcmac.h>
#include "rlc.h"

#include <stdint.h>

class Decoding {
public:
	struct RlcData {
		uint8_t	offset;
		uint8_t	length;
		bool	is_complete;
	};

	static int tlli_from_ul_data(const uint8_t *data, uint8_t len,
					uint32_t *tlli);
	static int rlc_data_from_ul_data(
		const struct gprs_rlc_ul_data_block_info *rdbi,
		GprsCodingScheme cs, const uint8_t *data, RlcData *chunks,
		unsigned int chunks_size, uint32_t *tlli);
	static uint8_t get_ms_class_by_capability(MS_Radio_Access_capability_t *cap);
	static uint8_t get_egprs_ms_class_by_capability(MS_Radio_Access_capability_t *cap);

	static void extract_rbb(const uint8_t *rbb, char *extracted_rbb);

	static int rlc_parse_ul_data_header(struct gprs_rlc_ul_header_egprs *rlc,
		const uint8_t *data, GprsCodingScheme cs);
	static unsigned int rlc_copy_to_aligned_buffer(
		const struct gprs_rlc_ul_header_egprs *rlc,
		unsigned int data_block_idx,
		const uint8_t *src, uint8_t *buffer);
	static const uint8_t *rlc_get_data_aligned(
		const struct gprs_rlc_ul_header_egprs *rlc,
		unsigned int data_block_idx,
		const uint8_t *src, uint8_t *buffer);
};
