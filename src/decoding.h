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

#ifdef __cplusplus
extern "C" {
#endif

#include "gsm_rlcmac.h"
#include "coding_scheme.h"

#ifdef __cplusplus
}
#endif

#include <stdint.h>

struct bitvec;

#ifdef __cplusplus

class Decoding {
public:
	/* represents (parts) LLC PDUs within one RLC Data block */
	struct RlcData {
		uint8_t	offset;
		uint8_t	length;
		bool	is_complete; /* if this PDU ends in this block */
	};

	static int rlc_data_from_ul_data(
		const struct gprs_rlc_data_block_info *rdbi,
		enum CodingScheme cs, const uint8_t *data, RlcData *chunks,
		unsigned int chunks_size, uint32_t *tlli);

	static void extract_rbb(const struct bitvec *rbb, char *show_rbb);
	static int rlc_parse_ul_data_header_egprs_type_3(
		struct gprs_rlc_data_info *rlc,
		const uint8_t *data,
		const enum CodingScheme &cs);
	static int rlc_parse_ul_data_header_egprs_type_2(
		struct gprs_rlc_data_info *rlc,
		const uint8_t *data,
		const enum CodingScheme &cs);
	static int rlc_parse_ul_data_header_egprs_type_1(
		struct gprs_rlc_data_info *rlc,
		const uint8_t *data,
		const enum CodingScheme &cs);
	static int rlc_parse_ul_data_header_gprs(
		struct gprs_rlc_data_info *rlc,
		const uint8_t *data,
		const enum CodingScheme &cs);
	static int rlc_parse_ul_data_header(struct gprs_rlc_data_info *rlc,
		const uint8_t *data, enum CodingScheme cs);
	static unsigned int rlc_copy_to_aligned_buffer(
		const struct gprs_rlc_data_info *rlc,
		unsigned int data_block_idx,
		const uint8_t *src, uint8_t *buffer);
	static const uint8_t *rlc_get_data_aligned(
		const struct gprs_rlc_data_info *rlc,
		unsigned int data_block_idx,
		const uint8_t *src, uint8_t *buffer);
	static int decode_egprs_acknack_bits(
		const EGPRS_AckNack_Desc_t *desc,
		struct bitvec *bits, int *bsn_begin, int *bsn_end,
		struct gprs_rlc_dl_window *window);
	static int decode_gprs_acknack_bits(
		const Ack_Nack_Description_t *desc,
		bitvec *bits, int *bsn_begin, int *bsn_end,
		gprs_rlc_dl_window *window);
};

#endif /* #ifdef __cplusplus */

#ifdef __cplusplus
extern "C" {
#endif

uint8_t get_ms_class_by_capability(MS_Radio_Access_capability_t *cap);
uint8_t get_egprs_ms_class_by_capability(MS_Radio_Access_capability_t *cap);

#ifdef __cplusplus
}
#endif
