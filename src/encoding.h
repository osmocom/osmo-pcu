/* encoding.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/gsm/l1sap.h>
#include "coding_scheme.h"
#include "gsm_rlcmac.h"
#ifdef __cplusplus
}
#endif

struct gprs_rlcmac_tbf;
struct bitvec;
struct gprs_llc;
struct gprs_rlc_data_block_info;

#ifdef __cplusplus
/**
 * I help with encoding data into CSN1 messages.
 * TODO: Nobody can remember a function signature like this. One should
 * fill out a struct with the request parameters and then hand the struct
 * to the code.
 */
class Encoding {
public:
	static int write_immediate_assignment(
			const struct gprs_rlcmac_pdch *pdch,
			const struct gprs_rlcmac_tbf *tbf,
			bitvec * dest, bool downlink, uint16_t ra,
			uint32_t ref_fn, uint8_t ta,
			uint8_t usf, bool polling,
			uint32_t fn, uint8_t alpha, uint8_t gamma,
			int8_t ta_idx,
			enum ph_burst_type burst_type);

	static int write_immediate_assignment_reject(
			bitvec *dest, uint16_t ra,
			uint32_t ref_fn,
			enum ph_burst_type burst_type,
			uint8_t t3142
		);

	static void encode_rbb(const char *show_rbb, bitvec *rbb);

	static unsigned write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
			uint8_t *identity, uint8_t chan_needed);

	static unsigned write_packet_paging_request(bitvec * dest);

	static int rlc_write_dl_data_header(
			const struct gprs_rlc_data_info *rlc,
			uint8_t *data);
	static unsigned int rlc_copy_from_aligned_buffer(
			const struct gprs_rlc_data_info *rlc,
			unsigned int data_block_idx,
			uint8_t *dst, const uint8_t *buffer);

	enum AppendResult {
		AR_NEED_MORE_BLOCKS,
		AR_COMPLETED_SPACE_LEFT,
		AR_COMPLETED_BLOCK_FILLED,
	};

	static AppendResult rlc_data_to_dl_append(
		struct gprs_rlc_data_block_info *rdbi, enum CodingScheme cs,
		gprs_llc *llc, int *offset, int *num_chunks,
		uint8_t *data, bool is_final, int *count_payload);
	static void rlc_data_to_dl_append_egprs_li_padding(
		const struct gprs_rlc_data_block_info *rdbi,
		int *offset, int *num_chunks, uint8_t *data_block);
};

#endif /* ifdef __cplusplus */

#ifdef __cplusplus
extern "C" {
#endif

void write_packet_access_reject(struct bitvec *dest, uint32_t tlli, unsigned long t3172_ms);

int write_paging_request(struct bitvec *dest, const struct osmo_mobile_identity *mi);

void write_packet_uplink_assignment(RlcMacDownlink_t *block, uint8_t old_tfi,
				    uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
				    const struct gprs_rlcmac_ul_tbf *tbf, uint8_t poll,
				    uint8_t rrbp, uint8_t alpha, uint8_t gamma, int8_t ta_idx,
				    bool use_egprs);

void write_packet_downlink_assignment(RlcMacDownlink_t * block, bool old_tfi_is_valid,
				      uint8_t old_tfi, uint8_t old_downlink,
				      const struct gprs_rlcmac_dl_tbf *tbf, uint8_t poll,
				      uint8_t rrbp, uint8_t alpha, uint8_t gamma,
				      int8_t ta_idx, uint8_t ta_ts, bool use_egprs,
				      uint8_t control_ack);

void write_packet_uplink_ack(struct bitvec *dest, struct gprs_rlcmac_ul_tbf *tbf,
			     bool is_final, uint8_t rrbp);

void write_packet_neighbour_cell_data(RlcMacDownlink_t *block,
		bool tfi_is_dl, uint8_t tfi, uint8_t container_id,
		uint8_t container_idx, PNCDContainer_t *container);

void write_packet_cell_change_continue(RlcMacDownlink_t *block, uint8_t poll, uint8_t rrbp,
				       bool tfi_is_dl, uint8_t tfi, bool exist_id,
				       uint16_t arfcn, uint8_t bsic, uint8_t container_id);

#ifdef __cplusplus
}
#endif
