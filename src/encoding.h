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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#pragma once

#include <stdint.h>
#include <gsm_rlcmac.h>

struct gprs_rlcmac_bts;
struct gprs_rlcmac_tbf;
struct bitvec;

/**
 * I help with encoding data into CSN1 messages.
 * TODO: Nobody can remember a function signature like this. One should
 * fill out a struct with the request parameters and then hand the struct
 * to the code.
 */
class Encoding {
public:
	static int write_immediate_assignment(
			struct gprs_rlcmac_bts *bts,
			bitvec * dest, uint8_t downlink, uint8_t ra, 
		        uint32_t ref_fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, 
		        uint8_t tfi, uint8_t usf, uint32_t tlli, uint8_t polling,
			uint32_t fn, uint8_t single_block, uint8_t alpha, uint8_t gamma,
			int8_t ta_idx);

	static void write_packet_uplink_assignment(
			struct gprs_rlcmac_bts *bts,
			bitvec * dest, uint8_t old_tfi,
			uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli, 
			struct gprs_rlcmac_ul_tbf *tbf, uint8_t poll, uint8_t alpha,
			uint8_t gamma, int8_t ta_idx, int8_t use_egprs);

	static void write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t old_tfi,
			uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll,
			uint8_t alpha, uint8_t gamma, int8_t ta_idx, uint8_t ta_ts);

	static void encode_rbb(const char *show_rbb, uint8_t *rbb);

	static void write_packet_uplink_ack(struct gprs_rlcmac_bts *bts, RlcMacDownlink_t * block, struct gprs_rlcmac_ul_tbf *tbf,
		        uint8_t final);

	static int write_paging_request(bitvec * dest, uint8_t *ptmsi, uint16_t ptmsi_len);

	static unsigned write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
			uint8_t *identity, uint8_t chan_needed);

	static unsigned write_packet_paging_request(bitvec * dest);
};
