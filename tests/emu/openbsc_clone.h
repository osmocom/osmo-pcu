/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef OPENBSC_CLONE_H
#define OPENBSC_CLONE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

enum gprs_llc_cmd {
	GPRS_LLC_NULL,
	GPRS_LLC_RR,
	GPRS_LLC_ACK,
	GPRS_LLC_RNR,
	GPRS_LLC_SACK,
	GPRS_LLC_DM,
	GPRS_LLC_DISC,
	GPRS_LLC_UA,
	GPRS_LLC_SABM,
	GPRS_LLC_FRMR,
	GPRS_LLC_XID,
	GPRS_LLC_UI,
};

struct gprs_llc_hdr_parsed {
	uint8_t sapi;
	uint8_t is_cmd:1,
		 ack_req:1,
		 is_encrypted:1;
	uint32_t seq_rx;
	uint32_t seq_tx;
	uint32_t fcs;
	uint32_t fcs_calc;
	const uint8_t *data;
	uint16_t data_len;
	uint16_t crc_length;
	enum gprs_llc_cmd cmd;
};

int gprs_llc_hdr_parse(struct gprs_llc_hdr_parsed *ghp, const uint8_t *llc_hdr, int len);

#ifdef __cplusplus
}
#endif

#endif
