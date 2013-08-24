/*
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

struct gprs_rlcmac_bts;

/* dispatch Unitdata.DL messages */
int tbf_handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const char *imsi, const uint8_t ms_class,
		const uint16_t delay_csec, const uint8_t *data, const uint16_t len);

struct gprs_rlcmac_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts,
	int8_t use_trx, uint8_t ms_class,
	uint32_t tlli, uint8_t ta, struct gprs_rlcmac_tbf *dl_tbf);
