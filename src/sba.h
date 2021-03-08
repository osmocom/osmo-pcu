/*
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <osmocom/core/linuxlist.h>

struct gprs_rlcmac_pdch;

/*
 * single block allocation entry
 */
struct gprs_rlcmac_sba {
	struct gprs_rlcmac_pdch *pdch; /* PDCH where the SBA is allocated on*/
	uint32_t fn;
	uint8_t ta;
};

struct gprs_rlcmac_sba *sba_alloc(void *ctx, struct gprs_rlcmac_pdch *pdch, uint8_t ta);
void sba_free(struct gprs_rlcmac_sba *sba);
void sba_timeout(struct gprs_rlcmac_sba *sba);

uint32_t find_sba_rts(struct gprs_rlcmac_pdch *pdch, uint32_t fn, uint8_t block_nr);

#ifdef __cplusplus
}
#endif
