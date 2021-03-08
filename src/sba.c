/* sba.c
 *
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <sba.h>
#include <gprs_debug.h>
#include <bts.h>
#include <pcu_utils.h>
#include <pdch.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm_utils.h>

#include "pdch.h"
#include "pdch_ul_controller.h"

/* starting time for assigning single slot
 * This offset must be a multiple of 13. */
#define AGCH_START_OFFSET 52


struct gprs_rlcmac_sba *sba_alloc(void *ctx, struct gprs_rlcmac_pdch *pdch, uint8_t ta)
{
	struct gprs_rlcmac_sba *sba;
	sba = talloc_zero(ctx, struct gprs_rlcmac_sba);
	if (!sba)
		return NULL;

	sba->pdch = pdch;
	sba->ta = ta;

	/* TODO: request ULC for next available FN instead of hardcoded AGCH_START_OFFSET */
	sba->fn = next_fn(pdch->last_rts_fn, AGCH_START_OFFSET);

	pdch_ulc_reserve_sba(pdch->ulc, sba);
	return sba;
}

/* Internal use */
static void sba_free_norelease(struct gprs_rlcmac_sba *sba)
{
	bts_do_rate_ctr_inc(sba->pdch->trx->bts, CTR_SBA_FREED);
	talloc_free(sba);
}

void sba_free(struct gprs_rlcmac_sba *sba)
{
	if (pdch_ulc_release_fn(sba->pdch->ulc, sba->fn) < 0)
		LOGPDCH(sba->pdch, DRLCMAC, LOGL_NOTICE,
			"Trying to release unregistered SBA (FN=%u, TA=%u)\n",
			sba->fn, sba->ta);
	sba_free_norelease(sba);
}

void sba_timeout(struct gprs_rlcmac_sba *sba)
{
	/* Upon timeout, the UL Controller node is already released */
	sba_free_norelease(sba);
}

uint32_t find_sba_rts(struct gprs_rlcmac_pdch *pdch, uint32_t fn, uint8_t block_nr)
{
	uint32_t sba_fn = rts_next_fn(fn, block_nr);
	struct gprs_rlcmac_sba *sba;

	sba = pdch_ulc_get_sba(pdch->ulc, sba_fn);
	if (sba)
		return sba_fn;

	return 0xffffffff;
}
