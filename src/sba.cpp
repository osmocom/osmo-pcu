/* sba.cpp
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

#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <bts.h>

extern "C" {
#include <osmocom/core/talloc.h>
}

#include <errno.h>

extern void *tall_pcu_ctx;

/* starting time for assigning single slot
 * This offset must be a multiple of 13. */
#define AGCH_START_OFFSET 52

LLIST_HEAD(gprs_rlcmac_sbas);

int sba_alloc(struct gprs_rlcmac_bts *bts,
		uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta)
{

	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_sba *sba;
	uint8_t trx, ts;
	uint32_t fn;

	sba = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_sba);
	if (!sba)
		return -ENOMEM;

	for (trx = 0; trx < 8; trx++) {
		for (ts = 0; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->is_enabled())
				continue;
			break;
		}
		if (ts < 8)
			break;
	}
	if (trx == 8) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		talloc_free(sba);
		return -EINVAL;
	}

	fn = (pdch->last_rts_fn + AGCH_START_OFFSET) % 2715648;

	sba->trx = trx;
	sba->ts = ts;
	sba->fn = fn;
	sba->ta = ta;

	llist_add(&sba->list, &gprs_rlcmac_sbas);

	*_trx = trx;
	*_ts = ts;
	*_fn = fn;
	return 0;
}

struct gprs_rlcmac_sba *sba_find(uint8_t trx, uint8_t ts, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	llist_for_each_entry(sba, &gprs_rlcmac_sbas, list) {
		if (sba->trx == trx && sba->ts == ts && sba->fn == fn)
			return sba;
	}

	return NULL;
}

uint32_t sched_sba(uint8_t trx, uint8_t ts, uint32_t fn, uint8_t block_nr)
{
	uint32_t sba_fn;
	struct gprs_rlcmac_sba *sba;

	/* check special TBF for events */
	sba_fn = fn + 4;
	if ((block_nr % 3) == 2)
		sba_fn ++;
	sba_fn = sba_fn % 2715648;
	sba = sba_find(trx, ts, sba_fn);
	if (sba)
		return sba_fn;

	return 0xffffffff;
}

int gprs_rlcmac_sba_timeout(struct gprs_rlcmac_sba *sba)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "Poll timeout for SBA\n");
	llist_del(&sba->list);
	talloc_free(sba);

	return 0;
}

