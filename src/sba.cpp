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

#include <sba.h>
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

SBAController::SBAController(BTS &bts)
	: m_bts(bts)
{
	INIT_LLIST_HEAD(&m_sbas);
}

int SBAController::alloc(
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
			pdch = &m_bts.bts_data()->trx[trx].pdch[ts];
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

	sba->trx_no = trx;
	sba->ts_no = ts;
	sba->fn = fn;
	sba->ta = ta;

	llist_add(&sba->list, &m_sbas);

	*_trx = trx;
	*_ts = ts;
	*_fn = fn;
	return 0;
}

gprs_rlcmac_sba *SBAController::find(uint8_t trx, uint8_t ts, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	llist_for_each_entry(sba, &m_sbas, list) {
		if (sba->trx_no == trx && sba->ts_no == ts && sba->fn == fn)
			return sba;
	}

	return NULL;
}

gprs_rlcmac_sba *SBAController::find(const gprs_rlcmac_pdch *pdch, uint32_t fn)
{
	return find(pdch->trx_no(), pdch->ts_no, fn);
}

uint32_t SBAController::sched(uint8_t trx, uint8_t ts, uint32_t fn, uint8_t block_nr)
{
	uint32_t sba_fn;
	struct gprs_rlcmac_sba *sba;

	/* check special TBF for events */
	sba_fn = fn + 4;
	if ((block_nr % 3) == 2)
		sba_fn ++;
	sba_fn = sba_fn % 2715648;
	sba = find(trx, ts, sba_fn);
	if (sba)
		return sba_fn;

	return 0xffffffff;
}

int SBAController::timeout(struct gprs_rlcmac_sba *sba)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "Poll timeout for SBA\n");
	llist_del(&sba->list);
	talloc_free(sba);

	return 0;
}

void SBAController::free_resources(struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_sba *sba, *sba2;
	const uint8_t trx_no = pdch->trx->trx_no;
	const uint8_t ts_no = pdch->ts_no;

	llist_for_each_entry_safe(sba, sba2, &m_sbas, list) {
		if (sba->trx_no == trx_no && sba->ts_no == ts_no) {
			llist_del(&sba->list);
			talloc_free(sba);
		}
	}
}
