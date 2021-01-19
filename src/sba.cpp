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
#include <gprs_debug.h>
#include <bts.h>
#include <pcu_utils.h>
#include <pdch.h>

extern "C" {
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm_utils.h>
}

#include <errno.h>

extern void *tall_pcu_ctx;

/* starting time for assigning single slot
 * This offset must be a multiple of 13. */
#define AGCH_START_OFFSET 52

SBAController::SBAController(struct gprs_rlcmac_bts &bts)
	: m_bts(bts)
{
	INIT_LLIST_HEAD(&m_sbas);
}

int SBAController::alloc(
		uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta)
{

	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_sba *sba;
	int8_t trx, ts;
	uint32_t fn;

	if (!gsm48_ta_is_valid(ta))
		return -EINVAL;

	sba = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_sba);
	if (!sba)
		return -ENOMEM;

	for (trx = 0; trx < 8; trx++) {
		for (ts = 7; ts >= 0; ts--) {
			pdch = &m_bts.trx[trx].pdch[ts];
			if (!pdch->is_enabled())
				continue;
			break;
		}
		if (ts >= 0)
			break;
	}
	if (trx == 8) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		talloc_free(sba);
		return -EINVAL;
	}

	fn = next_fn(pdch->last_rts_fn, AGCH_START_OFFSET);

	sba->trx_no = trx;
	sba->ts_no = ts;
	sba->fn = fn;
	sba->ta = ta;

	llist_add(&sba->list, &m_sbas);
	bts_do_rate_ctr_inc(&m_bts, CTR_SBA_ALLOCATED);

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
	uint32_t sba_fn = fn + 4;
	struct gprs_rlcmac_sba *sba;

	/* check special TBF for events */
	if ((block_nr % 3) == 2)
		sba_fn++;
	sba_fn = sba_fn % GSM_MAX_FN;
	sba = find(trx, ts, sba_fn);
	if (sba)
		return sba_fn;

	return 0xffffffff;
}

int SBAController::timeout(struct gprs_rlcmac_sba *sba)
{
	LOGP(DRLCMAC, LOGL_NOTICE,
	     "Poll timeout for SBA (TRX=%u, TS=%u, FN=%u, TA=%u)\n", sba->trx_no,
	     sba->ts_no, sba->fn, sba->ta);
	bts_do_rate_ctr_inc(&m_bts, CTR_SBA_TIMEDOUT);
	free_sba(sba);
	return 0;
}

void SBAController::free_sba(gprs_rlcmac_sba *sba)
{
	bts_do_rate_ctr_inc(&m_bts, CTR_SBA_FREED);
	llist_del(&sba->list);
	talloc_free(sba);
}

void SBAController::free_resources(struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_sba *sba, *sba2;
	const uint8_t trx_no = pdch->trx->trx_no;
	const uint8_t ts_no = pdch->ts_no;

	llist_for_each_entry_safe(sba, sba2, &m_sbas, list) {
		if (sba->trx_no == trx_no && sba->ts_no == ts_no)
			free_sba(sba);
	}
}
