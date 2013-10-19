/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <bts.h>
#include <poll_controller.h>
#include <tbf.h>

#include <gprs_rlcmac.h>

extern "C" {
	#include <osmocom/core/talloc.h>
}

#include <string.h>

static BTS s_bts;

BTS* BTS::main_bts()
{
	return &s_bts;
}

struct gprs_rlcmac_bts *BTS::bts_data()
{
	return &m_bts;
}

struct gprs_rlcmac_bts *bts_main_data()
{
	return BTS::main_bts()->bts_data();
}

BTS::BTS()
	: m_cur_fn(0)
	, m_pollController(*this)
{
	memset(&m_bts, 0, sizeof(m_bts));
	m_bts.bts = this;
}

void BTS::set_current_frame_number(int fn)
{
	m_cur_fn = fn;
	m_pollController.expireTimedout(m_cur_fn);
}

void gprs_rlcmac_pdch::enable()
{
	/* TODO: Check if there are still allocated resources.. */
	INIT_LLIST_HEAD(&paging_list);
	m_is_enabled = 1;
}

void gprs_rlcmac_pdch::disable()
{
	/* TODO.. kick free_resources once we know the TRX/TS we are on */
	m_is_enabled = 0;
}

void gprs_rlcmac_pdch::free_resources(uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_paging *pag;
	struct gprs_rlcmac_sba *sba, *sba2;

	/* we are not enabled. there should be no resources */
	if (!is_enabled())
		return;

	/* kick all TBF on slot */
	gprs_rlcmac_tbf::free_all(this);

	/* flush all pending paging messages */
	while ((pag = gprs_rlcmac_dequeue_paging(this)))
		talloc_free(pag);

	llist_for_each_entry_safe(sba, sba2, &gprs_rlcmac_sbas, list) {
		if (sba->trx == trx && sba->ts == ts) {
			llist_del(&sba->list);
			talloc_free(sba);
		}
	}
}
