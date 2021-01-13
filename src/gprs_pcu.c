/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <osmocom/core/utils.h>

#include "gprs_pcu.h"
#include "bts.h"

struct gprs_pcu *the_pcu;

struct gprs_pcu *gprs_pcu_alloc(void *ctx)
{
	struct gprs_pcu *pcu;

	pcu = (struct gprs_pcu *)talloc_zero(ctx, struct gprs_pcu);
	OSMO_ASSERT(pcu);

	pcu->vty.max_cs_ul = MAX_GPRS_CS;
	pcu->vty.max_cs_dl = MAX_GPRS_CS;
	pcu->vty.max_mcs_ul = MAX_EDGE_MCS;
	pcu->vty.max_mcs_dl = MAX_EDGE_MCS;

	return pcu;
}


void gprs_pcu_set_max_cs(struct gprs_pcu *pcu, uint8_t cs_dl, uint8_t cs_ul)
{
	the_pcu->vty.max_cs_dl = cs_dl;
	the_pcu->vty.max_cs_ul = cs_ul;
	/*TODO: once we support multiple bts, foreach(bts) apply */
	struct gprs_rlcmac_bts *bts = bts_data(pcu->bts);
	bts_recalc_max_cs(bts);
}
void gprs_pcu_set_max_mcs(struct gprs_pcu *pcu, uint8_t mcs_dl, uint8_t mcs_ul)
{
	the_pcu->vty.max_mcs_dl = mcs_dl;
	the_pcu->vty.max_mcs_ul = mcs_ul;
	/* TODO: once we support multiple bts, foreach(bts) apply */
	struct gprs_rlcmac_bts *bts = bts_data(pcu->bts);
	bts_recalc_max_mcs(bts);
}
