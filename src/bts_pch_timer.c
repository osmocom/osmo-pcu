/*
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Oliver Smith
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
#include <string.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/utils.h>

#include <gprs_debug.h>
#include <gprs_pcu.h>
#include <bts_pch_timer.h>

static struct bts_pch_timer *bts_pch_timer_get(struct gprs_rlcmac_bts *bts, const char *imsi)
{
	struct bts_pch_timer *p;

	llist_for_each_entry(p, &bts->pch_timer, entry) {
		if (strcmp(p->imsi, imsi) == 0)
			return p;
	}

	return NULL;
}

static void bts_pch_timer_remove(struct bts_pch_timer *p)
{
	osmo_timer_del(&p->T3113);
	llist_del(&p->entry);

	LOGP(DPCU, LOGL_DEBUG, "PCH paging timer stopped for IMSI=%s\n", p->imsi);
	talloc_free(p);
}

static void T3113_callback(void *data)
{
	struct bts_pch_timer *p = data;

	LOGP(DPCU, LOGL_INFO, "PCH paging timeout for IMSI=%s\n", p->imsi);
	bts_do_rate_ctr_inc(p->bts, CTR_PCH_REQUESTS_TIMEDOUT);
	bts_pch_timer_remove(p);
}

void bts_pch_timer_start(struct gprs_rlcmac_bts *bts, const char *imsi)
{
	if (bts_pch_timer_get(bts, imsi))
		return;

	struct bts_pch_timer *p;
	p = talloc_zero(bts, struct bts_pch_timer);
	llist_add_tail(&p->entry, &bts->pch_timer);
	osmo_strlcpy(p->imsi, imsi, sizeof(p->imsi));
	p->bts = bts;

	struct osmo_tdef *tdef = osmo_tdef_get_entry(the_pcu->T_defs, 3113);
	OSMO_ASSERT(tdef);
	osmo_timer_setup(&p->T3113, T3113_callback, p);
	osmo_timer_schedule(&p->T3113, tdef->val, 0);

	LOGP(DPCU, LOGL_DEBUG, "PCH paging timer started for IMSI=%s\n", p->imsi);
}

void bts_pch_timer_stop(struct gprs_rlcmac_bts *bts, const char *imsi)
{
	struct bts_pch_timer *p = bts_pch_timer_get(bts, imsi);

	if (p)
		bts_pch_timer_remove(p);
}

void bts_pch_timer_stop_all(struct gprs_rlcmac_bts *bts)
{
	struct bts_pch_timer *p, *n;

	llist_for_each_entry_safe(p, n, &bts->pch_timer, entry) {
		bts_pch_timer_remove(p);
	}
}
