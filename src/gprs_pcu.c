/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/ctrl/ports.h>

#include "gprs_pcu.h"
#include "bts.h"

struct gprs_pcu *the_pcu;

static struct osmo_tdef T_defs_pcu[] = {
	{ .T=3113,  .default_val=7, .unit=OSMO_TDEF_S, .desc="Timeout for paging", .val=0 },
	{ .T=3190,  .default_val=5,   .unit=OSMO_TDEF_S,  .desc="Return to packet idle mode after Packet DL Assignment on CCCH (s)", .val=0},
	{ .T=3141,  .default_val=10, .unit=OSMO_TDEF_S, .desc="Timeout for contention resolution procedure (s)", .val=0 },
	{ .T=3172,  .default_val=5000, .unit=OSMO_TDEF_MS, .desc="Wait Indication used in Imm Ass Reject during TBF Establishment (PACCH)", .val=0, .min_val = 0, .max_val = 255000 }, /* TS 44.060 7.1.3.2.1 */
	{ .T=PCU_TDEF_NEIGH_RESOLVE_TO,    .default_val=1000,  .unit=OSMO_TDEF_MS,   .desc="[ARFCN+BSIC]->[RAC+CI] resolution timeout (ms)", .val=0 },
	{ .T=PCU_TDEF_SI_RESOLVE_TO,	   .default_val=1000,  .unit=OSMO_TDEF_MS,   .desc="RIM RAN-INFO response timeout (ms)",	    .val=0 },
	{ .T=PCU_TDEF_NEIGH_CACHE_ALIVE,   .default_val=5,  .unit=OSMO_TDEF_S,   .desc="[ARFCN+BSIC]->[RAC+CI] resolution cache entry storage timeout (s)", .val=0 },
	{ .T=PCU_TDEF_SI_CACHE_ALIVE,      .default_val=5,  .unit=OSMO_TDEF_S,   .desc="[RAC+CI]->[SI] resolution cache entry storage timeout (s)", .val=0 },
	{ .T=-101,  .default_val=30,  .unit=OSMO_TDEF_S,  .desc="BSSGP (un)blocking procedures timer (s)",  .val=0 },
	{ .T=-102,  .default_val=30,  .unit=OSMO_TDEF_S,  .desc="BSSGP reset procedure timer (s)",          .val=0 },
	{ .T=-2000, .default_val=0,   .unit=OSMO_TDEF_MS, .desc="Delay release of UL TBF after tx Packet Access Reject (PACCH) (ms)", .val=0 },
	{ .T=-2001, .default_val=2,   .unit=OSMO_TDEF_S,  .desc="DL TBF PACCH assignment timeout (s)", .val=0 },
	{ .T=-2002, .default_val=200, .unit=OSMO_TDEF_MS, .desc="Waiting after IMM.ASS confirm timer (ms)", .val=0 },
	{ .T=-2030, .default_val=60,  .unit=OSMO_TDEF_S,  .desc="Time to keep an idle MS object alive (s)", .val=0 }, /* slightly above T3314 (default 44s, 24.008, 11.2.2) */
	{ .T=-2031, .default_val=2000, .unit=OSMO_TDEF_MS, .desc="Time to keep an idle DL TBF alive (ms)",  .val=0 },
	{ .T=0, .default_val=0, .unit=OSMO_TDEF_S, .desc=NULL, .val=0 } /* empty item at the end */
};

static void _update_stats_timer_cb(void *data)
{
	struct gprs_pcu *pcu = (struct gprs_pcu *)data;
	struct gprs_rlcmac_bts *bts;

	llist_for_each_entry(bts, &pcu->bts_list, list)
		osmo_time_cc_set_flag(&bts->all_allocated_pdch, bts_all_pdch_allocated(bts));

	osmo_timer_schedule(&pcu->update_stats_timer, 1, 0);
}

static int gprs_pcu_talloc_destructor(struct gprs_pcu *pcu)
{
	struct gprs_rlcmac_bts *bts;
	while ((bts = llist_first_entry_or_null(&pcu->bts_list, struct gprs_rlcmac_bts, list)))
		talloc_free(bts);

	osmo_timer_del(&pcu->update_stats_timer);
	neigh_cache_free(pcu->neigh_cache);
	si_cache_free(pcu->si_cache);
	return 0;
}

struct gprs_pcu *gprs_pcu_alloc(void *ctx)
{
	struct gprs_pcu *pcu;

	pcu = (struct gprs_pcu *)talloc_zero(ctx, struct gprs_pcu);
	OSMO_ASSERT(pcu);
	talloc_set_destructor(pcu, gprs_pcu_talloc_destructor);

	pcu->vty.fc_interval = 1;
	pcu->vty.max_cs_ul = MAX_GPRS_CS;
	pcu->vty.max_cs_dl = MAX_GPRS_CS;
	pcu->vty.max_mcs_ul = MAX_EDGE_MCS;
	pcu->vty.max_mcs_dl = MAX_EDGE_MCS;
	pcu->vty.force_alpha = (uint8_t)-1; /* don't force by default, use BTS SI13 provided value */
	pcu->vty.dl_tbf_preemptive_retransmission = true;
	/* By default resegmentation is supported in DL can also be configured
	 * through VTY */
	pcu->vty.dl_arq_type = EGPRS_ARQ1;
	pcu->vty.cs_adj_enabled = true;
	pcu->vty.cs_adj_upper_limit = 33; /* Decrease CS if the error rate is above */
	pcu->vty.cs_adj_lower_limit = 10; /* Increase CS if the error rate is below */
	pcu->vty.cs_downgrade_threshold = 200;
	/* CS-1 to CS-4 */
	pcu->vty.cs_lqual_ranges[0].low = -256;
	pcu->vty.cs_lqual_ranges[0].high = 6;
	pcu->vty.cs_lqual_ranges[1].low = 5;
	pcu->vty.cs_lqual_ranges[1].high = 8;
	pcu->vty.cs_lqual_ranges[2].low = 7;
	pcu->vty.cs_lqual_ranges[2].high = 13;
	pcu->vty.cs_lqual_ranges[3].low = 12;
	pcu->vty.cs_lqual_ranges[3].high = 256;
	/* MCS-1 to MCS-9 */
	/* Default thresholds are referenced from literature */
	/* Fig. 2.3, Chapter 2, Optimizing Wireless Communication Systems, Springer (2009) */
	pcu->vty.mcs_lqual_ranges[0].low = -256;
	pcu->vty.mcs_lqual_ranges[0].high = 6;
	pcu->vty.mcs_lqual_ranges[1].low = 5;
	pcu->vty.mcs_lqual_ranges[1].high = 8;
	pcu->vty.mcs_lqual_ranges[2].low = 7;
	pcu->vty.mcs_lqual_ranges[2].high = 13;
	pcu->vty.mcs_lqual_ranges[3].low = 12;
	pcu->vty.mcs_lqual_ranges[3].high = 15;
	pcu->vty.mcs_lqual_ranges[4].low = 14;
	pcu->vty.mcs_lqual_ranges[4].high = 17;
	pcu->vty.mcs_lqual_ranges[5].low = 16;
	pcu->vty.mcs_lqual_ranges[5].high = 18;
	pcu->vty.mcs_lqual_ranges[6].low = 17;
	pcu->vty.mcs_lqual_ranges[6].high = 20;
	pcu->vty.mcs_lqual_ranges[7].low = 19;
	pcu->vty.mcs_lqual_ranges[7].high = 24;
	pcu->vty.mcs_lqual_ranges[8].low = 23;
	pcu->vty.mcs_lqual_ranges[8].high = 256;
	pcu->vty.ns_dialect = GPRS_NS2_DIALECT_IPACCESS;
	pcu->vty.ns_ip_dscp = -1;
	pcu->vty.ns_priority = -1;
	/* TODO: increase them when CRBB decoding is implemented */
	pcu->vty.ws_base = 64;
	pcu->vty.ws_pdch = 0;
	pcu->vty.msclass_default = PCU_DEFAULT_MSLOT_CLASS;
	pcu->vty.llc_codel_interval_msec = LLC_CODEL_USE_DEFAULT;
	pcu->vty.llc_idle_ack_csec = 10;

	pcu->T_defs = T_defs_pcu;
	osmo_tdefs_reset(pcu->T_defs);

	INIT_LLIST_HEAD(&pcu->bts_list);

	pcu->neigh_cache = neigh_cache_alloc(pcu, osmo_tdef_get(pcu->T_defs, PCU_TDEF_NEIGH_CACHE_ALIVE, OSMO_TDEF_S, -1));
	pcu->si_cache = si_cache_alloc(pcu, osmo_tdef_get(pcu->T_defs, PCU_TDEF_SI_CACHE_ALIVE, OSMO_TDEF_S, -1));

	osmo_timer_setup(&pcu->update_stats_timer, _update_stats_timer_cb, pcu);
	osmo_timer_schedule(&pcu->update_stats_timer, 1, 0);

	return pcu;
}

struct gprs_rlcmac_bts *gprs_pcu_get_bts_by_nr(struct gprs_pcu *pcu, uint8_t bts_nr)
{
	struct gprs_rlcmac_bts *pos;
	llist_for_each_entry(pos, &pcu->bts_list, list) {
		if (pos->nr == bts_nr)
			return pos;
	}
	return NULL;
}

struct gprs_rlcmac_bts *gprs_pcu_get_bts_by_cgi_ps(struct gprs_pcu *pcu, struct osmo_cell_global_id_ps *cgi_ps)
{
	struct gprs_rlcmac_bts *pos;
	llist_for_each_entry(pos, &pcu->bts_list, list) {
		if (osmo_cgi_ps_cmp(&pos->cgi_ps, cgi_ps) == 0)
			return pos;
	}
	return NULL;
}

void gprs_pcu_set_initial_cs(struct gprs_pcu *pcu, uint8_t cs_dl, uint8_t cs_ul)
{
	struct gprs_rlcmac_bts *bts;

	the_pcu->vty.initial_cs_dl = cs_dl;
	the_pcu->vty.initial_cs_ul = cs_ul;

	llist_for_each_entry(bts, &pcu->bts_list, list) {
		bts_recalc_initial_cs(bts);
	}
}
void gprs_pcu_set_initial_mcs(struct gprs_pcu *pcu, uint8_t mcs_dl, uint8_t mcs_ul)
{
	struct gprs_rlcmac_bts *bts;

	the_pcu->vty.initial_mcs_dl = mcs_dl;
	the_pcu->vty.initial_mcs_ul = mcs_ul;

	llist_for_each_entry(bts, &pcu->bts_list, list) {
		bts_recalc_initial_mcs(bts);
	}
}

void gprs_pcu_set_max_cs(struct gprs_pcu *pcu, uint8_t cs_dl, uint8_t cs_ul)
{
	struct gprs_rlcmac_bts *bts;

	the_pcu->vty.max_cs_dl = cs_dl;
	the_pcu->vty.max_cs_ul = cs_ul;

	llist_for_each_entry(bts, &pcu->bts_list, list) {
		bts_recalc_max_cs(bts);
	}
}
void gprs_pcu_set_max_mcs(struct gprs_pcu *pcu, uint8_t mcs_dl, uint8_t mcs_ul)
{
	struct gprs_rlcmac_bts *bts;

	the_pcu->vty.max_mcs_dl = mcs_dl;
	the_pcu->vty.max_mcs_ul = mcs_ul;

	llist_for_each_entry(bts, &pcu->bts_list, list) {
		bts_recalc_max_mcs(bts);
	}
}
