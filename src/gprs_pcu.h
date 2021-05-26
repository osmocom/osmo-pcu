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
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/gsmtap_util.h>

#include "gprs_bssgp_pcu.h"
#include "coding_scheme.h"

#include "neigh_cache.h"

#define LLC_CODEL_DISABLE 0
#define LLC_CODEL_USE_DEFAULT (-1)

#define MAX_EDGE_MCS 9
#define MAX_GPRS_CS 4

#define PCU_TDEF_NEIGH_RESOLVE_TO (-1)
#define PCU_TDEF_SI_RESOLVE_TO (-2)
#define PCU_TDEF_NEIGH_CACHE_ALIVE (-10)
#define PCU_TDEF_SI_CACHE_ALIVE    (-11)
#define PCU_TDEF_ANR_SCHED_TBF	(-20)
#define PCU_TDEF_ANR_MS_TIMEOUT	(-21)

/* see bts->gsmtap_categ_mask */
enum pcu_gsmtap_category {
	PCU_GSMTAP_C_DL_UNKNOWN		= 0,	/* unknown or undecodable downlink blocks */
	PCU_GSMTAP_C_DL_DUMMY		= 1, 	/* downlink dummy blocks */
	PCU_GSMTAP_C_DL_CTRL		= 2,	/* downlink control blocks */
	PCU_GSMTAP_C_DL_DATA_GPRS	= 3,	/* downlink GPRS data blocks */
	PCU_GSMTAP_C_DL_DATA_EGPRS	= 4,	/* downlink EGPRS data blocks */
	PCU_GSMTAP_C_DL_PTCCH		= 5,	/* downlink PTCCH blocks */
	PCU_GSMTAP_C_DL_AGCH		= 6,	/* downlink AGCH blocks */
	PCU_GSMTAP_C_DL_PCH		= 7,	/* downlink PCH blocks */

	PCU_GSMTAP_C_UL_UNKNOWN		= 15,	/* unknown or undecodable uplink blocks */
	PCU_GSMTAP_C_UL_DUMMY		= 16,	/* uplink dummy blocks */
	PCU_GSMTAP_C_UL_CTRL		= 17,	/* uplink control blocks */
	PCU_GSMTAP_C_UL_DATA_GPRS	= 18,	/* uplink GPRS data blocks */
	PCU_GSMTAP_C_UL_DATA_EGPRS	= 19,	/* uplink EGPRS data blocks */
	PCU_GSMTAP_C_UL_RACH		= 20,	/* uplink RACH bursts */
	PCU_GSMTAP_C_UL_PTCCH		= 21,	/* uplink PTCCH bursts */
};

struct gprs_rlcmac_bts;
struct GprsMs;
struct gprs_rlcmac_tbf;

typedef int (*alloc_algorithm_func_t)(struct gprs_rlcmac_bts *bts,
				      struct gprs_rlcmac_tbf *tbf,
				      bool single, int8_t use_tbf);

struct gprs_pcu {

	/* Path to be used for the pcu-bts socket */
	char *pcu_sock_path;

	struct { /* Config Values set by VTY */
		uint8_t fc_interval;
		uint16_t fc_bucket_time;
		uint32_t fc_bvc_bucket_size;
		uint32_t fc_bvc_leak_rate;
		uint32_t fc_ms_bucket_size;
		uint32_t fc_ms_leak_rate;
		bool force_initial_cs;	/* false=use from BTS true=use from VTY */
		bool force_initial_mcs;	/* false=use from BTS true=use from VTY */
		uint8_t initial_cs_dl, initial_cs_ul;
		uint8_t initial_mcs_dl, initial_mcs_ul;
		uint8_t max_cs_dl, max_cs_ul;
		uint8_t max_mcs_dl, max_mcs_ul;
		uint8_t force_two_phase;
		uint8_t force_alpha, gamma;
		bool dl_tbf_preemptive_retransmission;
		enum egprs_arq_type dl_arq_type; /* EGPRS_ARQ1 to support resegmentation in DL, EGPRS_ARQ2 for no reseg */
		bool cs_adj_enabled; /* whether cs_adj_{upper,lower}_limit are used to adjust DL CS */
		uint8_t cs_adj_upper_limit; /* downgrade DL CS if error rate above its value */
		uint8_t cs_adj_lower_limit; /* upgrade DL CS if error rate below its value */
		/* downgrade DL CS when less than specified octets are left in tx queue. Optimization, see paper:
		  "Theoretical Analysis of GPRS Throughput and Delay" */
		uint16_t cs_downgrade_threshold;
		/* Link quality range for each UL (M)CS. Below or above, next/prev (M)CS is selected. */
		struct {int16_t low; int16_t high; } cs_lqual_ranges[MAX_GPRS_CS];
		struct {int16_t low; int16_t high; } mcs_lqual_ranges[MAX_EDGE_MCS];
		enum gprs_ns2_dialect ns_dialect; /* Are we talking Gb with IP-SNS (true) or classic Gb? */
		int ns_ip_dscp;
		int ns_priority;
		uint16_t ws_base;
		uint16_t ws_pdch; /* increase WS by this value per PDCH */
		uint16_t force_llc_lifetime; /* overrides lifetime from SGSN */
		uint32_t llc_discard_csec;
		uint32_t llc_idle_ack_csec;
		uint32_t llc_codel_interval_msec; /* 0=disabled, -1=use default interval */
		/* Remote BSS resolution sevice (CTRL iface) */
		char *neigh_ctrl_addr;
		uint16_t neigh_ctrl_port;
	} vty;

	struct gsmtap_inst *gsmtap;
	uint32_t gsmtap_categ_mask;

	struct llist_head bts_list; /* list of gprs_rlcmac_tbf */

	struct gprs_ns2_inst *nsi;

	alloc_algorithm_func_t alloc_algorithm;

	struct gprs_bssgp_pcu bssgp;

	struct osmo_tdef *T_defs; /* timers controlled by PCU */

	struct neigh_cache *neigh_cache; /* ARFC+BSIC -> CGI PS cache */
	struct si_cache *si_cache; /* ARFC+BSIC -> CGI PS cache */
};


extern struct gprs_pcu *the_pcu;

struct gprs_pcu *gprs_pcu_alloc(void *ctx);

struct gprs_rlcmac_bts *gprs_pcu_get_bts_by_nr(struct gprs_pcu *pcu, uint8_t bts_nr);
struct gprs_rlcmac_bts *gprs_pcu_get_bts_by_cgi_ps(struct gprs_pcu *pcu, struct osmo_cell_global_id_ps *cgi_ps);

void gprs_pcu_set_initial_cs(struct gprs_pcu *pcu, uint8_t cs_dl, uint8_t cs_ul);
void gprs_pcu_set_initial_mcs(struct gprs_pcu *pcu, uint8_t mcs_dl, uint8_t mcs_ul);
void gprs_pcu_set_max_cs(struct gprs_pcu *pcu, uint8_t cs_dl, uint8_t cs_ul);
void gprs_pcu_set_max_mcs(struct gprs_pcu *pcu, uint8_t mcs_dl, uint8_t mcs_ul);
