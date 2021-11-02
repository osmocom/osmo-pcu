/* bts.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de
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

#include <pdch.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gsm/l1sap.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_rest_octets.h>
#include <osmocom/gsm/gsm48.h>
#include "mslot_class.h"
#include "gsm_rlcmac.h"
#include "gprs_pcu.h"
#ifdef __cplusplus
}
#endif

#include "tbf.h"
#include "coding_scheme.h"

struct GprsMs;
struct gprs_rlcmac_bts;

struct gprs_rlcmac_trx {
	void *fl1h;
	uint16_t arfcn;
	struct gprs_rlcmac_pdch pdch[8];

	/* back pointers */
	struct gprs_rlcmac_bts *bts;
	uint8_t trx_no;

	/* list of uplink TBFs */
	struct llist_head ul_tbfs; /* list of gprs_rlcmac_tbf */
	/* list of downlink TBFs */
	struct llist_head dl_tbfs; /* list of gprs_rlcmac_tbf */

};


#ifdef __cplusplus
extern "C" {
#endif
void bts_trx_init(struct gprs_rlcmac_trx *trx, struct gprs_rlcmac_bts *bts, uint8_t trx_no);
void bts_trx_reserve_slots(struct gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction dir, uint8_t slots);
void bts_trx_unreserve_slots(struct gprs_rlcmac_trx *trx, enum gprs_rlcmac_tbf_direction dir, uint8_t slots);
void bts_trx_free_all_tbf(struct gprs_rlcmac_trx *trx);

void bts_update_tbf_ta(struct gprs_rlcmac_bts *bts, const char *p, uint32_t fn,
		       uint8_t trx_no, uint8_t ts, int8_t ta, bool is_rach);
#ifdef __cplusplus
}
#endif



enum {
	CTR_TBF_DL_ALLOCATED,
	CTR_TBF_DL_FREED,
	CTR_TBF_DL_ABORTED,
	CTR_TBF_UL_ALLOCATED,
	CTR_TBF_UL_FREED,
	CTR_TBF_UL_ABORTED,
	CTR_TBF_REUSED,
	CTR_TBF_ALLOC_ALGO_A,
	CTR_TBF_ALLOC_ALGO_B,
	CTR_TBF_ALLOC_FAIL,
	CTR_TBF_ALLOC_FAIL_NO_TFI,
	CTR_TBF_ALLOC_FAIL_NO_USF,
	CTR_TBF_ALLOC_FAIL_NO_SLOT_COMBI,
	CTR_TBF_ALLOC_FAIL_NO_SLOT_AVAIL,
	CTR_RLC_SENT,
	CTR_RLC_RESENT,
	CTR_RLC_RESTARTED,
	CTR_RLC_STALLED,
	CTR_RLC_NACKED,
	CTR_RLC_FINAL_BLOCK_RESENT,
	CTR_RLC_ASS_TIMEDOUT,
	CTR_RLC_ASS_FAILED,
	CTR_RLC_ACK_TIMEDOUT,
	CTR_RLC_ACK_FAILED,
	CTR_RLC_REL_TIMEDOUT,
	CTR_RLC_LATE_BLOCK,
	CTR_RLC_SENT_DUMMY,
	CTR_RLC_SENT_CONTROL,
	CTR_RLC_DL_BYTES,
	CTR_RLC_DL_PAYLOAD_BYTES,
	CTR_RLC_UL_BYTES,
	CTR_RLC_UL_PAYLOAD_BYTES,
	CTR_DECODE_ERRORS,
	CTR_SBA_ALLOCATED,
	CTR_SBA_FREED,
	CTR_SBA_TIMEDOUT,
	CTR_LLC_FRAME_TIMEDOUT,
	CTR_LLC_FRAME_DROPPED,
	CTR_LLC_FRAME_SCHED,
	CTR_LLC_DL_BYTES,
	CTR_LLC_UL_BYTES,
	CTR_PCH_REQUESTS,
	CTR_PCH_REQUESTS_TIMEDOUT,
	CTR_RACH_REQUESTS,
	CTR_RACH_REQUESTS_11BIT,
	CTR_RACH_REQUESTS_ONE_PHASE,
	CTR_RACH_REQUESTS_TWO_PHASE,
	CTR_SPB_UL_FIRST_SEGMENT,
	CTR_SPB_UL_SECOND_SEGMENT,
	CTR_SPB_DL_FIRST_SEGMENT,
	CTR_SPB_DL_SECOND_SEGMENT,
	CTR_IMMEDIATE_ASSIGN_UL_TBF,
	CTR_IMMEDIATE_ASSIGN_REJ,
	CTR_IMMEDIATE_ASSIGN_DL_TBF,
	CTR_CHANNEL_REQUEST_DESCRIPTION,
	CTR_PKT_UL_ASSIGNMENT,
	CTR_PKT_ACCESS_REJ,
	CTR_PKT_DL_ASSIGNMENT,
	CTR_PKT_CELL_CHG_NOTIFICATION,
	CTR_PKT_CELL_CHG_CONTINUE,
	CTR_PKT_NEIGH_CELL_DATA,
	CTR_RLC_RECV_CONTROL,
	CTR_PUA_POLL_TIMEDOUT,
	CTR_PUA_POLL_FAILED,
	CTR_PDA_POLL_TIMEDOUT,
	CTR_PDA_POLL_FAILED,
	CTR_PUAN_POLL_TIMEDOUT,
	CTR_PUAN_POLL_FAILED,
	CTR_PDAN_POLL_TIMEDOUT,
	CTR_PDAN_POLL_FAILED,
	CTR_GPRS_DL_CS1,
	CTR_GPRS_DL_CS2,
	CTR_GPRS_DL_CS3,
	CTR_GPRS_DL_CS4,
	CTR_EGPRS_DL_MCS1,
	CTR_EGPRS_DL_MCS2,
	CTR_EGPRS_DL_MCS3,
	CTR_EGPRS_DL_MCS4,
	CTR_EGPRS_DL_MCS5,
	CTR_EGPRS_DL_MCS6,
	CTR_EGPRS_DL_MCS7,
	CTR_EGPRS_DL_MCS8,
	CTR_EGPRS_DL_MCS9,
	CTR_GPRS_UL_CS1,
	CTR_GPRS_UL_CS2,
	CTR_GPRS_UL_CS3,
	CTR_GPRS_UL_CS4,
	CTR_EGPRS_UL_MCS1,
	CTR_EGPRS_UL_MCS2,
	CTR_EGPRS_UL_MCS3,
	CTR_EGPRS_UL_MCS4,
	CTR_EGPRS_UL_MCS5,
	CTR_EGPRS_UL_MCS6,
	CTR_EGPRS_UL_MCS7,
	CTR_EGPRS_UL_MCS8,
	CTR_EGPRS_UL_MCS9,
};

enum {
	STAT_MS_PRESENT,
	STAT_PDCH_AVAILABLE,
	STAT_PDCH_OCCUPIED,
	STAT_PDCH_OCCUPIED_GPRS,
	STAT_PDCH_OCCUPIED_EGPRS,
};

/* RACH.ind parameters (to be parsed) */
struct rach_ind_params {
	enum ph_burst_type burst_type;
	bool is_11bit;
	uint16_t ra;
	uint8_t trx_nr;
	uint8_t ts_nr;
	uint32_t rfn;
	int16_t qta;
};

/* [EGPRS Packet] Channel Request parameters (parsed) */
struct chan_req_params {
	unsigned int egprs_mslot_class;
	unsigned int priority;
	bool single_block;
};

struct GprsMsStorage;
struct pcu_l1_meas;

/**
 * I represent a GSM BTS. I have one or more TRX, I know the current
 * GSM time and I have controllers that help with allocating resources
 * on my TRXs.
 */
struct gprs_rlcmac_bts {
	uint8_t nr; /* bts_nr */
	struct llist_head list; /* queued in pcu->bts_list */
	bool active;
	struct osmo_cell_global_id_ps cgi_ps;
	uint8_t bsic;
	uint8_t cs_mask; /* Allowed CS mask from BTS */
	uint16_t mcs_mask;  /* Allowed MCS mask from BTS */
	struct { /* information stored from last received PCUIF info_ind message */
		uint8_t initial_cs;
		uint8_t initial_mcs;
	} pcuif_info_ind;
	uint8_t initial_cs_dl, initial_cs_ul;
	uint8_t initial_mcs_dl, initial_mcs_ul;
	/* Timer defintions */
	struct osmo_tdef *T_defs_bts; /* timers controlled by BTS, received through PCUIF */
	uint8_t n3101;
	uint8_t n3103;
	uint8_t n3105;
	struct gprs_rlcmac_trx trx[8];

	uint8_t si1[GSM_MACBLOCK_LEN];
	bool si1_is_set;
	uint8_t si2[GSM_MACBLOCK_LEN];
	bool si2_is_set;
	struct gsm_sysinfo_freq si2_bcch_cell_list[1024];
	uint8_t si3[GSM_MACBLOCK_LEN];
	bool si3_is_set;
	uint8_t si13[GSM_MACBLOCK_LEN];
	struct osmo_gsm48_si13_info si13_ro_decoded;
	bool si13_is_set;

	/* State for dynamic algorithm selection */
	int multislot_disabled;

	/* Packet Application Information (3GPP TS 44.060 11.2.47, usually ETWS primary message). We don't need to store
	 * more than one message, because they get sent so rarely. */
	struct msgb *app_info;
	uint32_t app_info_pending; /* Count of MS with active TBF, to which we did not send app_info yet */

	/* main nsei */
	struct gprs_ns2_nse *nse;

	/* back pointer to PCU object */
	struct gprs_pcu *pcu;

	uint32_t cur_fn;
	int cur_blk_fn;
	uint8_t max_cs_dl, max_cs_ul;
	uint8_t max_mcs_dl, max_mcs_ul;
	struct rate_ctr_group *ratectrs;
	struct osmo_stat_item_group *statg;

	struct GprsMsStorage *ms_store;

	/* List of struct bts_pch_timer for active PCH pagings */
	struct llist_head pch_timer;
};

#ifdef __cplusplus
extern "C" {
#endif

struct paging_req_cs {
	uint8_t chan_needed;
	uint32_t tlli; /* GSM_RESERVED_TMSI if not present */
	bool mi_tmsi_present;
	struct osmo_mobile_identity mi_tmsi;
	bool mi_imsi_present;
	struct osmo_mobile_identity mi_imsi;
};

struct GprsMs *bts_alloc_ms(struct gprs_rlcmac_bts *bts, uint8_t ms_class, uint8_t egprs_ms_class);
int bts_add_paging(struct gprs_rlcmac_bts *bts, const struct paging_req_cs *req, struct GprsMs *ms);

uint32_t bts_rfn_to_fn(const struct gprs_rlcmac_bts *bts, int32_t rfn);

struct gprs_rlcmac_dl_tbf *bts_dl_tbf_by_tfi(struct gprs_rlcmac_bts *bts, uint8_t tfi, uint8_t trx, uint8_t ts);
struct gprs_rlcmac_ul_tbf *bts_ul_tbf_by_tfi(struct gprs_rlcmac_bts *bts, uint8_t tfi, uint8_t trx, uint8_t ts);

void bts_snd_dl_ass(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf, uint16_t pgroup);

void bts_set_current_frame_number(struct gprs_rlcmac_bts *bts, uint32_t frame_number);
void bts_set_current_block_frame_number(struct gprs_rlcmac_bts *bts, int frame_number);
static inline uint32_t bts_current_frame_number(const struct gprs_rlcmac_bts *bts)
{
	return bts->cur_fn;
}

int bts_tfi_find_free(const struct gprs_rlcmac_bts *bts, enum gprs_rlcmac_tbf_direction dir,
		      uint8_t *_trx, int8_t use_trx);

int bts_rcv_rach(struct gprs_rlcmac_bts *bts, const struct rach_ind_params *rip);
int bts_rcv_ptcch_rach(struct gprs_rlcmac_bts *bts, const struct rach_ind_params *rip);
int bts_rcv_imm_ass_cnf(struct gprs_rlcmac_bts *bts, const uint8_t *data, uint32_t fn);

void bts_send_gsmtap(struct gprs_rlcmac_bts *bts,
		     enum pcu_gsmtap_category categ, bool uplink, uint8_t trx_no,
		     uint8_t ts_no, uint8_t channel, uint32_t fn,
		     const uint8_t *data, unsigned int len);
void bts_send_gsmtap_meas(struct gprs_rlcmac_bts *bts,
			  enum pcu_gsmtap_category categ, bool uplink, uint8_t trx_no,
			  uint8_t ts_no, uint8_t channel, uint32_t fn,
			  const uint8_t *data, unsigned int len, struct pcu_l1_meas *meas);
void bts_send_gsmtap_rach(struct gprs_rlcmac_bts *bts,
			  enum pcu_gsmtap_category categ, uint8_t channel,
			  const struct rach_ind_params *rip);

struct GprsMsStorage *bts_ms_store(const struct gprs_rlcmac_bts *bts);

struct GprsMs *bts_ms_by_tlli(struct gprs_rlcmac_bts *bts, uint32_t tlli, uint32_t old_tlli);

static inline struct rate_ctr_group *bts_rate_counters(struct gprs_rlcmac_bts *bts)
{
	return bts->ratectrs;
}

static inline struct osmo_stat_item_group *bts_stat_items(struct gprs_rlcmac_bts *bts)
{
	return bts->statg;
}

static inline void bts_do_rate_ctr_inc(const struct gprs_rlcmac_bts *bts, unsigned int ctr_id) {
	rate_ctr_inc(rate_ctr_group_get_ctr(bts->ratectrs, ctr_id));
}

static inline void bts_do_rate_ctr_add(const struct gprs_rlcmac_bts *bts, unsigned int ctr_id, int inc) {
	rate_ctr_add(rate_ctr_group_get_ctr(bts->ratectrs, ctr_id), inc);
}

static inline void bts_stat_item_add(struct gprs_rlcmac_bts *bts, unsigned int stat_id, int inc) {
	struct osmo_stat_item *item = osmo_stat_item_group_get_item(bts->statg, stat_id);
	int32_t val = osmo_stat_item_get_last(item);
	osmo_stat_item_set(item, val + inc);
}

#define bts_stat_item_inc(bts, stat_id) bts_stat_item_add(bts, stat_id, 1)

#define bts_stat_item_dec(bts, stat_id) bts_stat_item_add(bts, stat_id, -1)

struct gprs_rlcmac_bts *bts_alloc(struct gprs_pcu *pcu, uint8_t bts_nr);

struct gprs_rlcmac_sba *bts_alloc_sba(struct gprs_rlcmac_bts *bts, uint8_t ta);

void bts_recalc_initial_cs(struct gprs_rlcmac_bts *bts);
void bts_recalc_initial_mcs(struct gprs_rlcmac_bts *bts);
void bts_recalc_max_cs(struct gprs_rlcmac_bts *bts);
void bts_recalc_max_mcs(struct gprs_rlcmac_bts *bts);
struct GprsMs *bts_ms_by_imsi(struct gprs_rlcmac_bts *bts, const char *imsi);
uint8_t bts_max_cs_dl(const struct gprs_rlcmac_bts *bts);
uint8_t bts_max_cs_ul(const struct gprs_rlcmac_bts *bts);
uint8_t bts_max_mcs_dl(const struct gprs_rlcmac_bts *bts);
uint8_t bts_max_mcs_ul(const struct gprs_rlcmac_bts *bts);
void bts_set_max_cs_dl(struct gprs_rlcmac_bts *bts, uint8_t cs_dl);
void bts_set_max_cs_ul(struct gprs_rlcmac_bts *bts, uint8_t cs_ul);
void bts_set_max_mcs_dl(struct gprs_rlcmac_bts *bts, uint8_t mcs_dl);
void bts_set_max_mcs_ul(struct gprs_rlcmac_bts *bts, uint8_t mcs_ul);
bool bts_cs_dl_is_supported(const struct gprs_rlcmac_bts *bts, enum CodingScheme cs);
const struct llist_head* bts_ms_list(struct gprs_rlcmac_bts *bts);
uint8_t bts_get_ms_pwr_alpha(const struct gprs_rlcmac_bts *bts);
#ifdef __cplusplus
}
#endif
