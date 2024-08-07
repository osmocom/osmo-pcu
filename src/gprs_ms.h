/* gprs_ms.h
 *
 * Copyright (C) 2015-2020 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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
 */

#pragma once

struct gprs_codel;

#include "llc.h"
#include "tbf.h"
#include "tbf_ul.h"
#include "tbf_dl.h"
#include "pcu_l1_if.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/use_count.h>

#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/gsm48.h>

#include "coding_scheme.h"
#include <gsm_rlcmac.h>

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

enum ms_counter_id {
	MS_CTR_DL_CTRL_MSG_SCHED,
};

struct gprs_rlcmac_bts;
struct gprs_rlcmac_trx;
struct GprsMs;

struct GprsMs {
	struct llist_head list; /* list of all GprsMs */
	bool app_info_pending;

	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct llist_head old_tbfs; /* list of gprs_rlcmac_tbf */
	/* First common timeslot used both in UL and DL, or NULL if not set: */
	struct gprs_rlcmac_pdch *first_common_ts;

	uint32_t tlli;
	uint32_t new_ul_tlli;
	uint32_t new_dl_tlli;

	/* store IMSI for look-up and PCH retransmission */
	char imsi[OSMO_IMSI_BUF_SIZE];
	uint8_t ta;
	uint8_t ms_class;
	uint8_t egprs_ms_class;
	/* current coding scheme */
	enum CodingScheme current_cs_ul;
	enum CodingScheme current_cs_dl;

	struct gprs_llc_queue llc_queue;
	struct osmo_timer_list llc_timer;

	struct osmo_use_count use_count;
	struct osmo_timer_list release_timer;
	/* Time at which MS became idle and waiting to be released by release_timer: */
	struct timeval tv_idle_start;

	int64_t last_cs_not_low;

	struct pcu_l1_meas l1_meas;
	unsigned nack_rate_dl;
	uint8_t reserved_dl_slots;
	uint8_t reserved_ul_slots;
	struct gprs_rlcmac_trx *current_trx;
	enum mcs_kind mode;

	struct rate_ctr_group *ctrs;
	struct nacc_fsm_ctx *nacc;
};

struct GprsMs *ms_alloc(struct gprs_rlcmac_bts *bts, const char *use_ref);

struct gprs_rlcmac_pdch *ms_first_common_ts(const struct GprsMs *ms);
void ms_set_first_common_ts(struct GprsMs *ms, struct gprs_rlcmac_pdch *pdch);
void ms_set_reserved_slots(struct GprsMs *ms, struct gprs_rlcmac_trx *trx,
			   uint8_t ul_slots, uint8_t dl_slots);
void ms_set_mode(struct GprsMs *ms, enum mcs_kind mode);
void ms_set_ms_class(struct GprsMs *ms, uint8_t ms_class_);
void ms_set_egprs_ms_class(struct GprsMs *ms, uint8_t ms_class_);
void ms_set_ta(struct GprsMs *ms, uint8_t ta_);

enum CodingScheme ms_current_cs_dl(const struct GprsMs *ms, enum mcs_kind req_mcs_kind);
enum CodingScheme ms_max_cs_ul(const struct GprsMs *ms);
enum CodingScheme ms_max_cs_dl(const struct GprsMs *ms);
void ms_set_current_cs_dl(struct GprsMs *ms, enum CodingScheme scheme);

void ms_update_error_rate(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf, int error_rate);
uint8_t ms_current_pacch_slots(const struct GprsMs *ms);

void ms_update_announced_tlli(struct GprsMs *ms, uint32_t tlli);
void ms_merge_and_clear_ms(struct GprsMs *ms, struct GprsMs *old_ms);

void ms_attach_tbf(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf);
void ms_detach_tbf(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf);

void ms_set_tlli(struct GprsMs *ms, uint32_t tlli);
bool ms_confirm_tlli(struct GprsMs *ms, uint32_t tlli);
void ms_set_imsi(struct GprsMs *ms, const char *imsi);

void ms_update_l1_meas(struct GprsMs *ms, const struct pcu_l1_meas *meas);

struct gprs_rlcmac_tbf *ms_tbf(const struct GprsMs *ms, enum gprs_rlcmac_tbf_direction dir);
static inline struct gprs_rlcmac_ul_tbf *ms_ul_tbf(const struct GprsMs *ms) {return ms->ul_tbf;}
static inline struct gprs_rlcmac_dl_tbf *ms_dl_tbf(const struct GprsMs *ms) {return ms->dl_tbf;}

const char *ms_name(const struct GprsMs *ms);
char *ms_name_buf(const struct GprsMs *ms, char *buf, unsigned int buf_size);

int ms_nacc_start(struct GprsMs *ms, Packet_Cell_Change_Notification_t *notif);
bool ms_nacc_rts(const struct GprsMs *ms);
struct msgb *ms_nacc_create_rlcmac_msg(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf,
				       const struct gprs_rlcmac_pdch *pdch, uint32_t fn);

struct gprs_rlcmac_ul_tbf *ms_new_ul_tbf_assigned_pacch(struct GprsMs *ms, int8_t use_trx);
struct gprs_rlcmac_ul_tbf *ms_new_ul_tbf_assigned_agch(struct GprsMs *ms);
struct gprs_rlcmac_ul_tbf *ms_new_ul_tbf_rejected_pacch(struct GprsMs *ms, struct gprs_rlcmac_pdch *pdch);
int ms_new_dl_tbf_assigned_on_pacch(struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf);
int ms_new_dl_tbf_assigned_on_pch(struct GprsMs *ms);
int ms_append_llc_dl_data(struct GprsMs *ms, uint16_t pdu_delay_csec, const uint8_t *data, uint16_t len);

static inline bool ms_is_idle(const struct GprsMs *ms)
{
	return !ms->ul_tbf && !ms->dl_tbf &&
		llist_empty(&ms->old_tbfs);
}

static inline struct gprs_llc_queue *ms_llc_queue(struct GprsMs *ms)
{
	return &ms->llc_queue;
}

/* Function used in code where a ul_tbf related event occurs and hence its state
 * changes, which in turn may change the entire MS state (eg becoming reachable
 * over PCH or PACCH) and the caller may want to know if it is a good time to
 * assign a DL TBF (and whether we have DL data to send) */
static inline bool ms_need_dl_tbf(struct GprsMs *ms)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf = ms_dl_tbf(ms);
	if (dl_tbf) {
		switch (tbf_state(dl_tbf_as_tbf(dl_tbf))) {
		case TBF_ST_NEW:
		case TBF_ST_ASSIGN:
		case TBF_ST_FLOW:
		case TBF_ST_FINISHED:
		case TBF_ST_WAIT_RELEASE:
			return false; /* TBF in use, hence no need for new DL TBF */
		case TBF_ST_WAIT_REUSE_TFI:
		case TBF_ST_RELEASING:
			/* TBF cannot be used to send further data, a new one
			 * may be needed, check below */
			break;
		default:
			OSMO_ASSERT(0);
		}
	}

	return llc_queue_size(ms_llc_queue(ms)) > 0;
}

static inline uint32_t ms_tlli(const struct GprsMs *ms)
{
	if (ms->new_ul_tlli != GSM_RESERVED_TMSI)
		return ms->new_ul_tlli;
	if (ms->tlli != GSM_RESERVED_TMSI)
		return ms->tlli;

	return ms->new_dl_tlli;
}

static inline bool ms_check_tlli(struct GprsMs *ms, uint32_t tlli)
{
	return tlli != GSM_RESERVED_TMSI &&
		(tlli == ms->tlli || tlli == ms->new_ul_tlli || tlli == ms->new_dl_tlli);
}

static inline const char *ms_imsi(const struct GprsMs *ms)
{
	return ms->imsi;
}

static inline bool ms_imsi_is_valid(const struct GprsMs *ms)
{
	return ms->imsi[0] != '\0';
}

static inline uint8_t ms_ta(const struct GprsMs *ms)
{
	return ms->ta;
}

static inline uint8_t ms_ms_class(const struct GprsMs *ms)
{
	return ms->ms_class;
}

static inline uint8_t ms_egprs_ms_class(const struct GprsMs *ms)
{
	return ms->egprs_ms_class;
}

static inline enum CodingScheme ms_current_cs_ul(const struct GprsMs *ms)
{
	return ms->current_cs_ul;
}

static inline enum mcs_kind ms_mode(const struct GprsMs *ms)
{
	return ms->mode;
}

static inline unsigned ms_nack_rate_dl(const struct GprsMs *ms)
{
	return ms->nack_rate_dl;
}

static inline uint8_t ms_reserved_dl_slots(const struct GprsMs *ms)
{
	return ms->reserved_dl_slots;
}

static inline uint8_t ms_reserved_ul_slots(const struct GprsMs *ms)
{
	return ms->reserved_ul_slots;
}

static inline struct gprs_rlcmac_trx *ms_current_trx(const struct GprsMs *ms)
{
	return ms->current_trx;
}

#define MS_USE_TBF "tbf"
#define ms_ref(ms, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&(ms)->use_count, use, 1) == 0)
#define ms_unref(ms, use) \
	OSMO_ASSERT(osmo_use_count_get_put(&(ms)->use_count, use, -1) == 0)

#define LOGPMS(ms, category, level, fmt, args...) \
	LOGP(category, level, "%s " fmt, ms_name(ms), ## args)

#ifdef __cplusplus
}
#endif
