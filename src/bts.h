/* bts.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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

#pragma once


#ifdef __cplusplus
extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/timer.h>
}

#include "poll_controller.h"
#include "sba.h"
#include "tbf.h"
#include "gprs_ms_storage.h"
#include "gprs_coding_scheme.h"
#endif

#include <stdint.h>

#define LLC_CODEL_DISABLE 0
#define LLC_CODEL_USE_DEFAULT (-1)

struct BTS;
struct GprsMs;

/*
 * PDCH instance
 */
struct gprs_rlcmac_pdch {
#ifdef __cplusplus
	struct gprs_rlcmac_paging *dequeue_paging();
	struct msgb *packet_paging_request();

	void add_paging(struct gprs_rlcmac_paging *pag);

	void free_resources();

	bool is_enabled() const;

	void enable();
	void disable();

	/* dispatching of messages */
	int rcv_block(uint8_t *data, uint8_t len, uint32_t fn,
		struct pcu_l1_meas *meas);
	int rcv_block_gprs(uint8_t *data, uint32_t fn,
		struct pcu_l1_meas *meas, GprsCodingScheme cs);
	int rcv_block_egprs(uint8_t *data, uint32_t fn,
		struct pcu_l1_meas *meas, GprsCodingScheme cs);

	gprs_rlcmac_bts *bts_data() const;
	BTS *bts() const;
	uint8_t trx_no() const;

	struct gprs_rlcmac_ul_tbf *ul_tbf_by_tfi(uint8_t tfi);
	struct gprs_rlcmac_dl_tbf *dl_tbf_by_tfi(uint8_t tfi);

	void attach_tbf(gprs_rlcmac_tbf *tbf);
	void detach_tbf(gprs_rlcmac_tbf *tbf);

	unsigned num_tbfs(enum gprs_rlcmac_tbf_direction dir) const;

	void reserve(enum gprs_rlcmac_tbf_direction dir);
	void unreserve(enum gprs_rlcmac_tbf_direction dir);
	unsigned num_reserved(enum gprs_rlcmac_tbf_direction dir) const;

	uint8_t assigned_usf() const;
	uint32_t assigned_tfi(enum gprs_rlcmac_tbf_direction dir) const;
#endif

	uint8_t m_is_enabled; /* TS is enabled */
	uint8_t tsc; /* TSC of this slot */
	uint8_t next_ul_tfi; /* next uplink TBF/TFI to schedule (0..31) */
	uint8_t next_dl_tfi; /* next downlink TBF/TFI to schedule (0..31) */
	uint8_t next_ctrl_prio; /* next kind of ctrl message to schedule */
	struct llist_head paging_list; /* list of paging messages */
	uint32_t last_rts_fn; /* store last frame number of RTS */

	/* back pointers */
	struct gprs_rlcmac_trx *trx;
	uint8_t ts_no;

#ifdef __cplusplus
private:
	int rcv_data_block_acknowledged(uint8_t *data, uint8_t len,
		struct pcu_l1_meas *meas);
	int rcv_control_block(bitvec *rlc_block, uint32_t fn);

	void rcv_control_ack(Packet_Control_Acknowledgement_t *, uint32_t fn);
	void rcv_control_dl_ack_nack(Packet_Downlink_Ack_Nack_t *, uint32_t fn);
	void rcv_resource_request(Packet_Resource_Request_t *t, uint32_t fn);
	void rcv_measurement_report(Packet_Measurement_Report_t *t, uint32_t fn);
	gprs_rlcmac_tbf *tbf_from_list_by_tfi(struct llist_head *tbf_list, uint8_t tfi,
		enum gprs_rlcmac_tbf_direction dir);
	gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi,
		enum gprs_rlcmac_tbf_direction dir);
#endif

	uint8_t m_num_tbfs[2];
	uint8_t m_num_reserved[2];
	uint8_t m_assigned_usf; /* bit set */
	uint32_t m_assigned_tfi[2]; /* bit set */
	struct gprs_rlcmac_tbf *m_tbfs[2][32];
};

struct gprs_rlcmac_trx {
	void *fl1h;
	uint16_t arfcn;
	struct gprs_rlcmac_pdch pdch[8];

	/* back pointers */
	struct BTS *bts;
	uint8_t trx_no;

#ifdef __cplusplus
	void reserve_slots(enum gprs_rlcmac_tbf_direction dir, uint8_t slots);
	void unreserve_slots(enum gprs_rlcmac_tbf_direction dir, uint8_t slots);
#endif
};

/**
 * This is the data from C. As soon as our minimal compiler is gcc 4.7
 * we can start to compile pcu_vty.c with c++ and remove the split.
 */
struct gprs_rlcmac_bts {
	uint8_t bsic;
	uint8_t fc_interval;
	uint16_t fc_bucket_time;
	uint32_t fc_bvc_bucket_size;
	uint32_t fc_bvc_leak_rate;
	uint32_t fc_ms_bucket_size;
	uint32_t fc_ms_leak_rate;
	uint8_t cs1;
	uint8_t cs2;
	uint8_t cs3;
	uint8_t cs4;
	uint8_t initial_cs_dl, initial_cs_ul;
	uint8_t max_cs_dl, max_cs_ul;
	uint8_t force_cs;	/* 0=use from BTS 1=use from VTY */
	uint16_t force_llc_lifetime; /* overrides lifetime from SGSN */
	uint32_t llc_discard_csec;
	uint32_t llc_idle_ack_csec;
	uint32_t llc_codel_interval_msec; /* 0=disabled, -1=use default interval */
	uint8_t t3142;
	uint8_t t3169;
	uint8_t t3191;
	uint16_t t3193_msec;
	uint8_t t3195;
	uint8_t n3101;
	uint8_t n3103;
	uint8_t n3105;
	struct gprs_rlcmac_trx trx[8];
	int (*alloc_algorithm)(struct gprs_rlcmac_bts *bts,
		struct GprsMs *ms,
		struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single,
		int use_tbf);
	uint32_t alloc_algorithm_curst; /* options to customize algorithm */
	uint8_t force_two_phase;
	uint8_t alpha, gamma;
	uint8_t egprs_enabled;
	uint32_t dl_tbf_idle_msec; /* hold time for idle DL TBFs */
	uint32_t ms_idle_sec;
	uint8_t cs_adj_enabled;
	uint8_t cs_adj_upper_limit;
	uint8_t cs_adj_lower_limit;
	struct {int16_t low; int16_t high;} cs_lqual_ranges[4];
	uint16_t cs_downgrade_threshold; /* downgrade if less packets left (DL) */

	/* TBF handling, make private or move into TBFController */
	/* list of uplink TBFs */
	struct llist_head ul_tbfs;
	/* list of downlink TBFs */
	struct llist_head dl_tbfs;

	/* State for dynamic algorithm selection */
	int multislot_disabled;

	/**
	 * Point back to the C++ object. This is used during the transition
	 * period.
	 */
	struct BTS *bts;
};

#ifdef __cplusplus
/**
 * I represent a GSM BTS. I have one or more TRX, I know the current
 * GSM time and I have controllers that help with allocating resources
 * on my TRXs.
 */
struct BTS {
public:
	enum {
		CTR_TBF_DL_ALLOCATED,
		CTR_TBF_DL_FREED,
		CTR_TBF_UL_ALLOCATED,
		CTR_TBF_UL_FREED,
		CTR_TBF_REUSED,
		CTR_TBF_ALLOC_ALGO_A,
		CTR_TBF_ALLOC_ALGO_B,
		CTR_RLC_SENT,
		CTR_RLC_RESENT,
		CTR_RLC_RESTARTED,
		CTR_RLC_STALLED,
		CTR_RLC_NACKED,
		CTR_RLC_ASS_TIMEDOUT,
		CTR_RLC_ASS_FAILED,
		CTR_RLC_ACK_TIMEDOUT,
		CTR_RLC_ACK_FAILED,
		CTR_RLC_REL_TIMEDOUT,
		CTR_RLC_LATE_BLOCK,
		CTR_DECODE_ERRORS,
		CTR_SBA_ALLOCATED,
		CTR_SBA_FREED,
		CTR_SBA_TIMEDOUT,
		CTR_LLC_FRAME_TIMEDOUT,
		CTR_LLC_FRAME_DROPPED,
		CTR_LLC_FRAME_SCHED,
		CTR_RACH_REQUESTS,
	};

	enum {
		STAT_MS_PRESENT,
	};

	enum {
		TIMER_T3190_MSEC = 5000,
	};

	BTS();
	~BTS();

	static BTS* main_bts();

	struct gprs_rlcmac_bts *bts_data();
	SBAController *sba();

	/** TODO: change the number to unsigned */
	void set_current_frame_number(int frame_number);
	void set_current_block_frame_number(int frame_number, unsigned max_delay);
	int current_frame_number() const;

	/** add paging to paging queue(s) */
	int add_paging(uint8_t chan_needed, uint8_t *identity_lv);

	gprs_rlcmac_dl_tbf *dl_tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts);
	gprs_rlcmac_ul_tbf *ul_tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts);
	gprs_rlcmac_dl_tbf *dl_tbf_by_tfi(uint8_t tfi, uint8_t trx, uint8_t ts);
	gprs_rlcmac_ul_tbf *ul_tbf_by_tfi(uint8_t tfi, uint8_t trx, uint8_t ts);

	int tfi_find_free(enum gprs_rlcmac_tbf_direction dir, uint8_t *_trx, int8_t use_trx);

	int rcv_imm_ass_cnf(const uint8_t *data, uint32_t fn);
	int rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta);

	void trigger_dl_ass(gprs_rlcmac_dl_tbf *tbf, gprs_rlcmac_tbf *old_tbf);
	void snd_dl_ass(gprs_rlcmac_tbf *tbf, uint8_t poll, const char *imsi);

	GprsMsStorage &ms_store();
	GprsMs *ms_by_tlli(uint32_t tlli, uint32_t old_tlli = 0);
	GprsMs *ms_by_imsi(const char *imsi);
	GprsMs *ms_alloc(uint8_t ms_class, uint8_t egprs_ms_class = 0);

	/*
	 * Statistics
	 */
	void tbf_dl_created();
	void tbf_dl_freed();
	void tbf_ul_created();
	void tbf_ul_freed();
	void tbf_reused();
	void tbf_alloc_algo_a();
	void tbf_alloc_algo_b();
	void rlc_sent();
	void rlc_resent();
	void rlc_restarted();
	void rlc_stalled();
	void rlc_nacked();
	void rlc_ass_timedout();
	void rlc_ass_failed();
	void rlc_ack_timedout();
	void rlc_ack_failed();
	void rlc_rel_timedout();
	void rlc_late_block();
	void decode_error();
	void sba_allocated();
	void sba_freed();
	void sba_timedout();
	void llc_timedout_frame();
	void llc_dropped_frame();
	void llc_frame_sched();
	void rach_frame();

	void ms_present(int32_t n);
	int32_t ms_present_get();

	/*
	 * Below for C interface for the VTY
	 */
	struct rate_ctr_group *rate_counters() const;
	struct osmo_stat_item_group *stat_items() const;

private:
	int m_cur_fn;
	int m_cur_blk_fn;
	struct gprs_rlcmac_bts m_bts;
	PollController m_pollController;
	SBAController m_sba;
	struct rate_ctr_group *m_ratectrs;
	struct osmo_stat_item_group *m_statg;

	GprsMsStorage m_ms_store;

private:
	/* disable copying to avoid slicing */
	BTS(const BTS&);
	BTS& operator=(const BTS&);
};

inline int BTS::current_frame_number() const
{
	return m_cur_fn;
}

inline SBAController *BTS::sba()
{
	return &m_sba;
}

inline GprsMsStorage &BTS::ms_store()
{
	return m_ms_store;
}

inline GprsMs *BTS::ms_by_tlli(uint32_t tlli, uint32_t old_tlli)
{
	return ms_store().get_ms(tlli, old_tlli);
}

inline GprsMs *BTS::ms_by_imsi(const char *imsi)
{
	return ms_store().get_ms(0, 0, imsi);
}

inline BTS *gprs_rlcmac_pdch::bts() const
{
	return trx->bts;
}

inline unsigned gprs_rlcmac_pdch::num_tbfs(enum gprs_rlcmac_tbf_direction dir) const
{
	return m_num_tbfs[dir];
}

inline unsigned gprs_rlcmac_pdch::num_reserved(
	enum gprs_rlcmac_tbf_direction dir) const
{
	return gprs_rlcmac_pdch::m_num_reserved[dir];
}

inline uint8_t gprs_rlcmac_pdch::assigned_usf() const
{
	return m_assigned_usf;
}

inline uint32_t gprs_rlcmac_pdch::assigned_tfi(
	enum gprs_rlcmac_tbf_direction dir) const
{
	return m_assigned_tfi[dir];
}

inline struct rate_ctr_group *BTS::rate_counters() const
{
	return m_ratectrs;
}

inline struct osmo_stat_item_group *BTS::stat_items() const
{
	return m_statg;
}

#define CREATE_COUNT_INLINE(func_name, ctr_name) \
	inline void BTS::func_name() {\
		rate_ctr_inc(&m_ratectrs->ctr[ctr_name]); \
	}

CREATE_COUNT_INLINE(tbf_dl_created, CTR_TBF_DL_ALLOCATED)
CREATE_COUNT_INLINE(tbf_dl_freed, CTR_TBF_DL_FREED)
CREATE_COUNT_INLINE(tbf_ul_created, CTR_TBF_UL_ALLOCATED)
CREATE_COUNT_INLINE(tbf_ul_freed, CTR_TBF_UL_FREED)
CREATE_COUNT_INLINE(tbf_reused, CTR_TBF_REUSED)
CREATE_COUNT_INLINE(tbf_alloc_algo_a, CTR_TBF_ALLOC_ALGO_A)
CREATE_COUNT_INLINE(tbf_alloc_algo_b, CTR_TBF_ALLOC_ALGO_B)
CREATE_COUNT_INLINE(rlc_sent, CTR_RLC_SENT)
CREATE_COUNT_INLINE(rlc_resent, CTR_RLC_RESENT)
CREATE_COUNT_INLINE(rlc_restarted, CTR_RLC_RESTARTED)
CREATE_COUNT_INLINE(rlc_stalled, CTR_RLC_STALLED)
CREATE_COUNT_INLINE(rlc_nacked, CTR_RLC_NACKED)
CREATE_COUNT_INLINE(rlc_ass_timedout, CTR_RLC_ASS_TIMEDOUT);
CREATE_COUNT_INLINE(rlc_ass_failed, CTR_RLC_ASS_FAILED);
CREATE_COUNT_INLINE(rlc_ack_timedout, CTR_RLC_ACK_TIMEDOUT);
CREATE_COUNT_INLINE(rlc_ack_failed, CTR_RLC_ACK_FAILED);
CREATE_COUNT_INLINE(rlc_rel_timedout, CTR_RLC_REL_TIMEDOUT);
CREATE_COUNT_INLINE(rlc_late_block, CTR_RLC_LATE_BLOCK);
CREATE_COUNT_INLINE(decode_error, CTR_DECODE_ERRORS)
CREATE_COUNT_INLINE(sba_allocated, CTR_SBA_ALLOCATED)
CREATE_COUNT_INLINE(sba_freed, CTR_SBA_FREED)
CREATE_COUNT_INLINE(sba_timedout, CTR_SBA_TIMEDOUT)
CREATE_COUNT_INLINE(llc_timedout_frame, CTR_LLC_FRAME_TIMEDOUT);
CREATE_COUNT_INLINE(llc_dropped_frame, CTR_LLC_FRAME_DROPPED);
CREATE_COUNT_INLINE(llc_frame_sched, CTR_LLC_FRAME_SCHED);
CREATE_COUNT_INLINE(rach_frame, CTR_RACH_REQUESTS);

#undef CREATE_COUNT_INLINE

#define CREATE_STAT_INLINE(func_name, func_name_get, stat_name) \
	inline void BTS::func_name(int32_t val) {\
		osmo_stat_item_set(m_statg->items[stat_name], val); \
	} \
	inline int32_t BTS::func_name_get() {\
		return osmo_stat_item_get_last(m_statg->items[stat_name]); \
	}

CREATE_STAT_INLINE(ms_present, ms_present_get, STAT_MS_PRESENT);

#undef CREATE_STAT_INLINE

inline gprs_rlcmac_bts *gprs_rlcmac_pdch::bts_data() const
{
	return trx->bts->bts_data();
}

inline uint8_t gprs_rlcmac_pdch::trx_no() const
{
	return trx->trx_no;
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
	struct gprs_rlcmac_bts *bts_main_data();
	struct rate_ctr_group *bts_main_data_stats();
	struct osmo_stat_item_group *bts_main_data_stat_items();
#ifdef __cplusplus
}

inline bool gprs_rlcmac_pdch::is_enabled() const
{
	return m_is_enabled;
}
#endif
