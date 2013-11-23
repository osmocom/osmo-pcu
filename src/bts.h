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
#include <osmocom/core/timer.h>
}

#include "poll_controller.h"
#include "sba.h"
#include "ta.h"
#include "tbf.h"
#endif

#include <stdint.h>

struct BTS;

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
	int rcv_block(uint8_t *data, uint8_t len, uint32_t fn, int8_t rssi);

	gprs_rlcmac_bts *bts_data() const;
	BTS *bts() const;
	uint8_t trx_no() const;
#endif

	uint8_t m_is_enabled; /* TS is enabled */
	uint8_t tsc; /* TSC of this slot */
	uint8_t next_ul_tfi; /* next uplink TBF/TFI to schedule (0..31) */
	uint8_t next_dl_tfi; /* next downlink TBF/TFI to schedule (0..31) */
	struct gprs_rlcmac_tbf *ul_tbf[32]; /* array of UL TBF, by UL TFI */
	struct gprs_rlcmac_tbf *dl_tbf[32]; /* array of DL TBF, by DL TFI */
	struct llist_head paging_list; /* list of paging messages */
	uint32_t last_rts_fn; /* store last frame number of RTS */

	/* back pointers */
	struct gprs_rlcmac_trx *trx;
	uint8_t ts_no;

#ifdef __cplusplus
private:
	int rcv_data_block_acknowledged(uint8_t *data, uint8_t len, int8_t rssi);
	int rcv_control_block(bitvec *rlc_block, uint32_t fn);

	void rcv_control_ack(Packet_Control_Acknowledgement_t *, uint32_t fn);
	void rcv_control_dl_ack_nack(Packet_Downlink_Ack_Nack_t *, uint32_t fn);
	void rcv_resource_request(Packet_Resource_Request_t *t, uint32_t fn);
	void rcv_measurement_report(Packet_Measurement_Report_t *t, uint32_t fn);
#endif
};

struct gprs_rlcmac_trx {
	void *fl1h;
	uint16_t arfcn;
	struct gprs_rlcmac_pdch pdch[8];
	struct gprs_rlcmac_tbf *ul_tbf[32]; /* array of UL TBF, by UL TFI */
	struct gprs_rlcmac_tbf *dl_tbf[32]; /* array of DL TBF, by DL TFI */

	/* back pointers */
	struct BTS *bts;
	uint8_t trx_no;
};

/**
 * This is the data from C. As soon as our minimal compiler is gcc 4.7
 * we can start to compile pcu_vty.c with c++ and remove the split.
 */
struct gprs_rlcmac_bts {
	uint8_t bsic;
	uint8_t fc_interval;
	uint8_t cs1;
	uint8_t cs2;
	uint8_t cs3;
	uint8_t cs4;
	uint8_t initial_cs_dl, initial_cs_ul;
	uint8_t force_cs;	/* 0=use from BTS 1=use from VTY */
	uint16_t force_llc_lifetime; /* overrides lifetime from SGSN */
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
		struct gprs_rlcmac_tbf *old_tbf,
		struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);
	uint32_t alloc_algorithm_curst; /* options to customize algorithm */
	uint8_t force_two_phase;
	uint8_t alpha, gamma;

	/* TBF handling, make private or move into TBFController */
	/* list of uplink TBFs */
	struct llist_head ul_tbfs;
	/* list of downlink TBFs */
	struct llist_head dl_tbfs;


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
		CTR_RLC_SENT,
		CTR_RLC_RESENT,
		CTR_RLC_STALLED,
		CTR_RLC_NACKED,
		CTR_DECODE_ERRORS,
		CTR_SBA_ALLOCATED,
		CTR_SBA_FREED,
		CTR_SBA_TIMEDOUT,
		CTR_LLC_FRAME_TIMEDOUT,
		CTR_LLC_FRAME_DROPPED,
		CTR_LLC_FRAME_SCHED,
		CTR_RACH_REQUESTS,
	};

	BTS();
	~BTS();

	static BTS* main_bts();

	struct gprs_rlcmac_bts *bts_data();
	SBAController *sba();
	TimingAdvance *timing_advance();

	/** TODO: change the number to unsigned */
	void set_current_frame_number(int frame_number);
	int current_frame_number() const;

	/** add paging to paging queue(s) */
	int add_paging(uint8_t chan_needed, uint8_t *identity_lv);

	gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli, enum gprs_rlcmac_tbf_direction dir);
	gprs_rlcmac_tbf *tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts);
	gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi, uint8_t trx, enum gprs_rlcmac_tbf_direction dir);

	int tfi_find_free(enum gprs_rlcmac_tbf_direction dir, uint8_t *_trx, int8_t use_trx);

	int rcv_imm_ass_cnf(const uint8_t *data, uint32_t fn);
	int rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta);

	void trigger_dl_ass(gprs_rlcmac_tbf *tbf, gprs_rlcmac_tbf *old_tbf, const char *imsi);
	void snd_dl_ass(gprs_rlcmac_tbf *tbf, uint8_t poll, const char *imsi);

	/*
	 * Statistics
	 */
	void tbf_dl_created();
	void tbf_dl_freed();
	void tbf_ul_created();
	void tbf_ul_freed();
	void tbf_reused();
	void rlc_sent();
	void rlc_resent();
	void rlc_stalled();
	void rlc_nacked();
	void decode_error();
	void sba_allocated();
	void sba_freed();
	void sba_timedout();
	void llc_timedout_frame();
	void llc_dropped_frame();
	void llc_frame_sched();
	void rach_frame();

	/*
	 * Below for C interface for the VTY
	 */
	struct rate_ctr_group *rate_counters() const;

private:
	int m_cur_fn;
	struct gprs_rlcmac_bts m_bts;
	PollController m_pollController;
	SBAController m_sba;
	TimingAdvance m_ta;
	struct rate_ctr_group *m_ratectrs;

private:
	/* disable copying to avoid slicing */
	BTS(const BTS&);
	BTS& operator=(const BTS&);
};

inline int BTS::current_frame_number() const
{
	return m_cur_fn;
}

inline TimingAdvance *BTS::timing_advance()
{
	return &m_ta;
}

inline SBAController *BTS::sba()
{
	return &m_sba;
}

inline BTS *gprs_rlcmac_pdch::bts() const
{
	return trx->bts;
}

inline struct rate_ctr_group *BTS::rate_counters() const
{
	return m_ratectrs;
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
CREATE_COUNT_INLINE(rlc_sent, CTR_RLC_SENT)
CREATE_COUNT_INLINE(rlc_resent, CTR_RLC_RESENT)
CREATE_COUNT_INLINE(rlc_stalled, CTR_RLC_STALLED)
CREATE_COUNT_INLINE(rlc_nacked, CTR_RLC_NACKED)
CREATE_COUNT_INLINE(decode_error, CTR_DECODE_ERRORS)
CREATE_COUNT_INLINE(sba_allocated, CTR_SBA_ALLOCATED)
CREATE_COUNT_INLINE(sba_freed, CTR_SBA_FREED)
CREATE_COUNT_INLINE(sba_timedout, CTR_SBA_TIMEDOUT)
CREATE_COUNT_INLINE(llc_timedout_frame, CTR_LLC_FRAME_TIMEDOUT);
CREATE_COUNT_INLINE(llc_dropped_frame, CTR_LLC_FRAME_DROPPED);
CREATE_COUNT_INLINE(llc_frame_sched, CTR_LLC_FRAME_SCHED);
CREATE_COUNT_INLINE(rach_frame, CTR_RACH_REQUESTS);

#undef CREATE_COUNT_INLINE


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
#ifdef __cplusplus
}

inline bool gprs_rlcmac_pdch::is_enabled() const
{
	return m_is_enabled;
}
#endif
