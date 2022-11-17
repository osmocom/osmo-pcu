/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#ifdef __cplusplus

#include <stdbool.h>

#include "tbf.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <tbf_fsm.h>
#include <tbf_ul_ack_fsm.h>
#ifdef __cplusplus
}
#endif

/*
 * TBF instance
 */

enum tbf_gprs_ul_counters {
        TBF_CTR_GPRS_UL_CS1,
        TBF_CTR_GPRS_UL_CS2,
        TBF_CTR_GPRS_UL_CS3,
        TBF_CTR_GPRS_UL_CS4,
};

enum tbf_egprs_ul_counters {
        TBF_CTR_EGPRS_UL_MCS1,
        TBF_CTR_EGPRS_UL_MCS2,
        TBF_CTR_EGPRS_UL_MCS3,
        TBF_CTR_EGPRS_UL_MCS4,
        TBF_CTR_EGPRS_UL_MCS5,
        TBF_CTR_EGPRS_UL_MCS6,
        TBF_CTR_EGPRS_UL_MCS7,
        TBF_CTR_EGPRS_UL_MCS8,
        TBF_CTR_EGPRS_UL_MCS9,
};

/* Used in ul_tbf->m_usf[] to flag unassigned USF on a given TS: */
#define USF_INVALID 0xFF

struct gprs_rlcmac_ul_tbf : public gprs_rlcmac_tbf {
	gprs_rlcmac_ul_tbf(struct gprs_rlcmac_bts *bts, GprsMs *ms);
	~gprs_rlcmac_ul_tbf();
	gprs_rlc_window *window();
	/* blocks were acked */
	int rcv_data_block_acknowledged(
		const struct gprs_rlc_data_info *rlc,
		uint8_t *data, struct pcu_l1_meas *meas);


	/* TODO: extract LLC class? */
	int assemble_forward_llc(const gprs_rlc_data *data);
	int snd_ul_ud();

	egprs_rlc_ul_reseg_bsn_state handle_egprs_ul_spb(
		const struct gprs_rlc_data_info *rlc,
		struct gprs_rlc_data *block,
		uint8_t *data, const uint8_t block_idx);

	egprs_rlc_ul_reseg_bsn_state handle_egprs_ul_first_seg(
		const struct gprs_rlc_data_info *rlc,
		struct gprs_rlc_data *block,
		uint8_t *data, const uint8_t block_idx);

	egprs_rlc_ul_reseg_bsn_state handle_egprs_ul_second_seg(
		const struct gprs_rlc_data_info *rlc,
		struct gprs_rlc_data *block,
		uint8_t *data, const uint8_t block_idx);

	uint16_t window_size() const;
	void set_window_size();
	void update_coding_scheme_counter_ul(enum CodingScheme cs);
        void usf_timeout();
	void contention_resolution_start();
	void contention_resolution_success();

	/* Please note that all variables here will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	int32_t m_rx_counter; /* count all received blocks */
	uint8_t m_usf[8];	/* list USFs per PDCH (timeslot), initialized to USF_INVALID */
	bool m_contention_resolution_done; /* set after done */

	struct rate_ctr_group *m_ul_gprs_ctrs;
	struct rate_ctr_group *m_ul_egprs_ctrs;

	struct tbf_ul_fsm_ctx state_fsm;
	struct tbf_ul_ass_fsm_ctx ul_ack_fsm;

protected:
	void maybe_schedule_uplink_acknack(const gprs_rlc_data_info *rlc, bool countdown_finished);

	/* Please note that all variables below will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	gprs_rlc_ul_window m_window;
};

inline uint16_t gprs_rlcmac_ul_tbf::window_size() const
{
	return m_window.ws();
}

struct gprs_rlcmac_ul_tbf *handle_tbf_reject(struct gprs_rlcmac_bts *bts,
	GprsMs *ms, uint8_t trx_no, uint8_t ts_no);

#else /* ifdef __cplusplus */
struct gprs_rlcmac_ul_tbf;
#endif


#ifdef __cplusplus
extern "C" {
#endif
struct gprs_rlcmac_ul_tbf *ul_tbf_alloc(struct gprs_rlcmac_bts *bts, struct GprsMs *ms, int8_t use_trx, bool single_slot);
void update_tbf_ta(struct gprs_rlcmac_ul_tbf *tbf, int8_t ta_delta);
void set_tbf_ta(struct gprs_rlcmac_ul_tbf *tbf, uint8_t ta);
struct gprs_rlcmac_ul_tbf *tbf_as_ul_tbf(struct gprs_rlcmac_tbf *tbf);
const struct gprs_rlcmac_ul_tbf *tbf_as_ul_tbf_const(const struct gprs_rlcmac_tbf *tbf);
void tbf_usf_timeout(struct gprs_rlcmac_ul_tbf *tbf);
void ul_tbf_contention_resolution_start(struct gprs_rlcmac_ul_tbf *tbf);
void ul_tbf_contention_resolution_success(struct gprs_rlcmac_ul_tbf *tbf);
bool ul_tbf_contention_resolution_done(const struct gprs_rlcmac_ul_tbf *tbf);
struct osmo_fsm_inst *tbf_ul_ack_fi(const struct gprs_rlcmac_ul_tbf *tbf);

static inline struct gprs_rlcmac_tbf *ul_tbf_as_tbf(struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return (struct gprs_rlcmac_tbf *)ul_tbf;
}

static inline const struct gprs_rlcmac_tbf *ul_tbf_as_tbf_const(const struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return (const struct gprs_rlcmac_tbf *)ul_tbf;
}

#define LOGPTBFUL(ul_tbf, level, fmt, args...) LOGP(DTBFUL, level, "%s " fmt, tbf_name(ul_tbf_as_tbf_const(ul_tbf)), ## args)
#ifdef __cplusplus
}
#endif
