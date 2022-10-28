/*
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
 */

#pragma once

#ifdef __cplusplus

#include <string>

#include "llc.h"
#include "rlc.h"
#include "cxx_linuxlist.h"
#include "pcu_utils.h"
#include <gprs_debug.h>
#include <stdint.h>

struct bssgp_bvc_ctx;
struct gprs_rlcmac_bts;

#endif

struct GprsMs;

#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm48.h>

#include "coding_scheme.h"
#include <pdch_ul_controller.h>
#include <tbf_fsm.h>
#include <tbf_ul_ass_fsm.h>
#include <tbf_dl_ass_fsm.h>
#ifdef __cplusplus
}
#endif

/*
 * TBF instance
 */

enum gprs_rlcmac_tbf_direction {
	GPRS_RLCMAC_DL_TBF,
	GPRS_RLCMAC_UL_TBF
};

enum tbf_rlc_counters {
	TBF_CTR_RLC_NACKED,
};

enum tbf_gprs_counters {
	TBF_CTR_GPRS_DL_CS1,
	TBF_CTR_GPRS_DL_CS2,
	TBF_CTR_GPRS_DL_CS3,
	TBF_CTR_GPRS_DL_CS4,
};

enum tbf_egprs_counters {
	TBF_CTR_EGPRS_DL_MCS1,
	TBF_CTR_EGPRS_DL_MCS2,
	TBF_CTR_EGPRS_DL_MCS3,
	TBF_CTR_EGPRS_DL_MCS4,
	TBF_CTR_EGPRS_DL_MCS5,
	TBF_CTR_EGPRS_DL_MCS6,
	TBF_CTR_EGPRS_DL_MCS7,
	TBF_CTR_EGPRS_DL_MCS8,
	TBF_CTR_EGPRS_DL_MCS9,
};

extern const struct rate_ctr_group_desc tbf_ctrg_desc;
extern unsigned int next_tbf_ctr_group_id;

#define LOGPTBF(tbf, level, fmt, args...) LOGP(DTBF, level, "%s " fmt, tbf_name(tbf), ## args)

enum tbf_timers {
	/* Wait contention resolution success on UL TBFs assigned over CCCH */
	T3141,

	/* Wait for reuse of TFI(s) after sending of the last RLC Data Block on this TBF.
	   Wait for reuse of TFI(s) after sending the PACKET TBF RELEASE for an MBMS radio bearer. */
	T3191,

	T_MAX
};

enum tbf_counters { /* TBF counters from 3GPP TS 44.060 §13.4 */
	/* counters are reset when: */
	N3101, /* received a valid data block from mobile station in a block assigned for this USF */
	N3103, /* transmitting the final PACKET UPLINK ACK/NACK message */
	N3105, /* after sending a RRBP field in the downlink RLC data block, receives a valid RLC/MAC control message */
	N_MAX
};

#define GPRS_RLCMAC_FLAG_CCCH		0 /* assignment on CCCH */
#define GPRS_RLCMAC_FLAG_PACCH		1 /* assignment on PACCH */
#define GPRS_RLCMAC_FLAG_DL_ACK		2 /* DL TBF: At least one DL ACK/NACK was recieved since it was assigned */
#define GPRS_RLCMAC_FLAG_TO_DL_ACK	3 /* DL TBF: Failed to receive last polled DL ACK/NACK */
#define GPRS_RLCMAC_FLAG_TO_MASK	0xf0 /* timeout bits */

#define TBF_TS_UNSET 0xff
#define TBF_TFI_UNSET 0xff

#define T_START(tbf, t, T, r, f) tbf->t_start(t, T, r, f, __FILE__, __LINE__)

#ifdef __cplusplus
extern "C" {
#endif
struct gprs_rlcmac_tbf;
const char *tbf_name(const struct gprs_rlcmac_tbf *tbf);
enum tbf_fsm_states tbf_state(const struct gprs_rlcmac_tbf *tbf);
struct osmo_fsm_inst *tbf_ul_ass_fi(const struct gprs_rlcmac_tbf *tbf);
struct osmo_fsm_inst *tbf_dl_ass_fi(const struct gprs_rlcmac_tbf *tbf);
enum gprs_rlcmac_tbf_direction tbf_direction(const struct gprs_rlcmac_tbf *tbf);
void tbf_set_ms(struct gprs_rlcmac_tbf *tbf, struct GprsMs *ms);
struct llist_head *tbf_ms_list(struct gprs_rlcmac_tbf *tbf);
struct llist_head *tbf_trx_list(struct gprs_rlcmac_tbf *tbf);
struct GprsMs *tbf_ms(const struct gprs_rlcmac_tbf *tbf);
bool tbf_timers_pending(struct gprs_rlcmac_tbf *tbf, enum tbf_timers t);
void tbf_free(struct gprs_rlcmac_tbf *tbf);
struct gprs_llc *tbf_llc(struct gprs_rlcmac_tbf *tbf);
uint8_t tbf_first_common_ts(const struct gprs_rlcmac_tbf *tbf);
uint8_t tbf_dl_slots(const struct gprs_rlcmac_tbf *tbf);
uint8_t tbf_ul_slots(const struct gprs_rlcmac_tbf *tbf);
bool tbf_is_tfi_assigned(const struct gprs_rlcmac_tbf *tbf);
uint8_t tbf_tfi(const struct gprs_rlcmac_tbf *tbf);
bool tbf_is_egprs_enabled(const struct gprs_rlcmac_tbf *tbf);
void tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf);
int tbf_check_polling(const struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts, uint32_t *poll_fn, unsigned int *rrbp);
void tbf_set_polling(struct gprs_rlcmac_tbf *tbf, uint32_t new_poll_fn, uint8_t ts, enum pdch_ulc_tbf_poll_reason t);
void tbf_poll_timeout(struct gprs_rlcmac_tbf *tbf, struct gprs_rlcmac_pdch *pdch, uint32_t poll_fn, enum pdch_ulc_tbf_poll_reason reason);
void tbf_update_state_fsm_name(struct gprs_rlcmac_tbf *tbf);
const char* tbf_rlcmac_diag(const struct gprs_rlcmac_tbf *tbf);
bool tbf_is_control_ts(const struct gprs_rlcmac_tbf *tbf, uint8_t ts);
bool tbf_can_upgrade_to_multislot(const struct gprs_rlcmac_tbf *tbf);
int tbf_update(struct gprs_rlcmac_tbf *tbf);
struct gprs_rlcmac_trx *tbf_get_trx(struct gprs_rlcmac_tbf *tbf);
void tbf_stop_timers(struct gprs_rlcmac_tbf *tbf, const char *reason);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

struct gprs_rlcmac_tbf {
	gprs_rlcmac_tbf(struct gprs_rlcmac_bts *bts_, GprsMs *ms, gprs_rlcmac_tbf_direction dir);
	virtual ~gprs_rlcmac_tbf();

	virtual gprs_rlc_window *window() = 0;

	int setup(int8_t use_trx, bool single_slot);
	bool state_is(enum tbf_fsm_states rhs) const;
	bool state_is_not(enum tbf_fsm_states rhs) const;
	bool dl_ass_state_is(enum tbf_dl_ass_fsm_states rhs) const;
	bool ul_ass_state_is(enum tbf_ul_ass_fsm_states rhs) const;
	void poll_sched_set(const char *file, int line);
	void poll_sched_unset(const char *file, int line);
	bool check_n_clear(uint8_t state_flag);
	const char *state_name() const;

	const char *name() const;

	struct msgb *create_dl_ass(uint32_t fn, uint8_t ts);

	GprsMs *ms() const;
	void set_ms(GprsMs *ms);

	bool n_inc(enum tbf_counters n);
	void n_reset(enum tbf_counters n);

	int update();
	void handle_timeout();
	void stop_timers(const char *reason);
	bool timers_pending(enum tbf_timers t);
	void t_stop(enum tbf_timers t, const char *reason);
	void t_start(enum tbf_timers t, int T, const char *reason, bool force,
		     const char *file, unsigned line);

	int check_polling(uint32_t fn, uint8_t ts,
		uint32_t *poll_fn, unsigned int *rrbp) const;
	void set_polling(uint32_t poll_fn, uint8_t ts, enum pdch_ulc_tbf_poll_reason reason);
	void poll_timeout(struct gprs_rlcmac_pdch *pdch, uint32_t poll_fn, enum pdch_ulc_tbf_poll_reason reason);

	/** tlli handling */
	uint32_t tlli() const;
	bool is_tlli_valid() const;

	/** MS updating */
	void update_ms(uint32_t tlli, enum gprs_rlcmac_tbf_direction);

	uint8_t tfi() const;
	bool is_tfi_assigned() const;

	const char *imsi() const;
	uint8_t ta() const;
	void set_ta(uint8_t);
	uint8_t ms_class() const;
	enum CodingScheme current_cs() const;

	time_t created_ts() const;
	uint8_t dl_slots() const;
	uint8_t ul_slots() const;

	bool is_control_ts(uint8_t ts) const;

	/* EGPRS */
	bool is_egprs_enabled() const;

	/* attempt to make things a bit more fair */
	void rotate_in_list();

	enum gprs_rlcmac_tbf_direction direction;
	struct gprs_rlcmac_trx *trx;
	uint8_t first_ts; /* first TS used by TBF */
	uint8_t first_common_ts; /* first TS where the phone can send and
		receive simultaniously */
	uint8_t control_ts; /* timeslot control messages and polling */
	struct gprs_rlcmac_pdch *pdch[8]; /* list of PDCHs allocated to TBF */

	gprs_llc m_llc;
	gprs_rlc m_rlc;

	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */

	struct Meas {
		struct timespec rssi_tv; /* timestamp for rssi calculation */
		int32_t rssi_sum; /* sum of rssi values */
		int rssi_num; /* number of rssi values added since rssi_tv */

		Meas();
	} meas;

	/* Can/should we upgrade this tbf to use multiple slots? */
	bool upgrade_to_multislot;

	/* store the BTS this TBF belongs to */
	struct gprs_rlcmac_bts *bts;

	/*
	 * private fields. We can't make it private as it is breaking the
	 * llist macros.
	 */
	uint8_t m_tfi;
	time_t m_created_ts;

	struct rate_ctr_group *m_ctrs;
	struct tbf_fsm_ctx state_fsm;
	struct tbf_ul_ass_fsm_ctx ul_ass_fsm;
	struct tbf_ul_ass_fsm_ctx dl_ass_fsm;

	struct llist_item m_ms_list;
	struct llist_item m_trx_list;

protected:
	void merge_and_clear_ms(GprsMs *old_ms);

	gprs_llc_queue *llc_queue();
	const gprs_llc_queue *llc_queue() const;

	struct GprsMs *m_ms;
private:
	void enable_egprs();
	bool m_egprs_enabled;
	struct osmo_timer_list Tarr[T_MAX];
	uint8_t Narr[N_MAX];
	mutable char m_name_buf[60];
};

inline bool gprs_rlcmac_tbf::state_is(enum tbf_fsm_states rhs) const
{
	return tbf_state(this) == rhs;
}

inline bool gprs_rlcmac_tbf::dl_ass_state_is(enum tbf_dl_ass_fsm_states rhs) const
{
	return tbf_dl_ass_fi(this)->state == rhs;
}

inline bool gprs_rlcmac_tbf::ul_ass_state_is(enum tbf_ul_ass_fsm_states rhs) const
{
	return tbf_ul_ass_fi(this)->state == rhs;
}

inline bool gprs_rlcmac_tbf::state_is_not(enum tbf_fsm_states rhs) const
{
	return tbf_state(this) != rhs;
}


inline const char *gprs_rlcmac_tbf::state_name() const
{
	return osmo_fsm_inst_state_name(state_fsm.fi);
}

inline bool gprs_rlcmac_tbf::check_n_clear(uint8_t state_flag)
{
	if ((state_fsm.state_flags & (1 << state_flag))) {
		state_fsm.state_flags &= ~(1 << state_flag);
		return true;
	}

	return false;
}

inline GprsMs *gprs_rlcmac_tbf::ms() const
{
	return m_ms;
}

inline bool gprs_rlcmac_tbf::is_tlli_valid() const
{
	return tlli() != GSM_RESERVED_TMSI;
}

inline bool gprs_rlcmac_tbf::is_tfi_assigned() const
{
	/* The TBF is established or has been assigned by a IMM.ASS for
	 * download */
	return state_fsm.fi->state > TBF_ST_ASSIGN ||
		(direction == GPRS_RLCMAC_DL_TBF &&
		 state_fsm.fi->state == TBF_ST_ASSIGN &&
		 (state_fsm.state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)));
}

inline uint8_t gprs_rlcmac_tbf::tfi() const
{
	return m_tfi;
}

inline time_t gprs_rlcmac_tbf::created_ts() const
{
	return m_created_ts;
}

inline bool gprs_rlcmac_tbf::is_egprs_enabled() const
{
	return m_egprs_enabled;
}

inline enum gprs_rlcmac_tbf_direction reverse(enum gprs_rlcmac_tbf_direction dir)
{
	return (enum gprs_rlcmac_tbf_direction)
		((int)GPRS_RLCMAC_UL_TBF - (int)dir + (int)GPRS_RLCMAC_DL_TBF);
}

uint16_t egprs_window_size(const struct gprs_rlcmac_bts *bts, uint8_t slots);

#endif
