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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#pragma once

#ifdef __cplusplus

#include <string>

#include "llc.h"
#include "rlc.h"
#include "cxx_linuxlist.h"
#include <gprs_debug.h>
#include <gsm_timer.h>
#include <stdint.h>

extern "C" {
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>

#include "coding_scheme.h"
}

struct bssgp_bvc_ctx;
class GprsMs;
struct gprs_rlcmac_bts;

#endif

/*
 * TBF instance
 */

enum gprs_rlcmac_tbf_state {
	GPRS_RLCMAC_NULL = 0,	/* new created TBF */
	GPRS_RLCMAC_ASSIGN,	/* wait for downlink assignment */
	GPRS_RLCMAC_FLOW,	/* RLC/MAC flow, resource needed */
	GPRS_RLCMAC_FINISHED,	/* flow finished, wait for release */
	GPRS_RLCMAC_WAIT_RELEASE,/* wait for release or restart of DL TBF */
	GPRS_RLCMAC_RELEASING,	/* releasing, wait to free TBI/USF */
};

enum gprs_rlcmac_tbf_poll_type {
	GPRS_RLCMAC_POLL_UL_ASS,
	GPRS_RLCMAC_POLL_DL_ASS,
	GPRS_RLCMAC_POLL_UL_ACK,
	GPRS_RLCMAC_POLL_DL_ACK,
};

enum gprs_rlcmac_tbf_poll_state {
	GPRS_RLCMAC_POLL_NONE = 0,
	GPRS_RLCMAC_POLL_SCHED, /* a polling was scheduled */
};

extern const struct value_string gprs_rlcmac_tbf_poll_state_names[];

enum gprs_rlcmac_tbf_dl_ass_state {
	GPRS_RLCMAC_DL_ASS_NONE = 0,
	GPRS_RLCMAC_DL_ASS_SEND_ASS, /* send downlink assignment on next RTS */
	GPRS_RLCMAC_DL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

extern const struct value_string gprs_rlcmac_tbf_dl_ass_state_names[];

enum gprs_rlcmac_tbf_ul_ass_state {
	GPRS_RLCMAC_UL_ASS_NONE = 0,
	GPRS_RLCMAC_UL_ASS_SEND_ASS, /* send uplink assignment on next RTS */
	GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ, /* send assignment reject next RTS */
	GPRS_RLCMAC_UL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

extern const struct value_string gprs_rlcmac_tbf_ul_ass_state_names[];

enum gprs_rlcmac_tbf_ul_ack_state {
	GPRS_RLCMAC_UL_ACK_NONE = 0,
	GPRS_RLCMAC_UL_ACK_SEND_ACK, /* send acknowledge on next RTS */
	GPRS_RLCMAC_UL_ACK_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

extern const struct value_string gprs_rlcmac_tbf_ul_ack_state_names[];

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
	/* internal assign/reject timer */
	T0,

	/* Wait for reuse of USF and TFI(s) after the MS uplink assignment for this TBF is invalid. */
	T3169,

	/* Wait for reuse of TFI(s) after sending of the last RLC Data Block on this TBF.
	   Wait for reuse of TFI(s) after sending the PACKET TBF RELEASE for an MBMS radio bearer. */
	T3191,

	/* Wait for reuse of TFI(s) after reception of the final PACKET DOWNLINK ACK/NACK from the
	   MS for this TBF. */
	T3193,

	/* Wait for reuse of TFI(s) when there is no response from the MS
	   (radio failure or cell change) for this TBF/MBMS radio bearer. */
	T3195,
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
#define GPRS_RLCMAC_FLAG_UL_DATA	2 /* uplink data received */
#define GPRS_RLCMAC_FLAG_DL_ACK		3 /* downlink acknowledge received  */
#define GPRS_RLCMAC_FLAG_TO_UL_ACK	4
#define GPRS_RLCMAC_FLAG_TO_DL_ACK	5
#define GPRS_RLCMAC_FLAG_TO_UL_ASS	6
#define GPRS_RLCMAC_FLAG_TO_DL_ASS	7
#define GPRS_RLCMAC_FLAG_TO_MASK	0xf0 /* timeout bits */

#define T_START(tbf, t, T, r, f) tbf->t_start(t, T, r, f, __FILE__, __LINE__)

#define TBF_SET_STATE(t, st) do { t->set_state(st, __FILE__, __LINE__); } while(0)
#define TBF_SET_ASS_STATE_DL(t, st) do { t->set_ass_state_dl(st, __FILE__, __LINE__); } while(0)
#define TBF_SET_ASS_STATE_UL(t, st) do { t->set_ass_state_ul(st, __FILE__, __LINE__); } while(0)
#define TBF_SET_ACK_STATE(t, st) do { t->set_ack_state(st, __FILE__, __LINE__); } while(0)
#define TBF_POLL_SCHED_SET(t) do { t->poll_sched_set(__FILE__, __LINE__); } while(0)
#define TBF_POLL_SCHED_UNSET(t) do { t->poll_sched_unset(__FILE__, __LINE__); } while(0)
#define TBF_SET_ASS_ON(t, fl, chk) do { t->set_assigned_on(fl, chk, __FILE__, __LINE__); } while(0)
#define TBF_ASS_TYPE_SET(t, kind) do { t->ass_type_mod(kind, false, __FILE__, __LINE__); } while(0)
#define TBF_ASS_TYPE_UNSET(t, kind) do { t->ass_type_mod(kind, true, __FILE__, __LINE__); } while(0)

#ifdef __cplusplus

struct gprs_rlcmac_tbf {
	gprs_rlcmac_tbf(BTS *bts_, GprsMs *ms, gprs_rlcmac_tbf_direction dir);

	static void free_all(struct gprs_rlcmac_trx *trx);
	static void free_all(struct gprs_rlcmac_pdch *pdch);

	virtual gprs_rlc_window *window() = 0;

	int setup(int8_t use_trx, bool single_slot);
	bool state_is(enum gprs_rlcmac_tbf_state rhs) const;
	bool state_is_not(enum gprs_rlcmac_tbf_state rhs) const;
	bool dl_ass_state_is(enum gprs_rlcmac_tbf_dl_ass_state rhs) const;
	bool ul_ass_state_is(enum gprs_rlcmac_tbf_ul_ass_state rhs) const;
	bool ul_ack_state_is(enum gprs_rlcmac_tbf_ul_ack_state rhs) const;
	bool poll_scheduled() const;
	void set_state(enum gprs_rlcmac_tbf_state new_state, const char *file, int line);
	void set_ass_state_dl(enum gprs_rlcmac_tbf_dl_ass_state new_state, const char *file, int line);
	void set_ass_state_ul(enum gprs_rlcmac_tbf_ul_ass_state new_state, const char *file, int line);
	void set_ack_state(enum gprs_rlcmac_tbf_ul_ack_state new_state, const char *file, int line);
	void poll_sched_set(const char *file, int line);
	void poll_sched_unset(const char *file, int line);
	void check_pending_ass();
	bool check_n_clear(uint8_t state_flag);
	void set_assigned_on(uint8_t state_flag, bool check_ccch, const char *file, int line);
	void ass_type_mod(uint8_t t, bool unset, const char *file, int line);
	const char *state_name() const;

	const char *name() const;

	struct msgb *create_dl_ass(uint32_t fn, uint8_t ts);
	struct msgb *create_ul_ass(uint32_t fn, uint8_t ts);
	struct msgb *create_packet_access_reject();

	GprsMs *ms() const;
	void set_ms(GprsMs *ms);

	uint8_t tsc() const;

	std::string rlcmac_diag();

	bool n_inc(enum tbf_counters n);
	void n_reset(enum tbf_counters n);

	int update();
	void handle_timeout();
	void stop_timers(const char *reason);
	bool timers_pending(enum tbf_timers t);
	void t_stop(enum tbf_timers t, const char *reason);
	void t_start(enum tbf_timers t, int T, const char *reason, bool force,
		     const char *file, unsigned line);
	int establish_dl_tbf_on_pacch();

	int check_polling(uint32_t fn, uint8_t ts,
		uint32_t *poll_fn, unsigned int *rrbp);
	void set_polling(uint32_t poll_fn, uint8_t ts, enum gprs_rlcmac_tbf_poll_type t);
	void poll_timeout();

	/** tlli handling */
	uint32_t tlli() const;
	bool is_tlli_valid() const;

	/** MS updating */
	void update_ms(uint32_t tlli, enum gprs_rlcmac_tbf_direction);

	uint8_t tfi() const;
	bool is_tfi_assigned() const;

	const char *imsi() const;
	void assign_imsi(const char *imsi);
	uint8_t ta() const;
	void set_ta(uint8_t);
	uint8_t ms_class() const;
	enum CodingScheme current_cs() const;
	size_t llc_queue_size() const;

	time_t created_ts() const;
	uint8_t dl_slots() const;
	uint8_t ul_slots() const;

	bool is_control_ts(uint8_t ts) const;

	/* EGPRS */
	bool is_egprs_enabled() const;

	/* attempt to make things a bit more fair */
	void rotate_in_list();

	LListHead<gprs_rlcmac_tbf>& ms_list() {return this->m_ms_list;}
	const LListHead<gprs_rlcmac_tbf>& ms_list() const {return this->m_ms_list;}

	LListHead<gprs_rlcmac_tbf>& list();
	const LListHead<gprs_rlcmac_tbf>& list() const;

	uint32_t state_flags;
	enum gprs_rlcmac_tbf_direction direction;
	struct gprs_rlcmac_trx *trx;
	uint8_t first_ts; /* first TS used by TBF */
	uint8_t first_common_ts; /* first TS where the phone can send and
		receive simultaniously */
	uint8_t control_ts; /* timeslot control messages and polling */
	struct gprs_rlcmac_pdch *pdch[8]; /* list of PDCHs allocated to TBF */

	gprs_llc m_llc;

	uint32_t poll_fn; /* frame number to poll */
	uint8_t poll_ts; /* TS to poll */

	gprs_rlc m_rlc;

	struct osmo_gsm_timer_list	gsm_timer;
	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */

	struct Meas {
		struct timespec rssi_tv; /* timestamp for rssi calculation */
		int32_t rssi_sum; /* sum of rssi values */
		int rssi_num; /* number of rssi values added since rssi_tv */

		Meas();
	} meas;

	/* Remember if the tbf was in wait_release state when we want to
	 * schedule a new dl assignment */
	uint8_t was_releasing;

	/* Can/should we upgrade this tbf to use multiple slots? */
	uint8_t upgrade_to_multislot;

	/* store the BTS this TBF belongs to */
	BTS *bts;

	/*
	 * private fields. We can't make it private as it is breaking the
	 * llist macros.
	 */
	uint8_t m_tfi;
	time_t m_created_ts;

	struct rate_ctr_group *m_ctrs;

protected:
	gprs_rlcmac_bts *bts_data() const;
	void merge_and_clear_ms(GprsMs *old_ms);

	gprs_llc_queue *llc_queue();
	const gprs_llc_queue *llc_queue() const;

	static const char *tbf_state_name[6];

	class GprsMs *m_ms;
private:
	void enable_egprs();
	enum gprs_rlcmac_tbf_state state;
	enum gprs_rlcmac_tbf_dl_ass_state dl_ass_state;
	enum gprs_rlcmac_tbf_ul_ass_state ul_ass_state;
	enum gprs_rlcmac_tbf_ul_ack_state ul_ack_state;
	enum gprs_rlcmac_tbf_poll_state poll_state;
	LListHead<gprs_rlcmac_tbf> m_list;
	LListHead<gprs_rlcmac_tbf> m_ms_list;
	bool m_egprs_enabled;
	struct osmo_timer_list Tarr[T_MAX];
	uint8_t Narr[N_MAX];
	mutable char m_name_buf[60];
};

void tbf_free(struct gprs_rlcmac_tbf *tbf);

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf);

inline bool gprs_rlcmac_tbf::state_is(enum gprs_rlcmac_tbf_state rhs) const
{
	return state == rhs;
}

inline bool gprs_rlcmac_tbf::dl_ass_state_is(enum gprs_rlcmac_tbf_dl_ass_state rhs) const
{
	return dl_ass_state == rhs;
}

inline bool gprs_rlcmac_tbf::ul_ass_state_is(enum gprs_rlcmac_tbf_ul_ass_state rhs) const
{
	return ul_ass_state == rhs;
}

inline bool gprs_rlcmac_tbf::ul_ack_state_is(enum gprs_rlcmac_tbf_ul_ack_state rhs) const
{
	return ul_ack_state == rhs;
}

inline bool gprs_rlcmac_tbf::poll_scheduled() const
{
	return poll_state == GPRS_RLCMAC_POLL_SCHED;
}

inline bool gprs_rlcmac_tbf::state_is_not(enum gprs_rlcmac_tbf_state rhs) const
{
	return state != rhs;
}

const char *tbf_name(gprs_rlcmac_tbf *tbf);

inline const char *gprs_rlcmac_tbf::state_name() const
{
	return tbf_state_name[state];
}

/* Set assignment state and corrsponding flags */
inline void gprs_rlcmac_tbf::set_assigned_on(uint8_t state_flag, bool check_ccch, const char *file, int line)
{
	set_state(GPRS_RLCMAC_ASSIGN, file, line);
	if (check_ccch) {
		if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)))
			ass_type_mod(state_flag, false, file, line);
	} else
		state_flags |= (1 << state_flag);
}

inline void gprs_rlcmac_tbf::ass_type_mod(uint8_t t, bool unset, const char *file, int line)
{
	const char *ch = "UNKNOWN";
	switch (t) {
	case GPRS_RLCMAC_FLAG_CCCH:
		if (unset) {
			if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)))
				return;
		} else {
			if (state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))
				LOGPSRC(DTBF, LOGL_ERROR, file, line,
					"%s attempted to set ass. type CCCH which is already set.\n",
					tbf_name(this));
		}
		ch = "CCCH";
		break;
	case GPRS_RLCMAC_FLAG_PACCH:
		if (unset) {
			if (!(state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)))
				return;
		} else {
			if (state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))
				LOGPSRC(DTBF, LOGL_ERROR, file, line,
					"%s attempted to set ass. type PACCH which is already set.\n",
					tbf_name(this));
		}
		ch = "PACCH";
		break;
	default:
		LOGPSRC(DTBF, LOGL_ERROR, file, line, "%s attempted to %sset unexpected ass. type %d - FIXME!\n",
			tbf_name(this), unset ? "un" : "", t);
		return;
	}

	LOGPSRC(DTBF, LOGL_INFO, file, line, "%s %sset ass. type %s [prev CCCH:%u, PACCH:%u]\n",
		tbf_name(this), unset ? "un" : "", ch,
		state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH),
		state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH));

	if (unset) {
		state_flags &= GPRS_RLCMAC_FLAG_TO_MASK; /* keep to flags */
		state_flags &= ~(1 << t);
	} else
		state_flags |= (1 << t);
}

inline void gprs_rlcmac_tbf::set_state(enum gprs_rlcmac_tbf_state new_state, const char *file, int line)
{
	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s changes state from %s to %s\n",
		tbf_name(this),
		tbf_state_name[state], tbf_state_name[new_state]);
	state = new_state;
}

inline void gprs_rlcmac_tbf::set_ass_state_dl(enum gprs_rlcmac_tbf_dl_ass_state new_state, const char *file, int line)
{
	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s changes DL ASS state from %s to %s\n",
		tbf_name(this),
		get_value_string(gprs_rlcmac_tbf_dl_ass_state_names, dl_ass_state),
		get_value_string(gprs_rlcmac_tbf_dl_ass_state_names, new_state));
	dl_ass_state = new_state;
}

inline void gprs_rlcmac_tbf::set_ass_state_ul(enum gprs_rlcmac_tbf_ul_ass_state new_state, const char *file, int line)
{
	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s changes UL ASS state from %s to %s\n",
		tbf_name(this),
		get_value_string(gprs_rlcmac_tbf_ul_ass_state_names, ul_ass_state),
		get_value_string(gprs_rlcmac_tbf_ul_ass_state_names, new_state));
	ul_ass_state = new_state;
}

inline void gprs_rlcmac_tbf::set_ack_state(enum gprs_rlcmac_tbf_ul_ack_state new_state, const char *file, int line)
{
	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s changes UL ACK state from %s to %s\n",
		tbf_name(this),
		get_value_string(gprs_rlcmac_tbf_ul_ack_state_names, ul_ack_state),
		get_value_string(gprs_rlcmac_tbf_ul_ack_state_names, new_state));
	ul_ack_state = new_state;
}

inline void gprs_rlcmac_tbf::poll_sched_set(const char *file, int line)
{
	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s changes poll state from %s to GPRS_RLCMAC_POLL_SCHED\n",
		tbf_name(this), get_value_string(gprs_rlcmac_tbf_poll_state_names, poll_state));
	poll_state = GPRS_RLCMAC_POLL_SCHED;
}

inline void gprs_rlcmac_tbf::poll_sched_unset(const char *file, int line)
{
	LOGPSRC(DTBF, LOGL_DEBUG, file, line, "%s changes poll state from %s to GPRS_RLCMAC_POLL_NONE\n",
		tbf_name(this), get_value_string(gprs_rlcmac_tbf_poll_state_names, poll_state));
	poll_state = GPRS_RLCMAC_POLL_NONE;
}

inline void gprs_rlcmac_tbf::check_pending_ass()
{
	if (ul_ass_state != GPRS_RLCMAC_UL_ASS_NONE)
		LOGPTBF(this, LOGL_ERROR, "FIXME: Software error: Pending uplink assignment in state %s. "
			"This may not happen, because the assignment message never gets transmitted. "
			"Please be sure not to free in this state. PLEASE FIX!\n",
			get_value_string(gprs_rlcmac_tbf_ul_ass_state_names, ul_ass_state));

	if (dl_ass_state != GPRS_RLCMAC_DL_ASS_NONE)
		LOGPTBF(this, LOGL_ERROR, "FIXME: Software error: Pending downlink assignment in state %s. "
			"This may not happen, because the assignment message never gets transmitted. "
			"Please be sure not to free in this state. PLEASE FIX!\n",
			get_value_string(gprs_rlcmac_tbf_dl_ass_state_names, dl_ass_state));
}

inline bool gprs_rlcmac_tbf::check_n_clear(uint8_t state_flag)
{
	if ((state_flags & (1 << state_flag))) {
		state_flags &= ~(1 << state_flag);
		return true;
	}

	return false;
}

inline LListHead<gprs_rlcmac_tbf>& gprs_rlcmac_tbf::list()
{
	return this->m_list;
}

inline const LListHead<gprs_rlcmac_tbf>& gprs_rlcmac_tbf::list() const
{
	return this->m_list;
}

inline GprsMs *gprs_rlcmac_tbf::ms() const
{
	return m_ms;
}

inline bool gprs_rlcmac_tbf::is_tlli_valid() const
{
	return tlli() != 0;
}

inline bool gprs_rlcmac_tbf::is_tfi_assigned() const
{
	/* The TBF is established or has been assigned by a IMM.ASS for
	 * download */
	return state > GPRS_RLCMAC_ASSIGN ||
		(direction == GPRS_RLCMAC_DL_TBF &&
		 state == GPRS_RLCMAC_ASSIGN &&
		 (state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)));
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

inline void gprs_rlcmac_tbf::enable_egprs()
{
	m_egprs_enabled = true;
	window()->set_sns(RLC_EGPRS_SNS);
}

inline enum gprs_rlcmac_tbf_direction reverse(enum gprs_rlcmac_tbf_direction dir)
{
	return (enum gprs_rlcmac_tbf_direction)
		((int)GPRS_RLCMAC_UL_TBF - (int)dir + (int)GPRS_RLCMAC_DL_TBF);
}

uint16_t egprs_window_size(const struct gprs_rlcmac_bts *bts_data, uint8_t slots);

#endif
