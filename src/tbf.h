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

#include "gprs_rlcmac.h"
#include "llc.h"
#include "rlc.h"
#include "cxx_linuxlist.h"
#include <gprs_debug.h>

#include <stdint.h>

struct bssgp_bvc_ctx;
struct rlc_ul_header;
struct msgb;
struct pcu_l1_meas;
class GprsMs;

/*
 * TBF instance
 */

#define Tassign_agch 0,200000	/* waiting after IMM.ASS confirm */
#define Tassign_pacch 2,0	/* timeout for pacch assigment */

enum gprs_rlcmac_tbf_state {
	GPRS_RLCMAC_NULL = 0,	/* new created TBF */
	GPRS_RLCMAC_ASSIGN,     /* wait for DL transmission */
	GPRS_RLCMAC_WAIT_ASSIGN,/* wait for confirmation */
	GPRS_RLCMAC_FLOW,	/* RLC/MAC flow, resource needed */
	GPRS_RLCMAC_FINISHED,	/* flow finished, wait for release */
	GPRS_RLCMAC_WAIT_RELEASE,/* wait for release or restart of DL TBF */
	GPRS_RLCMAC_RELEASING,	/* releasing, wait to free TBI/USF */
	GPRS_RLCMAC_RECONFIGURING, // TS RECON. scheduled
};

enum gprs_rlcmac_tbf_poll_state {
	GPRS_RLCMAC_POLL_NONE = 0,
	GPRS_RLCMAC_POLL_SCHED, /* a polling was scheduled */
};

enum gprs_rlcmac_tbf_dl_ts_recon_state {
	GPRS_RLCMAC_DL_TS_RECON_NONE = 0,
	GPRS_RLCMAC_DL_TS_RECON_SEND, /* send PTSR on next RTS */	
	GPRS_RLCMAC_DL_TS_RECON_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_dl_ass_state {
	GPRS_RLCMAC_DL_ASS_NONE = 0,
	GPRS_RLCMAC_DL_ASS_SEND_ASS, /* send downlink assignment on next RTS */	
	GPRS_RLCMAC_DL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_ul_ass_state {
	GPRS_RLCMAC_UL_ASS_NONE = 0,
	GPRS_RLCMAC_UL_ASS_SEND_ASS, /* send uplink assignment on next RTS */
	GPRS_RLCMAC_UL_ASS_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_ul_ack_state {
	GPRS_RLCMAC_UL_ACK_NONE = 0,
	GPRS_RLCMAC_UL_ACK_SEND_ACK, /* send acknowledge on next RTS */
	GPRS_RLCMAC_UL_ACK_WAIT_ACK, /* wait for PACKET CONTROL ACK */
};

enum gprs_rlcmac_tbf_direction {
	GPRS_RLCMAC_DL_TBF,
	GPRS_RLCMAC_UL_TBF
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

struct gprs_rlcmac_tbf {
	gprs_rlcmac_tbf(BTS *bts_, gprs_rlcmac_tbf_direction dir);

	static void free_all(struct gprs_rlcmac_trx *trx);
	static void free_all(struct gprs_rlcmac_pdch *pdch);

	bool state_is(enum gprs_rlcmac_tbf_state rhs) const;
	bool state_is_not(enum gprs_rlcmac_tbf_state rhs) const;
	void set_state(enum gprs_rlcmac_tbf_state new_state);
	const char *state_name() const;

	const char *name() const;

	struct msgb *create_dl_ass(uint32_t fn, uint8_t ts);
        struct msgb *create_ul_ass(uint32_t fn, uint8_t ts);
        struct msgb *create_dl_ts_recon_exp(uint32_t fn, uint8_t ts);
        struct msgb *create_dl_ts_recon(uint32_t fn, uint8_t ts);
	GprsMs *ms() const;
	void set_ms(GprsMs *ms);

	gprs_rlc_window *window();

	uint8_t tsc() const;

	int rlcmac_diag();

	int update();
	void handle_timeout();
	void stop_timer();
	void stop_t3191();
	int establish_dl_tbf_on_pacch();

	int check_polling(uint32_t fn, uint8_t ts,
		uint32_t *poll_fn, unsigned int *rrbp);
	void set_polling(uint32_t poll_fn, uint8_t ts);
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
	void set_ms_class(uint8_t);
	GprsCodingScheme current_cs() const;
	gprs_llc_queue *llc_queue();
	const gprs_llc_queue *llc_queue() const;

	time_t created_ts() const;
	uint8_t dl_slots() const;
	uint8_t ul_slots() const;

	bool is_control_ts(uint8_t ts) const;

	/* EGPRS */
	bool is_egprs_enabled() const;
	void enable_egprs();
	void disable_egprs();

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
	uint8_t first_common_ts; /* first TS that the phone can send and
		reveive simultaniously */
	uint8_t control_ts; /* timeslot control messages and polling */
	struct gprs_rlcmac_pdch *pdch[8]; /* list of PDCHs allocated to TBF */

	gprs_llc m_llc;

	enum gprs_rlcmac_tbf_dl_ass_state dl_ass_state;
	enum gprs_rlcmac_tbf_ul_ass_state ul_ass_state;
	enum gprs_rlcmac_tbf_ul_ack_state ul_ack_state;

	enum gprs_rlcmac_tbf_poll_state poll_state;
	uint32_t poll_fn; /* frame number to poll */
	uint8_t poll_ts; /* TS to poll */

	gprs_rlc m_rlc;
	
	uint8_t n3105;	/* N3105 counter */

	struct osmo_timer_list	timer;
	unsigned int T; /* Txxxx number */
	unsigned int num_T_exp; /* number of consecutive T expirations */
	
	struct osmo_gsm_timer_list	gsm_timer;
	unsigned int fT; /* fTxxxx number */
	unsigned int num_fT_exp; /* number of consecutive fT expirations */

	struct Meas {
		struct timeval rssi_tv; /* timestamp for rssi calculation */
		int32_t rssi_sum; /* sum of rssi values */
		int rssi_num; /* number of rssi values added since rssi_tv */

		Meas();
	} meas;

	/* these should become protected but only after gprs_rlcmac_data.c
	 * stops to iterate over all tbf in its current form */
	enum gprs_rlcmac_tbf_state state;

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

protected:
	gprs_rlcmac_bts *bts_data() const;

	int set_tlli_from_ul(uint32_t new_tlli);
	void merge_and_clear_ms(GprsMs *old_ms);

	static const char *tbf_state_name[7];

	class GprsMs *m_ms;

	/* Fields to take the TA/MS class values if no MS is associated */
	uint8_t m_ta;
	uint8_t m_ms_class;

private:
	LListHead<gprs_rlcmac_tbf> m_list;
	LListHead<gprs_rlcmac_tbf> m_ms_list;
	bool m_egprs_enabled;

	mutable char m_name_buf[60];
};


struct gprs_rlcmac_ul_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts,
	int8_t use_trx, uint8_t ms_class, uint8_t egprs_ms_class,
	uint32_t tlli, uint8_t ta, GprsMs *ms);

struct gprs_rlcmac_ul_tbf *tbf_alloc_ul_tbf(struct gprs_rlcmac_bts *bts,
	GprsMs *ms, int8_t use_trx,
	uint8_t ms_class, uint8_t egprs_ms_class, uint8_t single_slot);

struct gprs_rlcmac_dl_tbf *tbf_alloc_dl_tbf(struct gprs_rlcmac_bts *bts,
	GprsMs *ms, int8_t use_trx,
	uint8_t ms_class, uint8_t egprs_ms_class, uint8_t single_slot);

void tbf_free(struct gprs_rlcmac_tbf *tbf);

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf);

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
                        unsigned int seconds, unsigned int microseconds);

inline bool gprs_rlcmac_tbf::state_is(enum gprs_rlcmac_tbf_state rhs) const
{
	return state == rhs;
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

inline void gprs_rlcmac_tbf::set_state(enum gprs_rlcmac_tbf_state new_state)
{
	LOGP(DRLCMAC, LOGL_DEBUG, "%s changes state from %s to %s\n",
		tbf_name(this),
		tbf_state_name[state], tbf_state_name[new_state]);
	state = new_state;
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
	return state > GPRS_RLCMAC_ASSIGN;
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
}

inline void gprs_rlcmac_tbf::disable_egprs()
{
	m_egprs_enabled = false;
}

struct gprs_rlcmac_dl_tbf : public gprs_rlcmac_tbf {
	gprs_rlcmac_dl_tbf(BTS *bts);

	void cleanup();

	/* dispatch Unitdata.DL messages */
	static int handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const uint32_t old_tlli,
		const char *imsi, const uint8_t ms_class,
		const uint8_t egprs_ms_class, const uint16_t delay_csec,
		const uint8_t *data, const uint16_t len);

	int append_data(const uint8_t ms_class,
			const uint16_t pdu_delay_csec,
			const uint8_t *data, const uint16_t len);

	int rcvd_dl_ack(uint8_t final, uint8_t ssn, uint8_t *rbb);
	int rcvd_dl_ack(uint8_t final_ack, unsigned first_bsn, struct bitvec *rbb);
	struct msgb *create_dl_acked_block(uint32_t fn, uint8_t ts);
	void request_dl_ack();
	bool need_control_ts() const;
	bool have_data() const;
	int frames_since_last_poll(unsigned fn) const;
	int frames_since_last_drain(unsigned fn) const;
	bool keep_open(unsigned fn) const;
	int release();
	int abort();

	/* TODO: add the gettimeofday as parameter */
	struct msgb *llc_dequeue(bssgp_bvc_ctx *bctx);

	/* Please note that all variables here will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	gprs_rlc_dl_window m_window;
	int32_t m_tx_counter; /* count all transmitted blocks */
	uint8_t m_wait_confirm; /* wait for CCCH IMM.ASS cnf */
	bool m_dl_ack_requested;
	int32_t m_last_dl_poll_fn;
	int32_t m_last_dl_drained_fn;

	struct BandWidth {
		struct timeval dl_bw_tv; /* timestamp for dl bw calculation */
		uint32_t dl_bw_octets; /* number of octets since bw_tv */

		struct timeval dl_loss_tv; /* timestamp for loss calculation */
		uint16_t dl_loss_lost; /* sum of lost packets */
		uint16_t dl_loss_received; /* sum of received packets */

		BandWidth();
	} m_bw;

protected:
	struct ana_result {
		unsigned received_packets;
		unsigned lost_packets;
		unsigned received_bytes;
		unsigned lost_bytes;
	};

	int take_next_bsn(uint32_t fn, int previous_bsn,
		bool *may_combine);
	bool restart_bsn_cycle();
	int create_new_bsn(const uint32_t fn, GprsCodingScheme cs);
	struct msgb *create_dl_acked_block(const uint32_t fn, const uint8_t ts,
					int index, int index2 = -1);
	int update_window(const uint8_t ssn, const uint8_t *rbb);
	int update_window(unsigned first_bsn, const struct bitvec *rbb);
	int maybe_start_new_window();
	bool dl_window_stalled() const;
	void reuse_tbf();
	void start_llc_timer();
	int analyse_errors(char *show_rbb, uint8_t ssn, ana_result *res);
	void schedule_next_frame();

	struct osmo_timer_list m_llc_timer;
};

struct gprs_rlcmac_ul_tbf : public gprs_rlcmac_tbf {
	gprs_rlcmac_ul_tbf(BTS *bts);

	struct msgb *create_ul_ack(uint32_t fn, uint8_t ts);

	/* blocks were acked */
	int rcv_data_block_acknowledged(
		const struct gprs_rlc_data_info *rlc,
		uint8_t *data, struct pcu_l1_meas *meas);


	/* TODO: extract LLC class? */
	int assemble_forward_llc(const gprs_rlc_data *data);
	int snd_ul_ud();

	/* Please note that all variables here will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	gprs_rlc_ul_window m_window;
	int32_t m_rx_counter; /* count all received blocks */
	uint8_t m_n3103;	/* N3103 counter */
	uint8_t m_usf[8];	/* list USFs per PDCH (timeslot) */
	uint8_t m_contention_resolution_done; /* set after done */
	uint8_t m_final_ack_sent; /* set if we sent final ack */

protected:
	void maybe_schedule_uplink_acknack(const gprs_rlc_data_info *rlc);
};

inline enum gprs_rlcmac_tbf_direction reverse(enum gprs_rlcmac_tbf_direction dir)
{
	return (enum gprs_rlcmac_tbf_direction)
		((int)GPRS_RLCMAC_UL_TBF - (int)dir + (int)GPRS_RLCMAC_DL_TBF);
}

inline gprs_rlcmac_ul_tbf *as_ul_tbf(gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_UL_TBF)
		return static_cast<gprs_rlcmac_ul_tbf *>(tbf);
	else
		return NULL;
}

inline gprs_rlcmac_dl_tbf *as_dl_tbf(gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_DL_TBF)
		return static_cast<gprs_rlcmac_dl_tbf *>(tbf);
	else
		return NULL;
}

inline gprs_rlc_window *gprs_rlcmac_tbf::window()
{
	switch (direction)
	{
	case GPRS_RLCMAC_UL_TBF: return &as_ul_tbf(this)->m_window;
	case GPRS_RLCMAC_DL_TBF: return &as_dl_tbf(this)->m_window;
	}
	return NULL;
}

#endif
