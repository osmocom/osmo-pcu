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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#pragma once

#ifdef __cplusplus

#include "tbf.h"

/*
 * TBF instance
 */

enum tbf_dl_prio {
	DL_PRIO_NONE,
	DL_PRIO_SENT_DATA, /* the data has been sent and not (yet) nacked */
	DL_PRIO_LOW_AGE,   /* the age has reached the first threshold */
	DL_PRIO_NEW_DATA,  /* the data has not been sent yet or nacked */
	DL_PRIO_HIGH_AGE,  /* the age has reached the second threshold */
	DL_PRIO_CONTROL,   /* a control block needs to be sent */
};

#define LOGPTBFDL(tbf, level, fmt, args...) LOGP(DTBFDL, level, "%s " fmt, tbf_name(tbf), ## args)

struct gprs_rlcmac_dl_tbf : public gprs_rlcmac_tbf {
	gprs_rlcmac_dl_tbf(BTS *bts, GprsMs *ms);
	gprs_rlc_window *window();
	void cleanup();
	/* dispatch Unitdata.DL messages */
	static int handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const uint32_t old_tlli,
		const char *imsi, const uint8_t ms_class,
		const uint8_t egprs_ms_class, const uint16_t delay_csec,
		const uint8_t *data, const uint16_t len);

	int append_data(uint16_t pdu_delay_csec,
			const uint8_t *data, uint16_t len);

	int rcvd_dl_ack(bool final, uint8_t ssn, uint8_t *rbb);
	int rcvd_dl_ack(bool final_ack, unsigned first_bsn, struct bitvec *rbb);
	struct msgb *create_dl_acked_block(uint32_t fn, uint8_t ts, enum mcs_kind req_mcs_kind = EGPRS);
	void trigger_ass(struct gprs_rlcmac_tbf *old_tbf);

	bool handle_ack_nack();
	void request_dl_ack();
	bool need_control_ts() const;
	bool have_data() const;
	int frames_since_last_poll(unsigned fn) const;
	int frames_since_last_drain(unsigned fn) const;
	bool keep_open(unsigned fn) const;
	int release();
	int abort();
	uint16_t window_size() const;
	void set_window_size();
	void update_coding_scheme_counter_dl(enum CodingScheme cs);

	struct msgb *llc_dequeue(bssgp_bvc_ctx *bctx);

	/* Please note that all variables here will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	int32_t m_tx_counter; /* count all transmitted blocks */
	uint8_t m_wait_confirm; /* wait for CCCH IMM.ASS cnf */
	bool m_dl_ack_requested;
	int32_t m_last_dl_poll_fn;
	int32_t m_last_dl_drained_fn;

	struct BandWidth {
		struct timespec dl_bw_tv; /* timestamp for dl bw calculation */
		uint32_t dl_bw_octets; /* number of octets since bw_tv */
		uint32_t dl_throughput; /* throughput to be displayed in stats */

		struct timespec dl_loss_tv; /* timestamp for loss calculation */
		uint16_t dl_loss_lost; /* sum of lost packets */
		uint16_t dl_loss_received; /* sum of received packets */

		BandWidth();
	} m_bw;

	struct rate_ctr_group *m_dl_gprs_ctrs;
	struct rate_ctr_group *m_dl_egprs_ctrs;

protected:
	struct ana_result {
		unsigned received_packets;
		unsigned lost_packets;
		unsigned received_bytes;
		unsigned lost_bytes;
	};

	int take_next_bsn(uint32_t fn, int previous_bsn, enum mcs_kind req_mcs_kind,
			  bool *may_combine);
	bool restart_bsn_cycle();
	int create_new_bsn(const uint32_t fn, enum CodingScheme cs);
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

	enum egprs_rlc_dl_reseg_bsn_state egprs_dl_get_data
		(int bsn, uint8_t **block_data);
	unsigned int get_egprs_dl_spb_status(int bsn);
	enum egprs_rlcmac_dl_spb get_egprs_dl_spb(int bsn);

	struct osmo_timer_list m_llc_timer;

	/* Please note that all variables below will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	gprs_rlc_dl_window m_window;
};

inline uint16_t gprs_rlcmac_dl_tbf::window_size() const
{
	return m_window.ws();
}

inline gprs_rlcmac_dl_tbf *as_dl_tbf(gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_DL_TBF)
		return static_cast<gprs_rlcmac_dl_tbf *>(tbf);
	else
		return NULL;
}

struct gprs_rlcmac_dl_tbf *tbf_alloc_dl_tbf(struct gprs_rlcmac_bts *bts, GprsMs *ms,
					    int8_t use_trx, bool single_slot);

#endif
