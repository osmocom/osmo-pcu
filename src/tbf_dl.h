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

#include "tbf.h"
#include "rlc_window_dl.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <tbf_fsm.h>
#ifdef __cplusplus
}
#endif

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

struct gprs_dl_llc_llist_item {
	struct llist_head list; /* this item added in dl_tbf->tx_llc_until_first_dl_ack_rcvd */
	struct gprs_llc llc;
};

struct gprs_rlcmac_dl_tbf : public gprs_rlcmac_tbf {
	gprs_rlcmac_dl_tbf(struct gprs_rlcmac_bts *bts, GprsMs *ms);
	~gprs_rlcmac_dl_tbf();
	gprs_rlc_window *window();
	void apply_allocated_resources(const struct alloc_resources_res *res);

	int rcvd_dl_ack(bool final_ack, unsigned first_bsn, struct bitvec *rbb);
	struct msgb *create_dl_acked_block(uint32_t fn, const gprs_rlcmac_pdch *pdch,
					   enum mcs_kind req_mcs_kind = EGPRS);

	void request_dl_ack();
	bool need_poll_for_dl_ack_nack() const;
	bool have_data() const;
	int frames_since_last_poll(unsigned fn) const;
	int frames_since_last_drain(unsigned fn) const;
	bool keep_open(unsigned fn) const;
	int release();
	uint16_t window_size() const;
	void set_window_size();
	void update_coding_scheme_counter_dl(enum CodingScheme cs);

	/* Please note that all variables here will be reset when changing
	 * from WAIT RELEASE back to FLOW state (re-use of TBF).
	 * All states that need reset must be in this struct, so this is why
	 * variables are in both (dl and ul) structs and not outside union.
	 */
	int32_t m_tx_counter; /* count all transmitted blocks */
	bool m_dl_ack_requested;
	int32_t m_last_dl_poll_fn;
	/* Whether we failed to receive ("poll timeout") last PKT CTRL ACK from
	 * MS polled during DL ACK/NACK with RRBP set in "m_last_dl_poll_fn": */
	bool m_last_dl_poll_ack_lost;
	int32_t m_last_dl_drained_fn;
	/* Whether we receive at least one PKT DL ACK/NACK from MS since this DL TBF was assigned: */
	bool m_first_dl_ack_rcvd;

	/* Keep transmitted LLC PDUs until first ACK to avoid losing them if MS is not there.
	 * list of gprs_dl_llc_llist_item, stored in inverse order of transmission (last transmitted
	 * is first in the list ) */
	struct llist_head tx_llc_until_first_dl_ack_rcvd;

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

	struct tbf_dl_fsm_ctx state_fsm;

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
	struct msgb *create_dl_acked_block(const uint32_t fn, const struct gprs_rlcmac_pdch *pdch,
					   int index, int index2 = -1);
	int update_window(unsigned first_bsn, const struct bitvec *rbb);
	int rcvd_dl_final_ack();
	bool dl_window_stalled() const;
	void reuse_tbf();
	int analyse_errors(char *show_rbb, uint8_t ssn, ana_result *res);
	void schedule_next_frame();

	enum egprs_rlc_dl_reseg_bsn_state egprs_dl_get_data
		(int bsn, uint8_t **block_data);
	unsigned int get_egprs_dl_spb_status(int bsn);
	enum egprs_rlcmac_dl_spb get_egprs_dl_spb(int bsn);

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

#else /* ifdef __cplusplus */
struct gprs_rlcmac_dl_tbf;
#endif

#ifdef __cplusplus
extern "C" {
#endif
struct gprs_rlcmac_bts;

struct gprs_rlcmac_dl_tbf *dl_tbf_alloc(struct gprs_rlcmac_bts *bts, struct GprsMs *ms);

struct gprs_rlcmac_dl_tbf *tbf_as_dl_tbf(struct gprs_rlcmac_tbf *tbf);
const struct gprs_rlcmac_dl_tbf *tbf_as_dl_tbf_const(const struct gprs_rlcmac_tbf *tbf);
/* dispatch Unitdata.DL messages */
int dl_tbf_handle(struct gprs_rlcmac_bts *bts,
		  const uint32_t tlli, const uint32_t old_tlli,
		  const char *imsi, const uint8_t ms_class,
		  const uint8_t egprs_ms_class, const uint16_t delay_csec,
		  const uint8_t *data, const uint16_t len);

void dl_tbf_apply_allocated_resources(struct gprs_rlcmac_dl_tbf *dl_tbf, const struct alloc_resources_res *res);
void dl_tbf_trigger_ass_on_pacch(struct gprs_rlcmac_dl_tbf *tbf, struct gprs_rlcmac_tbf *old_tbf);
void dl_tbf_trigger_ass_on_pch(struct gprs_rlcmac_dl_tbf *tbf);
void dl_tbf_request_dl_ack(struct gprs_rlcmac_dl_tbf *tbf);
bool dl_tbf_first_dl_ack_rcvd(const struct gprs_rlcmac_dl_tbf *tbf);
int dl_tbf_upgrade_to_multislot(struct gprs_rlcmac_dl_tbf *tbf);

void dl_tbf_copy_unacked_pdus_to_llc_queue(struct gprs_rlcmac_dl_tbf *tbf);

static inline struct gprs_rlcmac_tbf *dl_tbf_as_tbf(struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	return (struct gprs_rlcmac_tbf *)dl_tbf;
}

static inline const struct gprs_rlcmac_tbf *dl_tbf_as_tbf_const(const struct gprs_rlcmac_dl_tbf *dl_tbf)
{
	return (const struct gprs_rlcmac_tbf *)dl_tbf;
}

#define LOGPTBFDL(dl_tbf, level, fmt, args...) LOGP(DTBFDL, level, "%s " fmt, tbf_name(dl_tbf_as_tbf_const(dl_tbf)), ## args)
#ifdef __cplusplus
}
#endif
