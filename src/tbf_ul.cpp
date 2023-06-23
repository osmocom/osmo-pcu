/* Copied from tbf.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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

#include <bts.h>
#include <bts_pch_timer.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <rlc.h>
#include <encoding.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <decoding.h>
#include <pcu_l1_if.h>
#include <gprs_ms.h>
#include <llc.h>
#include "pcu_utils.h"
#include "alloc_algo.h"

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
	#include <osmocom/core/bitvec.h>
	#include <osmocom/core/logging.h>
	#include <osmocom/core/rate_ctr.h>
	#include <osmocom/core/stats.h>
	#include <osmocom/core/utils.h>
	#include <osmocom/gprs/gprs_bssgp_bss.h>
	#include <osmocom/gprs/protocol/gsm_08_18.h>
	#include <osmocom/gsm/tlv.h>
	#include "coding_scheme.h"
}

#include <errno.h>
#include <string.h>

/* After receiving these frames, we send ack/nack. */
#define SEND_ACK_AFTER_FRAMES 20

extern void *tall_pcu_ctx;

static const struct rate_ctr_desc tbf_ul_gprs_ctr_description[] = {
	{ "gprs:uplink:cs1",              "CS1        " },
	{ "gprs:uplink:cs2",              "CS2        " },
	{ "gprs:uplink:cs3",              "CS3        " },
	{ "gprs:uplink:cs4",              "CS4        " },
};

static const struct rate_ctr_desc tbf_ul_egprs_ctr_description[] = {
	{ "egprs:uplink:mcs1",            "MCS1        " },
	{ "egprs:uplink:mcs2",            "MCS2        " },
	{ "egprs:uplink:mcs3",            "MCS3        " },
	{ "egprs:uplink:mcs4",            "MCS4        " },
	{ "egprs:uplink:mcs5",            "MCS5        " },
	{ "egprs:uplink:mcs6",            "MCS6        " },
	{ "egprs:uplink:mcs7",            "MCS7        " },
	{ "egprs:uplink:mcs8",            "MCS8        " },
	{ "egprs:uplink:mcs9",            "MCS9        " },
};

static const struct rate_ctr_group_desc tbf_ul_gprs_ctrg_desc = {
	"tbf:gprs",
	"Data Blocks",
	OSMO_STATS_CLASS_SUBSCRIBER,
	ARRAY_SIZE(tbf_ul_gprs_ctr_description),
	tbf_ul_gprs_ctr_description,
};

static const struct rate_ctr_group_desc tbf_ul_egprs_ctrg_desc = {
	"tbf:egprs",
	"Data Blocks",
	OSMO_STATS_CLASS_SUBSCRIBER,
	ARRAY_SIZE(tbf_ul_egprs_ctr_description),
	tbf_ul_egprs_ctr_description,
};

gprs_rlcmac_ul_tbf::~gprs_rlcmac_ul_tbf()
{
	osmo_fsm_inst_free(ul_ack_fsm.fi);
	ul_ack_fsm.fi = NULL;

	rate_ctr_group_free(m_ul_egprs_ctrs);
	rate_ctr_group_free(m_ul_gprs_ctrs);
	/* ~gprs_rlcmac_tbf() is called automatically upon return */
}

static int ul_tbf_dtor(struct gprs_rlcmac_ul_tbf *tbf)
{
	tbf->~gprs_rlcmac_ul_tbf();
	return 0;
}

/* Generic function to alloc a UL TBF, later configured to be assigned either over CCCH or PACCH */
struct gprs_rlcmac_ul_tbf *ul_tbf_alloc(struct gprs_rlcmac_bts *bts, struct GprsMs *ms)
{
	struct gprs_rlcmac_ul_tbf *tbf;

	OSMO_ASSERT(ms != NULL);

	LOGPMS(ms, DTBF, LOGL_DEBUG, "********** UL-TBF starts here **********\n");
	LOGPMS(ms, DTBF, LOGL_INFO, "Allocating UL TBF\n");

	tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_ul_tbf);
	if (!tbf)
		return NULL;
	talloc_set_destructor(tbf, ul_tbf_dtor);
	new (tbf) gprs_rlcmac_ul_tbf(bts, ms);

	bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_UL_ALLOCATED);

	return tbf;
}

gprs_rlcmac_ul_tbf::gprs_rlcmac_ul_tbf(struct gprs_rlcmac_bts *bts_, GprsMs *ms) :
	gprs_rlcmac_tbf(bts_, ms, GPRS_RLCMAC_UL_TBF),
	m_rx_counter(0),
	m_contention_resolution_done(true),
	m_ul_gprs_ctrs(NULL),
	m_ul_egprs_ctrs(NULL)
{
	memset(&m_usf, USF_INVALID, sizeof(m_usf));

	memset(&state_fsm, 0, sizeof(state_fsm));
	state_fsm.ul_tbf = this;
	state_fi = osmo_fsm_inst_alloc(&tbf_ul_fsm, this, &state_fsm, LOGL_INFO, NULL);
	OSMO_ASSERT(state_fi);

	memset(&ul_ack_fsm, 0, sizeof(ul_ack_fsm));
	ul_ack_fsm.tbf = this;
	ul_ack_fsm.fi = osmo_fsm_inst_alloc(&tbf_ul_ack_fsm, this, &ul_ack_fsm, LOGL_INFO, NULL);

	m_ul_egprs_ctrs = rate_ctr_group_alloc(this, &tbf_ul_egprs_ctrg_desc, m_ctrs->idx);
	OSMO_ASSERT(m_ul_egprs_ctrs);
	m_ul_gprs_ctrs = rate_ctr_group_alloc(this, &tbf_ul_gprs_ctrg_desc, m_ctrs->idx);
	OSMO_ASSERT(m_ul_gprs_ctrs);

	/* This has to be called in child constructor because enable_egprs()
	 * uses the window() virtual function which is dependent on subclass. */
	if (ms_mode(m_ms) != GPRS)
		enable_egprs();
}

/*
 * Store received block data in LLC message(s) and forward to SGSN
 * if complete.
 */
int gprs_rlcmac_ul_tbf::assemble_forward_llc(const gprs_rlc_data *_data)
{
	const uint8_t *data = _data->block;
	uint8_t len = _data->len;
	const struct gprs_rlc_data_block_info *rdbi = &_data->block_info;
	enum CodingScheme cs = _data->cs_last;

	Decoding::RlcData frames[16], *frame;
	int i, num_frames = 0;
	uint32_t dummy_tlli;

	LOGPTBFUL(this, LOGL_DEBUG, "Assembling frames: (len=%d)\n", len);

	num_frames = Decoding::rlc_data_from_ul_data(
		rdbi, cs, data, &(frames[0]), ARRAY_SIZE(frames),
		&dummy_tlli);

	/* create LLC frames */
	for (i = 0; i < num_frames; i++) {
		frame = frames + i;

		if (frame->length) {
			bts_do_rate_ctr_add(bts, CTR_RLC_UL_PAYLOAD_BYTES, frame->length);

			LOGPTBFUL(this, LOGL_DEBUG, "Frame %d "
				"starts at offset %d, "
				"length=%d, is_complete=%d\n",
				i + 1, frame->offset, frame->length,
				frame->is_complete);

			llc_append_frame(&m_llc, data + frame->offset, frame->length);
			llc_consume(&m_llc, frame->length);
		}

		if (frame->is_complete) {
			/* send frame to SGSN */
			LOGPTBFUL(this, LOGL_DEBUG, "complete UL frame len=%d\n", llc_frame_length(&m_llc));
			snd_ul_ud();
			bts_do_rate_ctr_add(bts, CTR_LLC_UL_BYTES, llc_frame_length(&m_llc));
			llc_reset(&m_llc);
		}
	}

	return 0;
}

/* 3GPP TS 44.060 sec 7a.2.1 Contention Resolution */
void gprs_rlcmac_ul_tbf::contention_resolution_start()
{
	/* 3GPP TS 44.018 sec 11.1.2 Timers on the network side: "This timer is
	 * started when a temporary block flow is allocated with an IMMEDIATE
	 * ASSIGNMENT or an IMMEDIATE PACKET ASSIGNMENT or an EC IMMEDIATE
	 * ASSIGNMENT TYPE 1 message during a packet access procedure. It is
	 * stopped when the mobile station has correctly seized the temporary
	 * block flow."
	 * In our code base, it means we want to do contention resolution
	 * timeout only for one-phase packet access, since two-phase is handled
	 * through SBA structs, which are freed by the PDCH UL Controller if the
	 * single allocated block is lost. */
	m_contention_resolution_done = false;
	T_START(this, T3141, 3141, "Contention resolution (UL-TBF, CCCH)", true);
}
void gprs_rlcmac_ul_tbf::contention_resolution_success()
{
	/* now we must set this flag, so we are allowed to assign downlink
	 * TBF on PACCH. it is only allowed when TLLI is acknowledged
	 * (3GPP TS 44.060 sec 7.1.3.1). */
	m_contention_resolution_done = true;

	/* 3GPP TS 44.018 3.5.2.1.4 Packet access completion: The one phase
	   packet access procedure is completed at a successful contention
	   resolution. The mobile station has entered the packet transfer mode.
	   Timer T3141 is stopped on the network side */
	t_stop(T3141, "Contention resolution success (UL-TBF, CCCH)");

	bts_do_rate_ctr_inc(bts, CTR_IMMEDIATE_ASSIGN_UL_TBF_CONTENTION_RESOLUTION_SUCCESS);

	/* Check if we can create a DL TBF to start sending the enqueued
	* data. Otherwise it will be triggered later when it is reachable
	* again. */
	if (ms_need_dl_tbf(ms()) && !tbf_ul_ack_waiting_cnf_final_ack(this))
		ms_new_dl_tbf_assigned_on_pacch(ms(), this);
}

/*! \brief receive data from PDCH/L1 */
int gprs_rlcmac_ul_tbf::rcv_data_block_acknowledged(
	const struct gprs_rlc_data_info *rlc,
	uint8_t *data, struct pcu_l1_meas *meas)
{
	const struct gprs_rlc_data_block_info *rdbi;
	struct gprs_rlc_data *block;

	int8_t rssi = meas->have_rssi ? meas->rssi : 0;

	const uint16_t ws = m_window.ws();

	LOGPTBFUL(this, LOGL_DEBUG, "UL DATA TFI=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rlc->tfi, this->m_window.v_q(),
		this->m_window.v_r());

	if (tbf_state(this) == TBF_ST_RELEASING) {
		/* This may happen if MAX_N3101 is hit previously, moving the UL
		 * TBF to RELEASING state. Since we have an fn-advance where DL
		 * blocks are scheduled in advance, we may have requested USF for
		 * this UL TBF before triggering and hence we are now receiving a
		 * UL block from it. If this is the case, simply ignore the block.
		 */
		LOGPTBFUL(this, LOGL_INFO,
			  "UL DATA TFI=%d received (V(Q)=%d .. V(R)=%d) while in RELEASING state, discarding\n",
			  rlc->tfi, this->m_window.v_q(), this->m_window.v_r());
		return 0;
	}

	/* process RSSI */
	gprs_rlcmac_rssi(this, rssi);

	/* store measurement values */
	ms_update_l1_meas(ms(), meas);

	uint32_t new_tlli = GSM_RESERVED_TMSI;
	unsigned int block_idx;

	/* Increment RX-counter */
	this->m_rx_counter++;
	update_coding_scheme_counter_ul(rlc->cs);
	/* Loop over num_blocks */
	for (block_idx = 0; block_idx < rlc->num_data_blocks; block_idx++) {
		int num_chunks;
		uint8_t *rlc_data;
		rdbi = &rlc->block_info[block_idx];

		LOGPTBFUL(this, LOGL_DEBUG,
			  "Got %s RLC data block: CV=%d, BSN=%d, SPB=%d, PI=%d, E=%d, TI=%d, bitoffs=%d\n",
			  mcs_name(rlc->cs),
			  rdbi->cv, rdbi->bsn, rdbi->spb,
			  rdbi->pi, rdbi->e, rdbi->ti,
			  rlc->data_offs_bits[block_idx]);

		/* Check whether the block needs to be decoded */

		if (!m_window.is_in_window(rdbi->bsn)) {
			LOGPTBFUL(this, LOGL_DEBUG, "BSN %d out of window %d..%d (it's normal)\n",
				  rdbi->bsn,
				  m_window.v_q(), m_window.mod_sns(m_window.v_q() + ws - 1));
			continue;
		} else if (m_window.is_received(rdbi->bsn)) {
			LOGPTBFUL(this, LOGL_DEBUG,
				  "BSN %d already received\n", rdbi->bsn);
			continue;
		}

		/* Store block and meta info to BSN buffer */

		LOGPTBFUL(this, LOGL_DEBUG, "BSN %d storing in window (%d..%d)\n",
			  rdbi->bsn, m_window.v_q(),
			  m_window.mod_sns(m_window.v_q() + ws - 1));
		block = m_rlc.block(rdbi->bsn);
		OSMO_ASSERT(rdbi->data_len <= sizeof(block->block));
		rlc_data = &(block->block[0]);

		if (rdbi->spb) {
			egprs_rlc_ul_reseg_bsn_state assemble_status;

			assemble_status = handle_egprs_ul_spb(rlc,
						block, data, block_idx);

			if (assemble_status != EGPRS_RESEG_DEFAULT)
				return 0;
		} else {
			block->block_info = *rdbi;
			block->cs_last = rlc->cs;
			block->len =
				Decoding::rlc_copy_to_aligned_buffer(rlc,
				block_idx, data, rlc_data);
		}

		LOGPTBFUL(this, LOGL_DEBUG,
			  "data_length=%d, data=%s\n",
			  block->len, osmo_hexdump(rlc_data, block->len));
		/* Get/Handle TLLI */
		if (rdbi->ti) {
			num_chunks = Decoding::rlc_data_from_ul_data(
				rdbi, rlc->cs, rlc_data, NULL, 0, &new_tlli);

			if (num_chunks < 0) {
				bts_do_rate_ctr_inc(bts, CTR_DECODE_ERRORS);
				LOGPTBFUL(this, LOGL_NOTICE,
					  "Failed to decode TLLI of %s UL DATA TFI=%d.\n",
					  mcs_name(rlc->cs), rlc->tfi);
				m_window.invalidate_bsn(rdbi->bsn);
				continue;
			}
			if (!this->is_tlli_valid()) {
				if (new_tlli == GSM_RESERVED_TMSI) {
					LOGPTBFUL(this, LOGL_NOTICE,
						  "TLLI is 0x%08x within UL DATA?!?\n",
						  new_tlli);
					m_window.invalidate_bsn(rdbi->bsn);
					continue;
				}
				LOGPTBFUL(this, LOGL_INFO,
					  "Decoded premier TLLI=0x%08x of UL DATA TFI=%d.\n",
					  new_tlli, rlc->tfi);
				ms_update_announced_tlli(ms(), new_tlli);
				osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_FIRST_UL_DATA_RECVD, NULL);
			} else if (new_tlli != GSM_RESERVED_TMSI && new_tlli != tlli()) {
				LOGPTBFUL(this, LOGL_NOTICE,
					  "Decoded TLLI=%08x mismatch on UL DATA TFI=%d. (Ignoring due to contention resolution)\n",
					  new_tlli, rlc->tfi);
				m_window.invalidate_bsn(rdbi->bsn);
				continue;
			}
		} else if (!is_tlli_valid()) {
			LOGPTBFUL(this, LOGL_NOTICE, "Missing TLLI within UL DATA.\n");
			m_window.invalidate_bsn(rdbi->bsn);
			continue;
		}

		m_window.receive_bsn(rdbi->bsn);
	}

	/* Raise V(Q) if possible, and retrieve LLC frames from blocks.
	 * This is looped until there is a gap (non received block) or
	 * the window is empty.*/
	const uint16_t v_q_beg = m_window.v_q();
	const uint16_t count = m_window.raise_v_q();

	/* Retrieve LLC frames from blocks that are ready */
	for (uint16_t i = 0; i < count; ++i) {
		uint16_t index = m_window.mod_sns(v_q_beg + i);
		assemble_forward_llc(m_rlc.block(index));
	}

	/* Last frame in buffer: */
	block = m_rlc.block(m_window.mod_sns(m_window.v_r() - 1));
	rdbi = &block->block_info;

	/* Check if we already received all data TBF had to send: */
	if (this->state_is(TBF_ST_FLOW) /* still in flow state */
	 && this->m_window.v_q() == this->m_window.v_r() /* if complete */
	 && block->len) { /* if there was ever a last block received */
		LOGPTBFUL(this, LOGL_DEBUG,
			  "No gaps in received block, last block: BSN=%d CV=%d\n",
			  rdbi->bsn, rdbi->cv);
		if (rdbi->cv == 0) {
			LOGPTBFUL(this, LOGL_DEBUG, "Finished with UL TBF\n");
			osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_LAST_UL_DATA_RECVD, NULL);
			/* Reset N3103 counter. */
			this->n_reset(N3103);
		}
	}

	/* If TLLI is included or if we received half of the window, we send
	 * an ack/nack */
	maybe_schedule_uplink_acknack(rlc, block->len && rdbi->cv == 0);

	return 0;
}

void gprs_rlcmac_ul_tbf::maybe_schedule_uplink_acknack(
	const gprs_rlc_data_info *rlc, bool countdown_finished)
{
	bool require_ack = false;
	bool have_ti = rlc->block_info[0].ti ||
		(rlc->num_data_blocks > 1 && rlc->block_info[1].ti);

	if (rlc->si) {
		require_ack = true;
		LOGPTBFUL(this, LOGL_NOTICE,
			  "Scheduling Ack/Nack, because MS is stalled.\n");
	}
	if (have_ti) {
		require_ack = true;
		LOGPTBFUL(this, LOGL_DEBUG,
			  "Scheduling Ack/Nack, because TLLI is included.\n");
	}
	if (countdown_finished) {
		require_ack = true;
		if (state_is(TBF_ST_FLOW))
			LOGPTBFUL(this, LOGL_DEBUG,
				  "Scheduling Ack/Nack, because some data is missing and last block has CV==0.\n");
		else if (state_is(TBF_ST_FINISHED))
			LOGPTBFUL(this, LOGL_DEBUG,
				  "Scheduling final Ack/Nack, because all data was received and last block has CV==0.\n");
	}
	if ((m_rx_counter % SEND_ACK_AFTER_FRAMES) == 0) {
		require_ack = true;
		LOGPTBFUL(this, LOGL_DEBUG,
			  "Scheduling Ack/Nack, because %d frames received.\n",
			  SEND_ACK_AFTER_FRAMES);
	}

	if (!require_ack)
		return;

	osmo_fsm_inst_dispatch(this->ul_ack_fsm.fi, TBF_UL_ACK_EV_SCHED_ACK, NULL);
}

/* Send Uplink unit-data to SGSN. */
int gprs_rlcmac_ul_tbf::snd_ul_ud()
{
	uint8_t qos_profile[3];
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + llc_frame_length(&m_llc);
	struct bssgp_bvc_ctx *bctx = bts->pcu->bssgp.bctx;

	LOGP(DBSSGP, LOGL_INFO, "LLC [PCU -> SGSN] %s len=%d\n", tbf_name(this), llc_frame_length(&m_llc));
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		llc_reset_frame_space(&m_llc);
		return -EIO;
	}

	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	uint8_t *buf = msgb_push(llc_pdu, TL16V_GROSS_LEN(sizeof(uint8_t)*llc_frame_length(&m_llc)));
	tl16v_put(buf, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*llc_frame_length(&m_llc), m_llc.frame);
	qos_profile[0] = QOS_PROFILE >> 16;
	qos_profile[1] = QOS_PROFILE >> 8;
	qos_profile[2] = QOS_PROFILE;
	bssgp_tx_ul_ud(bctx, tlli(), qos_profile, llc_pdu);

	llc_reset_frame_space(&m_llc);
	return 0;
}

egprs_rlc_ul_reseg_bsn_state gprs_rlcmac_ul_tbf::handle_egprs_ul_second_seg(
	const struct gprs_rlc_data_info *rlc, struct gprs_rlc_data *block,
	uint8_t *data, const uint8_t block_idx)
{
	const gprs_rlc_data_block_info *rdbi = &rlc->block_info[block_idx];
	union split_block_status *spb_status = &block->spb_status;
	uint8_t *rlc_data = &block->block[0];

        bts_do_rate_ctr_inc(bts, CTR_SPB_UL_SECOND_SEGMENT);

	if (spb_status->block_status_ul &
				EGPRS_RESEG_FIRST_SEG_RXD) {
		LOGPTBFUL(this, LOGL_DEBUG,
			  "Second seg is received first seg is already present set the status to complete\n");
		spb_status->block_status_ul = EGPRS_RESEG_DEFAULT;

		block->len += Decoding::rlc_copy_to_aligned_buffer(rlc,
			block_idx, data, rlc_data + block->len);
		block->block_info.data_len += rdbi->data_len;
	} else if (spb_status->block_status_ul == EGPRS_RESEG_DEFAULT) {
		LOGPTBFUL(this, LOGL_DEBUG,
			  "Second seg is received first seg is not received set the status to second seg received\n");

		block->len = Decoding::rlc_copy_to_aligned_buffer(rlc,
				block_idx, data,
				rlc_data + rlc->block_info[block_idx].data_len);

		spb_status->block_status_ul = EGPRS_RESEG_SECOND_SEG_RXD;
		block->block_info = *rdbi;
	}
	return spb_status->block_status_ul;
}

egprs_rlc_ul_reseg_bsn_state gprs_rlcmac_ul_tbf::handle_egprs_ul_first_seg(
	const struct gprs_rlc_data_info *rlc, struct gprs_rlc_data *block,
	uint8_t *data, const uint8_t block_idx)
{
	const gprs_rlc_data_block_info *rdbi = &rlc->block_info[block_idx];
	uint8_t *rlc_data = &block->block[0];
	union split_block_status *spb_status = &block->spb_status;

	bts_do_rate_ctr_inc(bts, CTR_SPB_UL_FIRST_SEGMENT);

	if (spb_status->block_status_ul & EGPRS_RESEG_SECOND_SEG_RXD) {
		LOGPTBFUL(this, LOGL_DEBUG,
			  "First seg is received second seg is already present set the status to complete\n");

		block->len += Decoding::rlc_copy_to_aligned_buffer(rlc,
				block_idx, data, rlc_data);

		block->block_info.data_len = block->len;
		spb_status->block_status_ul = EGPRS_RESEG_DEFAULT;
	} else if (spb_status->block_status_ul == EGPRS_RESEG_DEFAULT) {
		LOGPTBFUL(this, LOGL_DEBUG,
			  "First seg is received second seg is not received set the status to first seg received\n");

		spb_status->block_status_ul = EGPRS_RESEG_FIRST_SEG_RXD;
		block->len = Decoding::rlc_copy_to_aligned_buffer(rlc,
					block_idx, data, rlc_data);
		block->block_info = *rdbi;
	}
	return spb_status->block_status_ul;
}

egprs_rlc_ul_reseg_bsn_state gprs_rlcmac_ul_tbf::handle_egprs_ul_spb(
	const struct gprs_rlc_data_info *rlc, struct gprs_rlc_data *block,
	uint8_t *data, const uint8_t block_idx)
{
	const gprs_rlc_data_block_info *rdbi = &rlc->block_info[block_idx];

	LOGPTBFUL(this, LOGL_DEBUG,
		  "Got SPB(%d) cs(%s) data block with BSN (%d), TFI(%d).\n",
		  rdbi->spb,  mcs_name(rlc->cs), rdbi->bsn, rlc->tfi);

	egprs_rlc_ul_reseg_bsn_state assemble_status = EGPRS_RESEG_INVALID;

	/* Section 10.4.8b of 44.060*/
	if (rdbi->spb == 2)
		assemble_status = handle_egprs_ul_first_seg(rlc,
						block, data, block_idx);
	else if (rdbi->spb == 3)
		assemble_status = handle_egprs_ul_second_seg(rlc,
						block, data, block_idx);
	else {
		LOGPTBFUL(this, LOGL_ERROR,
			  "spb(%d) Not supported SPB for this EGPRS configuration\n",
			  rdbi->spb);
	}

	/*
	 * When the block is successfully constructed out of segmented blocks
	 * upgrade the MCS to the type 2
	 */
	if (assemble_status == EGPRS_RESEG_DEFAULT) {
		switch (rlc->cs) {
		case MCS3 :
			block->cs_last = MCS6;
			LOGPTBFUL(this, LOGL_DEBUG, "Upgrading to MCS6\n");
			break;
		case MCS2 :
			block->cs_last = MCS5;
			LOGPTBFUL(this, LOGL_DEBUG, "Upgrading to MCS5\n");
			break;
		case MCS1 :
			LOGPTBFUL(this, LOGL_DEBUG, "Upgrading to MCS4\n");
			block->cs_last = MCS4;
			break;
		default:
			LOGPTBFUL(this, LOGL_ERROR,
				  "cs(%s) Error in Upgrading to higher MCS\n",
				  mcs_name(rlc->cs));
			break;
		}
	}
	return assemble_status;
}

void gprs_rlcmac_ul_tbf::update_coding_scheme_counter_ul(enum CodingScheme cs)
{
	switch (cs) {
	case CS1:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS1);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_gprs_ctrs, TBF_CTR_GPRS_UL_CS1));
		break;
	case CS2:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS2);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_gprs_ctrs, TBF_CTR_GPRS_UL_CS2));
		break;
	case CS3:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS3);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_gprs_ctrs, TBF_CTR_GPRS_UL_CS3));
		break;
	case CS4:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS4);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_gprs_ctrs, TBF_CTR_GPRS_UL_CS4));
		break;
	case MCS1:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS1);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS1));
		break;
	case MCS2:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS2);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS2));
		break;
	case MCS3:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS3);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS3));
		break;
	case MCS4:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS4);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS4));
		break;
	case MCS5:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS5);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS5));
		break;
	case MCS6:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS6);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS6));
		break;
	case MCS7:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS7);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS7));
		break;
	case MCS8:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS8);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS8));
		break;
	case MCS9:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS9);
		rate_ctr_inc(rate_ctr_group_get_ctr(m_ul_egprs_ctrs, TBF_CTR_EGPRS_UL_MCS9));
		break;
	default:
		LOGPTBFUL(this, LOGL_ERROR, "attempting to update rate counters for unsupported (M)CS %s\n",
			  mcs_name(cs));
	}
}

void gprs_rlcmac_ul_tbf::set_window_size()
{
	const struct gprs_rlcmac_bts *b = bts;
	uint16_t ws = egprs_window_size(b, ul_slots());
	LOGPTBFUL(this, LOGL_INFO, "setting EGPRS UL window size to %u, base(%u) slots(%u) ws_pdch(%u)\n",
		  ws, bts->pcu->vty.ws_base, pcu_bitcount(ul_slots()), bts->pcu->vty.ws_pdch);
	m_window.set_ws(ws);
}

gprs_rlc_window *gprs_rlcmac_ul_tbf::window()
{
	return &m_window;
}

void gprs_rlcmac_ul_tbf::apply_allocated_resources(const struct alloc_resources_res *res)
{
	uint8_t ts;

	if (this->trx)
		llist_del(&this->m_trx_list.list);

	llist_add(&this->m_trx_list.list, &res->trx->ul_tbfs);

	this->trx = res->trx;
	this->upgrade_to_multislot = res->upgrade_to_multislot;

	for (ts = 0; ts < ARRAY_SIZE(trx->pdch); ts++) {
		struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts];
		OSMO_ASSERT(!this->pdch[pdch->ts_no]);
		if (!(res->ass_slots_mask & (1 << ts)))
			continue;
		LOGPTBFUL(this, LOGL_DEBUG, "Assigning TS=%u TFI=%d USF=%u\n",
			  ts, res->tfi, res->usf[ts]);
		OSMO_ASSERT(res->usf[ts] >= 0);

		this->m_tfi = res->tfi;
		this->m_usf[pdch->ts_no] = res->usf[ts];

		this->pdch[pdch->ts_no] = pdch;
		pdch->attach_tbf(this);
	}

	/* assign initial control ts */
	tbf_assign_control_ts(this);

	/* res.ass_slots_mask == 0 -> special case for Rejected UL TBFs,
	 * see ms_new_ul_tbf_rejected_pacch() */
	if (res->ass_slots_mask != 0) {
		LOGPTBF(this, LOGL_INFO,
			"Allocated: trx = %d, ul_slots = %02x, dl_slots = %02x\n",
			this->trx->trx_no, ul_slots(), dl_slots());

		if (tbf_is_egprs_enabled(this))
			this->set_window_size();
	}

	tbf_update_state_fsm_name(this);
}

void ul_tbf_apply_allocated_resources(struct gprs_rlcmac_ul_tbf *ul_tbf, const struct alloc_resources_res *res)
{
	ul_tbf->apply_allocated_resources(res);
}

void gprs_rlcmac_ul_tbf::usf_timeout()
{
	if (n_inc(N3101))
		osmo_fsm_inst_dispatch(this->state_fi, TBF_EV_MAX_N3101, NULL);
}

struct gprs_rlcmac_ul_tbf *tbf_as_ul_tbf(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_UL_TBF)
		return static_cast<gprs_rlcmac_ul_tbf *>(tbf);
	else
		return NULL;
}

const struct gprs_rlcmac_ul_tbf *tbf_as_ul_tbf_const(const struct gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_UL_TBF)
		return static_cast<const gprs_rlcmac_ul_tbf *>(tbf);
	else
		return NULL;
}

void tbf_usf_timeout(struct gprs_rlcmac_ul_tbf *tbf)
{
	tbf->usf_timeout();
}


bool ul_tbf_contention_resolution_done(const struct gprs_rlcmac_ul_tbf *tbf)
{
	return tbf->m_contention_resolution_done;
}

struct osmo_fsm_inst *tbf_ul_ack_fi(const struct gprs_rlcmac_ul_tbf *tbf)
{
	return tbf->ul_ack_fsm.fi;
}

void ul_tbf_contention_resolution_start(struct gprs_rlcmac_ul_tbf *tbf)
{
	tbf->contention_resolution_start();
}

void ul_tbf_contention_resolution_success(struct gprs_rlcmac_ul_tbf *tbf)
{
	return tbf->contention_resolution_success();
}
