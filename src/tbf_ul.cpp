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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <bts.h>
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

static int ul_tbf_dtor(struct gprs_rlcmac_ul_tbf *tbf)
{
	tbf->~gprs_rlcmac_ul_tbf();
	return 0;
}

struct gprs_rlcmac_ul_tbf *tbf_alloc_ul_tbf(struct gprs_rlcmac_bts *bts, GprsMs *ms, int8_t use_trx, bool single_slot)
{
	struct gprs_rlcmac_ul_tbf *tbf;
	int rc;

	OSMO_ASSERT(ms != NULL);

	LOGPMS(ms, DTBF, LOGL_DEBUG, "********** UL-TBF starts here **********\n");
	LOGPMS(ms, DTBF, LOGL_INFO, "Allocating UL TBF\n");

	tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_ul_tbf);
	if (!tbf)
		return NULL;
	talloc_set_destructor(tbf, ul_tbf_dtor);
	new (tbf) gprs_rlcmac_ul_tbf(bts, ms);

	rc = tbf->setup(use_trx, single_slot);

	/* if no resource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}

	if (tbf->is_egprs_enabled())
		tbf->set_window_size();

	tbf->m_ul_egprs_ctrs = rate_ctr_group_alloc(tbf,
					&tbf_ul_egprs_ctrg_desc, tbf->m_ctrs->idx);
	tbf->m_ul_gprs_ctrs = rate_ctr_group_alloc(tbf,
					&tbf_ul_gprs_ctrg_desc, tbf->m_ctrs->idx);
	if (!tbf->m_ul_egprs_ctrs || !tbf->m_ul_gprs_ctrs) {
		LOGPTBF(tbf, LOGL_ERROR, "Couldn't allocate TBF UL counters\n");
		talloc_free(tbf);
		return NULL;
	}

	llist_add_tail(tbf_bts_list(tbf), &bts->ul_tbfs);
	bts_do_rate_ctr_inc(tbf->bts, CTR_TBF_UL_ALLOCATED);

	return tbf;
}


gprs_rlcmac_ul_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts, GprsMs *ms, int8_t use_trx,
				 uint32_t tlli)
{
	struct gprs_rlcmac_ul_tbf *tbf;

/* FIXME: Copy and paste with tbf_new_dl_assignment */
	/* create new TBF, use same TRX as DL TBF */
	/* use multislot class of downlink TBF */
	tbf = tbf_alloc_ul_tbf(bts, ms, use_trx, false);
	if (!tbf) {
		LOGPMS(ms, DTBF, LOGL_NOTICE, "No PDCH resource\n");
		/* FIXME: send reject */
		return NULL;
	}
	tbf->m_contention_resolution_done = 1;
	TBF_SET_ASS_ON(tbf, GPRS_RLCMAC_FLAG_PACCH, false);
	T_START(tbf, T3169, 3169, "allocation (UL-TBF)", true);
	tbf->update_ms(tlli, GPRS_RLCMAC_UL_TBF);
	OSMO_ASSERT(tbf->ms());

	return tbf;
}

struct gprs_rlcmac_ul_tbf *handle_tbf_reject(struct gprs_rlcmac_bts *bts,
			GprsMs *ms, uint32_t tlli, uint8_t trx_no, uint8_t ts)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf = NULL;
	struct gprs_rlcmac_trx *trx = &bts->trx[trx_no];

	if (!ms)
		ms = bts_alloc_ms(bts, 0, 0);
	ms_set_tlli(ms, tlli);

	ul_tbf = talloc(tall_pcu_ctx, struct gprs_rlcmac_ul_tbf);
	if (!ul_tbf)
		return ul_tbf;

	talloc_set_destructor(ul_tbf, ul_tbf_dtor);
	new (ul_tbf) gprs_rlcmac_ul_tbf(bts, ms);

	llist_add(tbf_bts_list((struct gprs_rlcmac_tbf *)ul_tbf), &bts->ul_tbfs);
	bts_do_rate_ctr_inc(ul_tbf->bts, CTR_TBF_UL_ALLOCATED);
	TBF_SET_ASS_ON(ul_tbf, GPRS_RLCMAC_FLAG_PACCH, false);

	ms_attach_tbf(ms, ul_tbf);
	ul_tbf->update_ms(tlli, GPRS_RLCMAC_UL_TBF);
	TBF_SET_ASS_STATE_UL(ul_tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ);
	ul_tbf->control_ts = ts;
	ul_tbf->trx = trx;
	ul_tbf->m_ctrs = rate_ctr_group_alloc(ul_tbf, &tbf_ctrg_desc, next_tbf_ctr_group_id++);
	ul_tbf->m_ul_egprs_ctrs = rate_ctr_group_alloc(ul_tbf,
						       &tbf_ul_egprs_ctrg_desc,
						       ul_tbf->m_ctrs->idx);
	ul_tbf->m_ul_gprs_ctrs = rate_ctr_group_alloc(ul_tbf,
						      &tbf_ul_gprs_ctrg_desc,
						      ul_tbf->m_ctrs->idx);
	if (!ul_tbf->m_ctrs || !ul_tbf->m_ul_egprs_ctrs || !ul_tbf->m_ul_gprs_ctrs) {
		LOGPTBF(ul_tbf, LOGL_ERROR, "Cound not allocate TBF UL rate counters\n");
		talloc_free(ul_tbf);
		return NULL;
	}

	return ul_tbf;
}

gprs_rlcmac_ul_tbf::gprs_rlcmac_ul_tbf(struct gprs_rlcmac_bts *bts_, GprsMs *ms) :
	gprs_rlcmac_tbf(bts_, ms, GPRS_RLCMAC_UL_TBF),
	m_rx_counter(0),
	m_contention_resolution_done(0),
	m_final_ack_sent(0),
	m_ul_gprs_ctrs(NULL),
	m_ul_egprs_ctrs(NULL)
{
	memset(&m_usf, USF_INVALID, sizeof(m_usf));
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

			m_llc.append_frame(data + frame->offset, frame->length);
			llc_consume(&m_llc, frame->length);
		}

		if (frame->is_complete) {
			/* send frame to SGSN */
			LOGPTBFUL(this, LOGL_DEBUG, "complete UL frame len=%d\n", llc_frame_length(&m_llc));
			snd_ul_ud();
			bts_do_rate_ctr_add(bts, CTR_LLC_UL_BYTES, llc_frame_length(&m_llc));
			m_llc.reset();
		}
	}

	return 0;
}

bool gprs_rlcmac_ul_tbf::ctrl_ack_to_toggle()
{
	if (check_n_clear(GPRS_RLCMAC_FLAG_TO_UL_ACK))
		return true; /* GPRS_RLCMAC_FLAG_TO_UL_ACK was set, now cleared */

	state_flags |= (1 << GPRS_RLCMAC_FLAG_TO_UL_ACK);
	return false; /* GPRS_RLCMAC_FLAG_TO_UL_ACK was unset, now set */
}

bool gprs_rlcmac_ul_tbf::handle_ctrl_ack()
{
	/* check if this control ack belongs to packet uplink ack */
	if (ul_ack_state_is(GPRS_RLCMAC_UL_ACK_WAIT_ACK)) {
		TBF_SET_ACK_STATE(this, GPRS_RLCMAC_UL_ACK_NONE);
		return true;
	}

	return false;
}

struct msgb *gprs_rlcmac_ul_tbf::create_ul_ack(uint32_t fn, uint8_t ts)
{
	int final = (state_is(GPRS_RLCMAC_FINISHED));
	struct msgb *msg;
	int rc;
	unsigned int rrbp = 0;
	uint32_t new_poll_fn = 0;

	if (final) {
		if (poll_scheduled() && ul_ack_state_is(GPRS_RLCMAC_UL_ACK_WAIT_ACK)) {
			LOGPTBFUL(this, LOGL_DEBUG,
				  "Polling is already scheduled, so we must wait for the final uplink ack...\n");
			return NULL;
		}

		rc = check_polling(fn, ts, &new_poll_fn, &rrbp);
		if (rc < 0)
			return NULL;
	}

	msg = msgb_alloc(23, "rlcmac_ul_ack");
	if (!msg)
		return NULL;
	bitvec *ack_vec = bitvec_alloc(23, tall_pcu_ctx);
	if (!ack_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ack_vec, DUMMY_VEC);
	Encoding::write_packet_uplink_ack(ack_vec, this, final, rrbp);
	bitvec_pack(ack_vec, msgb_put(msg, 23));
	bitvec_free(ack_vec);

	/* now we must set this flag, so we are allowed to assign downlink
	 * TBF on PACCH. it is only allowed when TLLI is acknowledged. */
	m_contention_resolution_done = 1;

	if (final) {
		set_polling(new_poll_fn, ts, GPRS_RLCMAC_POLL_UL_ACK);
		/* waiting for final acknowledge */
		m_final_ack_sent = 1;
	} else
		TBF_SET_ACK_STATE(this, GPRS_RLCMAC_UL_ACK_NONE);

	return msg;
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

	this->state_flags |= (1 << GPRS_RLCMAC_FLAG_UL_DATA);

	LOGPTBFUL(this, LOGL_DEBUG, "UL DATA TFI=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rlc->tfi, this->m_window.v_q(),
		this->m_window.v_r());

	/* process RSSI */
	gprs_rlcmac_rssi(this, rssi);

	/* store measurement values */
	if (ms())
		ms_update_l1_meas(ms(), meas);

	uint32_t new_tlli = GSM_RESERVED_TMSI;
	unsigned int block_idx;

	/* restart T3169 */
	T_START(this, T3169, 3169, "acked (data)", true);

	/* Increment RX-counter */
	this->m_rx_counter++;
	update_coding_scheme_counter_ul(rlc->cs);
	/* Loop over num_blocks */
	for (block_idx = 0; block_idx < rlc->num_data_blocks; block_idx++) {
		int num_chunks;
		uint8_t *rlc_data;
		rdbi = &rlc->block_info[block_idx];
		bool need_rlc_data = false;

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
		} else if (m_window.is_received(rdbi->bsn)) {
			LOGPTBFUL(this, LOGL_DEBUG,
				  "BSN %d already received\n", rdbi->bsn);
		} else {
			need_rlc_data = true;
		}

		if (!is_tlli_valid()) {
			if (!rdbi->ti) {
				LOGPTBFUL(this, LOGL_NOTICE, "Missing TLLI within UL DATA.\n");
				continue;
			}
			need_rlc_data = true;
		}

		if (!need_rlc_data)
			continue;

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
				update_ms(new_tlli, GPRS_RLCMAC_UL_TBF);
			} else if (new_tlli != GSM_RESERVED_TMSI && new_tlli != tlli()) {
				LOGPTBFUL(this, LOGL_NOTICE,
					  "Decoded TLLI=%08x mismatch on UL DATA TFI=%d. (Ignoring due to contention resolution)\n",
					  new_tlli, rlc->tfi);
				m_window.invalidate_bsn(rdbi->bsn);
				continue;
			}
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
	if (this->state_is(GPRS_RLCMAC_FLOW) /* still in flow state */
	 && this->m_window.v_q() == this->m_window.v_r()) { /* if complete */
		LOGPTBFUL(this, LOGL_DEBUG,
			  "No gaps in received block, last block: BSN=%d CV=%d\n",
			  rdbi->bsn, rdbi->cv);
		if (rdbi->cv == 0) {
			LOGPTBFUL(this, LOGL_DEBUG, "Finished with UL TBF\n");
			TBF_SET_STATE(this, GPRS_RLCMAC_FINISHED);
			/* Reset N3103 counter. */
			this->n_reset(N3103);
		}
	}

	/* If TLLI is included or if we received half of the window, we send
	 * an ack/nack */
	maybe_schedule_uplink_acknack(rlc, rdbi->cv == 0);

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
		if (state_is(GPRS_RLCMAC_FLOW))
			LOGPTBFUL(this, LOGL_DEBUG,
				  "Scheduling Ack/Nack, because some data is missing and last block has CV==0.\n");
		else if (state_is(GPRS_RLCMAC_FINISHED))
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

	if (ul_ack_state_is(GPRS_RLCMAC_UL_ACK_NONE)) {
		/* trigger sending at next RTS */
		TBF_SET_ACK_STATE(this, GPRS_RLCMAC_UL_ACK_SEND_ACK);
	} else {
		/* already triggered */
		LOGPTBFUL(this, LOGL_DEBUG,
			  "Sending Ack/Nack already scheduled, no need to re-schedule\n");
	}
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
		m_llc.reset_frame_space();
		return -EIO;
	}

	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	uint8_t *buf = msgb_push(llc_pdu, TL16V_GROSS_LEN(sizeof(uint8_t)*llc_frame_length(&m_llc)));
	tl16v_put(buf, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*llc_frame_length(&m_llc), m_llc.frame);
	qos_profile[0] = QOS_PROFILE >> 16;
	qos_profile[1] = QOS_PROFILE >> 8;
	qos_profile[2] = QOS_PROFILE;
	bssgp_tx_ul_ud(bctx, tlli(), qos_profile, llc_pdu);

	m_llc.reset_frame_space();
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
		rate_ctr_inc(&m_ul_gprs_ctrs->ctr[TBF_CTR_GPRS_UL_CS1]);
		break;
	case CS2:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS2);
		rate_ctr_inc(&m_ul_gprs_ctrs->ctr[TBF_CTR_GPRS_UL_CS2]);
		break;
	case CS3:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS3);
		rate_ctr_inc(&m_ul_gprs_ctrs->ctr[TBF_CTR_GPRS_UL_CS3]);
		break;
	case CS4:
		bts_do_rate_ctr_inc(bts, CTR_GPRS_UL_CS4);
		rate_ctr_inc(&m_ul_gprs_ctrs->ctr[TBF_CTR_GPRS_UL_CS4]);
		break;
	case MCS1:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS1);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS1]);
		break;
	case MCS2:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS2);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS2]);
		break;
	case MCS3:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS3);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS3]);
		break;
	case MCS4:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS4);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS4]);
		break;
	case MCS5:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS5);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS5]);
		break;
	case MCS6:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS6);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS6]);
		break;
	case MCS7:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS7);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS7]);
		break;
	case MCS8:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS8);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS8]);
		break;
	case MCS9:
		bts_do_rate_ctr_inc(bts, CTR_EGPRS_UL_MCS9);
		rate_ctr_inc(&m_ul_egprs_ctrs->ctr[TBF_CTR_EGPRS_UL_MCS9]);
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

struct gprs_rlcmac_ul_tbf *as_ul_tbf(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf && tbf->direction == GPRS_RLCMAC_UL_TBF)
		return static_cast<gprs_rlcmac_ul_tbf *>(tbf);
	else
		return NULL;
}
