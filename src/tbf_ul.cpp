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
#include <rlc.h>
#include <encoding.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <decoding.h>
#include <pcu_l1_if.h>

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
}

#include <errno.h>
#include <string.h>

/* After receiving these frames, we send ack/nack. */
#define SEND_ACK_AFTER_FRAMES 20

extern void *tall_pcu_ctx;

/*
 * Store received block data in LLC message(s) and forward to SGSN
 * if complete.
 */
int gprs_rlcmac_ul_tbf::assemble_forward_llc(const gprs_rlc_data *_data)
{
	const uint8_t *data = _data->block;
	uint8_t len = _data->len;
	const struct gprs_rlc_ul_data_block_info *rdbi = &_data->block_info;
	GprsCodingScheme cs = _data->cs;

	Decoding::RlcData frames[16], *frame;
	int i, num_frames = 0;
	uint32_t dummy_tlli;

	LOGP(DRLCMACUL, LOGL_DEBUG, "- Assembling frames: (len=%d)\n", len);

	num_frames = Decoding::rlc_data_from_ul_data(
		rdbi, cs, data, &(frames[0]), sizeof(frames),
		&dummy_tlli);

	/* create LLC frames */
	for (i = 0; i < num_frames; i++) {
		frame = frames + i;

		LOGP(DRLCMACUL, LOGL_DEBUG, "-- Frame %d starts at offset %d, "
			"length=%d, is_complete=%d\n",
			i + 1, frame->offset, frame->length, frame->is_complete);

		m_llc.append_frame(data + frame->offset, frame->length);
		m_llc.consume(frame->length);

		if (frame->is_complete) {
			/* send frame to SGSN */
			LOGP(DRLCMACUL, LOGL_INFO, "%s complete UL frame len=%d\n",
				tbf_name(this) , m_llc.frame_length());
			snd_ul_ud();
			m_llc.reset();
		}
	}

	return 0;
}


struct msgb *gprs_rlcmac_ul_tbf::create_ul_ack(uint32_t fn)
{
	int final = (state_is(GPRS_RLCMAC_FINISHED));
	struct msgb *msg;

	if (final) {
		if (poll_state != GPRS_RLCMAC_POLL_NONE) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
				"sheduled for %s, so we must wait for "
				"final uplink ack...\n", tbf_name(this));
			return NULL;
		}
		if (bts->sba()->find(trx->trx_no, control_ts, (fn + 13) % 2715648)) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
				"scheduled for single block allocation...\n");
			return NULL;
		}
	}

	msg = msgb_alloc(23, "rlcmac_ul_ack");
	if (!msg)
		return NULL;
	bitvec *ack_vec = bitvec_alloc(23);
	if (!ack_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ack_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	Encoding::write_packet_uplink_ack(bts_data(), mac_control_block, this, final);
	encode_gsm_rlcmac_downlink(ack_vec, mac_control_block);
	bitvec_pack(ack_vec, msgb_put(msg, 23));
	bitvec_free(ack_vec);
	talloc_free(mac_control_block);

	/* now we must set this flag, so we are allowed to assign downlink
	 * TBF on PACCH. it is only allowed when TLLI is acknowledged. */
	m_contention_resolution_done = 1;

	if (final) {
		poll_state = GPRS_RLCMAC_POLL_SCHED;
		poll_fn = (fn + 13) % 2715648;
		/* waiting for final acknowledge */
		ul_ack_state = GPRS_RLCMAC_UL_ACK_WAIT_ACK;
		m_final_ack_sent = 1;
	} else
		ul_ack_state = GPRS_RLCMAC_UL_ACK_NONE;

	return msg;
}

int gprs_rlcmac_ul_tbf::rcv_data_block_acknowledged(
	const struct gprs_rlc_ul_header_egprs *rlc,
	uint8_t *data, uint8_t len, struct pcu_l1_meas *meas)
{
	int8_t rssi = meas->have_rssi ? meas->rssi : 0;

	const uint16_t mod_sns = m_window.mod_sns();
	const uint16_t ws = m_window.ws();

	this->state_flags |= (1 << GPRS_RLCMAC_FLAG_UL_DATA);

	LOGP(DRLCMACUL, LOGL_DEBUG, "UL DATA TFI=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rlc->tfi, this->m_window.v_q(),
		this->m_window.v_r());

	/* process RSSI */
	gprs_rlcmac_rssi(this, rssi);

	/* store measurement values */
	if (ms())
		ms()->update_l1_meas(meas);

	uint32_t new_tlli = 0;
	unsigned int block_idx;

	/* restart T3169 */
	tbf_timer_start(this, 3169, bts_data()->t3169, 0);

	/* Increment RX-counter */
	this->m_rx_counter++;

	/* Loop over num_blocks */
	for (block_idx = 0; block_idx < rlc->num_data_blocks; block_idx++) {
		int num_chunks;
		uint8_t *rlc_data;
		const struct gprs_rlc_ul_data_block_info *rdbi =
			&rlc->block_info[block_idx];
		bool need_rlc_data = false;
		struct gprs_rlc_data *block;

		LOGP(DRLCMACUL, LOGL_DEBUG,
			"%s: Got %s RLC data block: "
			"CV=%d, BSN=%d, SPB=%d, "
			"PI=%d, E=%d, TI=%d, bitoffs=%d\n",
			name(), rlc->cs.name(),
			rdbi->cv, rdbi->bsn, rdbi->spb,
			rdbi->pi, rdbi->e, rdbi->ti,
			rlc->data_offs_bits[block_idx]);

		/* Check whether the block needs to be decoded */

		if (!m_window.is_in_window(rdbi->bsn)) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- BSN %d out of window "
				"%d..%d (it's normal)\n", rdbi->bsn,
				m_window.v_q(),
				(m_window.v_q() + ws - 1) & mod_sns);
		} else if (m_window.is_received(rdbi->bsn)) {
			LOGP(DRLCMACUL, LOGL_DEBUG,
				"- BSN %d already received\n", rdbi->bsn);
		} else {
			need_rlc_data = true;
		}

		if (!is_tlli_valid()) {
			if (!rdbi->ti) {
				LOGP(DRLCMACUL, LOGL_NOTICE,
					"%s: Missing TLLI within UL DATA.\n",
					name());
				continue;
			}
			need_rlc_data = true;
		}

		if (!need_rlc_data)
			continue;

		/* Store block and meta info to BSN buffer */

		LOGP(DRLCMACUL, LOGL_DEBUG, "- BSN %d storing in window (%d..%d)\n",
			rdbi->bsn, m_window.v_q(),
			(m_window.v_q() + ws - 1) & mod_sns);
		block = m_rlc.block(rdbi->bsn);
		block->block_info = *rdbi;
		block->cs = rlc->cs;
		OSMO_ASSERT(rdbi->data_len < sizeof(block->block));
		rlc_data = &(block->block[0]);
		/* TODO: Handle SPB != 0 -> Set length to 2*len, add offset if
		 * 2nd part. Note that resegmentation is currently disabled
		 * within the UL assignment.
		 */
		if (rdbi->spb) {
			LOGP(DRLCMACUL, LOGL_NOTICE,
				"Got SPB != 0 but resegmentation has been "
				"disabled, skipping %s data block with BSN %d, "
				"TFI=%d.\n", rlc->cs.name(), rdbi->bsn,
				rlc->tfi);
			continue;
		}

		block->len =
			Decoding::rlc_copy_to_aligned_buffer(rlc, block_idx, data,
				rlc_data);

		LOGP(DRLCMACUL, LOGL_DEBUG,
			"%s: data_length=%d, data=%s\n",
			name(), block->len, osmo_hexdump(rlc_data, block->len));

		/* TODO: Handle SPB != 0 -> set state to partly received
		 * (upper/lower) and continue with the loop, unless the other
		 * part is already present.
		 */

		/* Get/Handle TLLI */
		if (rdbi->ti) {
			num_chunks = Decoding::rlc_data_from_ul_data(
				rdbi, rlc->cs, rlc_data, NULL, 0, &new_tlli);

			if (num_chunks < 0) {
				bts->decode_error();
				LOGP(DRLCMACUL, LOGL_NOTICE,
					"Failed to decode TLLI of %s UL DATA "
					"TFI=%d.\n", rlc->cs.name(), rlc->tfi);
				m_window.invalidate_bsn(rdbi->bsn);
				continue;
			}
			if (!this->is_tlli_valid()) {
				if (!new_tlli) {
					LOGP(DRLCMACUL, LOGL_NOTICE,
						"%s: TLLI = 0 within UL DATA.\n",
						name());
					m_window.invalidate_bsn(rdbi->bsn);
					continue;
				}
				LOGP(DRLCMACUL, LOGL_INFO,
					"Decoded premier TLLI=0x%08x of "
					"UL DATA TFI=%d.\n", tlli(), rlc->tfi);
				set_tlli_from_ul(new_tlli);
			} else if (new_tlli && new_tlli != tlli()) {
				LOGP(DRLCMACUL, LOGL_NOTICE, "TLLI mismatch on UL "
					"DATA TFI=%d. (Ignoring due to contention "
					"resolution)\n", rlc->tfi);
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
		uint16_t index = (v_q_beg + i) & mod_sns;
		assemble_forward_llc(m_rlc.block(index));
	}

	/* Check CV of last frame in buffer */
	if (this->state_is(GPRS_RLCMAC_FLOW) /* still in flow state */
	 && this->m_window.v_q() == this->m_window.v_r()) { /* if complete */
		struct gprs_rlc_data *block =
			m_rlc.block((m_window.v_r() - 1) & mod_sns);
		const struct gprs_rlc_ul_data_block_info *rdbi =
			&block->block_info;

		LOGP(DRLCMACUL, LOGL_DEBUG, "- No gaps in received block, "
			"last block: BSN=%d CV=%d\n", rdbi->bsn,
			rdbi->cv);
		if (rdbi->cv == 0) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Finished with UL "
				"TBF\n");
			set_state(GPRS_RLCMAC_FINISHED);
			/* Reset N3103 counter. */
			this->m_n3103 = 0;
		}
	}

	/* If TLLI is included or if we received half of the window, we send
	 * an ack/nack */
	maybe_schedule_uplink_acknack(rlc);

	return 0;
}

void gprs_rlcmac_ul_tbf::maybe_schedule_uplink_acknack(
	const gprs_rlc_ul_header_egprs *rlc)
{
	bool have_ti = rlc->block_info[0].ti ||
		(rlc->num_data_blocks > 1 && rlc->block_info[1].ti);

	if (rlc->si || have_ti || state_is(GPRS_RLCMAC_FINISHED) ||
		(m_rx_counter % SEND_ACK_AFTER_FRAMES) == 0)
	{
		if (rlc->si) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "- Scheduling Ack/Nack, "
				"because MS is stalled.\n");
		}
		if (have_ti) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because TLLI is included.\n");
		}
		if (state_is(GPRS_RLCMAC_FINISHED)) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because last block has CV==0.\n");
		}
		if ((m_rx_counter % SEND_ACK_AFTER_FRAMES) == 0) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because %d frames received.\n",
				SEND_ACK_AFTER_FRAMES);
		}
		if (ul_ack_state == GPRS_RLCMAC_UL_ACK_NONE) {
			/* trigger sending at next RTS */
			ul_ack_state = GPRS_RLCMAC_UL_ACK_SEND_ACK;
		} else {
			/* already triggered */
			LOGP(DRLCMACUL, LOGL_DEBUG, "-  Sending Ack/Nack is "
				"already triggered, don't schedule!\n");
		}
	}
}

/* Send Uplink unit-data to SGSN. */
int gprs_rlcmac_ul_tbf::snd_ul_ud()
{
	uint8_t qos_profile[3];
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + m_llc.frame_length();
	struct bssgp_bvc_ctx *bctx = gprs_bssgp_pcu_current_bctx();

	LOGP(DBSSGP, LOGL_INFO, "LLC [PCU -> SGSN] %s len=%d\n", tbf_name(this), m_llc.frame_length());
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		m_llc.reset_frame_space();
		return -EIO;
	}
	
	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	uint8_t *buf = msgb_push(llc_pdu, TL16V_GROSS_LEN(sizeof(uint8_t)*m_llc.frame_length()));
	tl16v_put(buf, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*m_llc.frame_length(), m_llc.frame);
	qos_profile[0] = QOS_PROFILE >> 16;
	qos_profile[1] = QOS_PROFILE >> 8;
	qos_profile[2] = QOS_PROFILE;
	bssgp_tx_ul_ud(bctx, tlli(), qos_profile, llc_pdu);

	m_llc.reset_frame_space();
	return 0;
}

