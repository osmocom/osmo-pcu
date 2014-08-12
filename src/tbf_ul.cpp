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
	const struct rlc_ul_header *rh = (const struct rlc_ul_header *) data;
	uint8_t e, m;
	struct rlc_li_field *li;
	uint8_t frame_offset[16], offset = 0, chunk;
	int i, frames = 0;

	LOGP(DRLCMACUL, LOGL_DEBUG, "- Assembling frames: (len=%d)\n", len);

	data += 3;
	len -= 3;
	e = rh->e; /* if extended */
	m = 1; /* more frames, that means: the first frame */

	/* Parse frame offsets from length indicator(s), if any. */
	while (1) {
		if (frames == (int)sizeof(frame_offset)) {
			LOGP(DRLCMACUL, LOGL_ERROR, "%s too many frames in "
				"block\n", tbf_name(this));
			return -EINVAL;
		}
		frame_offset[frames++] = offset;
		LOGP(DRLCMACUL, LOGL_DEBUG, "-- Frame %d starts at offset "
			"%d\n", frames, offset);
		if (!len)
			break;
		/* M == 0 and E == 0 is not allowed in this version. */
		if (!m && !e) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "%s UL DATA "
				"ignored, because M='0' and E='0'.\n",
				tbf_name(this));
			return 0;
		}
		/* no more frames in this segment */
		if (e) {
			break;
		}
		/* There is a new frame and an LI that delimits it. */
		if (m) {
			li = (struct rlc_li_field *)data;
			LOGP(DRLCMACUL, LOGL_DEBUG, "-- Delimiter len=%d\n",
				li->li);
			/* Special case: LI == 0
			 * If the last segment would fit precisely into the
			 * rest of the RLC MAC block, there would be no way
			 * to delimit that this segment ends and is not
			 * continued in the next block.
			 * The special LI (0) is used to force the segment to
			 * extend into the next block, so it is delimited there.
			 * This LI must be skipped. Also it is the last LI.
			 */
			if (li->li == 0) {
				data++;
				len--;
				m = 1; /* M is ignored, we know there is more */
				break; /* handle E as '1', so we break! */
			}
			e = li->e;
			m = li->m;
			offset += li->li;
			data++;
			len--;
			continue;
		}
	}
	if (!m) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Last frame carries spare "
			"data\n");
	}

	LOGP(DRLCMACUL, LOGL_DEBUG, "- Data length after length fields: %d\n",
		len);
	/* TLLI */
	if (rh->ti) {
		if (len < 4) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "%s UL DATA TLLI out of "
				"frame border\n", tbf_name(this));
			return -EINVAL;
		}
		data += 4;
		len -= 4;
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Length after skipping TLLI: "
			"%d\n", len);
	}

	/* PFI */
	if (rh->pi) {
		LOGP(DRLCMACUL, LOGL_ERROR, "ERROR: PFI not supported, "
			"please disable in SYSTEM INFORMATION\n");
		if (len < 1) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "%s UL DATA PFI out of "
				"frame border\n", tbf_name(this));
			return -EINVAL;
		}
		data++;
		len--;
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Length after skipping PFI: "
			"%d\n", len);
	}

	/* Now we have:
	 * - a list of frames offsets: frame_offset[]
	 * - number of frames: i
	 * - m == 0: Last frame carries spare data (end of TBF).
	 */

	/* Check if last offset would exceed frame. */
	if (offset > len) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "%s UL DATA ignored, "
			"because LI delimits data that exceeds block size.\n",
			tbf_name(this));
		return -EINVAL;
	}

	/* create LLC frames */
	for (i = 0; i < frames; i++) {
		/* last frame ? */
		if (i == frames - 1) {
			/* no more data in last frame */
			if (!m)
				break;
			/* data until end of frame */
			chunk = len - frame_offset[i];
		} else {
			/* data until next frame */
			chunk = frame_offset[i + 1] - frame_offset[i];
		}
		if (!m_llc.fits_in_current_frame(chunk)) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "%s LLC frame exceeds "
				"maximum size %u.\n", tbf_name(this),
				m_llc.remaining_space());
			chunk = m_llc.remaining_space();
		}
		m_llc.append_frame(data + frame_offset[i], chunk);
		m_llc.consume(chunk);
		/* not last frame. */
		if (i != frames - 1) {
			/* send frame to SGSN */
			LOGP(DRLCMACUL, LOGL_INFO, "%s complete UL frame len=%d\n",
				tbf_name(this) , m_llc.frame_length());
			snd_ul_ud();
			m_llc.reset();
		/* also check if CV==0, because the frame may fill up the
		 * block precisely, then it is also complete. normally the
		 * frame would be extended into the next block with a 0-length
		 * delimiter added to this block. */
		} else if (rh->cv == 0) {
			/* send frame to SGSN */
			LOGP(DRLCMACUL, LOGL_INFO, "%s complete UL frame "
				"that fits precisely in last block: "
				"len=%d\n", tbf_name(this), m_llc.frame_length());
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

int gprs_rlcmac_ul_tbf::rcv_data_block_acknowledged(const uint8_t *data, size_t len, int8_t rssi)
{
	struct rlc_ul_header *rh = (struct rlc_ul_header *)data;
	int rc;

	const uint16_t mod_sns = m_window.mod_sns();
	const uint16_t ws = m_window.ws();

	this->state_flags |= (1 << GPRS_RLCMAC_FLAG_UL_DATA);

	LOGP(DRLCMACUL, LOGL_DEBUG, "UL DATA TFI=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rh->tfi, this->m_window.v_q(),
		this->m_window.v_r());

	/* process RSSI */
	gprs_rlcmac_rssi(this, rssi);

	/* get TLLI */
	if (!this->is_tlli_valid()) {
		if (!extract_tlli(data, len))
			return 0;
	/* already have TLLI, but we stille get another one */
	} else if (rh->ti) {
		uint32_t tlli;
		rc = Decoding::tlli_from_ul_data(data, len, &tlli);
		if (rc) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "Failed to decode TLLI "
				"of UL DATA TFI=%d.\n", rh->tfi);
			return 0;
		}
		if (tlli != this->tlli()) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "TLLI mismatch on UL "
				"DATA TFI=%d. (Ignoring due to contention "
				"resolution)\n", rh->tfi);
			return 0;
		}
	}

	/* restart T3169 */
	tbf_timer_start(this, 3169, bts_data()->t3169, 0);

	/* Increment RX-counter */
	this->m_rx_counter++;

	if (!m_window.is_in_window(rh->bsn)) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "- BSN %d out of window "
			"%d..%d (it's normal)\n", rh->bsn,
			m_window.v_q(),
			(m_window.v_q() + ws - 1) & mod_sns);
		maybe_schedule_uplink_acknack(rh);
		return 0;
	}

	/* Write block to buffer and set receive state array. */
	m_rlc.block(rh->bsn)->put_data(data, len);
	LOGP(DRLCMACUL, LOGL_DEBUG, "- BSN %d storing in window (%d..%d)\n",
		rh->bsn, m_window.v_q(),
		(m_window.v_q() + ws - 1) & mod_sns);

	/* Raise V(Q) if possible, and retrieve LLC frames from blocks.
	 * This is looped until there is a gap (non received block) or
	 * the window is empty.*/
	const uint16_t v_q_beg = m_window.v_q();

	const uint16_t count = m_window.receive_bsn(rh->bsn);

	/* Retrieve LLC frames from blocks that are ready */
	for (uint16_t i = 0; i < count; ++i) {
		uint16_t index = (v_q_beg + i) & mod_sns;
		assemble_forward_llc(m_rlc.block(index));
	}

	/* Check CV of last frame in buffer */
	if (this->state_is(GPRS_RLCMAC_FLOW) /* still in flow state */
	 && this->m_window.v_q() == this->m_window.v_r()) { /* if complete */
		struct rlc_ul_header *last_rh = (struct rlc_ul_header *)
			m_rlc.block((m_window.v_r() - 1) & mod_sns)->block;
		LOGP(DRLCMACUL, LOGL_DEBUG, "- No gaps in received block, "
			"last block: BSN=%d CV=%d\n", last_rh->bsn,
			last_rh->cv);
		if (last_rh->cv == 0) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Finished with UL "
				"TBF\n");
			set_state(GPRS_RLCMAC_FINISHED);
			/* Reset N3103 counter. */
			this->m_n3103 = 0;
		}
	}

	/* If TLLI is included or if we received half of the window, we send
	 * an ack/nack */
	maybe_schedule_uplink_acknack(rh);

	return 0;
}

void gprs_rlcmac_ul_tbf::maybe_schedule_uplink_acknack(const rlc_ul_header *rh)
{
	if (rh->si || rh->ti || state_is(GPRS_RLCMAC_FINISHED)
	 || (m_rx_counter % SEND_ACK_AFTER_FRAMES) == 0) {
		if (rh->si) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "- Scheduling Ack/Nack, "
				"because MS is stalled.\n");
		}
		if (rh->ti) {
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

