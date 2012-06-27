/* Data block transfer
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
 
#include <gprs_bssgp_pcu.h>
#include <gprs_rlcmac.h>

/* After receiving these framess, we send ack/nack. */
#define ACK_AFTER_FRAMES 20

extern "C" {
/* TS 04.60  10.2.2 */
struct rlc_dl_header {
	uint8_t	r:1,
		 si:1,
		 cv:4,
		 pt:2;
	uint8_t	ti:1,
		 tfi:5,
		 pi:1,
		 spare:1;
	uint8_t	e:1,
		 bsn:7;
} __attribute__ ((packed));

struct rlc_li_field {
	uint8_t	e:1,
		 m:1,
		 li:6;
} __attribute__ ((packed));
}

/* get TLLI from received UL data block */
static int tlli_from_ul_data(uint8_t *data, uint8_t len, uint32_t *tlli)
{
	struct rlc_dl_header *rh = (struct rlc_dl_header *)data;
	struct rlc_li_field *li;
	uint8_t e;

	if (!rh->ti)
		return -EINVAL;
	
	data += 3;
	len -= 3;
	e = rh->e;
	/* if E is not set (LI follows) */
	while (!e) {
		if (!len) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA LI extended, "
				"but no more data\n");
			return -EINVAL;
		}
		/* get new E */
		li = (struct rlc_li_field *)data;
		if (li->e == 0) /* if LI==0, E is interpreted as '1' */
			e = 1;
		else
			e = li->e;
		data++;
		len--;
	}
	if (len < 4) {
		LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA TLLI out of frame "
			"border\n");
		return -EINVAL;
	}
	*tlli = ntohl(*((uint32_t *)data));

	return 0;
}

/* Store received block data in LLC message(s) and forward to SGSN if complete.
 */
static int gprs_rlcmac_assemble_llc(struct gprs_rlcmac_tbf *tbf, uint8_t *data,
	uint8_t len)
{
	struct rlc_dl_header *rh = (struct rlc_dl_header *)data;
	uint8_t e, m;
	struct rlc_li_field *li;
	uint8_t frame_offset[16], offset = 0, chunk;
	int i, frames = 0;

	LOGP(DRLCMACDATA, LOGL_DEBUG, "- Assembling frames: (len=%d)\n", len);
	
	data += 3;
	len -= 3;
	e = rh->e; /* if extended */
	m = 1; /* more frames, that means: the first frame */

	/* Parse frame offsets from length indicator(s), if any. */
	while (1) {
		if (frames == (int)sizeof(frame_offset)) {
			LOGP(DRLCMACDATA, LOGL_ERROR, "Too many frames in "
				"block\n");
			return -EINVAL;
		}
		frame_offset[frames++] = offset;
		LOGP(DRLCMACDATA, LOGL_DEBUG, "-- Frame %d starts at offset "
			"%d\n", frames, offset);
		if (!len)
			break;
		/* M == 0 and E == 0 is not allowed in this version. */
		if (!m && !e) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA TFI=%d "
				"ignored, because M='0' and E='0'.\n",
				tbf->tfi);
			return 0;
		}
		/* no more frames in this segment */
		if (e) {
			break;
		}
		/* There is a new frame and an LI that delimits it. */
		if (m) {
			li = (struct rlc_li_field *)data;
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
		LOGP(DRLCMACDATA, LOGL_DEBUG, "- Last frame carries spare "
			"data\n");
	}

	LOGP(DRLCMACDATA, LOGL_DEBUG, "- Data length after length fields: %d\n",
		len);
	if (rh->ti) {
		data += 4;
		len -= 4;
		LOGP(DRLCMACDATA, LOGL_DEBUG, "- Length after skipping TLLI: "
			"%d\n", len);
	}

	/* Now we have:
	 * - a list of frames offsets: frame_offset[]
	 * - number of frames: i
	 * - m == 0: Last frame carries spare data (end of TBF).
	 */

	/* Check if last offset would exceed frame. */
	if (offset > len) {
		LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA TFI=%d ignored, "
			"because LI exceeds frame length.\n", tbf->tfi);
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
		LOGP(DRLCMACDATA, LOGL_DEBUG, "-- Appending chunk (len=%d) to "
			"frame at %d.\n", chunk, tbf->llc_index);
		if (tbf->llc_index + chunk > LLC_MAX_LEN) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "LLC frame exceeds "
				"maximum size.\n");
			chunk = LLC_MAX_LEN - tbf->llc_index;
		}
		memcpy(tbf->llc_frame + tbf->llc_index, data + frame_offset[i],
			chunk);
		tbf->llc_index += chunk;
		/* not last frame ? */
		if (i != frames - 1) {
			/* send frame to SGSN */
			LOGP(DRLCMACDATA, LOGL_INFO, "Complete UL frame for "
				"TFI=%d: %s\n", tbf->tfi,
				osmo_hexdump(tbf->llc_frame, tbf->llc_index));
			gprs_rlcmac_tx_ul_ud(tbf);
			tbf->llc_index = 0;
		}
	}

	return 0;
}

/* * generate uplink ack
 */
void write_packet_uplink_ack(bitvec * dest, struct gprs_rlcmac_tbf *tbf,
	uint8_t final)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	uint16_t i, bbn;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	char bit;

	LOGP(DRLCMACDATA, LOGL_DEBUG, "Sending Ack/Nack for TBF=%d "
		"(final=%d)\n", tbf->tfi, final);

	bitvec_write_field(dest, wp,0x1,2);  // payload
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber (N+13)
	bitvec_write_field(dest, wp,final,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	
	//bitvec_write_field(dest, wp,0x0,1);  // Reduced block sequence number
	//bitvec_write_field(dest, wp,BSN+6,5);  // Radio transaction identifier
	//bitvec_write_field(dest, wp,0x1,1);  // Final segment
	//bitvec_write_field(dest, wp,0x1,1);  // Address control

	//bitvec_write_field(dest, wp,0x0,2);  // Power reduction: 0
	//bitvec_write_field(dest, wp,TFI,5);  // Temporary flow identifier
	//bitvec_write_field(dest, wp,0x1,1);  // Direction

	bitvec_write_field(dest, wp,0x09,6); // MESSAGE TYPE
	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,2);
	bitvec_write_field(dest, wp,tbf->tfi,5); // Uplink TFI
	bitvec_write_field(dest, wp,0x0,1);
	
	bitvec_write_field(dest, wp,0x0,2);  // CS1
	bitvec_write_field(dest, wp,final,1);  // FINAL_ACK_INDICATION
	bitvec_write_field(dest, wp,tbf->dir.ul.v_r,7); // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	LOGP(DRLCMACDATA, LOGL_DEBUG, "- ack bitmap: \"");
	for (i = 0, bbn = (tbf->dir.ul.v_r - 1) & mod_sns_half; i < 64;
	     i++, bbn = (bbn - 1) & mod_sns_half) {
	     	bit = tbf->dir.ul.v_n[bbn];
		if (bit == 0)
			bit = ' ';
		LOGPC(DRLCMACDATA, LOGL_DEBUG, "%c", bit);
		bitvec_write_field(dest, wp,(bit == 'R'),1);
	}
		LOGPC(DRLCMACDATA, LOGL_DEBUG, "\"\n");
	bitvec_write_field(dest, wp,0x1,1);  // CONTENTION_RESOLUTION_TLLI = present
	bitvec_write_field(dest, wp,tbf->tlli,8*4);
	bitvec_write_field(dest, wp,0x00,4); //spare
	bitvec_write_field(dest, wp,0x5,4); //0101
}

struct msgb *gprs_rlcmac_send_uplink_ack(struct gprs_rlcmac_tbf *tbf,
	uint32_t fn)
{
	int final = (tbf->state == GPRS_RLCMAC_FINISHED);
	struct msgb *msg;

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
	write_packet_uplink_ack(ack_vec,  tbf, final);
	bitvec_pack(ack_vec, msgb_put(msg, 23));
	bitvec_free(ack_vec);

	if (final) {
		if (tbf->poll_state == GPRS_RLCMAC_POLL_SCHED)
			LOGP(DRLCMACDATA, LOGL_ERROR, "Polling is already "
				"sheduled for TBF=%d\n", tbf->tfi);
		tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
		tbf->poll_fn = (fn + 13) % 2715648;
		tbf->dir.ul.substate = GPRS_RLCMAC_UL_WAIT_POLL;
	} else
		tbf->dir.ul.substate = GPRS_RLCMAC_UL_NONE;

	return msg;
}

/* receive UL data block
 *
 * The blocks are defragmented and forwarded as LLC frames, if complete.
 */
int gprs_rlcmac_rcv_data_block_acknowledged(uint8_t *data, uint8_t len)
{
	struct gprs_rlcmac_tbf *tbf;
	struct rlc_dl_header *rh = (struct rlc_dl_header *)data;
	uint16_t mod_sns, mod_sns_half, offset_v_q, offset_v_r, index;
	int rc;

	if (len < 23) {
		LOGP(DRLCMACDATA, LOGL_ERROR, "Dropping short frame "
			"(len = %d)\n", len);
		return -EINVAL;
	}

	/* find TBF inst from given TFI */
	tbf = tbf_by_tfi(rh->tfi);
	if (!tbf) {
		LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA unknown TFI=%d\n",
			rh->tfi);
		return 0;
	}

	if (tbf->direction != GPRS_RLCMAC_UL_TBF) {
		LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA TFI=%d not Uplink "
			"tbf\n", rh->tfi);
		return 0;
	}

	LOGP(DRLCMACDATA, LOGL_INFO, "UL DATA TFI=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rh->tfi, tbf->dir.ul.v_q, tbf->dir.ul.v_r);

	/* get TLLI */
	if (!tbf->tlli_valid) {
		/* no TLLI yet */
		if (!rh->ti) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "UL DATA TFI=%d without "
				"TLLI, but no TLLI received yet\n", rh->tfi);
			return 0;
		}
		rc = tlli_from_ul_data(data, len, &tbf->tlli);
		if (rc) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "Failed to decode TLLI "
				"of UL DATA TFI=%d.\n", rh->tfi);
			return 0;
		}
		tbf->tlli_valid = 1;
		LOGP(DRLCMACDATA, LOGL_DEBUG, " Decoded premier TLLI=0x%08x of "
			"UL DATA TFI=%d.\n", tbf->tlli, rh->tfi);
	/* already have TLLI, but we stille get another one */
	} else if (rh->ti) {
		uint32_t tlli;
		rc = tlli_from_ul_data(data, len, &tlli);
		if (rc) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "Failed to decode TLLI "
				"of UL DATA TFI=%d.\n", rh->tfi);
			return 0;
		}
		if (tlli != tbf->tlli) {
			LOGP(DRLCMACDATA, LOGL_NOTICE, "TLLI mismatch on UL "
				"DATA TFI=%d. (Ignoring due to contention "
				"resolution)\n", rh->tfi);
			return 0;
		}
	}

	mod_sns = tbf->sns - 1;
	mod_sns_half = (tbf->sns >> 1) - 1;

	/* restart T3169 */
	tbf_timer_start(tbf, 3169, T3169);

	/* Increment RX-counter */
	tbf->dir.ul.rx_counter++;

	/* current block relative to lowest unreceived block */
	offset_v_q = (rh->bsn - tbf->dir.ul.v_q) & mod_sns;
	/* If out of window (may happen if blocks below V(Q) are received
	 * again. */
	if (offset_v_q >= tbf->ws) {
		LOGP(DRLCMACDATA, LOGL_DEBUG, "- BSN %d out of window "
			"%d..%d (it's normal)\n", rh->bsn, tbf->dir.ul.v_q,
			(tbf->dir.ul.v_q + tbf->ws - 1) & mod_sns);
		return 0;
	}
	/* Write block to buffer and set receive state array. */
	index = rh->bsn & mod_sns_half; /* memory index of block */
	memcpy(tbf->rlc_block[index], data, len); /* Copy block. */
	tbf->rlc_block_len[index] = len;
	tbf->dir.ul.v_n[index] = 'R'; /* Mark received block. */
	LOGP(DRLCMACDATA, LOGL_DEBUG, "- BSN %d storing in window (%d..%d)\n",
		rh->bsn, tbf->dir.ul.v_q,
		(tbf->dir.ul.v_q + tbf->ws - 1) & mod_sns);
	/* Raise V(R) to highest received sequence number not received. */
	offset_v_r = (rh->bsn + 1 - tbf->dir.ul.v_r) & mod_sns;
	if (offset_v_r < (tbf->sns >> 1)) { /* Positive offset, so raise. */
		while (offset_v_r--) {
			if (offset_v_r) /* all except the received block */
				tbf->dir.ul.v_n[tbf->dir.ul.v_r & mod_sns_half]
					= 'N'; /* Mark block as not received */
			tbf->dir.ul.v_r = (tbf->dir.ul.v_r + 1) & mod_sns;
				/* Inc V(R). */
		}
		LOGP(DRLCMACDATA, LOGL_DEBUG, "- Raising V(R) to %d\n",
			tbf->dir.ul.v_r);
	}

	/* Raise V(Q) if possible, and retrieve LLC frames from blocks.
	 * This is looped until there is a gap (non received block) or
	 * the window is empty.*/
	while (tbf->dir.ul.v_q != tbf->dir.ul.v_r && tbf->dir.ul.v_n[
			(index = tbf->dir.ul.v_q & mod_sns_half)] == 'R') {
		LOGP(DRLCMACDATA, LOGL_DEBUG, "- Taking block %d out, raising "
			"V(Q) to %d\n", tbf->dir.ul.v_q,
			(tbf->dir.ul.v_q + 1) & mod_sns);
		/* get LLC data from block */
		gprs_rlcmac_assemble_llc(tbf, tbf->rlc_block[index],
			tbf->rlc_block_len[index]);
		/* raise V(Q), because block already received */
		tbf->dir.ul.v_q = (tbf->dir.ul.v_q + 1) & mod_sns;
	}

	/* Check CV of last frame in buffer */
	if (tbf->state == GPRS_RLCMAC_FLOW /* still in flow state */
	 && tbf->dir.ul.v_q == tbf->dir.ul.v_r) { /* if complete */
		struct rlc_dl_header *last_rh = (struct rlc_dl_header *)
			tbf->rlc_block[(tbf->dir.ul.v_r - 1) & mod_sns_half];
		LOGP(DRLCMACDATA, LOGL_DEBUG, "- No gaps in received block, "
			"last block: BSN=%d CV=%d\n", last_rh->bsn,
			last_rh->cv);
		if (last_rh->cv == 0) {
			LOGP(DRLCMACDATA, LOGL_DEBUG, "- Finished with UL "
				"TBF\n");
			tbf->state = GPRS_RLCMAC_FINISHED;
			/* Start special timer instead of N3103 counter.
			 * If this expires, resend. */
			tbf_timer_start(tbf, 3103, 1);
			tbf->dir.ul.n3103 = 0;
		}
	}

	/* If TLLI is included or if we received half of the window, we send
	 * an ack/nack */
	if (rh->ti || tbf->state == GPRS_RLCMAC_FINISHED
	 || (tbf->dir.ul.rx_counter % ACK_AFTER_FRAMES) == 0) {
		if (rh->ti) {
			LOGP(DRLCMACDATA, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because TLLI is included.\n");
		}
		if (tbf->state == GPRS_RLCMAC_FINISHED) {
			LOGP(DRLCMACDATA, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because last block has CV==0.\n");
		}
		if ((tbf->dir.ul.rx_counter % ACK_AFTER_FRAMES) == 0) {
			LOGP(DRLCMACDATA, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because %d frames received.\n",
				ACK_AFTER_FRAMES);
		}
		/* trigger sending at next RTS */
		tbf->dir.ul.substate = GPRS_RLCMAC_UL_SEND_ACK;
	}

	return 0;
}

