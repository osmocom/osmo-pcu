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
#include <pcu_l1_if.h>
#include <bts.h>
#include <encoding.h>
#include <tbf.h>
#include <rlc.h>

static struct gprs_rlcmac_cs gprs_rlcmac_cs[] = {
/*	frame length	data block	max payload */
	{ 0,		0,		0  },
	{ 23,		23,		20 }, /* CS-1 */
	{ 34,		33,		30 }, /* CS-2 */
	{ 40,		39,		36 }, /* CS-3 */
	{ 54,		53,		50 }, /* CS-4 */
};


extern void *tall_pcu_ctx;

/* After sending these frames, we poll for ack/nack. */
#define POLL_ACK_AFTER_FRAMES 20

/* If acknowledgement to uplink/downlink assignmentshould be polled */
#define POLLING_ASSIGNMENT_UL 1


/*
 * UL data block flow
 */

struct msgb *gprs_rlcmac_send_packet_uplink_assignment(
	struct gprs_rlcmac_tbf *tbf, uint32_t fn)
{
	struct msgb *msg;
	struct gprs_rlcmac_tbf *new_tbf;
	gprs_rlcmac_bts *bts = tbf->bts->bts_data();

#if POLLING_ASSIGNMENT_UL == 1
	if (tbf->poll_state != GPRS_RLCMAC_POLL_NONE) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
			"sheduled for TBF=%d, so we must wait for uplink "
			"assignment...\n", tbf->tfi);
			return NULL;
	}
	if (tbf->bts->sba()->find(tbf->trx_no, tbf->control_ts, (fn + 13) % 2715648)) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already scheduled for "
			"single block allocation...\n");
			return NULL;
	}
#endif

	/* on down TBF we get the uplink TBF to be assigned. */
	if (tbf->direction == GPRS_RLCMAC_DL_TBF)
		new_tbf = tbf->bts->tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF);
	else
		new_tbf = tbf;
		
	if (!new_tbf) {
		LOGP(DRLCMACUL, LOGL_ERROR, "We have a schedule for uplink "
			"assignment at downlink TBF=%d, but there is no uplink "
			"TBF\n", tbf->tfi);
		tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
		return NULL;
	}

	msg = msgb_alloc(23, "rlcmac_ul_ass");
	if (!msg)
		return NULL;
	LOGP(DRLCMAC, LOGL_INFO, "TBF: START TFI: %u TLLI: 0x%08x Packet Uplink Assignment (PACCH)\n", new_tbf->tfi, new_tbf->tlli);
	bitvec *ass_vec = bitvec_alloc(23);
	if (!ass_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ass_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	Encoding::write_packet_uplink_assignment(bts, ass_vec, tbf->tfi,
		(tbf->direction == GPRS_RLCMAC_DL_TBF), tbf->tlli,
		tbf->tlli_valid, new_tbf, POLLING_ASSIGNMENT_UL, bts->alpha,
		bts->gamma, -1);
	bitvec_pack(ass_vec, msgb_put(msg, 23));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Assignment +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(ass_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Uplink Assignment -------------------------\n");
	bitvec_free(ass_vec);
	talloc_free(mac_control_block);

#if POLLING_ASSIGNMENT_UL == 1
	tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
	tbf->poll_fn = (fn + 13) % 2715648;
	tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_WAIT_ACK;
#else
	tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
	tbf_new_state(new_tbf, GPRS_RLCMAC_FLOW);
	tbf_assign_control_ts(new_tbf);
#endif
	debug_diagram(bts->bts, tbf->diag, "send UL-ASS");

	return msg;
}

/* send DL data block
 *
 * The messages are fragmented and forwarded as data blocks.
 */
struct msgb *gprs_rlcmac_send_data_block_acknowledged(
	struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts)
{
	struct rlc_dl_header *rh;
	struct rlc_li_field *li;
	uint8_t block_length; /* total length of block, including spare bits */
	uint8_t block_data; /* usable data of block, w/o spare bits, inc. MAC */
	struct msgb *msg, *dl_msg;
	uint8_t bsn;
	uint16_t mod_sns = tbf->sns - 1;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	uint16_t index;
	uint8_t *delimiter, *data, *e_pointer;
	uint8_t len;
	uint16_t space, chunk;
	int first_fin_ack = 0;
	gprs_rlcmac_bts *bts = tbf->bts->bts_data();

	LOGP(DRLCMACDL, LOGL_DEBUG, "DL DATA TBF=%d downlink (V(A)==%d .. "
		"V(S)==%d)\n", tbf->tfi, tbf->dir.dl.v_a, tbf->dir.dl.v_s);

do_resend:
	/* check if there is a block with negative acknowledgement */
	for (bsn = tbf->dir.dl.v_a; bsn != tbf->dir.dl.v_s; 
	     bsn = (bsn + 1) & mod_sns) {
		index = (bsn & mod_sns_half);
		if (tbf->dir.dl.v_b[index] == 'N'
		 || tbf->dir.dl.v_b[index] == 'X') {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Resending BSN %d\n",
				bsn);
			/* re-send block with negative aknowlegement */
			tbf->dir.dl.v_b[index] = 'U'; /* unacked */
			goto tx_block;
		}
	}

	/* if the window has stalled, or transfer is complete,
	 * send an unacknowledged block */
	if (tbf->state_is(GPRS_RLCMAC_FINISHED)
	 || ((tbf->dir.dl.v_s - tbf->dir.dl.v_a) & mod_sns) == tbf->ws) {
	 	int resend = 0;

		if (tbf->state_is(GPRS_RLCMAC_FINISHED))
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
				"because all blocks have been transmitted.\n",
					tbf->dir.dl.v_a);
		else
			LOGP(DRLCMACDL, LOGL_NOTICE, "- Restarting at BSN %d, "
				"because all window is stalled.\n",
					tbf->dir.dl.v_a);
		/* If V(S) == V(A) and finished state, we would have received
		 * acknowledgement of all transmitted block. In this case we
		 * would have transmitted the final block, and received ack
		 * from MS. But in this case we did not receive the final ack
		 * indication from MS. This should never happen if MS works
		 * correctly. */
		if (tbf->dir.dl.v_s == tbf->dir.dl.v_a) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- MS acked all blocks, "
				"so we re-transmit final block!\n");
			/* we just send final block again */
			index = ((tbf->dir.dl.v_s - 1) & mod_sns_half);
			goto tx_block;
		}
		
		/* cycle through all unacked blocks */
		for (bsn = tbf->dir.dl.v_a; bsn != tbf->dir.dl.v_s;
		     bsn = (bsn + 1) & mod_sns) {
			index = (bsn & mod_sns_half);
			if (tbf->dir.dl.v_b[index] == 'U') {
				/* mark to be re-send */
				tbf->dir.dl.v_b[index] = 'X';
				resend++;
			}
		}
		/* At this point there should be at leasst one unacked block
		 * to be resent. If not, this is an software error. */
		if (resend == 0) {
			LOGP(DRLCMACDL, LOGL_ERROR, "Software error: "
				"There are no unacknowledged blocks, but V(A) "
				" != V(S). PLEASE FIX!\n");
			/* we just send final block again */
			index = ((tbf->dir.dl.v_s - 1) & mod_sns_half);
			goto tx_block;
		}
		goto do_resend;
	}

	LOGP(DRLCMACDL, LOGL_DEBUG, "- Sending new block at BSN %d\n",
		tbf->dir.dl.v_s);

	/* now we still have untransmitted LLC data, so we fill mac block */
	index = tbf->dir.dl.v_s & mod_sns_half;
	data = tbf->rlc_block[index];
#warning "Selection of the CS doesn't belong here"
	if (tbf->cs == 0) {
		tbf->cs = bts->initial_cs_dl;
		if (tbf->cs < 1 || tbf->cs > 4)
			tbf->cs = 1;
	}
	block_length = gprs_rlcmac_cs[tbf->cs].block_length;
	block_data = gprs_rlcmac_cs[tbf->cs].block_data;
	memset(data, 0x2b, block_data); /* spare bits will be left 0 */
	rh = (struct rlc_dl_header *)data;
	rh->pt = 0; /* Data Block */
	rh->rrbp = rh->s_p = 0; /* Polling, set later, if required */
	rh->usf = 7; /* will be set at scheduler */
	rh->pr = 0; /* FIXME: power reduction */
	rh->tfi = tbf->tfi; /* TFI */
	rh->fbi = 0; /* Final Block Indicator, set late, if true */
	rh->bsn = tbf->dir.dl.v_s; /* Block Sequence Number */
	rh->e = 0; /* Extension bit, maybe set later */
	e_pointer = data + 2; /* points to E of current chunk */
	data += 3;
	delimiter = data; /* where next length header would be stored */
	space = block_data - 3;
	while (1) {
		chunk = tbf->llc_length - tbf->llc_index;
		/* if chunk will exceed block limit */
		if (chunk > space) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
				"larger than space (%d) left in block: copy "
				"only remaining space, and we are done\n",
				chunk, space);
			/* block is filled, so there is no extension */
			*e_pointer |= 0x01;
			/* fill only space */
			memcpy(data, tbf->llc_frame + tbf->llc_index, space);
			/* incement index */
			tbf->llc_index += space;
			/* return data block as message */
			break;
		}
		/* if FINAL chunk would fit precisely in space left */
		if (chunk == space && llist_empty(&tbf->llc_queue)) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
				"would exactly fit into space (%d): because "
				"this is a final block, we don't add length "
				"header, and we are done\n", chunk, space);
			LOGP(DRLCMACDL, LOGL_INFO, "Complete DL frame for "
				"TBF=%d that fits precisely in last block: "
				"len=%d\n", tbf->tfi, tbf->llc_length);
			gprs_rlcmac_dl_bw(tbf, tbf->llc_length);
			/* block is filled, so there is no extension */
			*e_pointer |= 0x01;
			/* fill space */
			memcpy(data, tbf->llc_frame + tbf->llc_index, space);
			/* reset LLC frame */
			tbf->llc_index = tbf->llc_length = 0;
			/* final block */
			rh->fbi = 1; /* we indicate final block */
			tbf_new_state(tbf, GPRS_RLCMAC_FINISHED);
			/* return data block as message */
			break;
		}
		/* if chunk would fit exactly in space left */
		if (chunk == space) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
				"would exactly fit into space (%d): add length "
				"header with LI=0, to make frame extend to "
				"next block, and we are done\n", chunk, space);
			/* make space for delimiter */
			if (delimiter != data)
				memcpy(delimiter + 1, delimiter,
					data - delimiter);
			data++;
			space--;
			/* add LI with 0 length */
			li = (struct rlc_li_field *)delimiter;
			li->e = 1; /* not more extension */
			li->m = 0; /* shall be set to 0, in case of li = 0 */
			li->li = 0; /* chunk fills the complete space */
			// no need to set e_pointer nor increase delimiter
			/* fill only space, which is 1 octet less than chunk */
			memcpy(data, tbf->llc_frame + tbf->llc_index, space);
			/* incement index */
			tbf->llc_index += space;
			/* return data block as message */
			break;
		}
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d is less "
			"than remaining space (%d): add length header to "
			"to delimit LLC frame\n", chunk, space);
		/* the LLC frame chunk ends in this block */
		/* make space for delimiter */
		if (delimiter != data)
			memcpy(delimiter + 1, delimiter, data - delimiter);
		data++;
		space--;
		/* add LI to delimit frame */
		li = (struct rlc_li_field *)delimiter;
		li->e = 0; /* Extension bit, maybe set later */
		li->m = 0; /* will be set later, if there is more LLC data */
		li->li = chunk; /* length of chunk */
		e_pointer = delimiter; /* points to E of current delimiter */
		delimiter++;
		/* copy (rest of) LLC frame to space */
		memcpy(data, tbf->llc_frame + tbf->llc_index, chunk);
		data += chunk;
		space -= chunk;
		LOGP(DRLCMACDL, LOGL_INFO, "Complete DL frame for TBF=%d: "
			"len=%d\n", tbf->tfi, tbf->llc_length);
		gprs_rlcmac_dl_bw(tbf, tbf->llc_length);
		/* reset LLC frame */
		tbf->llc_index = tbf->llc_length = 0;
		/* dequeue next LLC frame, if any */
		msg = tbf->llc_dequeue(gprs_bssgp_pcu_current_bctx());
		if (msg) {
			LOGP(DRLCMACDL, LOGL_INFO, "- Dequeue next LLC for "
				"TBF=%d (len=%d)\n", tbf->tfi, msg->len);
			tbf->update_llc_frame(msg);
			msgb_free(msg);
		}
		/* if we have more data and we have space left */
		if (space > 0 && tbf->llc_length) {
			li->m = 1; /* we indicate more frames to follow */
			continue;
		}
		/* if we don't have more LLC frames */
		if (!tbf->llc_length) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Final block, so we "
				"done.\n");
			li->e = 1; /* we cannot extend */
			rh->fbi = 1; /* we indicate final block */
			first_fin_ack = 1;
				/* + 1 indicates: first final ack */
			tbf_new_state(tbf, GPRS_RLCMAC_FINISHED);
			break;
		}
		/* we have no space left */
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- No space left, so we are "
			"done.\n");
		li->e = 1; /* we cannot extend */
		break;
	}
	LOGP(DRLCMACDL, LOGL_DEBUG, "data block: %s\n",
		osmo_hexdump(tbf->rlc_block[index], block_length));
	tbf->rlc_block_len[index] = block_length;
	/* raise send state and set ack state array */
	tbf->dir.dl.v_b[index] = 'U'; /* unacked */
	tbf->dir.dl.v_s = (tbf->dir.dl.v_s + 1) & mod_sns; /* inc send state */

tx_block:
	/* from this point on, new block is sent or old block is resent */

	/* get data and header from current block */
	data = tbf->rlc_block[index];
	len = tbf->rlc_block_len[index];
	rh = (struct rlc_dl_header *)data;

	/* Clear Polling, if still set in history buffer */
	rh->s_p = 0;
		
	/* poll after POLL_ACK_AFTER_FRAMES frames, or when final block is tx.
	 */
	if (tbf->dir.dl.tx_counter >= POLL_ACK_AFTER_FRAMES || first_fin_ack) {
		if (first_fin_ack) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because first final block sent.\n");
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because %d blocks sent.\n",
				POLL_ACK_AFTER_FRAMES);
		}
		/* scheduling not possible, because: */
		if (tbf->poll_state != GPRS_RLCMAC_POLL_NONE)
			LOGP(DRLCMAC, LOGL_DEBUG, "Polling is already "
				"sheduled for TBF=%d, so we must wait for "
				"requesting downlink ack\n", tbf->tfi);
		else if (tbf->control_ts != ts)
			LOGP(DRLCMAC, LOGL_DEBUG, "Polling cannot be "
				"sheduled in this TS %d, waiting for "
				"TS %d\n", ts, tbf->control_ts);
		else if (tbf->bts->sba()->find(tbf->trx_no, ts, (fn + 13) % 2715648))
			LOGP(DRLCMAC, LOGL_DEBUG, "Polling cannot be "
				"sheduled, because single block alllocation "
				"already exists\n");
		else  {
			LOGP(DRLCMAC, LOGL_DEBUG, "Polling sheduled in this "
				"TS %d\n", ts);
			tbf->dir.dl.tx_counter = 0;
			/* start timer whenever we send the final block */
			if (rh->fbi == 1)
				tbf_timer_start(tbf, 3191, bts->t3191, 0);

			/* schedule polling */
			tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
			tbf->poll_fn = (fn + 13) % 2715648;

#ifdef DEBUG_DIAGRAM
			debug_diagram(bts->bts, tbf->diag, "poll DL-ACK");
			if (first_fin_ack)
				debug_diagram(bts->bts, tbf->diag, "(is first FINAL)");
			if (rh->fbi)
				debug_diagram(bts->bts, tbf->diag, "(FBI is set)");
#endif

			/* set polling in header */
			rh->rrbp = 0; /* N+13 */
			rh->s_p = 1; /* Polling */

			/* Increment TX-counter */
			tbf->dir.dl.tx_counter++;
		}
	} else {
		/* Increment TX-counter */
		tbf->dir.dl.tx_counter++;
	}

	/* return data block as message */
	dl_msg = msgb_alloc(len, "rlcmac_dl_data");
	if (!dl_msg)
		return NULL;
	memcpy(msgb_put(dl_msg, len), data, len);

	return dl_msg;
}

int gprs_rlcmac_downlink_ack(
	struct gprs_rlcmac_tbf *tbf, uint8_t final,
	uint8_t ssn, uint8_t *rbb)
{
	char show_rbb[65], show_v_b[RLC_MAX_SNS + 1];
	uint16_t mod_sns = tbf->sns - 1;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	int i; /* must be signed */
	int16_t dist; /* must be signed */
	uint8_t bit;
	uint16_t bsn;
	struct msgb *msg;
	uint16_t lost = 0, received = 0;

	LOGP(DRLCMACDL, LOGL_DEBUG, "TBF=%d downlink acknowledge\n",
		tbf->tfi);

	if (!final) {
		/* show received array in debug (bit 64..1) */
		for (i = 63; i >= 0; i--) {
			bit = (rbb[i >> 3]  >>  (7 - (i&7)))   & 1;
			show_rbb[i] = (bit) ? '1' : 'o';
		}
		show_rbb[64] = '\0';
		LOGP(DRLCMACDL, LOGL_DEBUG, "- ack:  (BSN=%d)\"%s\""
			"(BSN=%d)  1=ACK o=NACK\n", (ssn - 64) & mod_sns,
			show_rbb, (ssn - 1) & mod_sns);

		/* apply received array to receive state (SSN-64..SSN-1) */
		/* calculate distance of ssn from V(S) */
		dist = (tbf->dir.dl.v_s - ssn) & mod_sns;
		/* check if distance is less than distance V(A)..V(S) */
		if (dist >= ((tbf->dir.dl.v_s - tbf->dir.dl.v_a) & mod_sns)) {
			/* this might happpen, if the downlink assignment
			 * was not received by ms and the ack refers
			 * to previous TBF
			 * FIXME: we should implement polling for
			 * control ack!*/
			LOGP(DRLCMACDL, LOGL_NOTICE, "- ack range is out of "
				"V(A)..V(S) range (DL TBF=%d) Free TFB!\n",
				tbf->tfi);
				return 1; /* indicate to free TBF */
		}
		/* SSN - 1 is in range V(A)..V(S)-1 */
		for (i = 63, bsn = (ssn - 1) & mod_sns;
		     i >= 0 && bsn != ((tbf->dir.dl.v_a - 1) & mod_sns);
		     i--, bsn = (bsn - 1) & mod_sns) {
			bit = (rbb[i >> 3]  >>  (7 - (i&7)))   & 1;
			if (bit) {
				LOGP(DRLCMACDL, LOGL_DEBUG, "- got "
					"ack for BSN=%d\n", bsn);
				if (tbf->dir.dl.v_b[bsn & mod_sns_half]
								!= 'A')
					received++;
				tbf->dir.dl.v_b[bsn & mod_sns_half] = 'A';
			} else {
				LOGP(DRLCMACDL, LOGL_DEBUG, "- got "
					"NACK for BSN=%d\n", bsn);
				tbf->dir.dl.v_b[bsn & mod_sns_half] = 'N';
				lost++;
			}
		}
		/* report lost and received packets */
		gprs_rlcmac_received_lost(tbf, received, lost);

		/* raise V(A), if possible */
		for (i = 0, bsn = tbf->dir.dl.v_a; bsn != tbf->dir.dl.v_s;
		     i++, bsn = (bsn + 1) & mod_sns) {
			if (tbf->dir.dl.v_b[bsn & mod_sns_half] == 'A') {
				tbf->dir.dl.v_b[bsn & mod_sns_half] = 'I';
					/* mark invalid */
				tbf->dir.dl.v_a = (tbf->dir.dl.v_a + 1)
								& mod_sns;
			} else
				break;
		}

		/* show receive state array in debug (V(A)..V(S)-1) */
		for (i = 0, bsn = tbf->dir.dl.v_a; bsn != tbf->dir.dl.v_s;
		     i++, bsn = (bsn + 1) & mod_sns) {
			show_v_b[i] = tbf->dir.dl.v_b[bsn & mod_sns_half];
			if (show_v_b[i] == 0)
				show_v_b[i] = ' ';
		}
		show_v_b[i] = '\0';
		LOGP(DRLCMACDL, LOGL_DEBUG, "- V(B): (V(A)=%d)\"%s\""
			"(V(S)-1=%d)  A=Acked N=Nacked U=Unacked "
			"X=Resend-Unacked\n", tbf->dir.dl.v_a, show_v_b,
			(tbf->dir.dl.v_s - 1) & mod_sns);

		if (tbf->state_is(GPRS_RLCMAC_FINISHED)
		 && tbf->dir.dl.v_s == tbf->dir.dl.v_a) {
			LOGP(DRLCMACDL, LOGL_NOTICE, "Received acknowledge of "
				"all blocks, but without final ack "
				"inidcation (don't worry)\n");
		}
		return 0;
	}

	LOGP(DRLCMACDL, LOGL_DEBUG, "- Final ACK received.\n");
	debug_diagram(tbf->bts, tbf->diag, "got Final ACK");
	/* range V(A)..V(S)-1 */
	for (bsn = tbf->dir.dl.v_a; bsn != tbf->dir.dl.v_s;
	     bsn = (bsn + 1) & mod_sns) {
		if (tbf->dir.dl.v_b[bsn & mod_sns_half] != 'A')
			received++;
	}

	/* report all outstanding packets as received */
	gprs_rlcmac_received_lost(tbf, received, lost);

	/* check for LLC PDU in the LLC Queue */
	msg = tbf->llc_dequeue(gprs_bssgp_pcu_current_bctx());
	if (!msg) {
		/* no message, start T3193, change state to RELEASE */
		LOGP(DRLCMACDL, LOGL_DEBUG, "- No new message, so we "
			"release.\n");
		/* start T3193 */
		debug_diagram(bts->bts, tbf->diag, "start T3193");
		tbf_timer_start(tbf, 3193,
			tbf->bts->bts_data()->t3193_msec / 1000,
			(tbf->bts->bts_data()->t3193_msec % 1000) * 1000);
		tbf_new_state(tbf, GPRS_RLCMAC_WAIT_RELEASE);

		return 0;
	}
	#warning "Copy and paste on the sender path"
	tbf->update_llc_frame(msg);
	msgb_free(msg);

	/* we have a message, so we trigger downlink assignment, and there
	 * set the state to ASSIGN. also we set old_downlink, because we
	 * re-use this tbf. */
	LOGP(DRLCMAC, LOGL_DEBUG, "Trigger dowlink assignment on PACCH, "
		"because another LLC PDU has arrived in between\n");
	memset(&tbf->dir.dl, 0, sizeof(tbf->dir.dl)); /* reset RLC states */
	tbf->state_flags &= GPRS_RLCMAC_FLAG_TO_MASK; /* keep TO flags */
	tbf->state_flags &= ~(1 << GPRS_RLCMAC_FLAG_CCCH);
	tbf->update();
	tbf->bts->trigger_dl_ass(tbf, tbf, NULL);
	return 0;
}


