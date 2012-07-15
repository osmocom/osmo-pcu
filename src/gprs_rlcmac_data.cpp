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

/* After receiving these framess, we send ack/nack. */
#define ACK_AFTER_FRAMES 20

/* If acknowledgement to uplink/downlin assignmentshould be polled */
#define POLLING_ASSIGNMENT 0

extern "C" {
/* TS 04.60  10.2.2 */
struct rlc_ul_header {
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

struct rlc_dl_header {
	uint8_t	usf:3,
		 s_p:1,
		 rrbp:2,
		 pt:2;
	uint8_t	fbi:1,
		 tfi:5,
		 pr:2;
	uint8_t	e:1,
		 bsn:7;
} __attribute__ ((packed));

struct rlc_li_field {
	uint8_t	e:1,
		 m:1,
		 li:6;
} __attribute__ ((packed));
}

int gprs_rlcmac_poll_timeout(struct gprs_rlcmac_tbf *tbf)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "Poll timeout for %s TBF=%d\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi);

	tbf->poll_state = GPRS_RLCMAC_POLL_NONE;

	if (tbf->ul_ack_state == GPRS_RLCMAC_UL_ACK_WAIT_ACK) {
		LOGP(DRLCMAC, LOGL_DEBUG, "- Timeout for polling PACKET "
			"CONTROL ACK for PACKET UPLINK ACK\n");
		tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_NONE;
		if (tbf->state == GPRS_RLCMAC_FINISHED) {
			struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

			tbf->dir.ul.n3103++;
			if (tbf->dir.ul.n3103 == bts->n3103) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- N3103 exceeded\n");
				tbf_new_state(tbf, GPRS_RLCMAC_RELEASING);
				tbf_timer_start(tbf, 3169, bts->t3169, 0);
				return 0;
			}
			/* reschedule UL ack */
			tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_SEND_ACK;
		}
	} else
	if (tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
		LOGP(DRLCMAC, LOGL_DEBUG, "- Timeout for polling PACKET "
			"CONTROL ACK for PACKET UPLINK ASSIGNMENT.\n");
		tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
	} else
	if (tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_WAIT_ACK) {
		LOGP(DRLCMAC, LOGL_DEBUG, "- Timeout for polling PACKET "
			"CONTROL ACK for PACKET DOWNLINK ASSIGNMENT.\n");
		tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		/* in case out downlink assigment failed: */
		if (tbf->state == GPRS_RLCMAC_ASSIGN) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Assignment failed\n");
			tbf_free(tbf);
		}
	} else
	if (tbf->direction == GPRS_RLCMAC_DL_TBF)
	{
		struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

		LOGP(DRLCMAC, LOGL_DEBUG, "- Timeout for polling PACKET "
			" DOWNLINK ACK.\n");
		tbf->dir.dl.n3105++;
		if (tbf->dir.dl.n3105 == bts->n3105) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- N3105 exceeded\n");
			tbf_new_state(tbf, GPRS_RLCMAC_RELEASING);
			tbf_timer_start(tbf, 3195, bts->t3195, 0);
			return 0;
		}
	}

	return 0;
}

/* Received Uplink RLC control block. */
int gprs_rlcmac_rcv_control_block(bitvec *rlc_block, uint8_t trx, uint8_t ts,
	uint32_t fn)
{
	int8_t tfi = 0; /* must be signed */
	uint32_t tlli = 0;
	struct gprs_rlcmac_tbf *tbf;

	RlcMacUplink_t * ul_control_block = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- RX : Uplink Control Block -------------------------\n");
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		tlli = ul_control_block->u.Packet_Control_Acknowledgement.TLLI;
		tbf = tbf_by_poll_fn(fn, trx, ts);
		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
				"unknown FN=%u TLL=0x%08x (TRX %d TS %d)\n",
				fn, tlli, trx, ts);
			break;
		}
		tfi = tbf->tfi;
		if (tlli != tbf->tlli) {
			LOGP(DRLCMAC, LOGL_INFO, "Phone changed TLLI to "
				"0x%08x\n", tlli);
			tbf->tlli = tlli;
		}
		LOGP(DRLCMAC, LOGL_DEBUG, "RX: [PCU <- BTS] TFI: %u TLLI: 0x%08x Packet Control Ack\n", tbf->tfi, tbf->tlli);
		tbf->poll_state = GPRS_RLCMAC_POLL_NONE;

		/* check if this control ack belongs to packet uplink ack */
		if (tbf->ul_ack_state == GPRS_RLCMAC_UL_ACK_WAIT_ACK) {
			LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [UPLINK] END TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
			tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_NONE;
			tbf_free(tbf);
			break;
		}
		if (tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_WAIT_ACK) {
			LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [UPLINK] DOWNLINK ASSIGNED TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
			tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
			break;
		}
		if (tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
			LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [DOWNLINK] UPLINK ASSIGNED TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
			tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
			break;
		}
		LOGP(DRLCMAC, LOGL_ERROR, "Error: received PACET CONTROL ACK "
			"at no request\n");
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		tfi = ul_control_block->u.Packet_Downlink_Ack_Nack.DOWNLINK_TFI;
		tbf = tbf_by_poll_fn(fn, trx, ts);
		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
				"unknown FN=%u TBF=%d (TRX %d TS %d)\n",
				fn, tfi, trx, ts);
			break;
		}
		/* reset N3105 */
		tbf->dir.dl.n3105 = 0;
		/* stop timer T3191 */
		tbf_timer_stop(tbf);
		tlli = tbf->tlli;
		LOGP(DRLCMAC, LOGL_DEBUG, "RX: [PCU <- BTS] TFI: %u TLLI: 0x%08x Packet Downlink Ack/Nack\n", tbf->tfi, tbf->tlli);
		tbf->poll_state = GPRS_RLCMAC_POLL_NONE;

		gprs_rlcmac_downlink_ack(tbf,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.FINAL_ACK_INDICATION,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP);
		/* check for channel request */
		if (ul_control_block->u.Packet_Downlink_Ack_Nack.Exist_Channel_Request_Description) {
			uint8_t trx, ts;
			struct gprs_rlcmac_tbf *ul_tbf;
			struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

			LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF in ack "
				"message, so we provide one:\n");
uplink_request:
			/* create new TBF, use sme TRX as DL TBF */
			tfi = tfi_alloc(GPRS_RLCMAC_UL_TBF, &trx, &ts, tbf->trx, tbf->first_ts);
			if (tfi < 0) {
				LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
				/* FIXME: send reject */
				break;
			}
			/* use multislot class of downlink TBF */
			ul_tbf = tbf_alloc(tbf, GPRS_RLCMAC_UL_TBF, tfi, trx,
				ts, tbf->ms_class, 0);
			if (!ul_tbf) {
				LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
				/* FIXME: send reject */
				break;
			}
			ul_tbf->tlli = tbf->tlli;
			ul_tbf->tlli_valid = 1; /* no content resolution */
			ul_tbf->ta = tbf->ta; /* use current TA */
			tbf_new_state(ul_tbf, GPRS_RLCMAC_FLOW);
			tbf_timer_start(ul_tbf, 3169, bts->t3169, 0);
			/* schedule uplink assignment */
			tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_SEND_ASS;
		}
		break;
	case MT_PACKET_RESOURCE_REQUEST:
		if (ul_control_block->u.Packet_Resource_Request.ID.UnionType) {
			tlli = ul_control_block->u.Packet_Resource_Request.ID.u.TLLI;
			tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
			if (!tbf) {
				LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown uplink TLLI=0x%08x\n", tlli);
				break;
			}
			tfi = tbf->tfi;
		} else {
			if (ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.UnionType) {
				tfi = ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.u.DOWNLINK_TFI;
				tbf = tbf_by_tfi(tfi, trx, ts, GPRS_RLCMAC_DL_TBF);
				if (!tbf) {
					LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown downlink TBF=%d\n", tlli);
					break;
				}
			} else {
				tfi = ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.u.UPLINK_TFI;
				tbf = tbf_by_tfi(tfi, trx, ts, GPRS_RLCMAC_UL_TBF);
				if (!tbf) {
					LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown uplink TBF=%d\n", tlli);
					break;
				}
			}
			tlli = tbf->tlli;
		}
		LOGP(DRLCMAC, LOGL_INFO, "RX: [PCU <- BTS] %s TFI: %u TLLI: 0x%08x Packet ressource request\n", (tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi, tbf->tlli);
#warning FIXME
puts("FIXME: UL request during UL request");	exit(0);


		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] unknown control block received\n");
	}
	free(ul_control_block);
	return 1;
}

#ifdef DEBUG_DL_ASS_IDLE
	char debug_imsi[16];
#endif

void tbf_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	LOGP(DRLCMAC, LOGL_DEBUG, "%s TBF=%d timer %u expired.\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi,
		tbf->T);

	tbf->num_T_exp++;

	switch (tbf->T) {
#ifdef DEBUG_DL_ASS_IDLE
	case 1234:
		gprs_rlcmac_trigger_downlink_assignment(tbf, 0, debug_imsi);
		break;
#endif
	case 0: /* assignment */
		/* change state to FLOW, so scheduler will start transmission */
		if (tbf->state == GPRS_RLCMAC_ASSIGN) {
			tbf_new_state(tbf, GPRS_RLCMAC_FLOW);
			tbf_assign_control_ts(tbf);
		} else
			LOGP(DRLCMAC, LOGL_ERROR, "Error: TBF is not in assign "
				"state\n");
		break;
	case 3169:
	case 3191:
	case 3195:
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF T%d timeout during "
			"transsmission\n", tbf->T);
		/* fall through */
	case 3193:
		LOGP(DRLCMAC, LOGL_DEBUG, "TBF will be freed due to timeout\n");
		/* free TBF */
		tbf_free(tbf);
		break;
	default:
		LOGP(DRLCMAC, LOGL_ERROR, "Timer expired in unknown mode: %u\n",
			tbf->T);
	}
}

/*
 * UL data block flow
 */

/* get TLLI from received UL data block */
static int tlli_from_ul_data(uint8_t *data, uint8_t len, uint32_t *tlli)
{
	struct rlc_ul_header *rh = (struct rlc_ul_header *)data;
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
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
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
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TLLI out of frame "
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
	struct rlc_ul_header *rh = (struct rlc_ul_header *)data;
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
			LOGP(DRLCMACUL, LOGL_ERROR, "Too many frames in "
				"block\n");
			return -EINVAL;
		}
		frame_offset[frames++] = offset;
		LOGP(DRLCMACUL, LOGL_DEBUG, "-- Frame %d starts at offset "
			"%d\n", frames, offset);
		if (!len)
			break;
		/* M == 0 and E == 0 is not allowed in this version. */
		if (!m && !e) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TBF=%d "
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
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TLLI out of "
				"frame border\n");
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
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA PFI out of "
				"frame border\n");
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
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TBF=%d ignored, "
			"because LI delimits data that exceeds block size.\n",
			tbf->tfi);
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
		LOGP(DRLCMACUL, LOGL_DEBUG, "-- Appending chunk (len=%d) to "
			"frame at %d.\n", chunk, tbf->llc_index);
		if (tbf->llc_index + chunk > LLC_MAX_LEN) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "LLC frame exceeds "
				"maximum size.\n");
			chunk = LLC_MAX_LEN - tbf->llc_index;
		}
		memcpy(tbf->llc_frame + tbf->llc_index, data + frame_offset[i],
			chunk);
		tbf->llc_index += chunk;
		/* not last frame. */
		if (i != frames - 1) {
			/* send frame to SGSN */
			LOGP(DRLCMACUL, LOGL_INFO, "Complete UL frame for "
				"TBF=%d: len=%d\n", tbf->tfi, tbf->llc_index);
			gprs_rlcmac_tx_ul_ud(tbf);
			tbf->llc_index = 0; /* reset frame space */
		/* also check if CV==0, because the frame may fill up the
		 * block precisely, then it is also complete. normally the
		 * frame would be extended into the next block with a 0-length
		 * delimiter added to this block. */
		} else if (rh->cv == 0) {
			/* send frame to SGSN */
			LOGP(DRLCMACUL, LOGL_INFO, "Complete UL frame for "
				"TBF=%d that fits precisely in last block: "
				"len=%d\n", tbf->tfi, tbf->llc_index);
			gprs_rlcmac_tx_ul_ud(tbf);
			tbf->llc_index = 0; /* reset frame space */
		}
	}

	return 0;
}

struct msgb *gprs_rlcmac_send_uplink_ack(struct gprs_rlcmac_tbf *tbf,
	uint32_t fn)
{
	int final = (tbf->state == GPRS_RLCMAC_FINISHED);
	struct msgb *msg;

	if (final && tbf->poll_state != GPRS_RLCMAC_POLL_NONE) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
			"sheduled for TBF=%d, so we must wait for final uplink "
			"ack...\n", tbf->tfi);
			return NULL;
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
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	write_packet_uplink_ack(mac_control_block, tbf, final);
	encode_gsm_rlcmac_downlink(ack_vec, mac_control_block);
	bitvec_pack(ack_vec, msgb_put(msg, 23));
	bitvec_free(ack_vec);
	free(mac_control_block);

	if (final) {
		tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
		tbf->poll_fn = (fn + 13) % 2715648;
		/* waiting for final acknowledge */
		tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_WAIT_ACK;
	} else
		tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_NONE;

	return msg;
}

/* receive UL data block
 *
 * The blocks are defragmented and forwarded as LLC frames, if complete.
 */
int gprs_rlcmac_rcv_data_block_acknowledged(uint8_t trx, uint8_t ts,
	uint8_t *data, uint8_t len)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_tbf *tbf;
	struct rlc_ul_header *rh = (struct rlc_ul_header *)data;
	uint16_t mod_sns, mod_sns_half, offset_v_q, offset_v_r, index;
	int rc;

	switch (len) {
		case 54:
			/* omitting spare bits */
			len = 53;
			break;
		case 40:
			/* omitting spare bits */
			len = 39;
			break;
		case 34:
			/* omitting spare bits */
			len = 33;
			break;
		case 23:
			break;
	default:
		LOGP(DRLCMACUL, LOGL_ERROR, "Dropping data block with invalid"
			"length: %d)\n", len);
		return -EINVAL;
	}

	/* find TBF inst from given TFI */
	tbf = tbf_by_tfi(rh->tfi, trx, ts, GPRS_RLCMAC_UL_TBF);
	if (!tbf) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA unknown TBF=%d\n",
			rh->tfi);
		return 0;
	}

	LOGP(DRLCMACUL, LOGL_DEBUG, "UL DATA TBF=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rh->tfi, tbf->dir.ul.v_q, tbf->dir.ul.v_r);

	/* get TLLI */
	if (!tbf->tlli_valid) {
		/* no TLLI yet */
		if (!rh->ti) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TBF=%d without "
				"TLLI, but no TLLI received yet\n", rh->tfi);
			return 0;
		}
		rc = tlli_from_ul_data(data, len, &tbf->tlli);
		if (rc) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "Failed to decode TLLI "
				"of UL DATA TBF=%d.\n", rh->tfi);
			return 0;
		}
		tbf->tlli_valid = 1;
		LOGP(DRLCMACUL, LOGL_INFO, "Decoded premier TLLI=0x%08x of "
			"UL DATA TBF=%d.\n", tbf->tlli, rh->tfi);
	/* already have TLLI, but we stille get another one */
	} else if (rh->ti) {
		uint32_t tlli;
		rc = tlli_from_ul_data(data, len, &tlli);
		if (rc) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "Failed to decode TLLI "
				"of UL DATA TBF=%d.\n", rh->tfi);
			return 0;
		}
		if (tlli != tbf->tlli) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "TLLI mismatch on UL "
				"DATA TBF=%d. (Ignoring due to contention "
				"resolution)\n", rh->tfi);
			return 0;
		}
	}

	mod_sns = tbf->sns - 1;
	mod_sns_half = (tbf->sns >> 1) - 1;

	/* restart T3169 */
	tbf_timer_start(tbf, 3169, bts->t3169, 0);

	/* Increment RX-counter */
	tbf->dir.ul.rx_counter++;

	/* current block relative to lowest unreceived block */
	offset_v_q = (rh->bsn - tbf->dir.ul.v_q) & mod_sns;
	/* If out of window (may happen if blocks below V(Q) are received
	 * again. */
	if (offset_v_q >= tbf->ws) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "- BSN %d out of window "
			"%d..%d (it's normal)\n", rh->bsn, tbf->dir.ul.v_q,
			(tbf->dir.ul.v_q + tbf->ws - 1) & mod_sns);
		return 0;
	}
	/* Write block to buffer and set receive state array. */
	index = rh->bsn & mod_sns_half; /* memory index of block */
	memcpy(tbf->rlc_block[index], data, len); /* Copy block. */
	tbf->rlc_block_len[index] = len;
	tbf->dir.ul.v_n[index] = 'R'; /* Mark received block. */
	LOGP(DRLCMACUL, LOGL_DEBUG, "- BSN %d storing in window (%d..%d)\n",
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
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Raising V(R) to %d\n",
			tbf->dir.ul.v_r);
	}

	/* Raise V(Q) if possible, and retrieve LLC frames from blocks.
	 * This is looped until there is a gap (non received block) or
	 * the window is empty.*/
	while (tbf->dir.ul.v_q != tbf->dir.ul.v_r && tbf->dir.ul.v_n[
			(index = tbf->dir.ul.v_q & mod_sns_half)] == 'R') {
		LOGP(DRLCMACUL, LOGL_DEBUG, "- Taking block %d out, raising "
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
		struct rlc_ul_header *last_rh = (struct rlc_ul_header *)
			tbf->rlc_block[(tbf->dir.ul.v_r - 1) & mod_sns_half];
		LOGP(DRLCMACUL, LOGL_DEBUG, "- No gaps in received block, "
			"last block: BSN=%d CV=%d\n", last_rh->bsn,
			last_rh->cv);
		if (last_rh->cv == 0) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Finished with UL "
				"TBF\n");
			tbf_new_state(tbf, GPRS_RLCMAC_FINISHED);
			/* Reset N3103 counter. */
			tbf->dir.ul.n3103 = 0;
		}
	}

	/* If TLLI is included or if we received half of the window, we send
	 * an ack/nack */
	if (rh->si || rh->ti || tbf->state == GPRS_RLCMAC_FINISHED
	 || (tbf->dir.ul.rx_counter % ACK_AFTER_FRAMES) == 0) {
		if (rh->si) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because MS is stalled.\n");
		}
		if (rh->ti) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because TLLI is included.\n");
		}
		if (tbf->state == GPRS_RLCMAC_FINISHED) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because last block has CV==0.\n");
		}
		if ((tbf->dir.ul.rx_counter % ACK_AFTER_FRAMES) == 0) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because %d frames received.\n",
				ACK_AFTER_FRAMES);
		}
		if (tbf->ul_ack_state == GPRS_RLCMAC_UL_ACK_NONE) {
			/* trigger sending at next RTS */
			tbf->ul_ack_state = GPRS_RLCMAC_UL_ACK_SEND_ACK;
		} else {
			/* already triggered */
			LOGP(DRLCMACUL, LOGL_DEBUG, "-  Sending Ack/Nack is "
				"already triggered, don't schedule!\n");
		}
	}

	return 0;
}

struct msgb *gprs_rlcmac_send_packet_uplink_assignment(
	struct gprs_rlcmac_tbf *tbf, uint32_t fn)
{
	struct msgb *msg;
	struct gprs_rlcmac_tbf *new_tbf;

#if POLLING_ASSIGNMENT == 1
	if (tbf->poll_state != GPRS_RLCMAC_POLL_NONE) {
		LOGP(DRLCMACUL, LOGL_DEBUG, "Polling is already "
			"sheduled for TBF=%d, so we must wait for uplink "
			"assignment...\n", tbf->tfi);
			return NULL;
	}
#endif

	/* on down TBF we get the uplink TBF to be assigned. */
	if (tbf->direction == GPRS_RLCMAC_DL_TBF)
		new_tbf = tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF);
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
	write_packet_uplink_assignment(ass_vec, tbf->tfi,
		(tbf->direction == GPRS_RLCMAC_DL_TBF), 0, 0, new_tbf,
		POLLING_ASSIGNMENT);
	bitvec_pack(ass_vec, msgb_put(msg, 23));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Assignment +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(ass_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Uplink Assignment -------------------------\n");
	bitvec_free(ass_vec);

#if POLLING_ASSIGNMENT == 1
	FIXME process does not work, also the acknowledgement is not checked.
	tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
	tbf->poll_fn = (fn + 13) % 2715648;
	tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_WAIT_ACK;
#else
	tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
#endif

	return msg;
}

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, int16_t qta)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_tbf *tbf;
	uint8_t trx, ts;
	int8_t tfi; /* must be signed */

	LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF on RACH, so we provide "
		"one:\n");
	// Create new TBF
	tfi = tfi_alloc(GPRS_RLCMAC_UL_TBF, &trx, &ts, -1, -1);
	if (tfi < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
		/* FIXME: send reject */
		return -EBUSY;
	}
	/* set class to 0, since we don't know the multislot class yet */
	tbf = tbf_alloc(NULL, GPRS_RLCMAC_UL_TBF, tfi, trx, ts, 0, 1);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
		/* FIXME: send reject */
		return -EBUSY;
	}
	if (qta < 0)
		qta = 0;
	if (qta > 252)
		qta = 252;
	tbf->ta = qta >> 2;
	tbf_new_state(tbf, GPRS_RLCMAC_FLOW);
	tbf_timer_start(tbf, 3169, bts->t3169, 0);
	LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [UPLINK] START TFI: %u\n", tbf->tfi);
	LOGP(DRLCMAC, LOGL_DEBUG, "RX: [PCU <- BTS] TFI: %u RACH qbit-ta=%d ra=%d, Fn=%d (%d,%d,%d)\n", tbf->tfi, qta, ra, Fn, (Fn / (26 * 51)) % 32, Fn % 51, Fn % 26);
	LOGP(DRLCMAC, LOGL_INFO, "TX: START TFI: %u Immediate Assignment Uplink (AGCH)\n", tbf->tfi);
	bitvec *immediate_assignment = bitvec_alloc(22) /* without plen */;
	bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	int plen = write_immediate_assignment(immediate_assignment, 0, ra, Fn, tbf->ta, tbf->arfcn, tbf->first_ts, tbf->tsc, tbf->tfi, tbf->dir.ul.usf[tbf->first_ts], 0, 0, 0);
	pcu_l1if_tx_agch(immediate_assignment, plen);
	bitvec_free(immediate_assignment);

	return 0;
}


/*
 * DL data block flow
 */

/* send DL data block
 *
 * The messages are fragmented and forwarded as data blocks.
 */
struct msgb *gprs_rlcmac_send_data_block_acknowledged(
	struct gprs_rlcmac_tbf *tbf, uint32_t fn, uint8_t ts)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
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
	if (tbf->state == GPRS_RLCMAC_FINISHED
	 || ((tbf->dir.dl.v_s - tbf->dir.dl.v_a) & mod_sns) == tbf->ws) {
	 	int resend = 0;

		if (tbf->state == GPRS_RLCMAC_FINISHED)
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
				"because all blocks have been transmitted.\n",
					tbf->dir.dl.v_a);
		else
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
				"because all window is stalled.\n",
					tbf->dir.dl.v_a);
		/* If V(S) == V(A) and finished state, we would have received
		 * acknowledgement of all transmitted block. In this case we
		 * would have transmitted the final block, and received ack
		 * from MS. But in this case we did not receive the final ack
		 * indication from MS. This should never happen if MS works
		 * correctly. */
		if (tbf->dir.dl.v_s == tbf->dir.dl.v_a) {
			LOGP(DRLCMACDL, LOGL_ERROR, "- MS acked all block, "
				"but we still transmitting!\n");
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
	switch (bts->initial_cs) {
	case 2: /* CS-2 */
		block_length = 34;
		block_data = 33;
		break;
	case 3: /* CS-3 */
		block_length = 40;
		block_data = 39;
		break;
	case 4: /* CS-4 */
		block_length = 54;
		block_data = 53;
		break;
	default: /* CS-1 */
		block_length = 23;
		block_data = 23;
	}
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
		/* reset LLC frame */
		tbf->llc_index = tbf->llc_length = 0;
		/* dequeue next LLC frame, if any */
		msg = msgb_dequeue(&tbf->llc_queue);
		if (msg) {
			LOGP(DRLCMACDL, LOGL_INFO, "- Dequeue next LLC for "
				"TBF=%d (len=%d)\n", tbf->tfi, msg->len);
			memcpy(tbf->llc_frame, msg->data, msg->len);
			tbf->llc_length = msg->len;
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
			tbf->dir.dl.tx_counter = ACK_AFTER_FRAMES + 1;
				/* + 1 indicates: force polling */
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
		
	/* poll after ACK_AFTER_FRAMES frames, or when final block is tx. */
	if (tbf->dir.dl.tx_counter >= ACK_AFTER_FRAMES) {
		if (tbf->dir.dl.tx_counter > ACK_AFTER_FRAMES) {
			/* if rx_counter is ACK_AFTER_FRAMES + 1, this
			 * indicates: poll caused by final ack. */
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because final block sent.\n");
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because %d blocks sent.\n",
				ACK_AFTER_FRAMES);
		}
		tbf->dir.dl.tx_counter = 0;
		/* scheduling not possible, because: */
		if (tbf->poll_state != GPRS_RLCMAC_POLL_NONE)
			LOGP(DRLCMAC, LOGL_DEBUG, "Polling is already "
				"sheduled for TBF=%d, so we must wait for "
				"requesting downlink ack\n", tbf->tfi);
		else if (tbf->control_ts != ts)
			LOGP(DRLCMAC, LOGL_DEBUG, "Polling cannot be "
				"sheduled in this TS %d, waiting for "
				"TS %d\n", ts, tbf->control_ts);
		else  {
			/* start timer whenever we send the final block */
			if (rh->fbi == 1)
				tbf_timer_start(tbf, 3191, bts->t3191, 0);

			/* schedule polling */
			tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
			tbf->poll_fn = (fn + 13) % 2715648;

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

int gprs_rlcmac_downlink_ack(struct gprs_rlcmac_tbf *tbf, uint8_t final,
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
			"(BSN=%d)  1=ACK o=NACK\n", ssn - 64, show_rbb,
			ssn - 1);

		/* apply received array to receive state (SSN-64..SSN-1) */
		/* calculate distance of ssn from V(S) */
		dist = (tbf->dir.dl.v_s - ssn) & mod_sns;
		/* check if distance is less than distance V(A)..V(S) */
		if (dist < ((tbf->dir.dl.v_s - tbf->dir.dl.v_a) & mod_sns)) {
			/* SSN - 1 is in range V(A)..V(S)-1 */
			for (i = 63, bsn = (ssn - 1) & mod_sns;
			     i >= 0 && bsn != ((tbf->dir.dl.v_a - 1) & mod_sns);
			     i--, bsn = (bsn - 1) & mod_sns) {
				bit = (rbb[i >> 3]  >>  (7 - (i&7)))   & 1;
				if (bit) {
					LOGP(DRLCMACDL, LOGL_DEBUG, "- got "
						"ack for BSN=%d\n", bsn);
					tbf->dir.dl.v_b[bsn & mod_sns_half]
						= 'A';
				} else {
					LOGP(DRLCMACDL, LOGL_DEBUG, "- got "
						"NACK for BSN=%d\n", bsn);
					tbf->dir.dl.v_b[bsn & mod_sns_half]
						= 'N';
				}
			}
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- ack range is out of "
				"V(A)..V(S) range\n");
		}

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

		if (tbf->state == GPRS_RLCMAC_FINISHED
		 && tbf->dir.dl.v_s == tbf->dir.dl.v_a) {
			LOGP(DRLCMACDL, LOGL_NOTICE, "Received final block, "
				"bit without final ack inidcation\n");
		} else
			return 0;
	}

	LOGP(DRLCMACDL, LOGL_DEBUG, "- Final ACK received.\n");

	/* check for LLC PDU in the LLC Queue */
	msg = msgb_dequeue(&tbf->llc_queue);
	if (!msg) {
		struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

		/* no message, start T3193, change state to RELEASE */
		LOGP(DRLCMACDL, LOGL_DEBUG, "- No new message, so we "
			"release.\n");
		/* start T3193 */
		tbf_timer_start(tbf, 3193, bts->t3193_msec / 1000,
			bts->t3193_msec & 1000);
		tbf_new_state(tbf, GPRS_RLCMAC_WAIT_RELEASE);

		return 0;
	}
	memcpy(tbf->llc_frame, msg->data, msg->len);
	tbf->llc_length = msg->len;
	msgb_free(msg);

	/* we have a message, so we trigger downlink assignment, and there
	 * set the state to ASSIGN. also we set old_downlink, because we
	 * re-use this tbf. */
	LOGP(DRLCMAC, LOGL_DEBUG, "Trigger dowlink assignment on PACCH, "
		"because another LLC PDU has arrived in between\n");
	memset(&tbf->dir.dl, 0, sizeof(tbf->dir.dl)); /* reset RLC states */
	tbf_update(tbf);
	gprs_rlcmac_trigger_downlink_assignment(tbf, 1, NULL);

	return 0;
}


struct msgb *gprs_rlcmac_send_packet_downlink_assignment(
	struct gprs_rlcmac_tbf *tbf, uint32_t fn)
{
	struct msgb *msg;
	struct gprs_rlcmac_tbf *new_tbf;

#if POLLING_ASSIGNMENT == 1
	if (tbf->poll_state != GPRS_RLCMAC_POLL_NONE) {
		LOGP(DRLCMAC, LOGL_DEBUG, "Polling is already "
			"sheduled for TBF=%d, so we must wait for downlink "
			"assignment...\n", tbf->tfi);
			return NULL;
	}
#endif

	/* on uplink TBF we get the downlink TBF to be assigned. */
	if (tbf->direction == GPRS_RLCMAC_UL_TBF)
		new_tbf = tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_DL_TBF);
	else
		new_tbf = tbf;
	if (!new_tbf) {
		LOGP(DRLCMACDL, LOGL_ERROR, "We have a schedule for downlink "
			"assignment at uplink TBF=%d, but there is no downlink "
			"TBF\n", tbf->tfi);
		tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
		return NULL;
	}

	msg = msgb_alloc(23, "rlcmac_dl_ass");
	if (!msg)
		return NULL;
	bitvec *ass_vec = bitvec_alloc(23);
	if (!ass_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ass_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	LOGP(DRLCMAC, LOGL_INFO, "TBF: START TFI: %u TLLI: 0x%08x Packet Downlink Assignment (PACCH)\n", new_tbf->tfi, new_tbf->tlli);
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	write_packet_downlink_assignment(mac_control_block, tbf->tfi,
		(tbf->direction == GPRS_RLCMAC_DL_TBF), new_tbf,
		POLLING_ASSIGNMENT);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Downlink Assignment +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink(ass_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Downlink Assignment -------------------------\n");
	bitvec_pack(ass_vec, msgb_put(msg, 23));
	bitvec_free(ass_vec);
	free(mac_control_block);

#if POLLING_ASSIGNMENT == 1
	tbf->poll_state = GPRS_RLCMAC_POLL_SCHED;
	tbf->poll_fn = (fn + 13) % 2715648;
	tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_WAIT_ACK;
#else
	tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
#endif

	return msg;
}

static void gprs_rlcmac_downlink_assignment(gprs_rlcmac_tbf *tbf, uint8_t poll,
	char *imsi)
{
	LOGP(DRLCMAC, LOGL_INFO, "TX: START TFI: %u TLLI: 0x%08x Immediate Assignment Downlink (PCH)\n", tbf->tfi, tbf->tlli);
	bitvec *immediate_assignment = bitvec_alloc(22); /* without plen */
	bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	/* use request reference that has maximum distance to current time,
	 * so the assignment will not conflict with possible RACH requests. */
	int plen = write_immediate_assignment(immediate_assignment, 1, 125, (tbf->pdch[tbf->first_ts]->last_rts_fn + 21216) % 2715648, tbf->ta, tbf->arfcn, tbf->first_ts, tbf->tsc, tbf->tfi, 0, tbf->tlli, poll, tbf->poll_fn);
	pcu_l1if_tx_pch(immediate_assignment, plen, imsi);
	bitvec_free(immediate_assignment);
}

/* depending on the current TBF, we assign on PACCH or AGCH */
void gprs_rlcmac_trigger_downlink_assignment(gprs_rlcmac_tbf *tbf,
	uint8_t old_downlink, char *imsi)
{
	gprs_rlcmac_tbf *old_tbf;

#ifdef DEBUG_DL_ASS_IDLE
	strncpy(debug_imsi, imsi);
	LOGP(DRLCMAC, LOGL_ERROR, "**** DEBUGGING DOWNLINK ASSIGNMENT ****\n");
#endif

	/* stop pending timer */
	tbf_timer_stop(tbf);

	/* check for downlink tbf:  */
	if (old_downlink)
		old_tbf = tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_DL_TBF);
	else
		old_tbf = tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF);
	if (old_tbf) {
#ifdef DEBUG_DL_ASS_IDLE
		LOGP(DRLCMAC, LOGL_ERROR, "We must wait for current TBF to be "
			"released.\n");
		/* wait one second until assignment */
		tbf_timer_start(tbf, 1234, 1,0);
#else
		LOGP(DRLCMAC, LOGL_DEBUG, "Send dowlink assignment on "
			"PACCH, because %s TBF=%d exists for TLLI=0x%08x\n",
			(old_tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			old_tbf->tfi, old_tbf->tlli);
		old_tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_SEND_ASS;
		/* use TA from old TBF */
		tbf->ta = old_tbf->ta;
		/* change state */
		tbf_new_state(tbf, GPRS_RLCMAC_ASSIGN);
		/* start timer */
		tbf_timer_start(tbf, 0, Tassign_pacch);
#endif
	} else {
		LOGP(DRLCMAC, LOGL_DEBUG, "Send dowlink assignment for TBF=%d on PCH, no TBF exist (IMSI=%s)\n", tbf->tfi, imsi);
		if (!imsi || strlen(imsi) < 3) {
			LOGP(DRLCMAC, LOGL_ERROR, "No valid IMSI!\n");
			return;
		}
		/* send immediate assignment */
		gprs_rlcmac_downlink_assignment(tbf, 0, imsi);
		/* change state */
		tbf_new_state(tbf, GPRS_RLCMAC_ASSIGN);
		/* start timer */
		tbf_timer_start(tbf, 0, Tassign_agch);
	}
								                }

