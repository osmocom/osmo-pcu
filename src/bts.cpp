/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <bts.h>
#include <poll_controller.h>
#include <tbf.h>
#include <encoding.h>
#include <decoding.h>
#include <rlc.h>

#include <gprs_rlcmac.h>
#include <gprs_debug.h>

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/msgb.h>
}

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>

extern void *tall_pcu_ctx;

static BTS s_bts;

BTS* BTS::main_bts()
{
	return &s_bts;
}

struct gprs_rlcmac_bts *BTS::bts_data()
{
	return &m_bts;
}

struct gprs_rlcmac_bts *bts_main_data()
{
	return BTS::main_bts()->bts_data();
}

BTS::BTS()
	: m_cur_fn(0)
	, m_pollController(*this)
	, m_sba(*this)
{
	memset(&m_bts, 0, sizeof(m_bts));
	INIT_LLIST_HEAD(&m_bts.ul_tbfs);
	INIT_LLIST_HEAD(&m_bts.dl_tbfs);
	m_bts.bts = this;

	/* initialize back pointers */
	for (size_t trx_no = 0; trx_no < ARRAY_SIZE(m_bts.trx); ++trx_no) {
		struct gprs_rlcmac_trx *trx = &m_bts.trx[trx_no];
		trx->trx_no = trx_no;
		trx->bts = this;

		for (size_t ts_no = 0; ts_no < ARRAY_SIZE(trx->pdch); ++ts_no) {
			struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];
			pdch->ts_no = ts_no;
			pdch->trx = trx;
		}
	}
}

void BTS::set_current_frame_number(int fn)
{
	m_cur_fn = fn;
	m_pollController.expireTimedout(m_cur_fn);
}

int BTS::add_paging(uint8_t chan_needed, uint8_t *identity_lv)
{
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_paging *pag;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	llist_head *tbfs_lists[] = {
		&m_bts.ul_tbfs,
		&m_bts.dl_tbfs,
		NULL
	};


	LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n",
		chan_needed, osmo_hexdump(identity_lv + 1, identity_lv[0]));

	/* collect slots to page
	 * Mark slots for every TBF, but only mark one of it.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));
	for (l = 0; tbfs_lists[l]; l++) {
		llist_for_each_entry(tbf, tbfs_lists[l], list) {
			first_ts = -1;
			for (ts = 0; ts < 8; ts++) {
				if (tbf->pdch[ts]) {
					/* remember the first slot found */
					if (first_ts < 0)
						first_ts = ts;
					/* break, if we already marked a slot */
					if ((slot_mask[tbf->trx_no] & (1 << ts)))
						break;
				}
			}
			/* mark first slot found, if none is marked already */
			if (ts == 8 && first_ts >= 0) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- %s TBF=%d uses "
					"TRX=%d TS=%d, so we mark\n",
					(tbf->direction == GPRS_RLCMAC_UL_TBF)
						? "UL" : "DL",
					tbf->tfi, tbf->trx_no, first_ts);
				slot_mask[tbf->trx_no] |= (1 << first_ts);
			} else
				LOGP(DRLCMAC, LOGL_DEBUG, "- %s TBF=%d uses "
					"already marked TRX=%d TS=%d\n",
					(tbf->direction == GPRS_RLCMAC_UL_TBF)
						? "UL" : "DL",
					tbf->tfi, tbf->trx_no, ts);
		}
	}

	/* Now we have a list of marked slots. Every TBF uses at least one
	 * of these slots. */

	/* schedule paging to all marked slots */
	for (trx = 0; trx < 8; trx++) {
		if (slot_mask[trx] == 0)
			continue;
		for (ts = 0; ts < 8; ts++) {
			if ((slot_mask[trx] & (1 << ts))) {
				/* schedule */
				pag = talloc_zero(tall_pcu_ctx,
					struct gprs_rlcmac_paging);
				if (!pag)
					return -ENOMEM;
				pag->chan_needed = chan_needed;
				memcpy(pag->identity_lv, identity_lv,
					identity_lv[0] + 1);
				m_bts.trx[trx].pdch[ts].add_paging(pag);
				LOGP(DRLCMAC, LOGL_INFO, "Paging on PACCH of "
					"TRX=%d TS=%d\n", trx, ts);
				any_tbf = 1;
			}
		}
	}

	if (!any_tbf)
		LOGP(DRLCMAC, LOGL_INFO, "No paging, because no TBF\n");

	return 0;
}

/* search for active downlink or uplink tbf */
gprs_rlcmac_tbf *BTS::tbf_by_tlli(uint32_t tlli, enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;
	if (dir == GPRS_RLCMAC_UL_TBF) {
		llist_for_each_entry(tbf, &m_bts.ul_tbfs, list) {
			if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
			 && tbf->tlli == tlli && tbf->tlli_valid)
				return tbf;
		}
	} else {
		llist_for_each_entry(tbf, &m_bts.dl_tbfs, list) {
			if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
			 && tbf->tlli == tlli)
				return tbf;
		}
	}
	return NULL;
}

gprs_rlcmac_tbf *BTS::tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_tbf *tbf;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each_entry(tbf, &m_bts.ul_tbfs, list) {
		if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn && tbf->trx_no == trx
		 && tbf->control_ts == ts)
			return tbf;
	}
	llist_for_each_entry(tbf, &m_bts.dl_tbfs, list) {
		if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn && tbf->trx_no == trx
		 && tbf->control_ts == ts)
			return tbf;
	}
	return NULL;
}


/*
 * PDCH code below. TODO: move to a separate file
 */

/* After receiving these frames, we send ack/nack. */
#define SEND_ACK_AFTER_FRAMES 20

void gprs_rlcmac_pdch::enable()
{
	/* TODO: Check if there are still allocated resources.. */
	INIT_LLIST_HEAD(&paging_list);
	m_is_enabled = 1;
}

void gprs_rlcmac_pdch::disable()
{
	/* TODO.. kick free_resources once we know the TRX/TS we are on */
	m_is_enabled = 0;
}

/* TODO: kill the parameter and make a pdch belong to a trx.. to a bts.. */
void gprs_rlcmac_pdch::free_resources()
{
	struct gprs_rlcmac_paging *pag;

	/* we are not enabled. there should be no resources */
	if (!is_enabled())
		return;

	/* kick all TBF on slot */
	gprs_rlcmac_tbf::free_all(this);

	/* flush all pending paging messages */
	while ((pag = dequeue_paging()))
		talloc_free(pag);

	trx->bts->sba()->free_resources(this);
}

struct gprs_rlcmac_paging *gprs_rlcmac_pdch::dequeue_paging()
{
	struct gprs_rlcmac_paging *pag;

	if (llist_empty(&paging_list))
		return NULL;
	pag = llist_entry(paging_list.next, struct gprs_rlcmac_paging, list);
	llist_del(&pag->list);

	return pag;
}

struct msgb *gprs_rlcmac_pdch::packet_paging_request()
{
	struct gprs_rlcmac_paging *pag;
	struct msgb *msg;
	unsigned wp = 0, len;

	/* no paging, no message */
	pag = dequeue_paging();
	if (!pag)
		return NULL;

	LOGP(DRLCMAC, LOGL_DEBUG, "Scheduling paging\n");

	/* alloc message */
	msg = msgb_alloc(23, "pag ctrl block");
	if (!msg) {
		talloc_free(pag);
		return NULL;
	}
	bitvec *pag_vec = bitvec_alloc(23);
	if (!pag_vec) {
		msgb_free(msg);
		talloc_free(pag);
		return NULL;
	}
	wp = Encoding::write_packet_paging_request(pag_vec);

	/* loop until message is full */
	while (pag) {
		/* try to add paging */
		if ((pag->identity_lv[1] & 0x07) == 4) {
			/* TMSI */
			LOGP(DRLCMAC, LOGL_DEBUG, "- TMSI=0x%08x\n",
				ntohl(*((uint32_t *)(pag->identity_lv + 1))));
			len = 1 + 1 + 1 + 32 + 2 + 1;
			if (pag->identity_lv[0] != 5) {
				LOGP(DRLCMAC, LOGL_ERROR, "TMSI paging with "
					"MI != 5 octets!\n");
				goto continue_next;
			}
		} else {
			/* MI */
			LOGP(DRLCMAC, LOGL_DEBUG, "- MI=%s\n",
				osmo_hexdump(pag->identity_lv + 1,
					pag->identity_lv[0]));
			len = 1 + 1 + 1 + 4 + (pag->identity_lv[0]<<3) + 2 + 1;
			if (pag->identity_lv[0] > 8) {
				LOGP(DRLCMAC, LOGL_ERROR, "Paging with "
					"MI > 8 octets!\n");
				goto continue_next;
			}
		}
		if (wp + len > 184) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Does not fit, so schedule "
				"next time\n");
			/* put back paging record, because does not fit */
			llist_add_tail(&pag->list, &paging_list);
			break;
		}
		Encoding::write_repeated_page_info(pag_vec, wp, pag->identity_lv[0],
			pag->identity_lv + 1, pag->chan_needed);

continue_next:
		talloc_free(pag);
		pag = dequeue_paging();
	}

	bitvec_pack(pag_vec, msgb_put(msg, 23));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Paging Request +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(pag_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Paging Request -------------------------\n");
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);

	return msg;
}

void gprs_rlcmac_pdch::add_paging(struct gprs_rlcmac_paging *pag)
{
	llist_add(&pag->list, &paging_list);
}

/* receive UL data block
 *
 * The blocks are defragmented and forwarded as LLC frames, if complete.
 */
int gprs_rlcmac_pdch::rcv_data_block_acknowledged(uint8_t *data, uint8_t len, int8_t rssi)
{
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
	tbf = tbf_by_tfi(bts_data(), rh->tfi, trx_no(), GPRS_RLCMAC_UL_TBF);
	if (!tbf) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA unknown TBF=%d\n",
			rh->tfi);
		return 0;
	}
	tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_UL_DATA);

	LOGP(DRLCMACUL, LOGL_DEBUG, "UL DATA TBF=%d received (V(Q)=%d .. "
		"V(R)=%d)\n", rh->tfi, tbf->dir.ul.v_q, tbf->dir.ul.v_r);

	/* process RSSI */
	gprs_rlcmac_rssi(tbf, rssi);

	/* get TLLI */
	if (!tbf->tlli_valid) {
		struct gprs_rlcmac_tbf *dl_tbf, *ul_tbf;

		/* no TLLI yet */
		if (!rh->ti) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TBF=%d without "
				"TLLI, but no TLLI received yet\n", rh->tfi);
			return 0;
		}
		rc = Decoding::tlli_from_ul_data(data, len, &tbf->tlli);
		if (rc) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "Failed to decode TLLI "
				"of UL DATA TBF=%d.\n", rh->tfi);
			return 0;
		}
		LOGP(DRLCMACUL, LOGL_INFO, "Decoded premier TLLI=0x%08x of "
			"UL DATA TBF=%d.\n", tbf->tlli, rh->tfi);
		if ((dl_tbf = bts()->tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_DL_TBF))) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "Got RACH from "
				"TLLI=0x%08x while DL TBF=%d still exists. "
				"Killing pending DL TBF\n", tbf->tlli,
				dl_tbf->tfi);
			tbf_free(dl_tbf);
		}
		/* tbf_by_tlli will not find your TLLI, because it is not
		 * yet marked valid */
		if ((ul_tbf = bts()->tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF))) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "Got RACH from "
				"TLLI=0x%08x while UL TBF=%d still exists. "
				"Killing pending UL TBF\n", tbf->tlli,
				ul_tbf->tfi);
			tbf_free(ul_tbf);
		}
		/* mark TLLI valid now */
		tbf->tlli_valid = 1;
		/* store current timing advance */
		bts()->timing_advance()->remember(tbf->tlli, tbf->ta);
	/* already have TLLI, but we stille get another one */
	} else if (rh->ti) {
		uint32_t tlli;
		rc = Decoding::tlli_from_ul_data(data, len, &tlli);
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
	tbf_timer_start(tbf, 3169, bts_data()->t3169, 0);

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
		tbf->assemble_forward_llc(tbf->rlc_block[index], tbf->rlc_block_len[index]);
		/* raise V(Q), because block already received */
		tbf->dir.ul.v_q = (tbf->dir.ul.v_q + 1) & mod_sns;
	}

	/* Check CV of last frame in buffer */
	if (tbf->state_is(GPRS_RLCMAC_FLOW) /* still in flow state */
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
	if (rh->si || rh->ti || tbf->state_is(GPRS_RLCMAC_FINISHED)
	 || (tbf->dir.ul.rx_counter % SEND_ACK_AFTER_FRAMES) == 0) {
		if (rh->si) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "- Scheduling Ack/Nack, "
				"because MS is stalled.\n");
		}
		if (rh->ti) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because TLLI is included.\n");
		}
		if (tbf->state_is(GPRS_RLCMAC_FINISHED)) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because last block has CV==0.\n");
		}
		if ((tbf->dir.ul.rx_counter % SEND_ACK_AFTER_FRAMES) == 0) {
			LOGP(DRLCMACUL, LOGL_DEBUG, "- Scheduling Ack/Nack, "
				"because %d frames received.\n",
				SEND_ACK_AFTER_FRAMES);
		}
		if (tbf->ul_ack_state == GPRS_RLCMAC_UL_ACK_NONE) {
#ifdef DEBUG_DIAGRAM
			if (rh->si)
				debug_diagram(bts->bts, tbf->diag, "sched UL-ACK stall");
			if (rh->ti)
				debug_diagram(bts->bts, tbf->diag, "sched UL-ACK TLLI");
			if (tbf->state_is(GPRS_RLCMAC_FINISHED))
				debug_diagram(bts->bts, tbf->diag, "sched UL-ACK CV==0");
			if ((tbf->dir.ul.rx_counter % SEND_ACK_AFTER_FRAMES) == 0)
				debug_diagram(bts->bts, tbf->diag, "sched UL-ACK n=%d",
					tbf->dir.ul.rx_counter);
#endif
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

/* Received Uplink RLC control block. */
int gprs_rlcmac_pdch::rcv_control_block(
	bitvec *rlc_block, uint32_t fn)
{
	int8_t tfi = 0; /* must be signed */
	uint32_t tlli = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_sba *sba;
	int rc;

	RlcMacUplink_t * ul_control_block = (RlcMacUplink_t *)talloc_zero(tall_pcu_ctx, RlcMacUplink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- RX : Uplink Control Block -------------------------\n");
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		tlli = ul_control_block->u.Packet_Control_Acknowledgement.TLLI;
		tbf = bts()->tbf_by_poll_fn(fn, trx_no(), ts_no);
		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
				"unknown FN=%u TLL=0x%08x (TRX %d TS %d)\n",
				fn, tlli, trx_no(), ts_no);
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
			debug_diagram(bts(), tbf->diag, "got CTL-ACK (fin)");
			if ((tbf->state_flags &
				(1 << GPRS_RLCMAC_FLAG_TO_UL_ACK))) {
				tbf->state_flags &=
					~(1 << GPRS_RLCMAC_FLAG_TO_UL_ACK);
				LOGP(DRLCMAC, LOGL_NOTICE, "Recovered uplink "
					"ack for UL TBF=%d\n", tbf->tfi);
			}
			tbf_free(tbf);
			break;
		}
		if (tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_WAIT_ACK) {
			LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [UPLINK] DOWNLINK ASSIGNED TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
			/* reset N3105 */
			tbf->n3105 = 0;
			tbf->dl_ass_state = GPRS_RLCMAC_DL_ASS_NONE;
			debug_diagram(bts(), tbf->diag, "got CTL-ACK DL-ASS");
			if (tbf->direction == GPRS_RLCMAC_UL_TBF)
				tbf = bts()->tbf_by_tlli(tbf->tlli,
							GPRS_RLCMAC_DL_TBF);
			if (!tbf) {
				LOGP(DRLCMAC, LOGL_ERROR, "Got ACK, but DL "
					"TBF is gone\n");
				break;
			}
			tbf_new_state(tbf, GPRS_RLCMAC_FLOW);
			/* stop pending assignment timer */
			tbf->stop_timer();
			if ((tbf->state_flags &
				(1 << GPRS_RLCMAC_FLAG_TO_DL_ASS))) {
				tbf->state_flags &=
					~(1 << GPRS_RLCMAC_FLAG_TO_DL_ASS);
				LOGP(DRLCMAC, LOGL_NOTICE, "Recovered downlink "
					"assignment for DL TBF=%d\n", tbf->tfi);
			}
			tbf_assign_control_ts(tbf);
			break;
		}
		if (tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_WAIT_ACK) {
			LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [DOWNLINK] UPLINK ASSIGNED TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
			/* reset N3105 */
			tbf->n3105 = 0;
			tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_NONE;
			debug_diagram(bts(), tbf->diag, "got CTL-AC UL-ASS");
			if (tbf->direction == GPRS_RLCMAC_DL_TBF)
				tbf = bts()->tbf_by_tlli(tbf->tlli,
							GPRS_RLCMAC_UL_TBF);
			if (!tbf) {
				LOGP(DRLCMAC, LOGL_ERROR, "Got ACK, but UL "
					"TBF is gone\n");
				break;
			}
			tbf_new_state(tbf, GPRS_RLCMAC_FLOW);
			if ((tbf->state_flags &
				(1 << GPRS_RLCMAC_FLAG_TO_UL_ASS))) {
				tbf->state_flags &=
					~(1 << GPRS_RLCMAC_FLAG_TO_UL_ASS);
				LOGP(DRLCMAC, LOGL_NOTICE, "Recovered uplink "
					"assignment for UL TBF=%d\n", tbf->tfi);
			}
			tbf_assign_control_ts(tbf);
			break;
		}
		LOGP(DRLCMAC, LOGL_ERROR, "Error: received PACET CONTROL ACK "
			"at no request\n");
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		tfi = ul_control_block->u.Packet_Downlink_Ack_Nack.DOWNLINK_TFI;
		tbf = bts()->tbf_by_poll_fn(fn, trx_no(), ts_no);
		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
				"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
				fn, tfi, trx_no(), ts_no);
			break;
		}
		if (tbf->tfi != tfi) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
				"wrong TFI=%d, ignoring!\n", tfi);
			break;
		}
		tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_DL_ACK);
		if ((tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK))) {
			tbf->state_flags &= ~(1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);
			LOGP(DRLCMAC, LOGL_NOTICE, "Recovered downlink ack "
				"for DL TBF=%d\n", tbf->tfi);
		}
		/* reset N3105 */
		tbf->n3105 = 0;
		tbf->stop_t3191();
		tlli = tbf->tlli;
		LOGP(DRLCMAC, LOGL_DEBUG, "RX: [PCU <- BTS] TFI: %u TLLI: 0x%08x Packet Downlink Ack/Nack\n", tbf->tfi, tbf->tlli);
		tbf->poll_state = GPRS_RLCMAC_POLL_NONE;
		debug_diagram(bts(), tbf->diag, "got DL-ACK");

		rc = gprs_rlcmac_downlink_ack(tbf,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.FINAL_ACK_INDICATION,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP);
		if (rc == 1) {
			tbf_free(tbf);
			break;
		}
		/* check for channel request */
		if (ul_control_block->u.Packet_Downlink_Ack_Nack.Exist_Channel_Request_Description) {
			LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF in ack "
				"message, so we provide one:\n");
			tbf_alloc_ul(bts_data(), tbf->trx_no, tbf->ms_class, tbf->tlli, tbf->ta, tbf);
			/* schedule uplink assignment */
			tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_SEND_ASS;
		}
		break;
	case MT_PACKET_RESOURCE_REQUEST:
		if (ul_control_block->u.Packet_Resource_Request.ID.UnionType) {
			tlli = ul_control_block->u.Packet_Resource_Request.ID.u.TLLI;
			tbf = bts()->tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
			if (tbf) {
				LOGP(DRLCMACUL, LOGL_NOTICE, "Got RACH from "
					"TLLI=0x%08x while UL TBF=%d still "
					"exists. Killing pending DL TBF\n",
					tlli, tbf->tfi);
				tbf_free(tbf);
				tbf = NULL;
			}
			if (!tbf) {
				uint8_t ms_class = 0;
				struct gprs_rlcmac_tbf *dl_tbf;
				uint8_t ta;

				if ((dl_tbf = bts()->tbf_by_tlli(tlli, GPRS_RLCMAC_DL_TBF))) {
					LOGP(DRLCMACUL, LOGL_NOTICE, "Got RACH from "
						"TLLI=0x%08x while DL TBF=%d still exists. "
						"Killing pending DL TBF\n", tlli,
						dl_tbf->tfi);
					tbf_free(dl_tbf);
				}
				LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF "
					"in packet ressource request of single "
					"block, so we provide one:\n");
				sba = bts()->sba()->find(this, fn);
				if (!sba) {
					LOGP(DRLCMAC, LOGL_NOTICE, "MS requests UL TBF "
						"in packet ressource request of single "
						"block, but there is no resource request "
						"scheduled!\n");
					rc = bts()->timing_advance()->recall(tlli);
					if (rc >= 0)
						ta = rc;
					else
						ta = 0;
				} else {
					ta = sba->ta;
					bts()->timing_advance()->remember(tlli, ta);
					llist_del(&sba->list);
					talloc_free(sba);
				}
				if (ul_control_block->u.Packet_Resource_Request.Exist_MS_Radio_Access_capability)
					ms_class = Decoding::get_ms_class_by_capability(&ul_control_block->u.Packet_Resource_Request.MS_Radio_Access_capability);
				if (!ms_class)
					LOGP(DRLCMAC, LOGL_NOTICE, "MS does not give us a class.\n");
				tbf = tbf_alloc_ul(bts_data(), trx_no(), ms_class, tlli, ta, NULL);
				if (!tbf)
					break;
				/* set control ts to current MS's TS, until assignment complete */
				LOGP(DRLCMAC, LOGL_DEBUG, "Change control TS to %d until assinment is complete.\n", ts_no);
				tbf->control_ts = ts_no;
				/* schedule uplink assignment */
				tbf->ul_ass_state = GPRS_RLCMAC_UL_ASS_SEND_ASS;
				debug_diagram(bts->bts, tbf->diag, "Res. REQ");
				break;
			}
			tfi = tbf->tfi;
		} else {
			if (ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.UnionType) {
				tfi = ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.u.DOWNLINK_TFI;
				tbf = tbf_by_tfi(bts_data(), tfi, trx_no(), GPRS_RLCMAC_DL_TBF);
				if (!tbf) {
					LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown downlink TBF=%d\n", tlli);
					break;
				}
			} else {
				tfi = ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.u.UPLINK_TFI;
				tbf = tbf_by_tfi(bts_data(), tfi, trx_no(), GPRS_RLCMAC_UL_TBF);
				if (!tbf) {
					LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown uplink TBF=%d\n", tlli);
					break;
				}
			}
			tlli = tbf->tlli;
		}
		LOGP(DRLCMAC, LOGL_ERROR, "RX: [PCU <- BTS] %s TFI: %u TLLI: 0x%08x FIXME: Packet ressource request\n", (tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi, tbf->tlli);
		break;
	case MT_PACKET_MEASUREMENT_REPORT:
		sba = bts()->sba()->find(this, fn);
		if (!sba) {
			LOGP(DRLCMAC, LOGL_NOTICE, "MS send measurement "
				"in packet ressource request of single "
				"block, but there is no resource request "
				"scheduled!\n");
		} else {
			bts()->timing_advance()->remember(ul_control_block->u.Packet_Measurement_Report.TLLI, sba->ta);
			llist_del(&sba->list);
			talloc_free(sba);
		}
		gprs_rlcmac_meas_rep(&ul_control_block->u.Packet_Measurement_Report);
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] unknown control block received\n");
	}
	talloc_free(ul_control_block);
	return 1;
}


/* received RLC/MAC block from L1 */
int gprs_rlcmac_pdch::rcv_block(uint8_t *data, uint8_t len, uint32_t fn, int8_t rssi)
{
	unsigned payload = data[0] >> 6;
	bitvec *block;
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = rcv_data_block_acknowledged(data, len, rssi);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		block = bitvec_alloc(len);
		if (!block)
			return -ENOMEM;
		bitvec_unpack(block, data);
		rc = rcv_control_block(block, fn);
		bitvec_free(block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload(%u).\n", payload);
		rc = -EINVAL;
	}

	return rc;
}
