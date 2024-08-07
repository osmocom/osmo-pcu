/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <bts.h>
#include <pdch.h>
#include <decoding.h>
#include <encoding.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <coding_scheme.h>
#include <gprs_ms.h>
#include <pcu_l1_if.h>
#include <rlc.h>
#include <sba.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <cxx_linuxlist.h>

extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

#include "coding_scheme.h"
#include "gsm_rlcmac.h"
#include "nacc_fsm.h"
}

#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

extern void *tall_pcu_ctx;

static void get_rx_qual_meas(struct pcu_l1_meas *meas, uint8_t rx_qual_enc)
{
	static const int16_t rx_qual_map[] = {
		0, /* 0,14 % */
		0, /* 0,28 % */
		1, /* 0,57 % */
		1, /* 1,13 % */
		2, /* 2,26 % */
		5, /* 4,53 % */
		9, /* 9,05 % */
		18, /* 18,10 % */
	};

	pcu_l1_meas_set_ms_rx_qual(meas, rx_qual_map[
					OSMO_MIN(rx_qual_enc, ARRAY_SIZE(rx_qual_map)-1)
					]);
}

static void get_meas(struct pcu_l1_meas *meas,
	const Packet_Resource_Request_t *qr)
{
	unsigned i;

	pcu_l1_meas_set_ms_c_value(meas, qr->C_VALUE);
	if (qr->Exist_SIGN_VAR)
		pcu_l1_meas_set_ms_sign_var(meas, (qr->SIGN_VAR + 2) / 4); /* SIGN_VAR * 0.25 dB */

	for (i = 0; i < OSMO_MIN(ARRAY_SIZE(qr->I_LEVEL_TN), ARRAY_SIZE(meas->ts)); i++)
	{
		if (qr->I_LEVEL_TN[i].Exist) {
			LOGP(DRLCMAC, LOGL_INFO,
				"Packet resource request: i_level[%d] = %d\n",
				i, qr->I_LEVEL_TN[i].I_LEVEL);
			pcu_l1_meas_set_ms_i_level(meas, i, -2 * qr->I_LEVEL_TN[i].I_LEVEL);
		}
	}
}

static void get_meas(struct pcu_l1_meas *meas,
	const Channel_Quality_Report_t *qr)
{
	unsigned i;

	get_rx_qual_meas(meas, qr->RXQUAL);
	pcu_l1_meas_set_ms_c_value(meas, qr->C_VALUE);
	pcu_l1_meas_set_ms_sign_var(meas, (qr->SIGN_VAR + 2) / 4); /* SIGN_VAR * 0.25 dB */

	for (i = 0; i < OSMO_MIN(ARRAY_SIZE(qr->Slot), ARRAY_SIZE(meas->ts)); i++)
	{
		if (qr->Slot[i].Exist) {
			LOGP(DRLCMAC, LOGL_DEBUG,
				"Channel quality report: i_level[%d] = %d\n",
				i, qr->Slot[i].I_LEVEL_TN);
			pcu_l1_meas_set_ms_i_level(meas, i, -2 * qr->Slot[i].I_LEVEL_TN);
		}
	}
}

static inline void sched_ul_ass_or_rej(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_dl_tbf *tbf)
{
	bts_do_rate_ctr_inc(bts, CTR_CHANNEL_REQUEST_DESCRIPTION);

	/* This call will register the new TBF with the MS on success */
	gprs_rlcmac_ul_tbf *ul_tbf = ms_new_ul_tbf_assigned_pacch(tbf->ms(), tbf->trx->trx_no);

	/* schedule uplink assignment or reject */
	if (ul_tbf) {
		LOGPTBFDL(tbf, LOGL_DEBUG, "MS requests UL TBF in ack message, so we provide one:\n");
		osmo_fsm_inst_dispatch(tbf->ul_ass_fsm.fi, TBF_UL_ASS_EV_SCHED_ASS, NULL);
	} else {
		LOGPTBFDL(tbf, LOGL_NOTICE, "MS requests UL TBF in ack message, but alloc failed: send PktAssRej\n");
		osmo_fsm_inst_dispatch(tbf->ul_ass_fsm.fi, TBF_UL_ASS_EV_SCHED_ASS_REJ, NULL);
	}
}

/* Make sure the PDCH vanished from the mask of reserved PDCHs for all MS, to
 * avoid alloc_algorithm using it. */
static void pdch_unreserve_all_ms_reserved_slots(struct gprs_rlcmac_pdch *pdch)
{
	struct llist_head *tmp;
	uint8_t ts_rm_mask = (~(1 << pdch->ts_no));
	struct gprs_rlcmac_trx *trx = pdch->trx;

	llist_for_each(tmp, &trx->bts->ms_list) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		if (ms->current_trx != trx)
			continue;
		uint8_t old_dl_slots = ms_reserved_dl_slots(ms);
		uint8_t old_ul_slots = ms_reserved_ul_slots(ms);
		uint8_t new_dl_slots = old_dl_slots & ts_rm_mask;
		uint8_t new_ul_slots = old_ul_slots & ts_rm_mask;
		if (old_dl_slots == new_dl_slots && old_ul_slots == new_ul_slots)
			continue;
		ms_set_reserved_slots(ms, trx, new_ul_slots, new_dl_slots);
	}
	if (pdch->num_reserved(GPRS_RLCMAC_UL_TBF) > 0 || pdch->num_reserved(GPRS_RLCMAC_DL_TBF) > 0)
		LOGPDCH(pdch, DRLCMAC, LOGL_ERROR,
			"Reserved TS count not zero after unreserving from all current MS in list! UL=%u DL=%u\n",
			pdch->num_reserved(GPRS_RLCMAC_UL_TBF), pdch->num_reserved(GPRS_RLCMAC_DL_TBF));
}

void pdch_init(struct gprs_rlcmac_pdch *pdch, struct gprs_rlcmac_trx *trx, uint8_t ts_nr)
{
	pdch->ts_no = ts_nr;
	pdch->trx = trx;

	/*  Initialize the PTCCH/D message (Packet Timing Advance Control Channel) */
	memset(pdch->ptcch_msg, PTCCH_TAI_FREE, PTCCH_TAI_NUM);
	memset(pdch->ptcch_msg + PTCCH_TAI_NUM, PTCCH_PADDING, 7);
}

void gprs_rlcmac_pdch::enable()
{
	LOGPDCH(this, DRLCMAC, LOGL_INFO, "PDCH state: %s => enabled\n", m_is_enabled ? "enabled" : "disabled");
	OSMO_ASSERT(m_is_enabled == 0);
	INIT_LLIST_HEAD(&paging_list);

	OSMO_ASSERT(!this->ulc);
	this->ulc = pdch_ulc_alloc(this, trx->bts);

	m_is_enabled = 1;
	bts_stat_item_inc(trx->bts, STAT_PDCH_AVAILABLE);
}

void gprs_rlcmac_pdch::disable()
{
	LOGPDCH(this, DRLCMAC, LOGL_INFO, "PDCH state: %s => disabled\n", m_is_enabled ? "enabled" : "disabled");
	OSMO_ASSERT(m_is_enabled == 1);
	this->free_resources();

	m_is_enabled = 0;
	bts_stat_item_dec(trx->bts, STAT_PDCH_AVAILABLE);
}

void gprs_rlcmac_pdch::free_resources()
{
	struct gprs_rlcmac_paging *pag;

	/* kick all TBF on slot */
	pdch_free_all_tbf(this);

	pdch_unreserve_all_ms_reserved_slots(this);

	/* flush all pending paging messages */
	while ((pag = dequeue_paging()))
		talloc_free(pag);

	talloc_free(this->ulc);
	this->ulc = NULL;
}

struct gprs_rlcmac_paging *gprs_rlcmac_pdch::dequeue_paging()
{
	struct gprs_rlcmac_paging *pag;

	if (llist_empty(&paging_list))
		return NULL;
	pag = llist_first_entry(&paging_list, struct gprs_rlcmac_paging, list);
	llist_del(&pag->list);

	return pag;
}

struct msgb *gprs_rlcmac_pdch::packet_paging_request()
{
	struct gprs_rlcmac_paging *pag;
	RlcMacDownlink_t *mac_control_block;
	bitvec *pag_vec;
	struct msgb *msg;
	unsigned wp = 0, len;
	int rc;

	/* no paging, no message */
	pag = dequeue_paging();
	if (!pag)
		return NULL;

	LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "Scheduling paging\n");

	/* alloc message */
	msg = msgb_alloc(23, "pag ctrl block");
	if (!msg) {
		talloc_free(pag);
		return NULL;
	}
	pag_vec = bitvec_alloc(23, tall_pcu_ctx);
	if (!pag_vec) {
		msgb_free(msg);
		talloc_free(pag);
		return NULL;
	}
	wp = Encoding::write_packet_paging_request(pag_vec);

	/* loop until message is full */
	while (pag) {
		if (log_check_level(DRLCMAC, LOGL_DEBUG)) {
			struct osmo_mobile_identity omi = {};
			char str[64];
			osmo_mobile_identity_decode(&omi, pag->identity_lv + 1, pag->identity_lv[0], true);
			osmo_mobile_identity_to_str_buf(str, sizeof(str), &omi);
			LOGP(DRLCMAC, LOGL_DEBUG, "Paging MI - %s\n", str);
		}

		/* try to add paging */
		if ((pag->identity_lv[1] & GSM_MI_TYPE_MASK) == GSM_MI_TYPE_TMSI) {
			/* TMSI */
			len = 1 + 1 + 1 + 32 + 2 + 1;
			if (pag->identity_lv[0] != 5) {
				LOGPDCH(this, DRLCMAC, LOGL_ERROR,
					"TMSI paging with MI != 5 octets!\n");
				goto continue_next;
			}
		} else {
			/* MI */
			len = 1 + 1 + 1 + 4 + (pag->identity_lv[0]<<3) + 2 + 1;
			if (pag->identity_lv[0] > 8) {
				LOGPDCH(this, DRLCMAC, LOGL_ERROR,
					"Paging with MI > 8 octets!\n");
				goto continue_next;
			}
		}
		if (wp + len > 184) {
			LOGPDCH(this, DRLCMAC, LOGL_DEBUG,
				"- Does not fit, so schedule next time\n");
			/* put back paging record, because does not fit */
			llist_add(&pag->list, &paging_list);
			break;
		}
		Encoding::write_repeated_page_info(pag_vec, wp, pag->identity_lv[0],
			pag->identity_lv + 1, pag->chan_needed);

continue_next:
		talloc_free(pag);
		pag = dequeue_paging();
	}

	bitvec_pack(pag_vec, msgb_put(msg, 23));
	mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Paging Request +++++++++++++++++++++++++\n");
	rc = decode_gsm_rlcmac_downlink(pag_vec, mac_control_block);
	if (rc < 0) {
		LOGPDCH(this, DRLCMAC, LOGL_ERROR, "Decoding of Downlink Packet Paging Request failed (%d): %s\n",
		     rc, osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		goto free_ret;
	}
	LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Paging Request -------------------------\n");
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);
	return msg;

free_ret:
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

bool gprs_rlcmac_pdch::add_paging(uint8_t chan_needed, const struct osmo_mobile_identity *mi)
{
	int rc;
	struct gprs_rlcmac_paging *pag = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_paging);
	if (!pag)
		return false;

	pag->chan_needed = chan_needed;
	rc = osmo_mobile_identity_encode_buf(pag->identity_lv + 1, sizeof(pag->identity_lv) - 1, mi, true);
	if (rc <= 0) {
		LOGPDCH(this, DRLCMAC, LOGL_ERROR, "Cannot encode Mobile Identity (rc=%d)\n", rc);
		talloc_free(pag);
		return false;
	}
	pag->identity_lv[0] = rc;

	llist_add(&pag->list, &paging_list);

	return true;
}

void gprs_rlcmac_pdch::rcv_control_ack(Packet_Control_Acknowledgement_t *packet, uint32_t fn)
{
	struct gprs_rlcmac_tbf *tbf, *new_tbf;
	uint32_t tlli = packet->TLLI;
	GprsMs *ms;
	gprs_rlcmac_ul_tbf *ul_tbf;
	enum pdch_ulc_tbf_poll_reason reason;
	struct pdch_ulc_node *poll;

	poll = pdch_ulc_get_node(ulc, fn);
	if (!poll || poll->type != PDCH_ULC_NODE_TBF_POLL) {
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with unknown FN=%u TLLI=0x%08x\n",
			fn, tlli);
		ms = bts_get_ms_by_tlli(bts(), tlli, GSM_RESERVED_TMSI);
		if (ms)
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
				"unknown TBF corresponds to %s\n", ms_name(ms));
		return;
	}
	OSMO_ASSERT(poll->tbf_poll.poll_tbf);
	tbf = poll->tbf_poll.poll_tbf;
	reason = poll->tbf_poll.reason;

	ms_update_announced_tlli(tbf->ms(), tlli);
	/* Gather MS from TBF again, since it may be NULL or may have been merged during ms_update_announced_tlli */
	ms = tbf->ms();

	LOGPTBF(tbf, LOGL_DEBUG, "FN=%" PRIu32 " Rx Packet Control Ack (reason=%s)\n",
		fn, get_value_string(pdch_ulc_tbf_poll_reason_names, reason));

	switch (reason) {
	case PDCH_ULC_POLL_UL_ACK:
		ul_tbf = tbf_as_ul_tbf(tbf);
		OSMO_ASSERT(ul_tbf);
		if (!tbf_ul_ack_exp_ctrl_ack(ul_tbf, fn, ts_no)) {
			LOGPTBF(tbf, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_UL_ACK not expected!\n",
				fn, ts_no, bts_current_frame_number(tbf->bts));
			return;
		}
		pdch_ulc_release_fn(ulc, fn);
		osmo_fsm_inst_dispatch(ul_tbf->ul_ack_fsm.fi, TBF_UL_ACK_EV_RX_CTRL_ACK, NULL);
		/* We only set polling on final UL ACK/NACK, something is wrong... */
		if (tbf_state(tbf) == TBF_ST_FINISHED)
			osmo_fsm_inst_dispatch(ul_tbf->state_fi, TBF_EV_FINAL_UL_ACK_CONFIRMED, (void*)false);
			/* ul_tbf is freed here! */
		else
			LOGPTBFUL(ul_tbf, LOGL_ERROR, "Received POLL_UL_ACK for UL TBF in unexpected state!\n");
		return;

	case PDCH_ULC_POLL_UL_ASS:
		if (!tbf->ul_ass_state_is(TBF_UL_ASS_WAIT_ACK)) {
			LOGPTBF(tbf, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_UL_ASS not expected! state is %s\n",
				fn, ts_no, bts_current_frame_number(tbf->bts),
				osmo_fsm_inst_state_name(tbf_ul_ass_fi(tbf)));
			return;
		}
		pdch_ulc_release_fn(ulc, fn);
		if (tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF)
			tbf->n_reset(N3105);
		osmo_fsm_inst_dispatch(tbf->ul_ass_fsm.fi, TBF_UL_ASS_EV_RX_ASS_CTRL_ACK, NULL);

		new_tbf = ms_ul_tbf(ms);
		if (!new_tbf) {
			LOGPDCH(this, DRLCMAC, LOGL_ERROR,
				"Got PKT_CTRL_ACK (UL_ASS) from %s, but UL TBF is gone (TLLI=0x%08x)\n",
				tbf_name(tbf), tlli);
			return;
		}
		LOGPTBF(tbf, LOGL_DEBUG, "Got PKT_CTRL_ACK confirming assignment of %s\n", tbf_name(new_tbf));

		osmo_fsm_inst_dispatch(new_tbf->state_fi, TBF_EV_ASSIGN_ACK_PACCH, NULL);
		/* there might be LLC packets waiting in the queue, but the DL
		 * TBF might have been released while the UL TBF has been
		 * established */
		if (ms_need_dl_tbf(new_tbf->ms()))
			ms_new_dl_tbf_assigned_on_pacch(new_tbf->ms(), new_tbf);
		return;

	case PDCH_ULC_POLL_DL_ASS:
		if (!tbf->dl_ass_state_is(TBF_DL_ASS_WAIT_ACK)) {
			LOGPTBF(tbf, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_DL_ASS not expected! state is %s\n",
				fn, ts_no, bts_current_frame_number(tbf->bts),
				osmo_fsm_inst_state_name(tbf_dl_ass_fi(tbf)));
			return;
		}
		pdch_ulc_release_fn(ulc, fn);
		if (tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF)
			tbf->n_reset(N3105);
		osmo_fsm_inst_dispatch(tbf->dl_ass_fsm.fi, TBF_DL_ASS_EV_RX_ASS_CTRL_ACK, NULL);

		new_tbf = ms_dl_tbf(ms);
		if (!new_tbf) {
			LOGPDCH(this, DRLCMAC, LOGL_ERROR,
				"Got PKT_CTRL_ACK (DL_ASS) from %s, but DL TBF is gone (TLLI=0x%08x)\n",
				tbf_name(tbf), tlli);
			return;
		}
		LOGPTBF(tbf, LOGL_DEBUG, "Got PKT_CTRL_ACK confirming assignment of %s\n", tbf_name(new_tbf));
		if ((tbf->state_is(TBF_ST_WAIT_RELEASE) ||
		     tbf->state_is(TBF_ST_WAIT_REUSE_TFI)) &&
		    tbf->direction == new_tbf->direction)
			tbf_free(tbf);

		osmo_fsm_inst_dispatch(new_tbf->state_fi, TBF_EV_ASSIGN_ACK_PACCH, NULL);
		return;

	case PDCH_ULC_POLL_CELL_CHG_CONTINUE:
		if (!ms->nacc || !nacc_fsm_exp_ctrl_ack(ms->nacc, fn, ts_no)) {
			LOGPTBF(tbf, LOGL_NOTICE, "FN=%d, TS=%d (curr FN %d): POLL_CELL_CHG_CONTINUE not expected!\n",
				fn, ts_no, bts_current_frame_number(tbf->bts));
			return;
		}
		pdch_ulc_release_fn(ulc, fn);
		osmo_fsm_inst_dispatch(ms->nacc->fi, NACC_EV_RX_CELL_CHG_CONTINUE_ACK, NULL);
		/* Don't assume MS is no longer reachable (hence don't free) after this: TS 44.060
		 * "When the mobile station receives the PACKET CELL CHANGE ORDER
		 * or the PACKET CELL CHANGE CONTINUE message the mobile station
		 * shall transmit a PACKET CONTROL ACKNOWLEDGMENT message in the
		 * specified uplink radio block if a valid RRBP field is
		 * received as part of the message; the mobile station _MAY_ then
		 * switch to a new cell."
		 */
		return;

	case PDCH_ULC_POLL_DL_ACK:
		/* Handled in rcv_control_dl_ack_nack() upon receival of DL ACK/NACK as a response to our POLL. */
		return;
	default:
		LOGPDCH(this, DRLCMAC, LOGL_ERROR, "FN=%" PRIu32 " "
			"Error: received PACKET CONTROL ACK at no request (reason=%s)\n", fn,
			get_value_string(pdch_ulc_tbf_poll_reason_names, reason));
	}
}

void gprs_rlcmac_pdch::rcv_control_dl_ack_nack(Packet_Downlink_Ack_Nack_t *ack_nack, uint32_t fn, struct pcu_l1_meas *meas)
{
	int8_t tfi = 0; /* must be signed */
	struct pdch_ulc_node *poll;
	struct gprs_rlcmac_dl_tbf *tbf;
	int rc;
	int num_blocks;
	uint8_t bits_data[RLC_GPRS_WS/8];
	bitvec bits;
	int bsn_begin, bsn_end;
	char show_bits[RLC_GPRS_WS + 1];

	tfi = ack_nack->DOWNLINK_TFI;
	poll = pdch_ulc_get_node(ulc, fn);
	if (!poll || poll->type != PDCH_ULC_NODE_TBF_POLL ||
	    poll->tbf_poll.reason != PDCH_ULC_POLL_DL_ACK) {
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
			"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
			fn, tfi, trx_no(), ts_no);
		return;
	}
	OSMO_ASSERT(poll->tbf_poll.poll_tbf);
	tbf = tbf_as_dl_tbf(poll->tbf_poll.poll_tbf);
	if (tbf->tfi() != tfi) {
		LOGPTBFDL(tbf, LOGL_NOTICE,
			  "PACKET DOWNLINK ACK with wrong TFI=%d, ignoring!\n", tfi);
		return;
	}

	pdch_ulc_release_fn(ulc, fn);

	LOGPTBF(tbf, LOGL_DEBUG, "RX: [PCU <- BTS] Packet Downlink Ack/Nack\n");

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	num_blocks = Decoding::decode_gprs_acknack_bits(
		&ack_nack->Ack_Nack_Description, &bits,
		&bsn_begin, &bsn_end, static_cast<gprs_rlc_dl_window *>(tbf->window()));

	LOGPDCH(this, DRLCMAC, LOGL_DEBUG,
		"Got GPRS DL ACK bitmap: SSN: %d, BSN %d to %d - 1 (%d blocks), "
		"\"%s\"\n",
		ack_nack->Ack_Nack_Description.STARTING_SEQUENCE_NUMBER,
		bsn_begin, bsn_end, num_blocks,
		(Decoding::extract_rbb(&bits, show_bits), show_bits));

	rc = tbf->rcvd_dl_ack(
		ack_nack->Ack_Nack_Description.FINAL_ACK_INDICATION,
		bsn_begin, &bits);
	if (rc == 1) {
		tbf_free(tbf);
		return;
	}
	/* check for channel request */
	if (ack_nack->Exist_Channel_Request_Description)
		sched_ul_ass_or_rej(bts(), tbf);

	/* get measurements */
	if (tbf->ms()) {
		get_meas(meas, &ack_nack->Channel_Quality_Report);
		ms_update_l1_meas(tbf->ms(), meas);
	}
}

void gprs_rlcmac_pdch::rcv_control_egprs_dl_ack_nack(EGPRS_PD_AckNack_t *ack_nack, uint32_t fn, struct pcu_l1_meas *meas)
{
	int8_t tfi = 0; /* must be signed */
	struct gprs_rlcmac_dl_tbf *tbf;
	struct pdch_ulc_node *poll;
	gprs_rlc_dl_window *window;
	int rc;
	int num_blocks;
	uint8_t bits_data[RLC_EGPRS_MAX_WS/8];
	char show_bits[RLC_EGPRS_MAX_WS + 1];
	bitvec bits;
	int bsn_begin, bsn_end;

	tfi = ack_nack->DOWNLINK_TFI;
	poll = pdch_ulc_get_node(ulc, fn);
	if (!poll || poll->type != PDCH_ULC_NODE_TBF_POLL ||
	    poll->tbf_poll.reason != PDCH_ULC_POLL_DL_ACK) {
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "EGPRS PACKET DOWNLINK ACK with "
			"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
			fn, tfi, trx_no(), ts_no);
		return;
	}
	OSMO_ASSERT(poll->tbf_poll.poll_tbf);
	tbf = tbf_as_dl_tbf(poll->tbf_poll.poll_tbf);
	if (tbf->tfi() != tfi) {
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "EGPRS PACKET DOWNLINK ACK with "
			"wrong TFI=%d, ignoring!\n", tfi);
		return;
	}

	pdch_ulc_release_fn(ulc, fn);

	LOGPTBF(tbf, LOGL_DEBUG,
		"RX: [PCU <- BTS] EGPRS Packet Downlink Ack/Nack\n");

	window = static_cast<gprs_rlc_dl_window *>(tbf->window());
	LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "EGPRS ACK/NACK: "
		"ut: %d, final: %d, bow: %d, eow: %d, ssn: %d, have_crbb: %d, "
		"urbb_len:%d, %p, %p, %d, %d, win: %d-%d, urbb: %s\n",
		(int)ack_nack->EGPRS_AckNack.UnionType,
		(int)ack_nack->EGPRS_AckNack.Desc.FINAL_ACK_INDICATION,
		(int)ack_nack->EGPRS_AckNack.Desc.BEGINNING_OF_WINDOW,
		(int)ack_nack->EGPRS_AckNack.Desc.END_OF_WINDOW,
		(int)ack_nack->EGPRS_AckNack.Desc.STARTING_SEQUENCE_NUMBER,
		(int)ack_nack->EGPRS_AckNack.Desc.Exist_CRBB,
		(int)ack_nack->EGPRS_AckNack.Desc.URBB_LENGTH,
		(void *)&ack_nack->EGPRS_AckNack.UnionType,
		(void *)&ack_nack->EGPRS_AckNack.Desc,
		(int)offsetof(EGPRS_AckNack_t, Desc),
		(int)offsetof(EGPRS_AckNack_w_len_t, Desc),
		window->v_a(),
		window->v_s(),
		osmo_hexdump((const uint8_t *)&ack_nack->EGPRS_AckNack.Desc.URBB,
			sizeof(ack_nack->EGPRS_AckNack.Desc.URBB)));

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	num_blocks = Decoding::decode_egprs_acknack_bits(
		&ack_nack->EGPRS_AckNack.Desc, &bits,
		&bsn_begin, &bsn_end, window);

	LOGPDCH(this, DRLCMAC, LOGL_DEBUG,
		"Got EGPRS DL ACK bitmap: SSN: %d, BSN %d to %d - 1 (%d blocks), "
		"\"%s\"\n",
		ack_nack->EGPRS_AckNack.Desc.STARTING_SEQUENCE_NUMBER,
		bsn_begin, bsn_end, num_blocks,
		(Decoding::extract_rbb(&bits, show_bits), show_bits)
	    );

	rc = tbf->rcvd_dl_ack(
		ack_nack->EGPRS_AckNack.Desc.FINAL_ACK_INDICATION,
		bsn_begin, &bits);
	if (rc == 1) {
		tbf_free(tbf);
		return;
	}

	/* check for channel request */
	if (ack_nack->Exist_ChannelRequestDescription)
		sched_ul_ass_or_rej(bts(), tbf);

	/* get measurements */
	if (tbf->ms()) {
		/* TODO: Implement Measurements parsing for EGPRS */
		/*
		get_meas(meas, &ack_nack->Channel_Quality_Report);
		tbf->ms()->update_l1_meas(meas);
		*/
	}
}

void gprs_rlcmac_pdch::rcv_resource_request(Packet_Resource_Request_t *request, uint32_t fn, struct pcu_l1_meas *meas)
{
	int rc;
	struct gprs_rlcmac_bts *bts = trx->bts;
	struct pdch_ulc_node *item;
	char buf[128];
	struct GprsMs *ms = NULL;
	struct gprs_rlcmac_sba *sba;
	struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;
	struct gprs_rlcmac_ul_tbf *ul_tbf = NULL;
	struct gprs_rlcmac_ul_tbf *new_ul_tbf = NULL;


	if (!(item = pdch_ulc_get_node(ulc, fn))) {
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "FN=%u PKT RESOURCE REQ: "
			"UL block not reserved\n", fn);
		return;
	}

	/* First gather MS from TLLI/DL_TFI/UL_TFI:*/
	if (request->ID.UnionType) { /* ID_TYPE = TLLI */
		uint32_t tlli = request->ID.u.TLLI;
		ms = bts_get_ms_by_tlli(bts, tlli, GSM_RESERVED_TMSI);
		if (!ms) {
			/* A reference is already hold immediately below in all cases, no
			 * need to hold and extra one, pass use_ref=NULL: */
			ms = ms_alloc(bts, NULL);
			ms_set_tlli(ms, tlli);
		}
	} else if (request->ID.u.Global_TFI.UnionType) { /* ID_TYPE = DL_TFI */
		int8_t tfi = request->ID.u.Global_TFI.u.DOWNLINK_TFI;
		dl_tbf = bts_dl_tbf_by_tfi(bts, tfi, trx_no(), ts_no);
		if (!dl_tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESOURCE REQ unknown downlink TFI=%d\n", tfi);
			return;
		}
		ms = tbf_ms(dl_tbf_as_tbf(dl_tbf));
		dl_tbf = NULL;
	} else { /* ID_TYPE = UL_TFI */
		int8_t tfi = request->ID.u.Global_TFI.u.UPLINK_TFI;
		ul_tbf = bts_ul_tbf_by_tfi(bts, tfi, trx_no(), ts_no);
		if (!ul_tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESOURCE REQ unknown uplink TFI=%d\n", tfi);
			return;
		}
		ms = tbf_ms(ul_tbf_as_tbf(ul_tbf));
		ul_tbf = NULL;
	}


	/* Here ms is available (non-null). Keep the ms, even if it gets idle
	 * temporarily, in order to avoid it being freed if we free any of its
	 * resources (TBF). */
	OSMO_ASSERT(ms);
	ms_ref(ms, __func__);


	switch (item->type) {
	case PDCH_ULC_NODE_TBF_USF:
		/* TS 44.060 to 8.1.1.1.2: An MS can send a PKT Res Req during USF, for instance to change its Radio Priority. */
		ul_tbf = item->tbf_usf.ul_tbf;
		if (tbf_ms(ul_tbf_as_tbf(ul_tbf)) != ms) {
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "FN=%u PKT RESOURCE REQ: "
				"Received from unexpected %s vs exp %s\n", fn,
				ms_name_buf(ms, buf, sizeof(buf)), ms_name(tbf_ms(ul_tbf_as_tbf(ul_tbf))));
			/* let common path expire the poll */
			goto return_unref;
		}
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "FN=%u PKT RESOURCE REQ: "
			"MS requests UL TBF upgrade through USF of %s\n",
			fn, tbf_name(item->tbf_usf.ul_tbf));
		pdch_ulc_release_node(ulc, item);
		/* FIXME OS#4947: Currenty we free the UL TBF and create a new one below in order to trigger the Pkt UL Ass.
		 * We should instead keep the same UL TBF working and upgrading it (modify ul_tbf->ul_ass_fsm.fi to
		 * handle the PktUlAss + PktCtrlAck).
		 * This is required by spec, and MS are know to continue using the TBF (due to delay in between DL and
		 * UL scheduling).
		 * TS 44.060 to 8.1.1.1.2:
		 * "If the mobile station or the network does not support multiple TBF procedures, then after the
		 * transmission of the PACKET RESOURCE REQUEST message with the reason for changing PFI, the radio
		 * priority or peak throughput class of an assigned uplink TBF the mobile station continue to use the
		 * currently assigned uplink TBF assuming that the requested radio priority or peak throughput class is
		 * already assigned to that TBF."
		 */
		tbf_free(ul_tbf);
		ul_tbf = NULL;
		break;
	case PDCH_ULC_NODE_SBA:
		sba = item->sba.sba;
		LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "FN=%u PKT RESOURCE REQ: "
			"MS requests UL TBF throguh SBA\n", fn);
		ms_set_ta(ms, sba->ta);
		sba_free(sba);
		/* If MS identified by TLLI sent us a PktResReq through SBA, it means it came
		 * from CCCH, so it's for sure not using previous UL BF; drop it if it still
		 * exits on our end:
		 */
		if ((ul_tbf = ms_ul_tbf(ms))) {
			/* Get rid of previous finished UL TBF before providing a new one */
			LOGPTBFUL(ul_tbf, LOGL_NOTICE,
				  "Got PACKET RESOURCE REQ while TBF not finished, killing pending UL TBF\n");
			tbf_free(ul_tbf);
			ul_tbf = NULL;
		}
		/* Similarly, it is for sure not using any DL-TBF. We still may have some because
		 * we were trying to assign a DL-TBF over CCCH when the MS proactively requested
		 * for a UL-TBF. In that case we'll need to re-assigna new DL-TBF through PACCH when
		 * contention resolution is done:
		 */
		if ((dl_tbf = ms_dl_tbf(ms))) {
			LOGPTBFDL(dl_tbf, LOGL_NOTICE,
				  "Got PACKET RESOURCE REQ while DL-TBF pending, killing it\n");
			tbf_free(dl_tbf);
			dl_tbf = NULL;
		}
		break;
	case PDCH_ULC_NODE_TBF_POLL:
		if (item->tbf_poll.poll_tbf->direction != GPRS_RLCMAC_UL_TBF) {
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "FN=%u PKT RESOURCE REQ: "
				"Unexpectedly received for DL TBF %s\n", fn,
				tbf_name(item->tbf_poll.poll_tbf));
			/* let common path expire the poll */
			goto return_unref;
		}
		ul_tbf = tbf_as_ul_tbf(item->tbf_poll.poll_tbf);
		if (item->tbf_poll.reason != PDCH_ULC_POLL_UL_ACK) {
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "FN=%u PKT RESOURCE REQ: "
				"Unexpectedly received, waiting for poll reason %d\n",
				fn, item->tbf_poll.reason);
			/* let common path expire the poll */
			goto return_unref;
		}
		if (tbf_ms(ul_tbf_as_tbf(ul_tbf)) != ms) {
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "FN=%u PKT RESOURCE REQ: "
				"Received from unexpected %s vs exp %s\n", fn,
				ms_name_buf(ms, buf, sizeof(buf)), ms_name(tbf_ms(ul_tbf_as_tbf(ul_tbf))));
			/* let common path expire the poll */
			goto return_unref;
		}
		/* 3GPP TS 44.060 $ 9.3.3.3 */
		LOGPTBFUL(ul_tbf, LOGL_DEBUG, "FN=%u PKT RESOURCE REQ: "
			"MS requests reuse of finished UL TBF in RRBP "
			"block of final UL ACK/NACK\n", fn);
		ul_tbf->n_reset(N3103);
		pdch_ulc_release_node(ulc, item);
		rc = osmo_fsm_inst_dispatch(ul_tbf->state_fi, TBF_EV_FINAL_UL_ACK_CONFIRMED, (void*)true);
		if (rc) {
			/* FSM failed handling, get rid of previous finished UL TBF before providing a new one */
			LOGPTBFUL(ul_tbf, LOGL_NOTICE,
					"Got PACKET RESOURCE REQ while TBF not finished, killing pending UL TBF\n");
			tbf_free(ul_tbf);
		} /* else: ul_tbf has been freed by state_fsm */
		ul_tbf = NULL;
		break;
	default:
		OSMO_ASSERT(0);
	}

	/* Here ul_tbf is NULL:
	 * - USF case: Previous TBF is explicitly freed (FIXME: this is incorrect, old TBF should be kept in this case)
	 * - SBA case: no previous TBF
	 * - POLL case: PktResReq is a final ACk confirmation and ul_tbf was freed
	 */

	if (request->Exist_MS_Radio_Access_capability2) {
		uint8_t ms_class, egprs_ms_class;
		ms_class = get_ms_class_by_capability(&request->MS_Radio_Access_capability2);
		egprs_ms_class = get_egprs_ms_class_by_capability(&request->MS_Radio_Access_capability2);
		if (ms_class)
			ms_set_ms_class(ms, ms_class);
		if (egprs_ms_class)
			ms_set_egprs_ms_class(ms, egprs_ms_class);
	}

	/* get measurements */
	get_meas(meas, request);
	ms_update_l1_meas(ms, meas);

	new_ul_tbf = ms_new_ul_tbf_assigned_pacch(ms, trx_no());
	if (!new_ul_tbf) {
		ms_new_ul_tbf_rejected_pacch(ms, this);
		goto return_unref;
	}

	/* Set control TS to the TS where this PktResReq was received,
	 * which in practice happens to be the control_ts from the
	 * previous UL-TBF or SBA. When CTRL ACK is received as RRBP of the Pkt
	 * UL Ass scheduled below, then TBF_EV_ASSIGN_ACK_PACCH will be
	 * sent to tbf_fsm which will call tbf_assign_control_ts(),
	 * effectively setting back control_ts to tbf->initial_common_ts.
	 */
	LOGPTBF(new_ul_tbf, LOGL_INFO, "Change control TS %s -> %s until assignment is complete.\n",
		new_ul_tbf->control_ts ? pdch_name_buf(new_ul_tbf->control_ts, buf, sizeof(buf)) : "(none)",
		pdch_name(this));

	new_ul_tbf->control_ts = this;
	/* schedule uplink assignment */
	osmo_fsm_inst_dispatch(new_ul_tbf->ul_ass_fsm.fi, TBF_UL_ASS_EV_SCHED_ASS, NULL);
return_unref:
	ms_unref(ms, __func__);
	return;
}

void gprs_rlcmac_pdch::rcv_measurement_report(Packet_Measurement_Report_t *report, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;
	struct pdch_ulc_node *poll;
	GprsMs *ms;
	bool ms_allocated = false;

	ms = bts_get_ms_by_tlli(bts(), report->TLLI, GSM_RESERVED_TMSI);
	if (!ms) {
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "MS send measurement "
			"but TLLI 0x%08x is unknown\n", report->TLLI);
		ms = ms_alloc(bts(), __func__);
		ms_set_tlli(ms, report->TLLI);
		/* Track that we need to free ref at the end: */
		ms_allocated = true;
	}
	if ((poll = pdch_ulc_get_node(ulc, fn))) {
		switch (poll->type) {
		case PDCH_ULC_NODE_TBF_USF:
			pdch_ulc_release_fn(ulc, fn);
			break;
		case PDCH_ULC_NODE_TBF_POLL:
			LOGPDCH(this, DRLCMAC, LOGL_INFO, "FN=%" PRIu32 " Rx Meas Report "
				"on RRBP POLL, this probably means a DL/CTRL ACK/NACk will "
				"need to be polled again later\n", fn);
			pdch_ulc_release_fn(ulc, fn);
			break;
		case PDCH_ULC_NODE_SBA:
			sba = poll->sba.sba;
			ms_set_ta(ms, sba->ta);
			sba_free(sba);
			break;
		}
	}
	gprs_rlcmac_meas_rep(ms, report);
	if (ms_allocated)
		ms_unref(ms, __func__);
}

void gprs_rlcmac_pdch::rcv_cell_change_notification(Packet_Cell_Change_Notification_t *notif,
						    uint32_t fn, struct pcu_l1_meas *meas)
{
	GprsMs *ms;

	bts_do_rate_ctr_inc(bts(), CTR_PKT_CELL_CHG_NOTIFICATION);

	if (notif->Global_TFI.UnionType == 0) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = ul_tbf_by_tfi(notif->Global_TFI.u.UPLINK_TFI);
		if (!ul_tbf) {
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "UL TBF TFI=0x%2x not found\n", notif->Global_TFI.u.UPLINK_TFI);
			return;
		}
		ms = ul_tbf->ms();
	} else if (notif->Global_TFI.UnionType == 1) {
		struct gprs_rlcmac_dl_tbf *dl_tbf = dl_tbf_by_tfi(notif->Global_TFI.u.DOWNLINK_TFI);
		if (!dl_tbf) {
			LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "DL TBF TFI=0x%2x not found\n", notif->Global_TFI.u.DOWNLINK_TFI);
			return;
		}
		ms = dl_tbf->ms();
	} else { OSMO_ASSERT(0); }

	pdch_ulc_release_fn(ulc, fn);

	ms_update_l1_meas(ms, meas);
	ms_nacc_start(ms, notif);
}

/* Received Uplink RLC control block. */
int gprs_rlcmac_pdch::rcv_control_block(const uint8_t *data, uint8_t data_len,
					uint32_t fn, struct pcu_l1_meas *meas, enum CodingScheme cs)
{
	bitvec *rlc_block;
	RlcMacUplink_t *ul_control_block;
	unsigned len = mcs_max_bytes_ul(cs);
	int rc;

	if (!(rlc_block = bitvec_alloc(len, tall_pcu_ctx)))
		return -ENOMEM;
	bitvec_unpack(rlc_block, data);
	ul_control_block = (RlcMacUplink_t *)talloc_zero(tall_pcu_ctx, RlcMacUplink_t);

	LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "FN=%u +++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n", fn);

	rc = decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	if (ul_control_block->u.MESSAGE_TYPE == MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK)
		bts_send_gsmtap_meas(bts(), PCU_GSMTAP_C_UL_DUMMY, true, trx_no(), ts_no, GSMTAP_CHANNEL_PACCH, fn, data, data_len, meas);
	else
		bts_send_gsmtap_meas(bts(), PCU_GSMTAP_C_UL_CTRL, true, trx_no(), ts_no, GSMTAP_CHANNEL_PACCH, fn, data, data_len, meas);

	if (rc < 0) {
		LOGPDCH(this, DRLCMACUL, LOGL_ERROR, "FN=%u Dropping Uplink Control Block "
			"with invalid content, decode failed: %d)\n", fn, rc);
		goto free_ret;
	}
	LOGPDCH(this, DRLCMAC, LOGL_DEBUG, "FN=%u ------------------------- RX : Uplink Control Block -------------------------\n", fn);

	bts_do_rate_ctr_inc(bts(), CTR_RLC_RECV_CONTROL);
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		rcv_control_ack(&ul_control_block->u.Packet_Control_Acknowledgement, fn);
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		rcv_control_dl_ack_nack(&ul_control_block->u.Packet_Downlink_Ack_Nack, fn, meas);
		break;
	case MT_EGPRS_PACKET_DOWNLINK_ACK_NACK:
		rcv_control_egprs_dl_ack_nack(&ul_control_block->u.Egprs_Packet_Downlink_Ack_Nack, fn, meas);
		break;
	case MT_PACKET_RESOURCE_REQUEST:
		rcv_resource_request(&ul_control_block->u.Packet_Resource_Request, fn, meas);
		break;
	case MT_PACKET_MEASUREMENT_REPORT:
		rcv_measurement_report(&ul_control_block->u.Packet_Measurement_Report, fn);
		break;
	case MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK:
		/* ignoring it. change the SI to not force sending these? */
		break;
	case MT_PACKET_CELL_CHANGE_NOTIFICATION:
		rcv_cell_change_notification(&ul_control_block->u.Packet_Cell_Change_Notification, fn, meas);
		break;
	default:
		bts_do_rate_ctr_inc(bts(), CTR_DECODE_ERRORS);
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE,
			"FN=%u RX: [PCU <- BTS] unknown control block(%d) received\n",
			fn, ul_control_block->u.MESSAGE_TYPE);
	}

free_ret:
	talloc_free(ul_control_block);
	bitvec_free(rlc_block);
	return rc;
}

/* received RLC/MAC block from L1 */
int gprs_rlcmac_pdch::rcv_block(uint8_t *data, uint8_t len, uint32_t fn,
	struct pcu_l1_meas *meas)
{
	/* No successfully decoded UL block was received during this FN: */
	if (len == 0)
		return 0;

	enum CodingScheme cs = mcs_get_by_size_ul(len);
	if (!cs) {
		bts_do_rate_ctr_inc(bts(), CTR_DECODE_ERRORS);
		LOGPDCH(this, DRLCMACUL, LOGL_ERROR, "Dropping data block with invalid "
			"length %d: %s\n", len, osmo_hexdump(data, len));
		return -EINVAL;
	}

	bts_do_rate_ctr_add(bts(), CTR_RLC_UL_BYTES, len);

	LOGPDCH(this, DRLCMACUL, LOGL_DEBUG, "Got RLC block, coding scheme: %s, "
		"length: %d (%d))\n", mcs_name(cs), len, mcs_used_size_ul(cs));

	if (mcs_is_gprs(cs))
		return rcv_block_gprs(data, len, fn, meas, cs);

	if (mcs_is_edge(cs))
		return rcv_data_block(data, len, fn, meas, cs);

	bts_do_rate_ctr_inc(bts(), CTR_DECODE_ERRORS);
	LOGPDCH(this, DRLCMACUL, LOGL_ERROR, "Unsupported coding scheme %s\n",
		mcs_name(cs));
	return -EINVAL;
}

/*! \brief process egprs and gprs data blocks */
int gprs_rlcmac_pdch::rcv_data_block(uint8_t *data, uint8_t data_len, uint32_t fn,
	struct pcu_l1_meas *meas, enum CodingScheme cs)
{
	int rc;
	struct gprs_rlc_data_info rlc_dec;
	struct gprs_rlcmac_ul_tbf *tbf;
	struct pdch_ulc_node *node;
	unsigned len = mcs_size_ul(cs);

	/* These are always data blocks, since EGPRS still uses CS-1 for
	 * control blocks (see 44.060, section 10.3, 1st par.)
	 */
	if (mcs_is_edge(cs)) {
		bts_send_gsmtap_meas(bts(), PCU_GSMTAP_C_UL_DATA_EGPRS, true,
					trx_no(), ts_no, GSMTAP_CHANNEL_PDTCH, fn,
					data, data_len, meas);
	} else {
		bts_send_gsmtap_meas(bts(), PCU_GSMTAP_C_UL_DATA_GPRS, true,
					trx_no(), ts_no, GSMTAP_CHANNEL_PDTCH, fn,
					data, data_len, meas);
	}

	LOGPDCH(this, DRLCMACUL, LOGL_DEBUG, "  UL data: %s\n", osmo_hexdump(data, len));

	rc = Decoding::rlc_parse_ul_data_header(&rlc_dec, data, cs);
	if (rc < 0) {
		LOGPDCH(this, DRLCMACUL, LOGL_ERROR,
			"Got %s RLC block but header parsing has failed\n",
			mcs_name(cs));
		bts_do_rate_ctr_inc(bts(), CTR_DECODE_ERRORS);
		return rc;
	}

	LOGPDCH(this, DRLCMACUL, LOGL_INFO,
		"Got %s RLC block: "
		"R=%d, SI=%d, TFI=%d, CPS=%d, RSB=%d, "
		"rc=%d\n",
		mcs_name(cs),
		rlc_dec.r, rlc_dec.si, rlc_dec.tfi, rlc_dec.cps, rlc_dec.rsb,
		rc);

	/* find TBF inst from given TFI */
	tbf = ul_tbf_by_tfi(rlc_dec.tfi);
	if (!tbf) {
		LOGPDCH(this, DRLCMACUL, LOGL_NOTICE, "UL DATA unknown TFI=%d\n",
			rlc_dec.tfi);
		return 0;
	}

	node = pdch_ulc_get_node(ulc, fn);
	if (node) {
		switch (node->type) {
		case PDCH_ULC_NODE_TBF_USF:
			if (tbf == node->tbf_usf.ul_tbf)
				pdch_ulc_release_node(ulc, node);
			else
				LOGPDCH(this, DRLCMACUL, LOGL_NOTICE, "FN=%" PRIu32 " "
					"Rx UL DATA from unexpected %s vs expected %s\n",
					fn, tbf_name(tbf), tbf_name(node->tbf_usf.ul_tbf));
			break;
		case PDCH_ULC_NODE_TBF_POLL:
			LOGPDCH(this, DRLCMACUL, LOGL_NOTICE, "FN=%" PRIu32 " "
				"Rx UL DATA from unexpected %s vs expected POLL %s reason=%s\n",
				fn, tbf_name(tbf), tbf_name(node->tbf_poll.poll_tbf),
				get_value_string(pdch_ulc_tbf_poll_reason_names, node->tbf_poll.reason));
			break;
		case PDCH_ULC_NODE_SBA:
			LOGPDCH(this, DRLCMACUL, LOGL_NOTICE, "FN=%" PRIu32 " "
				"Rx UL DATA from unexpected %s vs expected SBA\n",
				fn, tbf_name(tbf));
			break;
		}
	} else {
		LOGPDCH(this, DRLCMACUL, LOGL_NOTICE, "FN=%" PRIu32 " "
			"Rx UL DATA from unexpected %s\n", fn, tbf_name(tbf));
	}

	/* Reset N3101 counter: */
	tbf->n_reset(N3101);

	return tbf->rcv_data_block_acknowledged(&rlc_dec, data, meas);
}

int gprs_rlcmac_pdch::rcv_block_gprs(uint8_t *data, uint8_t data_len, uint32_t fn,
	struct pcu_l1_meas *meas, enum CodingScheme cs)
{
	unsigned payload = data[0] >> 6;
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = rcv_data_block(data, data_len, fn, meas, cs);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		rc = rcv_control_block(data, data_len, fn, meas, cs);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
		break;
	default:
		LOGPDCH(this, DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload(%u).\n", payload);
		rc = -EINVAL;
	}

	return rc;
}

gprs_rlcmac_tbf *gprs_rlcmac_pdch::tbf_from_list_by_tfi(
		LListHead<gprs_rlcmac_tbf> *tbf_list, uint8_t tfi,
		enum gprs_rlcmac_tbf_direction dir)
{
	gprs_rlcmac_tbf *tbf;
	LListHead<gprs_rlcmac_tbf> *pos;

	llist_for_each(pos, tbf_list) {
		tbf = pos->entry();
		if (tbf->tfi() != tfi)
			continue;
		if (!tbf->pdch[ts_no])
			continue;
		return tbf;
	}
	return NULL;
}

gprs_rlcmac_ul_tbf *gprs_rlcmac_pdch::ul_tbf_by_tfi(uint8_t tfi)
{
	return tbf_as_ul_tbf(tbf_by_tfi(tfi, GPRS_RLCMAC_UL_TBF));
}

gprs_rlcmac_dl_tbf *gprs_rlcmac_pdch::dl_tbf_by_tfi(uint8_t tfi)
{
	return tbf_as_dl_tbf(tbf_by_tfi(tfi, GPRS_RLCMAC_DL_TBF));
}

/* lookup TBF Entity (by TFI) */
gprs_rlcmac_tbf *gprs_rlcmac_pdch::tbf_by_tfi(uint8_t tfi,
	enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;

	if (tfi >= 32)
		return NULL;

	tbf = m_tbfs[dir][tfi];

	return tbf;
}

void gprs_rlcmac_pdch::num_tbfs_update(gprs_rlcmac_tbf *tbf, bool is_attach)
{
	int threshold = is_attach ? 0 : 1;
	int inc = is_attach ? 1 : -1;
	uint8_t ul_dl_gprs = m_num_tbfs_gprs[GPRS_RLCMAC_UL_TBF] +
			     m_num_tbfs_gprs[GPRS_RLCMAC_DL_TBF];
	uint8_t ul_dl_egprs = m_num_tbfs_egprs[GPRS_RLCMAC_UL_TBF] +
			      m_num_tbfs_egprs[GPRS_RLCMAC_DL_TBF];

	/* Count PDCHs with at least one TBF as "occupied", as in
	 * 3GPP TS 52.402 § B.2.1.42-44. So if transitioning from 0 (threshold)
	 * TBFs in this PDCH to 1, increase the counter by 1 (inc). */
	if (ul_dl_gprs + ul_dl_egprs == threshold)
		bts_stat_item_add(trx->bts, STAT_PDCH_OCCUPIED, inc);

	/* Update occupied GPRS/EGPRS stats (§ B.2.1.54-55) too */
	if (tbf->is_egprs_enabled() && ul_dl_egprs == threshold)
		bts_stat_item_add(trx->bts, STAT_PDCH_OCCUPIED_EGPRS, inc);
	else if (!tbf->is_egprs_enabled() && ul_dl_gprs == threshold)
		bts_stat_item_add(trx->bts, STAT_PDCH_OCCUPIED_GPRS, inc);

	if (tbf->is_egprs_enabled())
		m_num_tbfs_egprs[tbf->direction] += inc;
	else
		m_num_tbfs_gprs[tbf->direction] += inc;
}

void gprs_rlcmac_pdch::attach_tbf(gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	if (m_tbfs[tbf->direction][tbf->tfi()])
		LOGPDCH(this, DRLCMAC, LOGL_ERROR,
			"%s has not been detached, overwriting it\n",
			m_tbfs[tbf->direction][tbf->tfi()]->name());

	num_tbfs_update(tbf, true);
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		ul_tbf = tbf_as_ul_tbf(tbf);
		m_assigned_usf |= 1 << ul_tbf->m_usf[ts_no];
	}
	m_assigned_tfi[tbf->direction] |= 1UL << tbf->tfi();
	m_tbfs[tbf->direction][tbf->tfi()] = tbf;

	LOGPDCH(this, DRLCMAC, LOGL_INFO, "Attaching %s, %d TBFs, "
		"USFs = %02x, TFIs = %08x.\n",
		tbf->name(), num_tbfs(tbf->direction),
		m_assigned_usf, m_assigned_tfi[tbf->direction]);
}

void gprs_rlcmac_pdch::detach_tbf(gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	LOGPDCH(this, DRLCMAC, LOGL_INFO, "Detaching %s, %d TBFs, "
		"USFs = %02x, TFIs = %08x.\n",
		tbf->name(), num_tbfs(tbf->direction),
		m_assigned_usf, m_assigned_tfi[tbf->direction]);

	if (tbf->is_egprs_enabled()) {
		OSMO_ASSERT(m_num_tbfs_egprs[tbf->direction] > 0);
	} else {
		OSMO_ASSERT(m_num_tbfs_gprs[tbf->direction] > 0);
	}

	num_tbfs_update(tbf, false);
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		ul_tbf = tbf_as_ul_tbf(tbf);
		m_assigned_usf &= ~(1 << ul_tbf->m_usf[ts_no]);
	}
	m_assigned_tfi[tbf->direction] &= ~(1UL << tbf->tfi());
	m_tbfs[tbf->direction][tbf->tfi()] = NULL;

	pdch_ulc_release_tbf(ulc, tbf);
}

bool gprs_rlcmac_pdch::has_gprs_only_tbf_attached() const
{
	return (m_num_tbfs_gprs[GPRS_RLCMAC_UL_TBF] +
		m_num_tbfs_gprs[GPRS_RLCMAC_DL_TBF]) > 0;
}

void gprs_rlcmac_pdch::reserve(enum gprs_rlcmac_tbf_direction dir)
{
	m_num_reserved[dir] += 1;
}

void gprs_rlcmac_pdch::unreserve(enum gprs_rlcmac_tbf_direction dir)
{
	OSMO_ASSERT(m_num_reserved[dir] > 0);
	m_num_reserved[dir] -= 1;
}

inline struct gprs_rlcmac_bts *gprs_rlcmac_pdch::bts() const
{
	return trx->bts;
}

uint8_t gprs_rlcmac_pdch::trx_no() const
{
	return trx->trx_no;
}

uint8_t gprs_rlcmac_pdch::reserve_tai(uint8_t ta)
{
	uint8_t tai;

	for (tai = 0; tai < PTCCH_TAI_NUM; tai++) {
		if (ptcch_msg[tai] == PTCCH_TAI_FREE) {
			ptcch_msg[tai] = ta;
			return tai;
		}
	}

	/* Special case: no free TAI available */
	return PTCCH_TAI_FREE;
}

void gprs_rlcmac_pdch::release_tai(uint8_t tai)
{
	OSMO_ASSERT(tai < PTCCH_TAI_NUM);
	ptcch_msg[tai] = PTCCH_TAI_FREE;
}

void gprs_rlcmac_pdch::update_ta(uint8_t tai, uint8_t ta)
{
	OSMO_ASSERT(tai < PTCCH_TAI_NUM);
	ptcch_msg[tai] = ta;
}

void pdch_free_all_tbf(struct gprs_rlcmac_pdch *pdch)
{
	struct llist_item *pos;
	struct llist_item *pos2;

	for (uint8_t tfi = 0; tfi < 32; tfi++) {
		struct gprs_rlcmac_tbf *tbf;

		tbf = pdch->ul_tbf_by_tfi(tfi);
		if (tbf)
			tbf_free(tbf);
		tbf = pdch->dl_tbf_by_tfi(tfi);
		if (tbf)
			tbf_free(tbf);
	}

	/* Some temporary dummy TBFs to tx ImmAssRej may be left linked to the
	 * PDCH, since they have no TFI assigned (see handle_tbf_reject()).
	 * Get rid of them too: */
	llist_for_each_entry_safe(pos, pos2, &pdch->trx->ul_tbfs, list) {
		struct gprs_rlcmac_ul_tbf *ul_tbf = tbf_as_ul_tbf((struct gprs_rlcmac_tbf *)pos->entry);
		if (ul_tbf->control_ts == pdch)
			tbf_free(ul_tbf);
	}
}

void pdch_disable(struct gprs_rlcmac_pdch *pdch)
{
	pdch->disable();
}

bool pdch_is_enabled(const struct gprs_rlcmac_pdch *pdch)
{
	return pdch->is_enabled();
}

/* To be called only on enabled PDCHs. Used to gather information on whether the
 * PDCH is currently unable to allocate more TBFs due to any resource being
 * full. Used by bts_all_pdch_allocated() for counting purposes. */
bool pdch_is_full(const struct gprs_rlcmac_pdch *pdch)
{
	return pdch->assigned_tfi(GPRS_RLCMAC_UL_TBF) == NO_FREE_TFI ||
	       pdch->assigned_tfi(GPRS_RLCMAC_DL_TBF) == NO_FREE_TFI ||
	       find_free_usf(pdch->assigned_usf()) < 0;
}

const char *pdch_name(const struct gprs_rlcmac_pdch *pdch)
{
	static char _pdch_name_buf[128];
	return pdch_name_buf(pdch, _pdch_name_buf, sizeof(_pdch_name_buf));
}

char *pdch_name_buf(const struct gprs_rlcmac_pdch *pdch, char *buf, size_t buf_size)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_size };
	OSMO_STRBUF_PRINTF(sb, "PDCH(bts=%" PRIu8 ",trx=%" PRIu8 ",ts=%" PRIu8 ")",
			   pdch->trx->bts->nr, pdch->trx->trx_no, pdch->ts_no);
	return buf;
}
