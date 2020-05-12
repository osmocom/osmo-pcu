/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <pdch.h>
#include <decoding.h>
#include <encoding.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_coding_scheme.h>
#include <gprs_ms.h>
#include <gprs_ms_storage.h>
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

	meas->set_ms_rx_qual(rx_qual_map[
		OSMO_MIN(rx_qual_enc, ARRAY_SIZE(rx_qual_map)-1)
		]);
}

static void get_meas(struct pcu_l1_meas *meas,
	const Packet_Resource_Request_t *qr)
{
	unsigned i;

	meas->set_ms_c_value(qr->C_VALUE);
	if (qr->Exist_SIGN_VAR)
		meas->set_ms_sign_var((qr->SIGN_VAR + 2) / 4); /* SIGN_VAR * 0.25 dB */

	for (i = 0; i < OSMO_MIN(ARRAY_SIZE(qr->I_LEVEL_TN), ARRAY_SIZE(meas->ts)); i++)
	{
		if (qr->I_LEVEL_TN[i].Exist) {
			LOGP(DRLCMAC, LOGL_INFO,
				"Packet resource request: i_level[%d] = %d\n",
				i, qr->I_LEVEL_TN[i].I_LEVEL);
			meas->set_ms_i_level(i, -2 * qr->I_LEVEL_TN[i].I_LEVEL);
		}
	}
}

static void get_meas(struct pcu_l1_meas *meas,
	const Channel_Quality_Report_t *qr)
{
	unsigned i;

	get_rx_qual_meas(meas, qr->RXQUAL);
	meas->set_ms_c_value(qr->C_VALUE);
	meas->set_ms_sign_var((qr->SIGN_VAR + 2) / 4); /* SIGN_VAR * 0.25 dB */

	for (i = 0; i < OSMO_MIN(ARRAY_SIZE(qr->Slot), ARRAY_SIZE(meas->ts)); i++)
	{
		if (qr->Slot[i].Exist) {
			LOGP(DRLCMAC, LOGL_DEBUG,
				"Channel quality report: i_level[%d] = %d\n",
				i, qr->Slot[i].I_LEVEL_TN);
			meas->set_ms_i_level(i, -2 * qr->Slot[i].I_LEVEL_TN);
		}
	}
}

static inline void sched_ul_ass_or_rej(BTS *bts, gprs_rlcmac_bts *bts_data, struct gprs_rlcmac_dl_tbf *tbf)
{
	bts->channel_request_description();

	/* This call will register the new TBF with the MS on success */
	gprs_rlcmac_ul_tbf *ul_tbf = tbf_alloc_ul(bts_data, tbf->ms(), tbf->trx->trx_no, tbf->tlli());

	/* schedule uplink assignment or reject */
	if (ul_tbf) {
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF in ack message, so we provide one:\n");
		TBF_SET_ASS_STATE_UL(tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS);
	} else {
		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF in ack message, so we packet access reject:\n");
		TBF_SET_ASS_STATE_UL(tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ);
	}
}

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
	RlcMacDownlink_t *mac_control_block;
	bitvec *pag_vec;
	struct msgb *msg;
	unsigned wp = 0, len;
	int rc;

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
	pag_vec = bitvec_alloc(23, tall_pcu_ctx);
	if (!pag_vec) {
		msgb_free(msg);
		talloc_free(pag);
		return NULL;
	}
	wp = Encoding::write_packet_paging_request(pag_vec);

	/* loop until message is full */
	while (pag) {
		LOGP(DRLCMAC, LOGL_DEBUG, "Paging MI - %s\n",
		     osmo_mi_name(pag->identity_lv + 1, pag->identity_lv[0]));

		/* try to add paging */
		if ((pag->identity_lv[1] & GSM_MI_TYPE_MASK) == GSM_MI_TYPE_TMSI) {
			/* TMSI */
			len = 1 + 1 + 1 + 32 + 2 + 1;
			if (pag->identity_lv[0] != 5) {
				LOGP(DRLCMAC, LOGL_ERROR, "TMSI paging with "
					"MI != 5 octets!\n");
				goto continue_next;
			}
		} else {
			/* MI */
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
	mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Paging Request +++++++++++++++++++++++++\n");
	rc = decode_gsm_rlcmac_downlink(pag_vec, mac_control_block);
	if (rc < 0) {
		LOGP(DRLCMAC, LOGL_ERROR, "Decoding of Downlink Packet Paging Request failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Paging Request -------------------------\n");
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);
	return msg;

free_ret:
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

bool gprs_rlcmac_pdch::add_paging(uint8_t chan_needed, const uint8_t *mi, uint8_t mi_len)
{
	struct gprs_rlcmac_paging *pag = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_paging);
	if (!pag)
		return false;

	pag->chan_needed = chan_needed;
	pag->identity_lv[0] = mi_len;
	memcpy(&pag->identity_lv[1], mi, mi_len);

	llist_add(&pag->list, &paging_list);

	return true;
}

void gprs_rlcmac_pdch::rcv_control_ack(Packet_Control_Acknowledgement_t *packet, uint32_t fn)
{
	struct gprs_rlcmac_tbf *tbf, *new_tbf;
	uint32_t tlli = packet->TLLI;
	GprsMs *ms = bts()->ms_by_tlli(tlli);
	gprs_rlcmac_ul_tbf *ul_tbf;

	tbf = bts()->ul_tbf_by_poll_fn(fn, trx_no(), ts_no);
	if (!tbf)
		tbf = bts()->dl_tbf_by_poll_fn(fn, trx_no(), ts_no);

	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
			"unknown FN=%u TLLI=0x%08x (TRX %d TS %d)\n",
			fn, tlli, trx_no(), ts_no);
		if (ms)
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET CONTROL ACK with "
			     "unknown TBF corresponds to MS with IMSI %s, TA %d, "
			     "uTBF (TFI=%d, state=%s), dTBF (TFI=%d, state=%s)\n",
			     ms->imsi(), ms->ta(),
			     ms->ul_tbf() ? ms->ul_tbf()->tfi() : 0,
			     ms->ul_tbf() ? ms->ul_tbf()->state_name() : "None",
			     ms->dl_tbf() ? ms->dl_tbf()->tfi() : 0,
			     ms->dl_tbf() ? ms->dl_tbf()->state_name() : "None");
		return;
	}

	/* Reset N3101 counter: */
	tbf->n_reset(N3101);

	tbf->update_ms(tlli, GPRS_RLCMAC_UL_TBF);

	LOGPTBF(tbf, LOGL_DEBUG, "RX: [PCU <- BTS] Packet Control Ack\n");
	TBF_POLL_SCHED_UNSET(tbf);

	/* check if this control ack belongs to packet uplink ack */
	ul_tbf = as_ul_tbf(tbf);
	if (ul_tbf && ul_tbf->handle_ctrl_ack()) {
		LOGPTBF(tbf, LOGL_DEBUG, "[UPLINK] END\n");
		if (ul_tbf->ctrl_ack_to_toggle())
			LOGPTBF(tbf, LOGL_NOTICE, "Recovered uplink ack for UL\n");

		tbf_free(tbf);
		return;
	}
	if (tbf->dl_ass_state_is(GPRS_RLCMAC_DL_ASS_WAIT_ACK)) {
		LOGPTBF(tbf, LOGL_DEBUG, "[UPLINK] DOWNLINK ASSIGNED\n");
		/* reset N3105 */
		tbf->n_reset(N3105);
		TBF_SET_ASS_STATE_DL(tbf, GPRS_RLCMAC_DL_ASS_NONE);

		new_tbf = tbf->ms() ? tbf->ms()->dl_tbf() : NULL;
		if (!new_tbf) {
			LOGP(DRLCMAC, LOGL_ERROR, "Got ACK, but DL "
				"TBF is gone TLLI=0x%08x\n", tlli);
			return;
		}
		if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE) &&
				tbf->direction == new_tbf->direction)
			tbf_free(tbf);

		if (new_tbf->check_n_clear(GPRS_RLCMAC_FLAG_CCCH)) {
			/* We now know that the PACCH really existed */
			LOGPTBF(new_tbf, LOGL_INFO,
				"The TBF has been confirmed on the PACCH, "
				"changed type from CCCH to PACCH\n");
			TBF_ASS_TYPE_SET(new_tbf, GPRS_RLCMAC_FLAG_PACCH);
		}
		TBF_SET_STATE(new_tbf, GPRS_RLCMAC_FLOW);
		/* stop pending assignment timer */
		new_tbf->t_stop(T0, "control acked (DL-TBF)");
		if (new_tbf->check_n_clear(GPRS_RLCMAC_FLAG_TO_DL_ASS))
			LOGPTBF(new_tbf, LOGL_NOTICE, "Recovered downlink assignment\n");

		tbf_assign_control_ts(new_tbf);
		return;
	}
	if (tbf->ul_ass_state_is(GPRS_RLCMAC_UL_ASS_WAIT_ACK)) {
		LOGPTBF(tbf, LOGL_DEBUG, "[DOWNLINK] UPLINK ASSIGNED\n");
		/* reset N3105 */
		tbf->n_reset(N3105);
		TBF_SET_ASS_STATE_UL(tbf, GPRS_RLCMAC_UL_ASS_NONE);

		new_tbf = tbf->ms() ? tbf->ms()->ul_tbf() : NULL;
		if (!new_tbf) {
			LOGP(DRLCMAC, LOGL_ERROR, "Got ACK, but UL "
				"TBF is gone TLLI=0x%08x\n", tlli);
			return;
		}
		if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE) &&
				tbf->direction == new_tbf->direction)
			tbf_free(tbf);

		TBF_SET_STATE(new_tbf, GPRS_RLCMAC_FLOW);
		if (new_tbf->check_n_clear(GPRS_RLCMAC_FLAG_TO_UL_ASS))
			LOGPTBF(new_tbf, LOGL_NOTICE, "Recovered uplink assignment for UL\n");

		tbf_assign_control_ts(new_tbf);
		/* there might be LLC packets waiting in the queue, but the DL
		 * TBF might have been released while the UL TBF has been
		 * established */
		if (new_tbf->ms()->need_dl_tbf())
			new_tbf->establish_dl_tbf_on_pacch();

		return;
	}
	LOGP(DRLCMAC, LOGL_ERROR, "Error: received PACET CONTROL ACK "
		"at no request\n");
}

void gprs_rlcmac_pdch::rcv_control_dl_ack_nack(Packet_Downlink_Ack_Nack_t *ack_nack, uint32_t fn, struct pcu_l1_meas *meas)
{
	int8_t tfi = 0; /* must be signed */
	struct gprs_rlcmac_dl_tbf *tbf;
	int rc;
	int num_blocks;
	uint8_t bits_data[RLC_GPRS_WS/8];
	bitvec bits;
	int bsn_begin, bsn_end;
	char show_bits[RLC_GPRS_WS + 1];

	tfi = ack_nack->DOWNLINK_TFI;
	tbf = bts()->dl_tbf_by_poll_fn(fn, trx_no(), ts_no);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
			"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
			fn, tfi, trx_no(), ts_no);
		return;
	}
	if (tbf->tfi() != tfi) {
		LOGP(DRLCMAC, LOGL_NOTICE, "PACKET DOWNLINK ACK with "
			"wrong TFI=%d, ignoring!\n", tfi);
		return;
	}

	/* Reset N3101 counter: */
	tbf->n_reset(N3101);

	if (tbf->handle_ack_nack())
		LOGPTBF(tbf, LOGL_NOTICE, "Recovered downlink ack\n");

	LOGPTBF(tbf, LOGL_DEBUG, "RX: [PCU <- BTS] Packet Downlink Ack/Nack\n");

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	num_blocks = Decoding::decode_gprs_acknack_bits(
		&ack_nack->Ack_Nack_Description, &bits,
		&bsn_begin, &bsn_end, tbf->window());

	LOGP(DRLCMAC, LOGL_DEBUG,
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
		sched_ul_ass_or_rej(bts(), bts_data(), tbf);

	/* get measurements */
	if (tbf->ms()) {
		get_meas(meas, &ack_nack->Channel_Quality_Report);
		tbf->ms()->update_l1_meas(meas);
	}
}

void gprs_rlcmac_pdch::rcv_control_egprs_dl_ack_nack(EGPRS_PD_AckNack_t *ack_nack, uint32_t fn, struct pcu_l1_meas *meas)
{
	int8_t tfi = 0; /* must be signed */
	struct gprs_rlcmac_dl_tbf *tbf;
	int rc;
	int num_blocks;
	uint8_t bits_data[RLC_EGPRS_MAX_WS/8];
	char show_bits[RLC_EGPRS_MAX_WS + 1];
	bitvec bits;
	int bsn_begin, bsn_end;

	tfi = ack_nack->DOWNLINK_TFI;
	tbf = bts()->dl_tbf_by_poll_fn(fn, trx_no(), ts_no);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "EGPRS PACKET DOWNLINK ACK with "
			"unknown FN=%u TFI=%d (TRX %d TS %d)\n",
			fn, tfi, trx_no(), ts_no);
		return;
	}
	if (tbf->tfi() != tfi) {
		LOGP(DRLCMAC, LOGL_NOTICE, "EGPRS PACKET DOWNLINK ACK with "
			"wrong TFI=%d, ignoring!\n", tfi);
		return;
	}

	/* Reset N3101 counter: */
	tbf->n_reset(N3101);

	if (tbf->handle_ack_nack())
		LOGPTBF(tbf, LOGL_NOTICE, "Recovered EGPRS downlink ack\n");

	LOGPTBF(tbf, LOGL_DEBUG,
		"RX: [PCU <- BTS] EGPRS Packet Downlink Ack/Nack\n");

	LOGP(DRLCMAC, LOGL_DEBUG, "EGPRS ACK/NACK: "
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
		tbf->window()->v_a(),
		tbf->window()->v_s(),
		osmo_hexdump((const uint8_t *)&ack_nack->EGPRS_AckNack.Desc.URBB,
			sizeof(ack_nack->EGPRS_AckNack.Desc.URBB)));

	bits.data = bits_data;
	bits.data_len = sizeof(bits_data);
	bits.cur_bit = 0;

	num_blocks = Decoding::decode_egprs_acknack_bits(
		&ack_nack->EGPRS_AckNack.Desc, &bits,
		&bsn_begin, &bsn_end, tbf->window());

	LOGP(DRLCMAC, LOGL_DEBUG,
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
		sched_ul_ass_or_rej(bts(), bts_data(), tbf);

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
	struct gprs_rlcmac_sba *sba;

	if (request->ID.UnionType) {
		struct gprs_rlcmac_ul_tbf *ul_tbf;
		struct gprs_rlcmac_dl_tbf *dl_tbf;
		uint32_t tlli = request->ID.u.TLLI;
		bool found = true;

		GprsMs *ms = bts()->ms_by_tlli(tlli);
		if (!ms) {
			found = false;
			ms = bts()->ms_alloc(0, 0); /* ms class updated later */
		}

		/* Keep the ms, even if it gets idle temporarily */
		GprsMs::Guard guard(ms);

		if (found) {
			ul_tbf = ms->ul_tbf();
			dl_tbf = ms->dl_tbf();
			/* We got a RACH so the MS was in packet idle mode and thus
			 * didn't have any active TBFs */
			if (ul_tbf) {
				LOGPTBFUL(ul_tbf, LOGL_NOTICE,
					  "Got RACH from TLLI=0x%08x while TBF still exists. Killing pending UL TBF\n",
					  tlli);
				tbf_free(ul_tbf);
			}
			if (dl_tbf) {
				LOGPTBFUL(dl_tbf, LOGL_NOTICE,
					  "Got RACH from TLLI=0x%08x while TBF still exists. Release pending DL TBF\n",
					  tlli);
				tbf_free(dl_tbf);
			}
		}

		LOGP(DRLCMAC, LOGL_DEBUG, "MS requests UL TBF "
			"in packet resource request of single "
			"block, so we provide one:\n");
		sba = bts()->sba()->find(this, fn);
		if (!sba) {
			LOGP(DRLCMAC, LOGL_NOTICE, "MS requests UL TBF "
				"in packet resource request of single "
				"block, but there is no resource request "
				"scheduled!\n");
		} else {
			ms->set_ta(sba->ta);
			bts()->sba()->free_sba(sba);
		}
		if (request->Exist_MS_Radio_Access_capability2) {
			uint8_t ms_class, egprs_ms_class;
			ms_class = Decoding::get_ms_class_by_capability(
				&request->MS_Radio_Access_capability2);
			ms->set_ms_class(ms_class);
			egprs_ms_class =
				Decoding::get_egprs_ms_class_by_capability(
					&request->MS_Radio_Access_capability2);
			ms->set_egprs_ms_class(egprs_ms_class);
		}
		if (!ms->ms_class())
			LOGP(DRLCMAC, LOGL_NOTICE, "MS does not give us a class.\n");
		if (ms->egprs_ms_class())
			LOGP(DRLCMAC, LOGL_INFO,
				"MS supports EGPRS multislot class %d.\n",
				ms->egprs_ms_class());

		ul_tbf = tbf_alloc_ul(bts_data(), ms, trx_no(), tlli);
		if (!ul_tbf) {
			handle_tbf_reject(bts_data(), ms, tlli,
				trx_no(), ts_no);
			return;
		}

		/* set control ts to current MS's TS, until assignment complete */
		LOGPTBF(ul_tbf, LOGL_DEBUG, "change control TS %d -> %d until assignment is complete.\n",
			ul_tbf->control_ts, ts_no);

		ul_tbf->control_ts = ts_no;
		/* schedule uplink assignment */
		TBF_SET_ASS_STATE_UL(ul_tbf, GPRS_RLCMAC_UL_ASS_SEND_ASS);

		/* get measurements */
		if (ul_tbf->ms()) {
			get_meas(meas, request);
			ul_tbf->ms()->update_l1_meas(meas);
		}
		return;
	}

	if (request->ID.u.Global_TFI.UnionType) {
		struct gprs_rlcmac_dl_tbf *dl_tbf;
		int8_t tfi = request->ID.u.Global_TFI.u.DOWNLINK_TFI;
		dl_tbf = bts()->dl_tbf_by_tfi(tfi, trx_no(), ts_no);
		if (!dl_tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESOURCE REQ unknown downlink TFI=%d\n", tfi);
			return;
		}
		LOGPTBFDL(dl_tbf, LOGL_ERROR,
			"RX: [PCU <- BTS] FIXME: Packet resource request\n");

		/* Reset N3101 counter: */
		dl_tbf->n_reset(N3101);
	} else {
		struct gprs_rlcmac_ul_tbf *ul_tbf;
		int8_t tfi = request->ID.u.Global_TFI.u.UPLINK_TFI;
		ul_tbf = bts()->ul_tbf_by_tfi(tfi, trx_no(), ts_no);
		if (!ul_tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESOURCE REQ unknown uplink TFI=%d\n", tfi);
			return;
		}
		LOGPTBFUL(ul_tbf, LOGL_ERROR,
			"RX: [PCU <- BTS] FIXME: Packet resource request\n");

		/* Reset N3101 counter: */
		ul_tbf->n_reset(N3101);
	}
}

void gprs_rlcmac_pdch::rcv_measurement_report(Packet_Measurement_Report_t *report, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	sba = bts()->sba()->find(this, fn);
	if (!sba) {
		LOGP(DRLCMAC, LOGL_NOTICE, "MS send measurement "
			"in packet resource request of single "
			"block, but there is no resource request "
			"scheduled! TLLI=0x%08x\n", report->TLLI);
	} else {
		GprsMs *ms = bts()->ms_store().get_ms(report->TLLI);
		if (!ms)
			LOGP(DRLCMAC, LOGL_NOTICE, "MS send measurement "
				"but TLLI 0x%08x is unknown\n", report->TLLI);
		else
			ms->set_ta(sba->ta);

		bts()->sba()->free_sba(sba);
	}
	gprs_rlcmac_meas_rep(report);
}

/* Received Uplink RLC control block. */
int gprs_rlcmac_pdch::rcv_control_block(const uint8_t *data, uint8_t data_len,
					uint32_t fn, struct pcu_l1_meas *meas, GprsCodingScheme cs)
{
	bitvec *rlc_block;
	RlcMacUplink_t *ul_control_block;
	unsigned len = cs.maxBytesUL();
	int rc;

	if (!(rlc_block = bitvec_alloc(len, tall_pcu_ctx)))
		return -ENOMEM;
	bitvec_unpack(rlc_block, data);
	ul_control_block = (RlcMacUplink_t *)talloc_zero(tall_pcu_ctx, RlcMacUplink_t);

	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");

	rc = decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	if (ul_control_block->u.MESSAGE_TYPE == MT_PACKET_UPLINK_DUMMY_CONTROL_BLOCK)
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_DUMMY, true, trx_no(), ts_no, GSMTAP_CHANNEL_PACCH, fn, data, data_len);
	else
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_CTRL, true, trx_no(), ts_no, GSMTAP_CHANNEL_PACCH, fn, data, data_len);

	if(rc < 0) {
		LOGP(DRLCMACUL, LOGL_ERROR, "Dropping Uplink Control Block with invalid "
		     "content, decode failed: %d)\n", rc);
		goto free_ret;
	}
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- RX : Uplink Control Block -------------------------\n");

	bts()->rlc_rcvd_control();
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
	default:
		bts()->decode_error();
		LOGP(DRLCMAC, LOGL_NOTICE,
			"RX: [PCU <- BTS] unknown control block(%d) received\n",
			ul_control_block->u.MESSAGE_TYPE);
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
	GprsCodingScheme cs = GprsCodingScheme::getBySizeUL(len);
	if (!cs) {
		bts()->decode_error();
		LOGP(DRLCMACUL, LOGL_ERROR, "Dropping data block with invalid"
			"length: %d)\n", len);
		return -EINVAL;
	}

	bts()->rlc_ul_bytes(len);

	LOGP(DRLCMACUL, LOGL_DEBUG, "Got RLC block, coding scheme: %s, "
		"length: %d (%d))\n", mcs_name(cs), len, cs.usedSizeUL());

	if (mcs_is_gprs(cs))
		return rcv_block_gprs(data, len, fn, meas, cs);

	if (mcs_is_edge(cs))
		return rcv_data_block(data, len, fn, meas, cs);

	bts()->decode_error();
	LOGP(DRLCMACUL, LOGL_ERROR, "Unsupported coding scheme %s\n",
		mcs_name(cs));
	return -EINVAL;
}

/*! \brief process egprs and gprs data blocks */
int gprs_rlcmac_pdch::rcv_data_block(uint8_t *data, uint8_t data_len, uint32_t fn,
	struct pcu_l1_meas *meas, GprsCodingScheme cs)
{
	int rc;
	struct gprs_rlc_data_info rlc_dec;
	struct gprs_rlcmac_ul_tbf *tbf;
	unsigned len = cs.sizeUL();

	/* These are always data blocks, since EGPRS still uses CS-1 for
	 * control blocks (see 44.060, section 10.3, 1st par.)
	 */
	if (mcs_is_edge(cs)) {
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_DATA_EGPRS, true, trx_no(), ts_no, GSMTAP_CHANNEL_PDTCH, fn,
				   data, data_len);
		if (!bts()->bts_data()->egprs_enabled) {
			LOGP(DRLCMACUL, LOGL_ERROR,
				"Got %s RLC block but EGPRS is not enabled\n",
				mcs_name(cs));
			return 0;
		}
	} else {
		bts()->send_gsmtap(PCU_GSMTAP_C_UL_DATA_GPRS, true, trx_no(), ts_no, GSMTAP_CHANNEL_PDTCH, fn,
				   data, data_len);
	}

	LOGP(DRLCMACUL, LOGL_DEBUG, "  UL data: %s\n", osmo_hexdump(data, len));

	rc = Decoding::rlc_parse_ul_data_header(&rlc_dec, data, cs);
	if (rc < 0) {
		LOGP(DRLCMACUL, LOGL_ERROR,
			"Got %s RLC block but header parsing has failed\n",
			mcs_name(cs));
		bts()->decode_error();
		return rc;
	}

	LOGP(DRLCMACUL, LOGL_INFO,
		"Got %s RLC block: "
		"R=%d, SI=%d, TFI=%d, CPS=%d, RSB=%d, "
		"rc=%d\n",
		mcs_name(cs),
		rlc_dec.r, rlc_dec.si, rlc_dec.tfi, rlc_dec.cps, rlc_dec.rsb,
		rc);

	/* find TBF inst from given TFI */
	tbf = ul_tbf_by_tfi(rlc_dec.tfi);
	if (!tbf) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA unknown TFI=%d\n",
			rlc_dec.tfi);
		return 0;
	}

	/* Reset N3101 counter: */
	tbf->n_reset(N3101);

	return tbf->rcv_data_block_acknowledged(&rlc_dec, data, meas);
}

int gprs_rlcmac_pdch::rcv_block_gprs(uint8_t *data, uint8_t data_len, uint32_t fn,
	struct pcu_l1_meas *meas, GprsCodingScheme cs)
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
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload(%u).\n", payload);
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
	return as_ul_tbf(tbf_by_tfi(tfi, GPRS_RLCMAC_UL_TBF));
}

gprs_rlcmac_dl_tbf *gprs_rlcmac_pdch::dl_tbf_by_tfi(uint8_t tfi)
{
	return as_dl_tbf(tbf_by_tfi(tfi, GPRS_RLCMAC_DL_TBF));
}

/* lookup TBF Entity (by TFI) */
gprs_rlcmac_tbf *gprs_rlcmac_pdch::tbf_by_tfi(uint8_t tfi,
	enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;

	if (tfi >= 32)
		return NULL;

	tbf = m_tbfs[dir][tfi];

	if (!tbf)
		return NULL;

	if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)) {
		return tbf;
	}

	return NULL;
}

void gprs_rlcmac_pdch::attach_tbf(gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	if (m_tbfs[tbf->direction][tbf->tfi()])
		LOGP(DRLCMAC, LOGL_ERROR, "PDCH(TS %d, TRX %d): "
			"%s has not been detached, overwriting it\n",
			ts_no, trx_no(),
			m_tbfs[tbf->direction][tbf->tfi()]->name());

	m_num_tbfs[tbf->direction] += 1;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		ul_tbf = as_ul_tbf(tbf);
		m_assigned_usf |= 1 << ul_tbf->m_usf[ts_no];
	}
	m_assigned_tfi[tbf->direction] |= 1UL << tbf->tfi();
	m_tbfs[tbf->direction][tbf->tfi()] = tbf;

	LOGP(DRLCMAC, LOGL_INFO, "PDCH(TS %d, TRX %d): Attaching %s, %d TBFs, "
		"USFs = %02x, TFIs = %08x.\n",
		ts_no, trx_no(), tbf->name(), m_num_tbfs[tbf->direction],
		m_assigned_usf, m_assigned_tfi[tbf->direction]);
}

void gprs_rlcmac_pdch::detach_tbf(gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf;

	OSMO_ASSERT(m_num_tbfs[tbf->direction] > 0);

	m_num_tbfs[tbf->direction] -= 1;
	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		ul_tbf = as_ul_tbf(tbf);
		m_assigned_usf &= ~(1 << ul_tbf->m_usf[ts_no]);
	}
	m_assigned_tfi[tbf->direction] &= ~(1UL << tbf->tfi());
	m_tbfs[tbf->direction][tbf->tfi()] = NULL;

	LOGP(DRLCMAC, LOGL_INFO, "PDCH(TS %d, TRX %d): Detaching %s, %d TBFs, "
		"USFs = %02x, TFIs = %08x.\n",
		ts_no, trx_no(), tbf->name(), m_num_tbfs[tbf->direction],
		m_assigned_usf, m_assigned_tfi[tbf->direction]);
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

inline BTS *gprs_rlcmac_pdch::bts() const
{
	return trx->bts;
}

uint8_t gprs_rlcmac_pdch::trx_no() const
{
	return trx->trx_no;
}

inline gprs_rlcmac_bts *gprs_rlcmac_pdch::bts_data() const
{
	return trx->bts->bts_data();
}

/* PTCCH (Packet Timing Advance Control Channel) */
void gprs_rlcmac_pdch::init_ptcch_msg(void)
{
	memset(ptcch_msg, PTCCH_TAI_FREE, PTCCH_TAI_NUM);
	memset(ptcch_msg + PTCCH_TAI_NUM, PTCCH_PADDING, 7);
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
