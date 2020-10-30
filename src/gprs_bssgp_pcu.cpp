/* gprs_bssgp_pcu.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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

#include <gprs_rlcmac.h>
#include <gprs_bssgp_pcu.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <bts.h>
#include <tbf.h>
#include <coding_scheme.h>
#include <pdch.h>
#include <decoding.h>

extern "C" {
	#include <osmocom/gsm/protocol/gsm_23_003.h>
	#include <osmocom/gprs/protocol/gsm_08_16.h>
	#include <osmocom/core/utils.h>
	#include "coding_scheme.h"
}

/* Tuning parameters for BSSGP flow control */
#define FC_DEFAULT_LIFE_TIME_SECS 10		/* experimental value, 10s */
#define FC_MS_BUCKET_SIZE_BY_BMAX(bmax) ((bmax) / 2 + 500) /* experimental */
#define FC_FALLBACK_BVC_BUCKET_SIZE 2000	/* e.g. on R = 0, value taken from PCAP files */
#define FC_MS_MAX_RX_SLOTS 4			/* limit MS default R to 4 TS per MS */

/* Constants for BSSGP flow control */
#define FC_MAX_BUCKET_LEAK_RATE (6553500 / 8)	/* Byte/s */
#define FC_MAX_BUCKET_SIZE 6553500		/* Octets */

static struct gprs_bssgp_pcu the_pcu = { 0, };

extern void *tall_pcu_ctx;
extern uint16_t spoof_mcc, spoof_mnc;
extern bool spoof_mnc_3_digits;

static void bvc_timeout(void *_priv);

static int parse_ra_cap(struct tlv_parsed *tp, MS_Radio_Access_capability_t *rac)
{
	bitvec *block;
	uint8_t cap_len;
	uint8_t *cap;

	memset(rac, 0, sizeof(*rac));

	if (!TLVP_PRESENT(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP))
		return -EINVAL;

	cap_len = TLVP_LEN(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP);
	cap = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP);

	LOGP(DBSSGP, LOGL_DEBUG, "Got BSSGP RA Capability of size %d\n", cap_len);

	block = bitvec_alloc(cap_len, tall_pcu_ctx);
	bitvec_unpack(block, cap);

	/* TS 24.008, 10.5.5.12a */
	decode_gsm_ra_cap(block, rac);

	bitvec_free(block);
	return 0;
}

static int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg, struct tlv_parsed *tp)
{
	struct bssgp_ud_hdr *budh;

	uint32_t tlli;
	uint32_t tlli_old = 0;
	uint8_t *data;
	uint16_t len;
	uint8_t ms_class = 0;
	uint8_t egprs_ms_class = 0;
	int rc;
	MS_Radio_Access_capability_t rac;
	/* TODO: is it really necessary to initialize this as a "000" IMSI? It seems, the function should just return an
	 * error if no IMSI IE was found. */
	struct osmo_mobile_identity mi_imsi = {
		.type = GSM_MI_TYPE_TMSI,
	};
	OSMO_STRLCPY_ARRAY(mi_imsi.imsi, "000");

	budh = (struct bssgp_ud_hdr *)msgb_bssgph(msg);
	tlli = ntohl(budh->tlli);

	/* LLC_PDU is mandatory IE */
	if (!TLVP_PRESENT(tp, BSSGP_IE_LLC_PDU))
	{
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP TLLI=0x%08x Rx UL-UD missing mandatory IE\n", tlli);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
	}

	data = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_LLC_PDU);
	len = TLVP_LEN(tp, BSSGP_IE_LLC_PDU);
	if (len > LLC_MAX_LEN)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP TLLI=0x%08x Rx UL-UD IE_LLC_PDU too large\n", tlli);
		return bssgp_tx_status(BSSGP_CAUSE_COND_IE_ERR, NULL, msg);
	}

	/* read IMSI. if no IMSI exists, use first paging block (any paging),
	 * because during attachment the IMSI might not be known, so the MS
	 * will listen to all paging blocks. */
	if (TLVP_PRESENT(tp, BSSGP_IE_IMSI))
	{
		rc = osmo_mobile_identity_decode(&mi_imsi, TLVP_VAL(tp, BSSGP_IE_IMSI), TLVP_LEN(tp, BSSGP_IE_IMSI),
						 true);
		if (rc < 0 || mi_imsi.type != GSM_MI_TYPE_IMSI) {
			LOGP(DBSSGP, LOGL_NOTICE, "Failed to parse IMSI IE (rc=%d)\n", rc);
			return bssgp_tx_status(BSSGP_CAUSE_COND_IE_ERR, NULL, msg);
		}
	}

	/* parse ms radio access capability */
	if (parse_ra_cap(tp, &rac) >= 0) {
		/* Get the EGPRS class from the RA capability */
		ms_class = Decoding::get_ms_class_by_capability(&rac);
		egprs_ms_class =
			Decoding::get_egprs_ms_class_by_capability(&rac);
		LOGP(DBSSGP, LOGL_DEBUG, "Got downlink MS class %d/%d\n",
			ms_class, egprs_ms_class);
	}

	/* get lifetime */
	uint16_t delay_csec = 0xffff;
	if (TLVP_PRESENT(tp, BSSGP_IE_PDU_LIFETIME))
	{
		uint8_t lt_len = TLVP_LEN(tp, BSSGP_IE_PDU_LIFETIME);
		if (lt_len == 2)
			delay_csec = tlvp_val16be(tp, BSSGP_IE_PDU_LIFETIME);
		else
			LOGP(DBSSGP, LOGL_NOTICE, "BSSGP invalid length of "
				"PDU_LIFETIME IE\n");
	} else
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP missing mandatory "
			"PDU_LIFETIME IE\n");

	/* get optional TLLI old */
	if (TLVP_PRESENT(tp, BSSGP_IE_TLLI))
	{
		uint8_t tlli_len = TLVP_LEN(tp, BSSGP_IE_PDU_LIFETIME);
		if (tlli_len == 2)
			tlli_old = tlvp_val16be(tp, BSSGP_IE_TLLI);
		else
			LOGP(DBSSGP, LOGL_NOTICE, "BSSGP invalid length of "
				"TLLI (old) IE\n");
	}

	LOGP(DBSSGP, LOGL_INFO, "LLC [SGSN -> PCU] = TLLI: 0x%08x IMSI: %s len: %d\n", tlli, mi_imsi.imsi, len);

	return gprs_rlcmac_dl_tbf::handle(the_pcu.bts, tlli, tlli_old, mi_imsi.imsi,
			ms_class, egprs_ms_class, delay_csec, data, len);
}

/* Returns 0 on success, suggested BSSGP cause otherwise */
static unsigned int get_paging_mi(struct osmo_mobile_identity *mi, const struct tlv_parsed *tp)
{
	/* Use TMSI (if present) or IMSI */
	if (TLVP_PRESENT(tp, BSSGP_IE_TMSI)) {
		/* Be safe against an evil SGSN - check the length */
		if (TLVP_LEN(tp, BSSGP_IE_TMSI) != GSM23003_TMSI_NUM_BYTES) {
			LOGP(DBSSGP, LOGL_NOTICE, "TMSI IE has odd length (!= 4)\n");
			return BSSGP_CAUSE_COND_IE_ERR;
		}

		/* NOTE: TMSI (unlike IMSI) IE comes without MI type header */
		*mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_TMSI,
		};
		mi->tmsi = osmo_load32be(TLVP_VAL(tp, BSSGP_IE_TMSI));
	} else if (TLVP_PRESENT(tp, BSSGP_IE_IMSI)) {
		int rc = osmo_mobile_identity_decode(mi, TLVP_VAL(tp, BSSGP_IE_IMSI), TLVP_LEN(tp, BSSGP_IE_IMSI),
						     true);
		if (rc < 0 || mi->type != GSM_MI_TYPE_IMSI) {
			LOGP(DBSSGP, LOGL_ERROR, "Invalid IMSI Mobile Identity\n");
			return BSSGP_CAUSE_COND_IE_ERR;
		}
	} else {
		LOGP(DBSSGP, LOGL_ERROR, "Neither TMSI IE nor IMSI IE is present\n");
		return BSSGP_CAUSE_MISSING_COND_IE;
	}

	return 0;
}

static int gprs_bssgp_pcu_rx_paging_cs(struct msgb *msg, struct tlv_parsed *tp)
{
	struct osmo_mobile_identity mi;
	int rc;

	if ((rc = get_paging_mi(&mi, tp)) > 0)
		return bssgp_tx_status((enum gprs_bssgp_cause) rc, NULL, msg);

	return BTS::main_bts()->add_paging(tlvp_val8(tp, BSSGP_IE_CHAN_NEEDED, 0), &mi);
}

static int gprs_bssgp_pcu_rx_paging_ps(struct msgb *msg, struct tlv_parsed *tp)
{
	struct osmo_mobile_identity mi_imsi;
	struct osmo_mobile_identity paging_mi;
	uint16_t pgroup;
	int rc;

	if (!TLVP_PRESENT(tp, BSSGP_IE_IMSI)) {
		LOGP(DBSSGP, LOGL_ERROR, "No IMSI\n");
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
	}

	rc = osmo_mobile_identity_decode(&mi_imsi, TLVP_VAL(tp, BSSGP_IE_IMSI), TLVP_LEN(tp, BSSGP_IE_IMSI), true);
	if (rc < 0 || mi_imsi.type != GSM_MI_TYPE_IMSI) {
		LOGP(DBSSGP, LOGL_NOTICE, "Failed to parse IMSI IE (rc=%d)\n", rc);
		return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
	}
	pgroup = imsi2paging_group(mi_imsi.imsi);
	if (pgroup > 999) {
		LOGP(DBSSGP, LOGL_NOTICE, "Failed to compute IMSI %s paging group\n", mi_imsi.imsi);
		return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
	}

	if ((rc = get_paging_mi(&paging_mi, tp)) > 0)
		return bssgp_tx_status((enum gprs_bssgp_cause) rc, NULL, msg);

	return gprs_rlcmac_paging_request(&paging_mi, pgroup);
}

/* Receive a BSSGP PDU from a BSS on a PTP BVCI */
static int gprs_bssgp_pcu_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	enum bssgp_pdu_type pdu_type = (enum bssgp_pdu_type) bgph->pdu_type;
	int bvci = bctx ? bctx->bvci : -1;
	unsigned rc = 0;

	if (!bctx)
		return -EINVAL;

	/* If traffic is received on a BVC that is marked as blocked, the
	* received PDU shall not be accepted and a STATUS PDU (Cause value:
	* BVC Blocked) shall be sent to the peer entity on the signalling BVC */
	if (bctx->state & BVC_S_BLOCKED && pdu_type != BSSGP_PDUT_STATUS)
	{
		uint16_t bvci = msgb_bvci(msg);
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVC_S_BLOCKED\n");
		return bssgp_tx_status(BSSGP_CAUSE_BVCI_BLOCKED, &bvci, msg);
	}

	switch (pdu_type) {
	case BSSGP_PDUT_STATUS:
		/* already handled in libosmogb */
		OSMO_ASSERT(0);
		break;
	case BSSGP_PDUT_DL_UNITDATA:
		LOGP(DBSSGP, LOGL_DEBUG, "Rx BSSGP BVCI=%d (PTP) DL_UNITDATA\n", bvci);
		if (the_pcu.on_dl_unit_data)
			the_pcu.on_dl_unit_data(&the_pcu, msg, tp);
		gprs_bssgp_pcu_rx_dl_ud(msg, tp);
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
	case BSSGP_PDUT_FLOW_CONTROL_MS_ACK:
		LOGP(DBSSGP, LOGL_DEBUG, "Rx BSSGP BVCI=%d (PTP) %s\n",
		     bvci, bssgp_pdu_str(pdu_type));
		break;
	case BSSGP_PDUT_PAGING_CS:
		gprs_bssgp_pcu_rx_paging_cs(msg, tp);
		break;
	case BSSGP_PDUT_PAGING_PS:
		gprs_bssgp_pcu_rx_paging_ps(msg, tp);
		break;
	case BSSGP_PDUT_RA_CAPABILITY:
	case BSSGP_PDUT_RA_CAPA_UPDATE_ACK:
		LOGP(DBSSGP, LOGL_INFO, "Rx BSSGP BVCI=%d (PTP) PDU type %s not implemented\n",
		     bvci, bssgp_pdu_str(pdu_type));
		break;
	/* See TS 08.18 5.4.1 */
	case BSSGP_PDUT_SUSPEND:
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
	case BSSGP_PDUT_FLUSH_LL:
	case BSSGP_PDUT_FLUSH_LL_ACK:
	case BSSGP_PDUT_LLC_DISCARD:
	case BSSGP_PDUT_BVC_BLOCK:
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
	case BSSGP_PDUT_BVC_RESET:
	case BSSGP_PDUT_BVC_RESET_ACK:
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		LOGP(DBSSGP, LOGL_NOTICE, "Rx BSSGP BVCI=%u (PTP) PDU type %s unexpected at PTP\n",
			bctx->bvci, bssgp_pdu_str(pdu_type));
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	default:
		LOGP(DBSSGP, LOGL_NOTICE, "Rx BSSGP BVCI=%u (PTP) PDU type %s unknown\n",
			bctx->bvci, bssgp_pdu_str(pdu_type));
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}
	return rc;
}

/* Receive a BSSGP PDU from a SGSN on a SIGNALLING BVCI */
static int gprs_bssgp_pcu_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	enum bssgp_pdu_type pdu_type = (enum bssgp_pdu_type) bgph->pdu_type;
	int rc = 0;
	int bvci = bctx ? bctx->bvci : msgb_bvci(msg);
	switch (pdu_type) {
	case BSSGP_PDUT_STATUS:
		/* already handled in libosmogb */
		OSMO_ASSERT(0);
		break;
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_BVC_BLOCK_ACK:
		LOGP(DBSSGP, LOGL_DEBUG, "Rx BSSGP BVCI=%d (SIGN) %s\n",
		     bvci, bssgp_pdu_str(pdu_type));
		break;
	case BSSGP_PDUT_BVC_RESET_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "Rx BSSGP BVCI=%d (SIGN) BVC_RESET_ACK\n", bvci);
		if (!the_pcu.bvc_sig_reset)
			the_pcu.bvc_sig_reset = 1;
		else
			the_pcu.bvc_reset = 1;
		bvc_timeout(NULL);
		break;
	case BSSGP_PDUT_PAGING_CS:
		gprs_bssgp_pcu_rx_paging_cs(msg, tp);
		break;
	case BSSGP_PDUT_PAGING_PS:
		gprs_bssgp_pcu_rx_paging_ps(msg, tp);
		break;
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "Rx BSSGP BVCI=%d (SIGN) BVC_UNBLOCK_ACK\n", bvci);
		the_pcu.bvc_unblocked = 1;
		if (the_pcu.on_unblock_ack)
			the_pcu.on_unblock_ack(&the_pcu);
		bvc_timeout(NULL);
		break;
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_NACK:
	case BSSGP_PDUT_FLUSH_LL:
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		LOGP(DBSSGP, LOGL_INFO, "Rx BSSGP BVCI=%d (SIGN) PDU type %s not implemented\n",
		     bvci, bssgp_pdu_str(pdu_type));
		break;
	/* See TS 08.18 5.4.1 */
	case BSSGP_PDUT_UL_UNITDATA:
	case BSSGP_PDUT_DL_UNITDATA:
	case BSSGP_PDUT_RA_CAPABILITY:
	case BSSGP_PDUT_PTM_UNITDATA:
	case BSSGP_PDUT_RA_CAPA_UDPATE:
	case BSSGP_PDUT_RA_CAPA_UPDATE_ACK:
	case BSSGP_PDUT_RADIO_STATUS:
	case BSSGP_PDUT_FLOW_CONTROL_BVC:
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
	case BSSGP_PDUT_FLOW_CONTROL_MS:
	case BSSGP_PDUT_FLOW_CONTROL_MS_ACK:
	case BSSGP_PDUT_DOWNLOAD_BSS_PFC:
	case BSSGP_PDUT_CREATE_BSS_PFC:
	case BSSGP_PDUT_CREATE_BSS_PFC_ACK:
	case BSSGP_PDUT_CREATE_BSS_PFC_NACK:
	case BSSGP_PDUT_MODIFY_BSS_PFC:
	case BSSGP_PDUT_MODIFY_BSS_PFC_ACK:
	case BSSGP_PDUT_DELETE_BSS_PFC:
	case BSSGP_PDUT_DELETE_BSS_PFC_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "Rx BSSGP BVCI=%d (SIGN) PDU type %s unexpected at SIGN\n",
		     bvci, bssgp_pdu_str(pdu_type));
		break;
	default:
		LOGP(DBSSGP, LOGL_NOTICE, "Rx BSSGP BVCI=%d (SIGN) PDU type %s unknown\n",
		     bvci, bssgp_pdu_str(pdu_type));
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}
	return rc;
}

static int gprs_bssgp_pcu_rcvmsg(struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	enum bssgp_pdu_type pdu_type = (enum bssgp_pdu_type) bgph->pdu_type;
	enum gprs_bssgp_cause cause = BSSGP_CAUSE_OML_INTERV;
	uint16_t ns_bvci = msgb_bvci(msg), nsei = msgb_nsei(msg);
	int data_len;
	int rc = 0;
	struct bssgp_bvc_ctx *bctx;

	if (pdu_type == BSSGP_PDUT_STATUS)
		/* Pass the message to the generic BSSGP parser, which handles
		 * STATUS and RESET messages in either direction. */
		return bssgp_rcvmsg(msg);

	/* Identifiers from DOWN: NSEI, BVCI (both in msg->cb) */

	/* UNITDATA BSSGP headers have TLLI in front */
	if (pdu_type != BSSGP_PDUT_UL_UNITDATA && pdu_type != BSSGP_PDUT_DL_UNITDATA)
	{
		data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
		rc = bssgp_tlv_parse(&tp, bgph->data, data_len);
	}
	else
	{
		data_len = msgb_bssgp_len(msg) - sizeof(*budh);
		rc = bssgp_tlv_parse(&tp, budh->data, data_len);
	}
	if (rc < 0) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to parse BSSGP %s message. Invalid message was: %s\n",
		     bssgp_pdu_str(pdu_type), msgb_hexdump(msg));
		return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
	}

	if (pdu_type == BSSGP_PDUT_BVC_RESET) {
		rc = bssgp_rcvmsg(msg);
		if (ns_bvci != BVCI_SIGNALLING)
			return rc;

		if (TLVP_PRES_LEN(&tp, BSSGP_IE_CAUSE, 1))
			cause = (enum gprs_bssgp_cause)*TLVP_VAL(&tp, BSSGP_IE_CAUSE);
		else
			LOGP(DBSSGP, LOGL_ERROR, "NSEI=%u BVC RESET without cause?!\n", nsei);

		rc = bssgp_tx_bvc_ptp_reset(nsei, cause);
		if (rc < 0)
			LOGP(DBSSGP, LOGL_ERROR, "NSEI=%u BVC PTP reset procedure failed: %d\n", nsei, rc);

		return rc;
	}

	/* look-up or create the BTS context for this BVC */
	bctx = btsctx_by_bvci_nsei(ns_bvci, msgb_nsei(msg));

	if (!bctx && ns_bvci != BVCI_SIGNALLING)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "NSEI=%u/BVCI=%u Rejecting PDU type %s for unknown BVCI\n",
		     nsei, ns_bvci, bssgp_pdu_str(pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
	}

	if (bctx)
	{
		log_set_context(LOG_CTX_GB_BVC, bctx);
		rate_ctr_inc(&bctx->ctrg->ctr[BSSGP_CTR_PKTS_IN]);
		rate_ctr_add(&bctx->ctrg->ctr[BSSGP_CTR_BYTES_IN], msgb_bssgp_len(msg));
	}

	if (ns_bvci == BVCI_SIGNALLING)
	{
		LOGP(DBSSGP, LOGL_DEBUG, "rx BVCI_SIGNALLING gprs_bssgp_rx_sign\n");
		rc = gprs_bssgp_pcu_rx_sign(msg, &tp, bctx);
	}
	else if (ns_bvci == BVCI_PTM)
	{
		LOGP(DBSSGP, LOGL_DEBUG, "rx BVCI_PTM bssgp_tx_status\n");
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
	}
	else
	{
		LOGP(DBSSGP, LOGL_DEBUG, "rx BVCI_PTP=%u gprs_bssgp_rx_ptp\n", ns_bvci);
		rc = gprs_bssgp_pcu_rx_ptp(msg, &tp, bctx);
	}
	return rc;
}

static void handle_nm_status(struct osmo_bssgp_prim *bp)
{
	enum gprs_bssgp_cause cause;

	LOGP(DPCU, LOGL_DEBUG,
		"Got NM-STATUS.ind, BVCI=%d, NSEI=%d\n",
		bp->bvci, bp->nsei);

	if (!TLVP_PRESENT(bp->tp, BSSGP_IE_CAUSE))
		return;

	cause = (enum gprs_bssgp_cause)*TLVP_VAL(bp->tp, BSSGP_IE_CAUSE);

	if (cause != BSSGP_CAUSE_BVCI_BLOCKED &&
		cause != BSSGP_CAUSE_UNKNOWN_BVCI)
		return;

	if (!TLVP_PRESENT(bp->tp, BSSGP_IE_BVCI))
		return;

	if (gprs_bssgp_pcu_current_bctx()->bvci != bp->bvci) {
		LOGP(DPCU, LOGL_NOTICE,
			"Received BSSGP STATUS message for an unknown BVCI (%d), "
			"ignored\n",
			bp->bvci);
		return;
	}

	switch (cause) {
	case BSSGP_CAUSE_BVCI_BLOCKED:
		if (the_pcu.bvc_unblocked) {
			the_pcu.bvc_unblocked = 0;
			bvc_timeout(NULL);
		}
		break;

	case BSSGP_CAUSE_UNKNOWN_BVCI:
		if (the_pcu.bvc_reset) {
			the_pcu.bvc_reset = 0;
			bvc_timeout(NULL);
		}
		break;
	default:
		break;
	}
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_bssgp_prim *bp;
	bp = container_of(oph, struct osmo_bssgp_prim, oph);

	switch (oph->sap) {
	case SAP_BSSGP_NM:
		if (oph->primitive == PRIM_NM_STATUS)
			handle_nm_status(bp);
		break;
	default:
		break;
	}
	return 0;
}

void gprs_ns_prim_status_cb(struct osmo_gprs_ns2_prim *nsp)
{
	switch (nsp->u.status.cause) {
	case NS_AFF_CAUSE_SNS_CONFIGURED:
		LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d SNS configured.\n", nsp->nsei);
		break;
	case NS_AFF_CAUSE_RECOVERY:
		LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became available\n", nsp->nsei);
		if (!the_pcu.nsvc_unblocked) {
			the_pcu.bvc_sig_reset = 0;
			the_pcu.bvc_reset = 0;
			the_pcu.nsvc_unblocked = 1;
			bvc_timeout(NULL);
		}
		break;
	case NS_AFF_CAUSE_FAILURE:
		LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became unavailable\n", nsp->nsei);
		if (the_pcu.nsvc_unblocked) {
			the_pcu.nsvc_unblocked = 0;
			osmo_timer_del(&the_pcu.bvc_timer);
			the_pcu.bvc_sig_reset = 0;
			the_pcu.bvc_reset = 0;
			the_pcu.bvc_unblocked = 0;
		}
		break;
	default:
		LOGP(DPCU, LOGL_NOTICE,
		     "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, nsp->oph.operation),
		     nsp->oph.primitive);
		break;
	}
}

/* called by the ns layer */
int gprs_ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_gprs_ns2_prim *nsp;
	int rc = 0;

	if (oph->sap != SAP_NS)
		return 0;

	nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	if (oph->operation != PRIM_OP_INDICATION) {
		LOGP(DPCU, LOGL_NOTICE, "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation),
		     oph->operation);
		return 0;
	}

	switch (oph->primitive) {
	case PRIM_NS_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		/* add required msg fields for Gb layer */
		msgb_bssgph(oph->msg) = oph->msg->l3h;
		msgb_bvci(oph->msg) = nsp->bvci;
		msgb_nsei(oph->msg) = nsp->nsei;
		rc = gprs_bssgp_pcu_rcvmsg(oph->msg);
		break;
	case PRIM_NS_STATUS:
		gprs_ns_prim_status_cb(nsp);
		break;
	default:
		LOGP(DPCU, LOGL_NOTICE,
		     "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation),
		     oph->primitive);
		break;
	}

	return rc;
}

/* called by the bssgp layer to send NS PDUs */
int gprs_gp_send_cb(void *ctx, struct msgb *msg)
{
	struct gprs_ns2_inst *nsi = (struct gprs_ns2_inst *) ctx;
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = msgb_nsei(msg);
	nsp.bvci = msgb_bvci(msg);
	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_UNIT_DATA,
			PRIM_OP_REQUEST, msg);
	return gprs_ns2_recv_prim(nsi, &nsp.oph);
}

static unsigned count_pdch(const struct gprs_rlcmac_bts *bts)
{
	size_t trx_no, ts_no;
	unsigned num_pdch = 0;

	for (trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); ++trx_no) {
		const struct gprs_rlcmac_trx *trx = &bts->trx[trx_no];

		for (ts_no = 0; ts_no < ARRAY_SIZE(trx->pdch); ++ts_no) {
			const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts_no];

			if (pdch->is_enabled())
				num_pdch += 1;
		}
	}

	return num_pdch;
}

static uint32_t gprs_bssgp_max_leak_rate(enum CodingScheme cs, int num_pdch)
{
	int bytes_per_rlc_block = mcs_max_data_block_bytes(cs) * num_data_blocks(mcs_header_type(cs));

	/* n byte payload per 20ms */
	return bytes_per_rlc_block * (1000 / 20) * num_pdch;
}

static uint32_t compute_bucket_size(struct gprs_rlcmac_bts *bts,
	uint32_t leak_rate, uint32_t fallback)
{
	uint32_t bucket_size = 0;
	uint16_t bucket_time = bts->fc_bucket_time;

	if (bucket_time == 0)
		bucket_time = bts->force_llc_lifetime;

	if (bucket_time == 0xffff)
		bucket_size = FC_MAX_BUCKET_SIZE;

	if (bucket_size == 0 && bucket_time && leak_rate)
		bucket_size = (uint64_t)leak_rate * bucket_time / 100;

	if (bucket_size == 0 && leak_rate)
		bucket_size = leak_rate * FC_DEFAULT_LIFE_TIME_SECS;

	if (bucket_size == 0)
		bucket_size = fallback;

	if (bucket_size > FC_MAX_BUCKET_SIZE)
		bucket_size = FC_MAX_BUCKET_SIZE;

	return bucket_size;
}

static uint32_t get_and_reset_avg_queue_delay(void)
{
	struct timespec *delay_sum = &the_pcu.queue_delay_sum;
	uint32_t delay_sum_ms = delay_sum->tv_sec * 1000 +
			delay_sum->tv_nsec / 1000000000;
	uint32_t avg_delay_ms = 0;

	if (the_pcu.queue_delay_count > 0)
		avg_delay_ms = delay_sum_ms / the_pcu.queue_delay_count;

	/* Reset accumulator */
	delay_sum->tv_sec = delay_sum->tv_nsec = 0;
	the_pcu.queue_delay_count = 0;

	return avg_delay_ms;
}

static int get_and_reset_measured_leak_rate(int *usage_by_1000, unsigned num_pdch)
{
	int rate; /* byte per second */

	if (the_pcu.queue_frames_sent == 0)
		return -1;

	if (the_pcu.queue_frames_recv == 0)
		return -1;

	*usage_by_1000 = the_pcu.queue_frames_recv * 1000 /
		the_pcu.queue_frames_sent;

	/* 20ms/num_pdch is the average RLC block duration, so the rate is
	 * calculated as:
	 * rate = bytes_recv / (block_dur * block_count) */
	rate = the_pcu.queue_bytes_recv * 1000 * num_pdch /
		(20 * the_pcu.queue_frames_recv);

	the_pcu.queue_frames_sent = 0;
	the_pcu.queue_bytes_recv = 0;
	the_pcu.queue_frames_recv = 0;

	return rate;
}

static enum CodingScheme max_coding_scheme_dl(struct gprs_rlcmac_bts *bts)
{
	int num;

	if (bts->egprs_enabled) {
		if (!bts->cs_adj_enabled) {
			if (bts->initial_mcs_dl)
				num = bts->initial_mcs_dl;
			else
				num = 1;
		} else if (bts->max_mcs_dl) {
			num = bts->max_mcs_dl;
		} else {
			num = 9;
		}

		return mcs_get_egprs_by_num(num);
	}

	if (!bts->cs_adj_enabled) {
		if (bts->initial_cs_dl)
			num = bts->initial_cs_dl;
		else if (bts->cs4)
			num = 4;
		else if (bts->cs3)
			num = 3;
		else if (bts->cs2)
			num = 2;
		else
			num = 1;
	} else if (bts->max_cs_dl) {
		num = bts->max_cs_dl;
	} else {
		num = 4;
	}

	return mcs_get_gprs_by_num(num);
}

static int gprs_bssgp_tx_fc_bvc(void)
{
	struct gprs_rlcmac_bts *bts;
	uint32_t bucket_size; /* oct */
	uint32_t ms_bucket_size; /* oct */
	uint32_t leak_rate; /* oct/s */
	uint32_t ms_leak_rate; /* oct/s */
	uint32_t avg_delay_ms;
	int num_pdch = -1;
	enum CodingScheme max_cs_dl;

	if (!the_pcu.bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	bts = bts_main_data();

	max_cs_dl = max_coding_scheme_dl(bts);

	bucket_size = bts->fc_bvc_bucket_size;
	leak_rate = bts->fc_bvc_leak_rate;
	ms_bucket_size = bts->fc_ms_bucket_size;
	ms_leak_rate = bts->fc_ms_leak_rate;

	if (leak_rate == 0) {
		int meas_rate;
		int usage; /* in 0..1000 */

		if (num_pdch < 0)
			num_pdch = count_pdch(bts);

		meas_rate = get_and_reset_measured_leak_rate(&usage, num_pdch);
		if (meas_rate > 0) {
			leak_rate = gprs_bssgp_max_leak_rate(max_cs_dl, num_pdch);
			leak_rate =
				(meas_rate * usage + leak_rate * (1000 - usage)) /
				1000;
			LOGP(DBSSGP, LOGL_DEBUG,
				"Estimated BVC leak rate = %d "
				"(measured %d, usage %d%%)\n",
				leak_rate, meas_rate, usage/10);
		}
	}

	if (leak_rate == 0) {
		if (num_pdch < 0)
			num_pdch = count_pdch(bts);

		leak_rate = gprs_bssgp_max_leak_rate(max_cs_dl, num_pdch);

		LOGP(DBSSGP, LOGL_DEBUG,
			"Computed BVC leak rate = %d, num_pdch = %d, cs = %s\n",
			leak_rate, num_pdch, mcs_name(max_cs_dl));
	};

	if (ms_leak_rate == 0) {
		int ms_num_pdch;
		int max_pdch = gprs_alloc_max_dl_slots_per_ms(bts);

		if (num_pdch < 0)
			num_pdch = count_pdch(bts);

		ms_num_pdch = num_pdch;
		if (max_pdch > FC_MS_MAX_RX_SLOTS)
			max_pdch = FC_MS_MAX_RX_SLOTS;
		if (ms_num_pdch > max_pdch)
			ms_num_pdch = max_pdch;

		ms_leak_rate = gprs_bssgp_max_leak_rate(max_cs_dl, ms_num_pdch);

		/* TODO: To properly support multiple TRX, the per MS leak rate
		 * should be derived from the max number of PDCH TS per TRX.
		 */
		LOGP(DBSSGP, LOGL_DEBUG,
			"Computed MS default leak rate = %d, ms_num_pdch = %d, "
			"cs = %s\n",
			ms_leak_rate, ms_num_pdch, mcs_name(max_cs_dl));
	};

	/* TODO: Force leak_rate to 0 on buffer bloat */

	if (bucket_size == 0)
		bucket_size = compute_bucket_size(bts, leak_rate,
			FC_FALLBACK_BVC_BUCKET_SIZE);

	if (ms_bucket_size == 0)
		ms_bucket_size = compute_bucket_size(bts, ms_leak_rate,
			FC_MS_BUCKET_SIZE_BY_BMAX(bucket_size));

	if (leak_rate > FC_MAX_BUCKET_LEAK_RATE)
		leak_rate = FC_MAX_BUCKET_LEAK_RATE;

	if (ms_leak_rate > FC_MAX_BUCKET_LEAK_RATE)
		ms_leak_rate = FC_MAX_BUCKET_LEAK_RATE;

	/* Avg queue delay monitoring */
	avg_delay_ms = get_and_reset_avg_queue_delay();

	/* Update tag */
	the_pcu.fc_tag += 1;

	LOGP(DBSSGP, LOGL_DEBUG,
		"Sending FLOW CONTROL BVC, Bmax = %d, R = %d, Bmax_MS = %d, "
		"R_MS = %d, avg_dly = %d\n",
		bucket_size, leak_rate, ms_bucket_size, ms_leak_rate,
		avg_delay_ms);

	return bssgp_tx_fc_bvc(the_pcu.bctx, the_pcu.fc_tag,
		bucket_size, leak_rate,
		ms_bucket_size, ms_leak_rate,
		NULL, &avg_delay_ms);
}

static void bvc_timeout(void *_priv)
{
	unsigned long secs;
	if (!the_pcu.bvc_sig_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI 0\n");
		bssgp_tx_bvc_reset(the_pcu.bctx, 0, BSSGP_CAUSE_OML_INTERV);
		secs = osmo_tdef_get(the_pcu.bts->T_defs_pcu, 2, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&the_pcu.bvc_timer, secs, 0);
		return;
	}

	if (!the_pcu.bvc_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI %d\n",
			the_pcu.bctx->bvci);
		bssgp_tx_bvc_reset(the_pcu.bctx, the_pcu.bctx->bvci, BSSGP_CAUSE_OML_INTERV);
		secs = osmo_tdef_get(the_pcu.bts->T_defs_pcu, 2, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&the_pcu.bvc_timer, secs, 0);
		return;
	}

	if (!the_pcu.bvc_unblocked) {
		LOGP(DBSSGP, LOGL_INFO, "Sending unblock on BVCI %d\n",
			the_pcu.bctx->bvci);
		bssgp_tx_bvc_unblock(the_pcu.bctx);
		secs = osmo_tdef_get(the_pcu.bts->T_defs_pcu, 1, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&the_pcu.bvc_timer, secs, 0);
		return;
	}

	LOGP(DBSSGP, LOGL_DEBUG, "Sending flow control info on BVCI %d\n",
		the_pcu.bctx->bvci);
	gprs_bssgp_tx_fc_bvc();
	osmo_timer_schedule(&the_pcu.bvc_timer, the_pcu.bts->fc_interval, 0);
}

static int ns_create_nsvc(struct gprs_rlcmac_bts *bts,
			  uint16_t nsei,
			  const struct osmo_sockaddr *local,
			  const struct osmo_sockaddr *remote,
			  const uint16_t *nsvci,
			  uint16_t valid)
{
	int i, rc;
	uint16_t binds = 0;
	bool nsvcs = false;
	struct gprs_ns2_vc *nsvc;
	struct gprs_ns2_vc_bind *bind[PCU_IF_NUM_NSVC] = { };

	if (!valid)
		return -1;

	for (i = 0; i < PCU_IF_NUM_NSVC; i++) {
		if (!(valid & (1 << i)))
			continue;

		if (!gprs_ns2_ip_bind_by_sockaddr(bts->nsi, &local[i])) {
			rc = gprs_ns2_ip_bind(bts->nsi, &local[i], 0, &bind[i]);
			if (rc < 0) {
				LOGP(DBSSGP, LOGL_ERROR, "Failed to bind to %s\n", osmo_sockaddr_to_str(&local[i]));
				continue;
			}
		}

		binds |= 1 << i;
	}

	if (!binds) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to bind to any NS-VC\n");
		return -1;
	}

	bts->nse = gprs_ns2_nse_by_nsei(bts->nsi, nsei);
	if (!bts->nse)
		bts->nse = gprs_ns2_create_nse(bts->nsi, nsei);

	if (!bts->nse) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NSE\n");
		gprs_ns2_free_binds(bts->nsi);
		return 1;
	}

	for (i = 0; i < PCU_IF_NUM_NSVC; i++) {
		if (!(binds & (1 << i)))
			continue;

		/* FIXME: for SNS we just use the first successful NS-VC instead of all for the initial connect */
		if (bts->gb_dialect_sns) {
			rc = gprs_ns2_ip_connect_sns(bind[i], &remote[i], nsei);
			if (!rc)
				return rc;
			else
				LOGP(DBSSGP, LOGL_ERROR, "Failed to connect to (SNS) towards SGSN %s!\n", osmo_sockaddr_to_str(&remote[i]));
		} else {
			nsvc = gprs_ns2_ip_connect(bind[i], &remote[i], bts->nse, nsvci[i]);
			if (nsvc)
				nsvcs = true;
			else
				LOGP(DBSSGP, LOGL_ERROR, "Failed to connect to towards SGSN %s!\n", osmo_sockaddr_to_str(&remote[i]));
		}
	}

	return nsvcs ? 0 : -1;
}

struct nsvc_cb {
	const struct osmo_sockaddr *local;
	const struct osmo_sockaddr *remote;
	const uint16_t *nsvci;
	/* [in] bitmask of valid nsvc in local/remote */
	uint16_t valid;
	/* [out] bitmask of found nsvcs */
	uint16_t found;
};

static int ns_conf_vc_cb(struct gprs_ns2_vc *nsvc, void *ctx)
{
	struct nsvc_cb *data = (struct nsvc_cb *) ctx;

	for (unsigned int i = 0; i < PCU_IF_NUM_NSVC; i++) {
		if (!(data->valid & (1 << i)))
			continue;
		if (data->found & (1 << i))
			continue;

		if (gprs_ns2_ip_vc_equal(nsvc, &data->local[i],
					 &data->remote[i],
					 data->nsvci[i])) {
			data->found |= 1 << i;
			return 0;
		}
	}

	/* Found an extra nsvc */
	LOGP(DBSSGP, LOGL_DEBUG, " Removing NSVC %s\n", gprs_ns2_ll_str(nsvc));
	gprs_ns2_free_nsvc(nsvc);

	return 0;
}

int gprs_ns_config(struct gprs_rlcmac_bts *bts, uint16_t nsei,
		   const struct osmo_sockaddr *local,
		   const struct osmo_sockaddr *remote,
		   uint16_t *nsvci, uint16_t valid)
{
	int rc = 0;
	if (!bts->nse) {
		/* there shouldn't any previous state. */
		gprs_ns2_free_nses(bts->nsi);
		gprs_ns2_free_binds(bts->nsi);
		rc = ns_create_nsvc(bts, nsei, local, remote, nsvci, valid);
	} else if (nsei != gprs_ns2_nse_nsei(bts->nse)) {
		/* the NSEI has changed */
		gprs_ns2_free_nses(bts->nsi);
		gprs_ns2_free_binds(bts->nsi);
		rc = ns_create_nsvc(bts, nsei, local, remote, nsvci, valid);
	} else if (bts->gb_dialect_sns) {
		/* SNS: check if the initial nsvc is the same, if not recreate it */
		const struct osmo_sockaddr *initial = gprs_ns2_nse_sns_remote(bts->nse);
		for (unsigned int i = 0; i < PCU_IF_NUM_NSVC; i++) {
			if (!(valid & (1 << i)))
				continue;

			/* found the initial - everything should be fine */
			if (!osmo_sockaddr_cmp(initial, &remote[i]))
				return 0;
		}

		gprs_ns2_free_nses(bts->nsi);
		gprs_ns2_free_binds(bts->nsi);
		rc = ns_create_nsvc(bts, nsei, local, remote, nsvci, valid);
	} else {
		/* check if all NSVC are still the same. */
		struct nsvc_cb data = {
			.local = &local[0],
			.remote = &remote[0],
			.nsvci = &nsvci[0],
			.valid = valid,
			.found = 0,
		};

		/* search the current active nsvcs */
		gprs_ns2_nse_foreach_nsvc(bts->nse, &ns_conf_vc_cb, &data);

		/* we found all our valid nsvcs and might have removed all other nsvcs */
		if (valid == data.found)
			return 0;

		/* remove all found nsvcs from the valid field */
		valid &= ~data.found;
		rc = ns_create_nsvc(bts, nsei, local, remote, nsvci, valid);
	}

	if (rc)
		LOGP(DBSSGP, LOGL_ERROR, "Failed to connect!\n");

	return rc;
}

struct gprs_bssgp_pcu *gprs_bssgp_init(
		struct gprs_rlcmac_bts *bts,
		uint16_t nsei, uint16_t bvci,
		uint16_t mcc, uint16_t mnc, bool mnc_3_digits,
		uint16_t lac, uint16_t rac, uint16_t cell_id)
{

	/* if already created... return the current address */
	if (the_pcu.bctx)
		return &the_pcu;

	the_pcu.bts = bts;
	the_pcu.bctx = btsctx_alloc(bvci, nsei);
	if (!the_pcu.bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create BSSGP context\n");
		the_pcu.bts->nse = NULL;
		return NULL;
	}
	the_pcu.bctx->ra_id.mcc = spoof_mcc ? : mcc;
	if (spoof_mnc) {
		the_pcu.bctx->ra_id.mnc = spoof_mnc;
		the_pcu.bctx->ra_id.mnc_3_digits = spoof_mnc_3_digits;
	} else {
		the_pcu.bctx->ra_id.mnc = mnc;
		the_pcu.bctx->ra_id.mnc_3_digits = mnc_3_digits;
	}
	the_pcu.bctx->ra_id.lac = lac;
	the_pcu.bctx->ra_id.rac = rac;
	the_pcu.bctx->cell_id = cell_id;

	osmo_timer_setup(&the_pcu.bvc_timer, bvc_timeout, bts);

	return &the_pcu;
}

void gprs_bssgp_destroy(struct gprs_rlcmac_bts *bts)
{
	osmo_timer_del(&the_pcu.bvc_timer);

	/* FIXME: blocking... */
	the_pcu.nsvc_unblocked = 0;
	the_pcu.bvc_sig_reset = 0;
	the_pcu.bvc_reset = 0;
	the_pcu.bvc_unblocked = 0;

	bssgp_bvc_ctx_free(the_pcu.bctx);
	the_pcu.bctx = NULL;

	gprs_ns2_free(bts->nsi);
	bts->nsi = NULL;
	bts->nse = NULL;
}

struct bssgp_bvc_ctx *gprs_bssgp_pcu_current_bctx(void)
{
	return the_pcu.bctx;
}

void gprs_bssgp_update_frames_sent()
{
	the_pcu.queue_frames_sent += 1;
}

void gprs_bssgp_update_bytes_received(unsigned bytes_recv, unsigned frames_recv)
{
	the_pcu.queue_bytes_recv += bytes_recv;
	the_pcu.queue_frames_recv += frames_recv;
}

void gprs_bssgp_update_queue_delay(const struct timespec *tv_recv,
	const struct timespec *tv_now)
{
	struct timespec *delay_sum = &the_pcu.queue_delay_sum;
	struct timespec tv_delay;

	timespecsub(tv_now, tv_recv, &tv_delay);
	timespecadd(delay_sum, &tv_delay, delay_sum);

	the_pcu.queue_delay_count += 1;
}
