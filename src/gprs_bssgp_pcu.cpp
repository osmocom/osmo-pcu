/* gprs_bssgp_pcu.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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

struct sgsn_instance *sgsn;
void *tall_bsc_ctx;
struct bssgp_bvc_ctx *bctx = btsctx_alloc(BVCI, NSEI);

int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg, struct tlv_parsed *tp)
{
	struct bssgp_ud_hdr *budh;
	int i = 0;

	budh = (struct bssgp_ud_hdr *)msgb_bssgph(msg);
	
	struct gprs_rlcmac_tbf *tbf;
	tbf = tbf_alloc(GPRS_RLCMAC_DL_TBF, ntohl(budh->tlli));

	if (!tbf)
	{
		return -1;
	}
	/* LLC_PDU is mandatory IE */
	if (!TLVP_PRESENT(tp, BSSGP_IE_LLC_PDU))
	{
		LOGP(DBSSGP, LOGL_ERROR, "BSSGP TLLI=0x%08x Rx UL-UD missing mandatory IE\n", tbf->tlli);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
	}

	uint16_t imsi_len = 0;
	uint8_t *imsi = NULL;
	if (TLVP_PRESENT(tp, BSSGP_IE_IMSI))
	{
		imsi_len = TLVP_LEN(tp, BSSGP_IE_IMSI);
		imsi = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_IMSI);
		
		LOGPC(DBSSGP, LOGL_NOTICE, " IMSI = ");
		for (i = 0; i < imsi_len; i++)
		{
			LOGPC(DBSSGP, LOGL_NOTICE, "%02x", imsi[i]);
		}
		LOGP(DBSSGP, LOGL_NOTICE, "\n");
	}
	
	tbf_dl_establish(tbf, imsi);

	uint8_t *llc_pdu = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_LLC_PDU);
	uint16_t llc_pdu_len = TLVP_LEN(tp, BSSGP_IE_LLC_PDU);
	
	tbf_dl_data_transfer(tbf, llc_pdu, llc_pdu_len);
}


/* Receive a BSSGP PDU from a BSS on a PTP BVCI */
int gprs_bssgp_pcu_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;
	unsigned rc = 0;

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
	case BSSGP_PDUT_DL_UNITDATA:
		LOGP(DBSSGP, LOGL_NOTICE, "RX: [SGSN->PCU] BSSGP_PDUT_DL_UNITDATA\n");
		gprs_bssgp_pcu_rx_dl_ud(msg, tp);
		break;
	case BSSGP_PDUT_PAGING_PS:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_PS\n");
		break;
	case BSSGP_PDUT_PAGING_CS:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_CS\n");
		break;
	case BSSGP_PDUT_RA_CAPA_UPDATE_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_RA_CAPA_UPDATE_ACK\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_FLOW_CONTROL_BVC_ACK\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_MS_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_FLOW_CONTROL_MS_ACK\n");
		break;
	default:
		DEBUGP(DBSSGP, "BSSGP BVCI=%u PDU type 0x%02x unknown\n", bctx->bvci, pdu_type);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}
	return rc;
}

/* Receive a BSSGP PDU from a SGSN on a SIGNALLING BVCI */
int gprs_bssgp_pcu_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	int rc = 0;
	switch (bgph->pdu_type) {
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		DEBUGP(DBSSGP, "BSSGP BVCI=%u Rx BVC STATUS\n", bctx->bvci);
		/* FIXME: send NM_STATUS.ind to NM */
		break;
		case BSSGP_PDUT_SUSPEND_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SUSPEND_ACK\n");
			break;
		case BSSGP_PDUT_SUSPEND_NACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SUSPEND_NACK\n");
			break;
		case BSSGP_PDUT_BVC_RESET_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_BVC_RESET_ACK\n");
			break;
		case BSSGP_PDUT_PAGING_PS:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_PS\n");
			break;
		case BSSGP_PDUT_PAGING_CS:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_CS\n");
			break;
		case BSSGP_PDUT_RESUME_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_RESUME_ACK\n");
			break;
		case BSSGP_PDUT_RESUME_NACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_RESUME_NACK\n");
			break;
		case BSSGP_PDUT_FLUSH_LL:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_FLUSH_LL\n");
			break;
		case BSSGP_PDUT_BVC_BLOCK_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SUSPEND_ACK\n");
			break;
		case BSSGP_PDUT_BVC_UNBLOCK_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_BVC_UNBLOCK_ACK\n");
			break;
		case BSSGP_PDUT_SGSN_INVOKE_TRACE:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SGSN_INVOKE_TRACE\n");
			break;
		default:
			DEBUGP(DBSSGP, "BSSGP BVCI=%u Rx PDU type 0x%02x unknown\n", bctx->bvci, bgph->pdu_type);
			rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
			break;
	}
	return rc;
}

int gprs_bssgp_pcu_rcvmsg(struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	uint16_t ns_bvci = msgb_bvci(msg);
	int data_len;
	int rc = 0;

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

	/* look-up or create the BTS context for this BVC */
	bctx = btsctx_by_bvci_nsei(ns_bvci, msgb_nsei(msg));

	/* Only a RESET PDU can create a new BVC context */
	if (!bctx)
	{
		bctx = btsctx_alloc(ns_bvci, msgb_nsei(msg));
	}

	if (!bctx && pdu_type != BSSGP_PDUT_BVC_RESET_ACK)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "NSEI=%u/BVCI=%u Rejecting PDU "
			"type %u for unknown BVCI\n", msgb_nsei(msg), ns_bvci,
			pdu_type);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
	}

	if (bctx)
	{
		log_set_context(BSC_CTX_BVC, bctx);
		rate_ctr_inc(&bctx->ctrg->ctr[BSSGP_CTR_PKTS_IN]);
		rate_ctr_add(&bctx->ctrg->ctr[BSSGP_CTR_BYTES_IN], msgb_bssgp_len(msg));
	}

	if (ns_bvci == BVCI_SIGNALLING)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVCI_SIGNALLING gprs_bssgp_rx_sign\n");
		rc = gprs_bssgp_pcu_rx_sign(msg, &tp, bctx);
	}
	else if (ns_bvci == BVCI_PTM)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVCI_PTM bssgp_tx_status\n");
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
	}
	else
	{
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVCI_PTP gprs_bssgp_rx_ptp\n");
		rc = gprs_bssgp_pcu_rx_ptp(msg, &tp, bctx);
	}
	return rc;
}
