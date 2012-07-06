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
struct bssgp_bvc_ctx *bctx = NULL;
struct gprs_nsvc *nsvc = NULL;
extern uint16_t spoof_mcc, spoof_mnc;

int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg, struct tlv_parsed *tp)
{
	struct bssgp_ud_hdr *budh;
	int tfi;
	uint32_t tlli;
	int i = 0;
	uint8_t trx, ts;
	uint8_t *data;
	uint16_t len;
	struct gprs_rlcmac_tbf *tbf;

	budh = (struct bssgp_ud_hdr *)msgb_bssgph(msg);
	tlli = ntohl(budh->tlli);

	/* LLC_PDU is mandatory IE */
	if (!TLVP_PRESENT(tp, BSSGP_IE_LLC_PDU))
	{
		LOGP(DBSSGP, LOGL_ERROR, "BSSGP TLLI=0x%08x Rx UL-UD missing mandatory IE\n", tlli);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
	}

	data = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_LLC_PDU);
	len = TLVP_LEN(tp, BSSGP_IE_LLC_PDU);
	if (len > sizeof(tbf->llc_frame))
	{
		LOGP(DBSSGP, LOGL_ERROR, "BSSGP TLLI=0x%08x Rx UL-UD IE_LLC_PDU too large\n", tlli);
		return bssgp_tx_status(BSSGP_CAUSE_COND_IE_ERR, NULL, msg);
	}
	LOGP(DBSSGP, LOGL_NOTICE, "LLC PDU = (TLLI=0x%08x) %s\n", tlli, osmo_hexdump(data, len));

	uint16_t imsi_len = 0;
	uint8_t *imsi;
	if (TLVP_PRESENT(tp, BSSGP_IE_IMSI))
	{
		imsi_len = TLVP_LEN(tp, BSSGP_IE_IMSI);
		imsi = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_IMSI);
		
		LOGPC(DBSSGP, LOGL_NOTICE, " IMSI = ");
		for (i = 0; i < imsi_len; i++)
		{
			LOGPC(DBSSGP, LOGL_NOTICE, "%02x", imsi[i]);
		}
		LOGPC(DBSSGP, LOGL_NOTICE, "\n");
	}

	/* check for existing TBF */
	if ((tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_DL_TBF))) {
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] APPEND TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
		if (tbf->state == GPRS_RLCMAC_WAIT_RELEASE) {
			LOGP(DRLCMAC, LOGL_NOTICE, "TBF in WAIT RELEASE state "
				"(T3193), so reuse TBF\n");
			memcpy(tbf->llc_frame, data, len);
			tbf->llc_length = len;
			memset(&tbf->dir.dl, 0, sizeof(tbf->dir.dl)); /* reset
								rlc states */
			gprs_rlcmac_trigger_downlink_assignment(tbf, 1);
		} else {
			/* the TBF exists, so we must write it in the queue */
			struct msgb *llc_msg = msgb_alloc(len, "llc_pdu_queue");
			if (!llc_msg)
				return -ENOMEM;
			memcpy(msgb_put(llc_msg, len), data, len);
			msgb_enqueue(&tbf->llc_queue, llc_msg);
		}
	} else {
		// Create new TBF
		tfi = tfi_alloc(&trx, &ts);
		if (tfi < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
			/* FIXME: send reject */
			return -EBUSY;
		}
		tbf = tbf_alloc(tfi, trx, ts);
		tbf->direction = GPRS_RLCMAC_DL_TBF;
		tbf->tlli = tlli;
		tbf->tlli_valid = 1;

		LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] START TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);

		/* new TBF, so put first frame */
		memcpy(tbf->llc_frame, data, len);
		tbf->llc_length = len;

		/* trigger downlink assignment and set state to ASSIGN.
		 * we don't use old_downlink, so the possible uplink is used
		 * to trigger downlink assignment. if there is no uplink,
		 * AGCH is used. */
		gprs_rlcmac_trigger_downlink_assignment(tbf, 0);
	}

	return 0;
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
	struct bssgp_bvc_ctx *bctx;

	if (pdu_type == BSSGP_PDUT_STATUS) {
		LOGP(DBSSGP, LOGL_NOTICE, "NSEI=%u/BVCI=%u received STATUS\n",
			msgb_nsei(msg), ns_bvci);
		return 0;
	}

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

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}

static int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc, struct msgb *msg, uint16_t bvci)
{
	int rc = 0;
	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = gprs_bssgp_pcu_rcvmsg(msg);
		break;
	default:
		LOGP(DPCU, LOGL_ERROR, "RLCMAC: Unknown event %u from NS\n", event);
		if (msg)
			talloc_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}

static int nsvc_unblocked = 0;

static int nsvc_signal_cb(unsigned int subsys, unsigned int signal,
	void *handler_data, void *signal_data)
{
	struct ns_signal_data *nssd;

	if (subsys != SS_L_NS)
		return -EINVAL;

	nssd = (struct ns_signal_data *)signal_data;
	if (nssd->nsvc != nsvc) {
		LOGP(DPCU, LOGL_ERROR, "Signal received of unknown NSVC\n");
		return -EINVAL;
	}

	switch (signal) {
	case S_NS_UNBLOCK:
		if (!nsvc_unblocked) {
			nsvc_unblocked = 1;
			LOGP(DPCU, LOGL_NOTICE, "NS-VC is unblocked.\n");
			bssgp_tx_bvc_reset(bctx, bctx->bvci,
				BSSGP_CAUSE_PROTO_ERR_UNSPEC);
		}
		break;
	case S_NS_BLOCK:
		if (nsvc_unblocked) {
			nsvc_unblocked = 0;
			LOGP(DPCU, LOGL_NOTICE, "NS-VC is blocked.\n");
		}
		break;
	}

	return 0;
}

/* create BSSGP/NS layer instances */
int gprs_bssgp_create(uint32_t sgsn_ip, uint16_t sgsn_port, uint16_t nsei,
	uint16_t nsvci, uint16_t bvci, uint16_t mcc, uint16_t mnc, uint16_t lac,
	uint16_t rac, uint16_t cell_id)
{
	struct sockaddr_in dest;

	if (bctx)
		return 0; /* if already created, must return 0: no error */

	bssgp_nsi = gprs_ns_instantiate(&sgsn_ns_cb, NULL);
	if (!bssgp_nsi) {
		LOGP(DBSSGP, LOGL_NOTICE, "Failed to create NS instance\n");
		return -EINVAL;
	}
	gprs_ns_nsip_listen(bssgp_nsi);

	dest.sin_family = AF_INET;
	dest.sin_port = htons(sgsn_port);
	dest.sin_addr.s_addr = htonl(sgsn_ip);

	nsvc = gprs_ns_nsip_connect(bssgp_nsi, &dest, nsei, nsvci);
	if (!nsvc) {
		LOGP(DBSSGP, LOGL_NOTICE, "Failed to create NSVCt\n");
		gprs_ns_destroy(bssgp_nsi);
		bssgp_nsi = NULL;
		return -EINVAL;
	}

	bctx = btsctx_alloc(bvci, nsei);
	if (!bctx) {
		LOGP(DBSSGP, LOGL_NOTICE, "Failed to create BSSGP context\n");
		nsvc = NULL;
		gprs_ns_destroy(bssgp_nsi);
		bssgp_nsi = NULL;
		return -EINVAL;
	}
	bctx->ra_id.mcc = spoof_mcc ? : mcc;
	bctx->ra_id.mnc = spoof_mnc ? : mnc;
	bctx->ra_id.lac = lac;
	bctx->ra_id.rac = rac;
	bctx->cell_id = cell_id;

	osmo_signal_register_handler(SS_L_NS, nsvc_signal_cb, NULL);

//	bssgp_tx_bvc_reset(bctx, bctx->bvci, BSSGP_CAUSE_PROTO_ERR_UNSPEC);

	return 0;
}

void gprs_bssgp_destroy(void)
{
	if (!bssgp_nsi)
		return;

	osmo_signal_unregister_handler(SS_L_NS, nsvc_signal_cb, NULL);

	nsvc = NULL;

	/* FIXME: move this to libgb: btsctx_free() */
	llist_del(&bctx->list);
	talloc_free(bctx);
	bctx = NULL;

	/* FIXME: blocking... */

	gprs_ns_destroy(bssgp_nsi);
	bssgp_nsi = NULL;
}

