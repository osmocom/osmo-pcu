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
static int bvc_sig_reset = 0, bvc_reset = 0, bvc_unblocked = 0;
extern uint16_t spoof_mcc, spoof_mnc;

struct osmo_timer_list bvc_timer;

static void bvc_timeout(void *_priv);

int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg, struct tlv_parsed *tp)
{
	struct bssgp_ud_hdr *budh;

	int8_t tfi; /* must be signed */
	uint32_t tlli;
	int i, j;
	uint8_t *data;
	uint16_t len;
	struct gprs_rlcmac_tbf *tbf;

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
	if (len > sizeof(tbf->llc_frame))
	{
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP TLLI=0x%08x Rx UL-UD IE_LLC_PDU too large\n", tlli);
		return bssgp_tx_status(BSSGP_CAUSE_COND_IE_ERR, NULL, msg);
	}

	/* read IMSI. if no IMSI exists, use first paging block (any paging),
	 * because during attachment the IMSI might not be known, so the MS
	 * will listen to all paging blocks. */
	char imsi[16] = "000";
	if (TLVP_PRESENT(tp, BSSGP_IE_IMSI))
	{
		uint8_t imsi_len = TLVP_LEN(tp, BSSGP_IE_IMSI);
		uint8_t *bcd_imsi = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_IMSI);
		if ((bcd_imsi[0] & 0x08))
			imsi_len = imsi_len * 2 - 1;
		else
			imsi_len = (imsi_len - 1) * 2;
		for (i = 0, j = 0; j < imsi_len && j < 16; j++)
		{
			if (!(j & 1)) {
				imsi[j] = (bcd_imsi[i] >> 4) + '0';
				i++;
			} else
				imsi[j] = (bcd_imsi[i] & 0xf) + '0';
		}
		imsi[j] = '\0';
	}

	/* parse ms radio access capability */
	uint8_t ms_class = 0;
	if (TLVP_PRESENT(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP))
	{
		bitvec *block;
		uint8_t cap_len = TLVP_LEN(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP);
		uint8_t *cap = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP);
		unsigned rp = 0;

		block = bitvec_alloc(cap_len);
		bitvec_unpack(block, cap);
		bitvec_read_field(block, rp, 4); // Access Technology Type
		bitvec_read_field(block, rp, 7); // Length of Access Capabilities
		bitvec_read_field(block, rp, 3); // RF Power Capability
		if (bitvec_read_field(block, rp, 1)) // A5 Bits Present
			bitvec_read_field(block, rp, 7); // A5 Bits
		bitvec_read_field(block, rp, 1); // ES IND
		bitvec_read_field(block, rp, 1); // PS
		bitvec_read_field(block, rp, 1); // VGCS
		bitvec_read_field(block, rp, 1); // VBS
		if (bitvec_read_field(block, rp, 1)) { // Multislot Cap Present
			if (bitvec_read_field(block, rp, 1)) // HSCSD Present
				bitvec_read_field(block, rp, 5); // Class
			if (bitvec_read_field(block, rp, 1)) { // GPRS Present
				ms_class = bitvec_read_field(block, rp, 5); // Class
				bitvec_read_field(block, rp, 1); // Ext.
			}
			if (bitvec_read_field(block, rp, 1)) // SMS Present
				bitvec_read_field(block, rp, 4); // SMS Value
				bitvec_read_field(block, rp, 4); // SMS Value
		}
	}
	/* get lifetime */
	uint16_t delay_csec = 0xffff;
	if (TLVP_PRESENT(tp, BSSGP_IE_PDU_LIFETIME))
	{
		uint8_t lt_len = TLVP_LEN(tp, BSSGP_IE_PDU_LIFETIME);
		uint16_t *lt = (uint16_t *) TLVP_VAL(tp, BSSGP_IE_PDU_LIFETIME);
		if (lt_len == 2)
			delay_csec = ntohs(*lt);
		else
			LOGP(DBSSGP, LOGL_NOTICE, "BSSGP invalid length of "
				"PDU_LIFETIME IE\n");
	} else
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP missing mandatory "
			"PDU_LIFETIME IE\n");

	LOGP(DBSSGP, LOGL_INFO, "LLC [SGSN -> PCU] = TLLI: 0x%08x IMSI: %s len: %d\n", tlli, imsi, len);

	/* check for existing TBF */
	if ((tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_DL_TBF))) {
		LOGP(DRLCMAC, LOGL_INFO, "TBF: APPEND TFI: %u TLLI: 0x%08x\n", tbf->tfi, tbf->tlli);
		if (tbf->state == GPRS_RLCMAC_WAIT_RELEASE) {
			LOGP(DRLCMAC, LOGL_DEBUG, "TBF in WAIT RELEASE state "
				"(T3193), so reuse TBF\n");
			memcpy(tbf->llc_frame, data, len);
			tbf->llc_length = len;
			memset(&tbf->dir.dl, 0, sizeof(tbf->dir.dl)); /* reset
								rlc states */
			tbf->state_flags = 0;
			if (!tbf->ms_class && ms_class)
				tbf->ms_class = ms_class;
			tbf_update(tbf);
			gprs_rlcmac_trigger_downlink_assignment(tbf, tbf, NULL);
		} else {
			/* the TBF exists, so we must write it in the queue
			 * we prepend lifetime in front of PDU */
			struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
			struct timeval *tv;
			struct msgb *llc_msg = msgb_alloc(len + sizeof(*tv),
				"llc_pdu_queue");
			if (!llc_msg)
				return -ENOMEM;
			tv = (struct timeval *)msgb_put(llc_msg, sizeof(*tv));
			if (bts->force_llc_lifetime)
				delay_csec = bts->force_llc_lifetime;
			/* keep timestap at 0 for infinite delay */
			if (delay_csec != 0xffff) {
				/* calculate timestamp of timeout */
				gettimeofday(tv, NULL);
				tv->tv_usec += (delay_csec % 100) * 10000;
				tv->tv_sec += delay_csec / 100;
				if (tv->tv_usec > 999999) {
					tv->tv_usec -= 1000000;
					tv->tv_sec++;
				}
			}
			memcpy(msgb_put(llc_msg, len), data, len);
			msgb_enqueue(&tbf->llc_queue, llc_msg);
			/* set ms class for updating TBF */
			if (!tbf->ms_class && ms_class)
				tbf->ms_class = ms_class;
		}
	} else {
		uint8_t trx, ts, use_trx, first_ts, ta, ss;
		struct gprs_rlcmac_tbf *old_tbf;

		/* check for uplink data, so we copy our informations */
		tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
		if (tbf && tbf->dir.ul.contention_resolution_done
		 && !tbf->dir.ul.final_ack_sent) {
			use_trx = tbf->trx;
			first_ts = tbf->first_ts;
			ta = tbf->ta;
			ss = 0;
			old_tbf = tbf;
		} else {
			use_trx = -1;
			first_ts = -1;
			ta = 0; /* FIXME: initial TA */
			ss = 1; /* PCH assignment only allows one timeslot */
			old_tbf = NULL;
		}

		// Create new TBF (any TRX)
		tfi = tfi_alloc(GPRS_RLCMAC_DL_TBF, &trx, &ts, use_trx, first_ts);
		if (tfi < 0) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
			/* FIXME: send reject */
			return -EBUSY;
		}
		/* set number of downlink slots according to multislot class */
		tbf = tbf_alloc(tbf, GPRS_RLCMAC_DL_TBF, tfi, trx, ts, ms_class,
			ss);
		if (!tbf) {
			LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
			/* FIXME: send reject */
			return -EBUSY;
		}
		tbf->tlli = tlli;
		tbf->tlli_valid = 1;
		tbf->ta = ta;

		LOGP(DRLCMAC, LOGL_DEBUG, "TBF: [DOWNLINK] START TFI: %d TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);

		/* new TBF, so put first frame */
		memcpy(tbf->llc_frame, data, len);
		tbf->llc_length = len;

		/* trigger downlink assignment and set state to ASSIGN.
		 * we don't use old_downlink, so the possible uplink is used
		 * to trigger downlink assignment. if there is no uplink,
		 * AGCH is used. */
		gprs_rlcmac_trigger_downlink_assignment(tbf, old_tbf, imsi);
	}

	return 0;
}

/* Receive a BSSGP PDU from a BSS on a PTP BVCI */
int gprs_bssgp_pcu_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;
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
	case BSSGP_PDUT_DL_UNITDATA:
		LOGP(DBSSGP, LOGL_DEBUG, "RX: [SGSN->PCU] BSSGP_PDUT_DL_UNITDATA\n");
		gprs_bssgp_pcu_rx_dl_ud(msg, tp);
		break;
	case BSSGP_PDUT_PAGING_PS:
		LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_PAGING_PS\n");
		break;
	case BSSGP_PDUT_PAGING_CS:
		LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_PAGING_CS\n");
		break;
	case BSSGP_PDUT_RA_CAPA_UPDATE_ACK:
		LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_RA_CAPA_UPDATE_ACK\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
		LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_FLOW_CONTROL_BVC_ACK\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_MS_ACK:
		LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_FLOW_CONTROL_MS_ACK\n");
		break;
	default:
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP BVCI=%u PDU type 0x%02x unknown\n", bctx->bvci, pdu_type);
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
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_SUSPEND_ACK\n");
			break;
		case BSSGP_PDUT_SUSPEND_NACK:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_SUSPEND_NACK\n");
			break;
		case BSSGP_PDUT_BVC_RESET_ACK:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_BVC_RESET_ACK\n");
			if (!bvc_sig_reset)
				bvc_sig_reset = 1;
			else
				bvc_reset = 1;
			bvc_timeout(NULL);
			break;
		case BSSGP_PDUT_PAGING_PS:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_PAGING_PS\n");
			break;
		case BSSGP_PDUT_PAGING_CS:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_PAGING_CS\n");
			break;
		case BSSGP_PDUT_RESUME_ACK:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_RESUME_ACK\n");
			break;
		case BSSGP_PDUT_RESUME_NACK:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_RESUME_NACK\n");
			break;
		case BSSGP_PDUT_FLUSH_LL:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_FLUSH_LL\n");
			break;
		case BSSGP_PDUT_BVC_BLOCK_ACK:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_SUSPEND_ACK\n");
			break;
		case BSSGP_PDUT_BVC_UNBLOCK_ACK:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_BVC_UNBLOCK_ACK\n");
			bvc_unblocked = 1;
			bvc_timeout(NULL);
			break;
		case BSSGP_PDUT_SGSN_INVOKE_TRACE:
			LOGP(DBSSGP, LOGL_DEBUG, "rx BSSGP_PDUT_SGSN_INVOKE_TRACE\n");
			break;
		default:
			LOGP(DBSSGP, LOGL_NOTICE, "BSSGP BVCI=%u Rx PDU type 0x%02x unknown\n", bctx->bvci, bgph->pdu_type);
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

	if (!bctx
	 && pdu_type != BSSGP_PDUT_BVC_RESET_ACK
	 && pdu_type != BSSGP_PDUT_BVC_UNBLOCK_ACK)
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
		LOGP(DBSSGP, LOGL_DEBUG, "rx BVCI_PTP gprs_bssgp_rx_ptp\n");
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
		LOGP(DPCU, LOGL_NOTICE, "RLCMAC: Unknown event %u from NS\n", event);
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
			LOGP(DPCU, LOGL_NOTICE, "NS-VC %d is unblocked.\n",
				nsvc->nsvci);
			bvc_sig_reset = 0;
			bvc_reset = 0;
			bvc_unblocked = 0;
			bvc_timeout(NULL);
		}
		break;
	case S_NS_BLOCK:
		if (nsvc_unblocked) {
			nsvc_unblocked = 0;
			if (osmo_timer_pending(&bvc_timer))
				osmo_timer_del(&bvc_timer);
			bvc_sig_reset = 0;
			bvc_reset = 0;
			bvc_unblocked = 0;
			LOGP(DPCU, LOGL_NOTICE, "NS-VC is blocked.\n");
		}
		break;
	}

	return 0;
}

int gprs_bssgp_tx_fc_bvc(void)
{
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	/* FIXME: use real values */
	return bssgp_tx_fc_bvc(bctx, 1, 6553500, 819100, 50000, 50000,
		NULL, NULL);
//	return bssgp_tx_fc_bvc(bctx, 1, 84000, 25000, 48000, 45000,
//		NULL, NULL);
}

static void bvc_timeout(void *_priv)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;

	if (!bvc_sig_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI 0\n");
		bssgp_tx_bvc_reset(bctx, 0, BSSGP_CAUSE_OML_INTERV);
		osmo_timer_schedule(&bvc_timer, 1, 0);
		return;
	}

	if (!bvc_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI %d\n",
			bctx->bvci);
		bssgp_tx_bvc_reset(bctx, bctx->bvci, BSSGP_CAUSE_OML_INTERV);
		osmo_timer_schedule(&bvc_timer, 1, 0);
		return;
	}

	if (!bvc_unblocked) {
		LOGP(DBSSGP, LOGL_INFO, "Sending unblock on BVCI %d\n",
			bctx->bvci);
		bssgp_tx_bvc_unblock(bctx);
		osmo_timer_schedule(&bvc_timer, 1, 0);
		return;
	}

	LOGP(DBSSGP, LOGL_DEBUG, "Sending flow control info on BVCI %d\n",
		bctx->bvci);
	gprs_bssgp_tx_fc_bvc();
	osmo_timer_schedule(&bvc_timer, bts->fc_interval, 0);
}

/* create BSSGP/NS layer instances */
int gprs_bssgp_create(uint32_t sgsn_ip, uint16_t sgsn_port, uint16_t nsei,
	uint16_t nsvci, uint16_t bvci, uint16_t mcc, uint16_t mnc, uint16_t lac,
	uint16_t rac, uint16_t cell_id)
{
	struct sockaddr_in dest;

	mcc = ((mcc & 0xf00) >> 8) * 100 + ((mcc & 0x0f0) >> 4) * 10 + (mcc & 0x00f);
	mnc = ((mnc & 0xf00) >> 8) * 100 + ((mnc & 0x0f0) >> 4) * 10 + (mnc & 0x00f);
	cell_id = ntohs(cell_id);

	if (bctx)
		return 0; /* if already created, must return 0: no error */

	bssgp_nsi = gprs_ns_instantiate(&sgsn_ns_cb, NULL);
	if (!bssgp_nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		return -EINVAL;
	}
	gprs_ns_nsip_listen(bssgp_nsi);

	dest.sin_family = AF_INET;
	dest.sin_port = htons(sgsn_port);
	dest.sin_addr.s_addr = htonl(sgsn_ip);

	nsvc = gprs_ns_nsip_connect(bssgp_nsi, &dest, nsei, nsvci);
	if (!nsvc) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NSVCt\n");
		gprs_ns_destroy(bssgp_nsi);
		bssgp_nsi = NULL;
		return -EINVAL;
	}

	bctx = btsctx_alloc(bvci, nsei);
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create BSSGP context\n");
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

	bvc_timer.cb = bvc_timeout;


	return 0;
}

void gprs_bssgp_destroy(void)
{
	if (!bssgp_nsi)
		return;

	if (osmo_timer_pending(&bvc_timer))
		osmo_timer_del(&bvc_timer);

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

