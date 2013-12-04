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
#include <bts.h>
#include <tbf.h>

static struct gprs_bssgp_pcu the_pcu = { 0, };

extern void *tall_pcu_ctx;
extern uint16_t spoof_mcc, spoof_mnc;

static void bvc_timeout(void *_priv);

static int parse_imsi(struct tlv_parsed *tp, char *imsi)
{
	uint8_t imsi_len;
	uint8_t *bcd_imsi;
	int i, j;

	if (!TLVP_PRESENT(tp, BSSGP_IE_IMSI))
		return -EINVAL;

	imsi_len = TLVP_LEN(tp, BSSGP_IE_IMSI);
	bcd_imsi = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_IMSI);

	if ((bcd_imsi[0] & 0x08))
		imsi_len = imsi_len * 2 - 1;
	else
		imsi_len = (imsi_len - 1) * 2;
	for (i = 0, j = 0; j < imsi_len && j < 15; j++)
	{
		if (!(j & 1)) {
			imsi[j] = (bcd_imsi[i] >> 4) + '0';
			i++;
		} else
			imsi[j] = (bcd_imsi[i] & 0xf) + '0';
	}
	imsi[j] = '\0';

	return 0;
}

static int parse_ra_cap_ms_class(struct tlv_parsed *tp)
{
	bitvec *block;
	unsigned rp = 0;
	uint8_t ms_class = 0;
	uint8_t cap_len;
	uint8_t *cap;

	if (!TLVP_PRESENT(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP))
		return ms_class;

	cap_len = TLVP_LEN(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP);
	cap = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_MS_RADIO_ACCESS_CAP);

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
	}

	bitvec_free(block);
	return ms_class;
}

static int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg, struct tlv_parsed *tp)
{
	struct bssgp_ud_hdr *budh;

	uint32_t tlli;
	uint8_t *data;
	uint16_t len;
	char imsi[16] = "000";

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
	if (len > sizeof(gprs_llc::frame))
	{
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP TLLI=0x%08x Rx UL-UD IE_LLC_PDU too large\n", tlli);
		return bssgp_tx_status(BSSGP_CAUSE_COND_IE_ERR, NULL, msg);
	}

	/* read IMSI. if no IMSI exists, use first paging block (any paging),
	 * because during attachment the IMSI might not be known, so the MS
	 * will listen to all paging blocks. */
	parse_imsi(tp, imsi);

	/* parse ms radio access capability */
	uint8_t ms_class = parse_ra_cap_ms_class(tp);

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

	return gprs_rlcmac_tbf::handle(the_pcu.bts, tlli, imsi, ms_class, delay_csec, data, len);
}

int gprs_bssgp_pcu_rx_paging_ps(struct msgb *msg, struct tlv_parsed *tp)
{
	char imsi[16];
	uint8_t *ptmsi = (uint8_t *) TLVP_VAL(tp, BSSGP_IE_TMSI);
	uint16_t ptmsi_len = TLVP_LEN(tp, BSSGP_IE_TMSI);

	LOGP(DBSSGP, LOGL_NOTICE, " P-TMSI = ");
	for (int i = 0; i < ptmsi_len; i++)
	{
		LOGPC(DBSSGP, LOGL_NOTICE, "%02x", ptmsi[i]);
	}
	LOGPC(DBSSGP, LOGL_NOTICE, "\n");

	if (parse_imsi(tp, imsi))
	{
		LOGP(DBSSGP, LOGL_ERROR, "No IMSI\n");
		return -EINVAL;
	}

	return gprs_rlcmac_paging_request(ptmsi, ptmsi_len, imsi);
}

/* Receive a BSSGP PDU from a BSS on a PTP BVCI */
static int gprs_bssgp_pcu_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
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
		if (the_pcu.on_dl_unit_data)
			the_pcu.on_dl_unit_data(&the_pcu, msg, tp);
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
static int gprs_bssgp_pcu_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
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
		if (!the_pcu.bvc_sig_reset)
			the_pcu.bvc_sig_reset = 1;
		else
			the_pcu.bvc_reset = 1;
		bvc_timeout(NULL);
		break;
	case BSSGP_PDUT_PAGING_PS:
		LOGP(DBSSGP, LOGL_NOTICE, "RX: [SGSN->PCU] BSSGP_PDUT_PAGING_PS\n");
		gprs_bssgp_pcu_rx_paging_ps(msg, tp);
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
		the_pcu.bvc_unblocked = 1;
		if (the_pcu.on_unblock_ack)
			the_pcu.on_unblock_ack(&the_pcu);
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

static int gprs_bssgp_pcu_rcvmsg(struct msgb *msg)
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
	 && pdu_type != BSSGP_PDUT_BVC_UNBLOCK_ACK
	 && pdu_type != BSSGP_PDUT_PAGING_PS)
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
		rc = -EIO;
		break;
	}
	return rc;
}


static int nsvc_signal_cb(unsigned int subsys, unsigned int signal,
	void *handler_data, void *signal_data)
{
	struct ns_signal_data *nssd;

	if (subsys != SS_L_NS)
		return -EINVAL;

	nssd = (struct ns_signal_data *)signal_data;
	if (nssd->nsvc != the_pcu.nsvc) {
		LOGP(DPCU, LOGL_ERROR, "Signal received of unknown NSVC\n");
		return -EINVAL;
	}

	switch (signal) {
	case S_NS_UNBLOCK:
		if (!the_pcu.nsvc_unblocked) {
			the_pcu.nsvc_unblocked = 1;
			LOGP(DPCU, LOGL_NOTICE, "NS-VC %d is unblocked.\n",
				the_pcu.nsvc->nsvci);
			the_pcu.bvc_sig_reset = 0;
			the_pcu.bvc_reset = 0;
			the_pcu.bvc_unblocked = 0;
			bvc_timeout(NULL);
		}
		break;
	case S_NS_BLOCK:
		if (the_pcu.nsvc_unblocked) {
			the_pcu.nsvc_unblocked = 0;
			osmo_timer_del(&the_pcu.bvc_timer);
			the_pcu.bvc_sig_reset = 0;
			the_pcu.bvc_reset = 0;
			the_pcu.bvc_unblocked = 0;
			LOGP(DPCU, LOGL_NOTICE, "NS-VC is blocked.\n");
		}
		break;
	}

	return 0;
}

int gprs_bssgp_tx_fc_bvc(void)
{
	if (!the_pcu.bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	/* FIXME: use real values */
	printf("FOR FLOW CONTROL: %zu\n", the_pcu.bts->bts->dl_octets_sent_reset());
	return bssgp_tx_fc_bvc(the_pcu.bctx, 1, 2250*5 , 400, 2250*5, 400,
		NULL, NULL);
}

static void bvc_timeout(void *_priv)
{
	if (!the_pcu.bvc_sig_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI 0\n");
		bssgp_tx_bvc_reset(the_pcu.bctx, 0, BSSGP_CAUSE_OML_INTERV);
		osmo_timer_schedule(&the_pcu.bvc_timer, 1, 0);
		return;
	}

	if (!the_pcu.bvc_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI %d\n",
			the_pcu.bctx->bvci);
		bssgp_tx_bvc_reset(the_pcu.bctx, the_pcu.bctx->bvci, BSSGP_CAUSE_OML_INTERV);
		osmo_timer_schedule(&the_pcu.bvc_timer, 1, 0);
		return;
	}

	if (!the_pcu.bvc_unblocked) {
		LOGP(DBSSGP, LOGL_INFO, "Sending unblock on BVCI %d\n",
			the_pcu.bctx->bvci);
		bssgp_tx_bvc_unblock(the_pcu.bctx);
		osmo_timer_schedule(&the_pcu.bvc_timer, 1, 0);
		return;
	}

	LOGP(DBSSGP, LOGL_DEBUG, "Sending flow control info on BVCI %d\n",
		the_pcu.bctx->bvci);
	gprs_bssgp_tx_fc_bvc();
	osmo_timer_schedule(&the_pcu.bvc_timer, the_pcu.bts->fc_interval, 0);
}

/* create BSSGP/NS layer instances */
struct gprs_bssgp_pcu *gprs_bssgp_create_and_connect(struct gprs_rlcmac_bts *bts,
	uint16_t local_port, uint32_t sgsn_ip,
	uint16_t sgsn_port, uint16_t nsei, uint16_t nsvci, uint16_t bvci,
	uint16_t mcc, uint16_t mnc, uint16_t lac, uint16_t rac,
	uint16_t cell_id)
{
	struct sockaddr_in dest;
	int rc;

	mcc = ((mcc & 0xf00) >> 8) * 100 + ((mcc & 0x0f0) >> 4) * 10 + (mcc & 0x00f);
	mnc = ((mnc & 0xf00) >> 8) * 100 + ((mnc & 0x0f0) >> 4) * 10 + (mnc & 0x00f);
	cell_id = ntohs(cell_id);

	/* if already created... return the current address */
	if (the_pcu.bctx)
		return &the_pcu;

	the_pcu.bts = bts;

	bssgp_nsi = gprs_ns_instantiate(&sgsn_ns_cb, tall_pcu_ctx);
	if (!bssgp_nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		return NULL;
	}
	gprs_ns_vty_init(bssgp_nsi);
	bssgp_nsi->nsip.local_port = local_port;
	rc = gprs_ns_nsip_listen(bssgp_nsi);
	if (rc < 0) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create socket\n");
		gprs_ns_destroy(bssgp_nsi);
		bssgp_nsi = NULL;
		return NULL;
	}

	dest.sin_family = AF_INET;
	dest.sin_port = htons(sgsn_port);
	dest.sin_addr.s_addr = htonl(sgsn_ip);

	the_pcu.nsvc = gprs_ns_nsip_connect(bssgp_nsi, &dest, nsei, nsvci);
	if (!the_pcu.nsvc) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NSVCt\n");
		gprs_ns_destroy(bssgp_nsi);
		bssgp_nsi = NULL;
		return NULL;
	}

	the_pcu.bctx = btsctx_alloc(bvci, nsei);
	if (!the_pcu.bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create BSSGP context\n");
		the_pcu.nsvc = NULL;
		gprs_ns_destroy(bssgp_nsi);
		bssgp_nsi = NULL;
		return NULL;
	}
	the_pcu.bctx->ra_id.mcc = spoof_mcc ? : mcc;
	the_pcu.bctx->ra_id.mnc = spoof_mnc ? : mnc;
	the_pcu.bctx->ra_id.lac = lac;
	the_pcu.bctx->ra_id.rac = rac;
	the_pcu.bctx->cell_id = cell_id;

	osmo_signal_register_handler(SS_L_NS, nsvc_signal_cb, NULL);

	the_pcu.bvc_timer.cb = bvc_timeout;


	return &the_pcu;
}

void gprs_bssgp_destroy_or_exit(void)
{
	if (the_pcu.exit_on_destroy) {
		LOGP(DBSSGP, LOGL_NOTICE, "Exiting on BSSGP destruction.\n");
		exit(0);
	}

	if (!bssgp_nsi)
		return;

	osmo_timer_del(&the_pcu.bvc_timer);

	osmo_signal_unregister_handler(SS_L_NS, nsvc_signal_cb, NULL);

	the_pcu.nsvc = NULL;

	/* FIXME: move this to libgb: btsctx_free() */
	llist_del(&the_pcu.bctx->list);
	talloc_free(the_pcu.bctx);
	the_pcu.bctx = NULL;

	/* FIXME: blocking... */
	the_pcu.nsvc_unblocked = 0;
	the_pcu.bvc_sig_reset = 0;
	the_pcu.bvc_reset = 0;
	the_pcu.bvc_unblocked = 0;	

	gprs_ns_destroy(bssgp_nsi);
	bssgp_nsi = NULL;
}

void gprs_bssgp_exit_on_destroy(void)
{
	LOGP(DBSSGP, LOGL_NOTICE, "Going to quit on BSSGP destruction\n");
	the_pcu.exit_on_destroy = 1;
}

struct bssgp_bvc_ctx *gprs_bssgp_pcu_current_bctx(void)
{
	return the_pcu.bctx;
}
