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

#define BSSGP_TIMER_T1	30	/* Guards the (un)blocking procedures */
#define BSSGP_TIMER_T2	30	/* Guards the reset procedure */

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
	uint32_t tlli_old = 0;
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

	/* get optional TLLI old */
	if (TLVP_PRESENT(tp, BSSGP_IE_TLLI))
	{
		uint8_t tlli_len = TLVP_LEN(tp, BSSGP_IE_PDU_LIFETIME);
		uint16_t *e_tlli_old = (uint16_t *) TLVP_VAL(tp, BSSGP_IE_TLLI);
		if (tlli_len == 2)
			tlli_old = ntohs(*e_tlli_old);
		else
			LOGP(DBSSGP, LOGL_NOTICE, "BSSGP invalid length of "
				"TLLI (old) IE\n");
	}

	LOGP(DBSSGP, LOGL_INFO, "LLC [SGSN -> PCU] = TLLI: 0x%08x IMSI: %s len: %d\n", tlli, imsi, len);

	return gprs_rlcmac_dl_tbf::handle(the_pcu.bts, tlli, tlli_old, imsi,
			ms_class, delay_csec, data, len);
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
	int bvci = bctx ? bctx->bvci : -1;
	switch (bgph->pdu_type) {
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		DEBUGP(DBSSGP, "BSSGP BVCI=%d Rx BVC STATUS\n", bvci);
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
		LOGP(DBSSGP, LOGL_NOTICE, "BSSGP BVCI=%d Rx PDU type 0x%02x unknown\n",
			bvci, bgph->pdu_type);
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

	if (pdu_type == BSSGP_PDUT_STATUS)
		/* Pass the message to the generic BSSGP parser, which handles
		 * STATUS message in either direction. */
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
	case S_NS_ALIVE_EXP:
		LOGP(DPCU, LOGL_NOTICE, "Tns alive expired too often, "
			"re-starting RESET procedure\n");
		gprs_ns_reconnect(nssd->nsvc);
		break;
	}

	return 0;
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

static uint32_t gprs_bssgp_max_leak_rate(unsigned cs, int num_pdch)
{
	static const uint32_t max_lr_per_ts[4] = {
		20 * (1000 / 20), /* CS-1: 20 byte payload per 20ms */
		30 * (1000 / 20), /* CS-2: 30 byte payload per 20ms */
		36 * (1000 / 20), /* CS-3: 36 byte payload per 20ms */
		50 * (1000 / 20), /* CS-4: 50 byte payload per 20ms */
	};

	if (cs > ARRAY_SIZE(max_lr_per_ts))
		cs = 1;

	return max_lr_per_ts[cs-1] * num_pdch;
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
	struct timeval *delay_sum = &the_pcu.queue_delay_sum;
	uint32_t delay_sum_ms = delay_sum->tv_sec * 1000 +
			delay_sum->tv_usec / 1000000;
	uint32_t avg_delay_ms = 0;

	if (the_pcu.queue_delay_count > 0)
		avg_delay_ms = delay_sum_ms / the_pcu.queue_delay_count;

	/* Reset accumulator */
	delay_sum->tv_sec = delay_sum->tv_usec = 0;
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

int gprs_bssgp_tx_fc_bvc(void)
{
	struct gprs_rlcmac_bts *bts;
	uint32_t bucket_size; /* oct */
	uint32_t ms_bucket_size; /* oct */
	uint32_t leak_rate; /* oct/s */
	uint32_t ms_leak_rate; /* oct/s */
	uint32_t avg_delay_ms;
	int num_pdch = -1;
	int max_cs_dl;

	if (!the_pcu.bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	bts = bts_main_data();

	if (bts->cs_adj_enabled) {
		max_cs_dl = bts->max_cs_dl;
		if (!max_cs_dl) {
			if (bts->cs4)
				max_cs_dl = 4;
			else if (bts->cs3)
				max_cs_dl = 3;
			else if (bts->cs2)
				max_cs_dl = 2;
			else
				max_cs_dl = 1;
		}
	} else {
		max_cs_dl = bts->initial_cs_dl;
	}

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
			"Computed BVC leak rate = %d, num_pdch = %d, cs = %d\n",
			leak_rate, num_pdch, max_cs_dl);
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
			"Computed MS default leak rate = %d, ms_num_pdch = %d, cs = %d\n",
			ms_leak_rate, ms_num_pdch, max_cs_dl);
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
	if (!the_pcu.bvc_sig_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI 0\n");
		bssgp_tx_bvc_reset(the_pcu.bctx, 0, BSSGP_CAUSE_OML_INTERV);
		osmo_timer_schedule(&the_pcu.bvc_timer, BSSGP_TIMER_T2, 0);
		return;
	}

	if (!the_pcu.bvc_reset) {
		LOGP(DBSSGP, LOGL_INFO, "Sending reset on BVCI %d\n",
			the_pcu.bctx->bvci);
		bssgp_tx_bvc_reset(the_pcu.bctx, the_pcu.bctx->bvci, BSSGP_CAUSE_OML_INTERV);
		osmo_timer_schedule(&the_pcu.bvc_timer, BSSGP_TIMER_T2, 0);
		return;
	}

	if (!the_pcu.bvc_unblocked) {
		LOGP(DBSSGP, LOGL_INFO, "Sending unblock on BVCI %d\n",
			the_pcu.bctx->bvci);
		bssgp_tx_bvc_unblock(the_pcu.bctx);
		osmo_timer_schedule(&the_pcu.bvc_timer, BSSGP_TIMER_T1, 0);
		return;
	}

	LOGP(DBSSGP, LOGL_DEBUG, "Sending flow control info on BVCI %d\n",
		the_pcu.bctx->bvci);
	gprs_bssgp_tx_fc_bvc();
	osmo_timer_schedule(&the_pcu.bvc_timer, the_pcu.bts->fc_interval, 0);
}

int gprs_ns_reconnect(struct gprs_nsvc *nsvc)
{
	struct gprs_nsvc *nsvc2;

	if (!bssgp_nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "NS instance does not exist\n");
		return -EINVAL;
	}

	if (nsvc != the_pcu.nsvc) {
		LOGP(DBSSGP, LOGL_ERROR, "NSVC is invalid\n");
		return -EBADF;
	}

	nsvc2 = gprs_ns_nsip_connect(bssgp_nsi, &nsvc->ip.bts_addr,
		nsvc->nsei, nsvc->nsvci);

	if (!nsvc2) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to reconnect NSVC\n");
		return -EIO;
	}

	return 0;
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

void gprs_bssgp_destroy(void)
{
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

void gprs_bssgp_update_queue_delay(const struct timeval *tv_recv,
	const struct timeval *tv_now)
{
	struct timeval *delay_sum = &the_pcu.queue_delay_sum;
	struct timeval tv_delay;

	timersub(tv_now, tv_recv, &tv_delay);
	timeradd(delay_sum, &tv_delay, delay_sum);

	the_pcu.queue_delay_count += 1;
}
