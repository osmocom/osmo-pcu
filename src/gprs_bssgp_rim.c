#include <gprs_rlcmac.h>
#include <gprs_bssgp_rim.h>
#include <pcu_l1_if.h>
#include <gprs_debug.h>
#include <bts.h>
#include <gprs_bssgp_pcu.h>

#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_ns.h>

/* Match the destination ran information in the request PDU to the cell id / routing area id of the local bvc ctx */
static bool match_destination_ran_info(struct bssgp_ran_information_pdu *req_pdu, uint16_t nsei)
{
	struct bssgp_bvc_ctx *bctx = gprs_bssgp_pcu_current_bctx();

	if (req_pdu->routing_info_dest.geran.cid != bctx->cell_id) {
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) cell id (%04x != %04x) unknown to this pcu\n",
		     nsei, req_pdu->routing_info_dest.geran.cid, bctx->cell_id);
		return false;
	}

	if (memcmp
	    (&req_pdu->routing_info_dest.geran.raid, &bctx->ra_id,
	     sizeof(req_pdu->routing_info_dest.geran.raid) != 0)) {
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) routing area id (%s != %s) unknown to this pcu\n", nsei,
		     osmo_rai_name(&req_pdu->routing_info_dest.geran.raid), osmo_rai_name(&bctx->ra_id));
		return false;
	}

	return true;
}

/* Check if the application ID in the request PDU is actually BSSGP_RAN_INF_APP_ID_NACC */
static bool match_app_id(struct bssgp_ran_information_pdu *req_pdu)
{
	switch (req_pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		if (req_pdu->decoded.req_rim_cont.app_id == BSSGP_RAN_INF_APP_ID_NACC)
			return true;
	case BSSGP_IE_RI_RIM_CONTAINER:
		if (req_pdu->decoded.rim_cont.app_id == BSSGP_RAN_INF_APP_ID_NACC)
			return true;
	case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
		if (req_pdu->decoded.app_err_rim_cont.app_id == BSSGP_RAN_INF_APP_ID_NACC)
			return true;
	case BSSGP_IE_RI_ACK_RIM_CONTAINER:
		if (req_pdu->decoded.ack_rim_cont.app_id == BSSGP_RAN_INF_APP_ID_NACC)
			return true;
	case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
		if (req_pdu->decoded.err_rim_cont.app_id == BSSGP_RAN_INF_APP_ID_NACC)
			return true;
	default:
		return false;
	}
}

/* Mirror RIM routing information of a given PDU, see also 3GPP TS 48.018, section 8c.1.4.3 */
static void mirror_rim_routing_info(struct bssgp_ran_information_pdu *resp_pdu,
				    struct bssgp_ran_information_pdu *req_pdu)
{
	memcpy(&resp_pdu->routing_info_dest, &req_pdu->routing_info_src, sizeof(resp_pdu->routing_info_dest));
	memcpy(&resp_pdu->routing_info_src, &req_pdu->routing_info_dest, sizeof(resp_pdu->routing_info_src));
}

/* Fill NACC application container with data (cell identifier, sysinfo) */
static void fill_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *app_cont, const struct gprs_rlcmac_bts *bts)
{
	struct bssgp_bvc_ctx *bctx = gprs_bssgp_pcu_current_bctx();

	app_cont->reprt_cell.rai.lac.plmn.mcc = bctx->ra_id.mcc;
	app_cont->reprt_cell.rai.lac.plmn.mnc = bctx->ra_id.mnc;
	app_cont->reprt_cell.rai.lac.plmn.mnc_3_digits = bctx->ra_id.mnc_3_digits;
	app_cont->reprt_cell.rai.lac.lac = bctx->ra_id.lac;
	app_cont->reprt_cell.rai.rac = bctx->ra_id.rac;
	app_cont->reprt_cell.cell_identity = bctx->cell_id;
	app_cont->num_si = 0;

	if (bts->si1_is_set) {
		app_cont->si[app_cont->num_si] = bts->si1 + 2;
		app_cont->num_si++;
	}

	if (bts->si3_is_set) {
		app_cont->si[app_cont->num_si] = bts->si3 + 2;
		app_cont->num_si++;
	}

	if (bts->si13_is_set) {
		app_cont->si[app_cont->num_si] = bts->si13 + 2;
		app_cont->num_si++;
	}

	/* Note: It is possible that the resulting PDU will not contain any system information, even if this is
	 * an unlikely case since the BTS immediately updates the system information after startup. The
	 * specification permits to send zero system information, see also: 3GPP TS 48.018 section 11.3.63.2.1 */
}

/* Format a RAN INFORMATION PDU that contains the requested system information */
static void format_response_pdu(struct bssgp_ran_information_pdu *resp_pdu, struct bssgp_ran_information_pdu *req_pdu,
				const struct gprs_rlcmac_bts *bts)
{
	memset(resp_pdu, 0, sizeof(*resp_pdu));
	mirror_rim_routing_info(resp_pdu, req_pdu);

	resp_pdu->decoded.rim_cont = (struct bssgp_ran_inf_rim_cont) {
		.app_id = BSSGP_RAN_INF_APP_ID_NACC,
		.seq_num = 1,	/* single report has only one message in response */
		.pdu_ind = {
			    .pdu_type_ext = RIM_PDU_TYPE_SING_REP,
			     },
		.prot_ver = 1,
	};

	fill_app_cont_nacc(&resp_pdu->decoded.rim_cont.u.app_cont_nacc, bts);
	resp_pdu->decoded_present = true;
	resp_pdu->rim_cont_iei = BSSGP_IE_RI_RIM_CONTAINER;
}

/* Format a RAN INFORMATION ERROR PDU */
static void format_response_pdu_err(struct bssgp_ran_information_pdu *resp_pdu,
				    struct bssgp_ran_information_pdu *req_pdu)
{
	memset(resp_pdu, 0, sizeof(*resp_pdu));
	mirror_rim_routing_info(resp_pdu, req_pdu);

	resp_pdu->decoded.err_rim_cont = (struct bssgp_ran_inf_err_rim_cont) {
		.app_id = BSSGP_RAN_INF_APP_ID_NACC,
		.prot_ver = 1,
		.err_pdu = req_pdu->rim_cont,
		.err_pdu_len = req_pdu->rim_cont_len,
	};

	resp_pdu->decoded_present = true;
	resp_pdu->rim_cont_iei = BSSGP_IE_RI_ERROR_RIM_COINTAINER;
}

int sgsn_rim_rx(struct osmo_bssgp_prim *bp, struct msgb *msg, struct gprs_rlcmac_bts *bts)
{
	uint16_t nsei = msgb_nsei(msg);
	struct bssgp_ran_information_pdu *req_pdu = &bp->u.rim_pdu;
	struct bssgp_ran_information_pdu resp_pdu;

	/* At the moment we only support GERAN, so we block all other network
	 * types here. */
	if (req_pdu->routing_info_dest.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) only GERAN supported, destination cell is not a GERAN cell -- rejected.\n",
		     nsei);
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}
	if (req_pdu->routing_info_src.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) only GERAN supported, source cell is not a GERAN cell -- rejected.\n", nsei);
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}

	/* Check if the RIM pdu is really addressed to this PCU, see also
	 * 3GPP TS 48.018, section 8c.3.1.2 */
	if (!match_destination_ran_info(req_pdu, nsei))
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_DST, NULL, msg);

	/* Check if the incoming RIM PDU is parseable, if not we must report
	 * an error to the controlling BSS 3GPP TS 48.018, 8c.3.4 and 8c.3.4.2 */
	if (!req_pdu->decoded_present) {
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) errornous RIM PDU received -- rejected.\n", nsei);
		format_response_pdu_err(&resp_pdu, req_pdu);
		return 0;
	}

	/* Check if the RIM container inside the incoming RIM PDU has the correct
	 * application ID */
	if (!match_app_id(req_pdu)) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) RIM PDU with unknown/wrong application ID received -- rejected.\n", nsei);
		format_response_pdu_err(&resp_pdu, req_pdu);
		return 0;
	}

	/* Handle incoming RIM container */
	switch (req_pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		LOGP(DRIM, LOGL_DEBUG, "BSSGP RIM (NSEI=%u) responding to RAN INFORMATION REQUEST ...\n", nsei);
		format_response_pdu(&resp_pdu, req_pdu, bts);
		bssgp_tx_rim(&resp_pdu, nsei);
		break;
	case BSSGP_IE_RI_RIM_CONTAINER:
	case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
	case BSSGP_IE_RI_ACK_RIM_CONTAINER:
	case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) RIM PDU not handled by this application\n", nsei);
		return -EINVAL;
	default:
		/* This should never happen. If the RIM PDU is parsed correctly, then the rim_cont_iei will
		 * be set to one of the cases above and if parsing failes this switch statement is guarded
		 * by the check on decoded_present above */
		OSMO_ASSERT(false);
	}

	return 0;
}
