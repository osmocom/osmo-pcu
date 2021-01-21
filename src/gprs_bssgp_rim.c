/* gprs_bssgp_pcu.cpp
 *
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/core/prim.h>
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <bts.h>

#include "gprs_debug.h"
#include "gprs_pcu.h"

static inline void gprs_ra_id_ci_to_cgi_ps(struct osmo_cell_global_id_ps *cgi_ps,
					   struct gprs_ra_id *raid, uint16_t cid)
{
	*cgi_ps = (struct osmo_cell_global_id_ps) {
		.rai.lac.plmn.mcc = raid->mcc,
		.rai.lac.plmn.mnc = raid->mnc,
		.rai.lac.plmn.mnc_3_digits = raid->mnc_3_digits,
		.rai.lac.lac = raid->lac,
		.rai.rac = raid->rac,
		.cell_identity = cid,
	};
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

/* Check if the application ID in the request PDU is actually BSSGP_RAN_INF_APP_ID_NACC */
static enum bssgp_ran_inf_app_id *get_app_id(struct bssgp_ran_information_pdu *pdu)
{
	switch (pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		return &pdu->decoded.req_rim_cont.app_id;
	case BSSGP_IE_RI_RIM_CONTAINER:
		return &pdu->decoded.rim_cont.app_id;
	case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
		return &pdu->decoded.app_err_rim_cont.app_id;
	case BSSGP_IE_RI_ACK_RIM_CONTAINER:
		return &pdu->decoded.ack_rim_cont.app_id;
	case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
		return &pdu->decoded.err_rim_cont.app_id;
	default:
		return NULL;
	}
}

/* Check if the application ID in the request PDU is of a certian type */
static bool match_app_id(struct bssgp_ran_information_pdu *pdu, enum bssgp_ran_inf_app_id exp_app_id)
{
	enum bssgp_ran_inf_app_id *app_id = get_app_id(pdu);
	if (app_id && *app_id == exp_app_id)
		return true;
	return false;
}

int handle_rim(struct osmo_bssgp_prim *bp)
{
	struct msgb *msg = bp->oph.msg;
	uint16_t nsei = msgb_nsei(msg);
	struct bssgp_ran_information_pdu *pdu = &bp->u.rim_pdu;
	struct bssgp_ran_information_pdu resp_pdu;
	struct osmo_cell_global_id_ps dst_addr;
	struct gprs_rlcmac_bts *bts;

	/* At the moment we only support GERAN, so we block all other network
	 * types here. */
	if (pdu->routing_info_dest.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) only GERAN supported, destination cell is not a GERAN cell -- rejected.\n",
		     nsei);
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}
	if (pdu->routing_info_src.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) only GERAN supported, source cell is not a GERAN cell -- rejected.\n", nsei);
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}

	/* Check if the RIM pdu is really addressed to this PCU, see also
	 * 3GPP TS 48.018, section 8c.3.1.2 */
	gprs_ra_id_ci_to_cgi_ps(&dst_addr, &pdu->routing_info_dest.geran.raid,
				pdu->routing_info_dest.geran.cid);
	bts = gprs_pcu_get_bts_by_cgi_ps(the_pcu, &dst_addr);
	if (!bts) {
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) cell %s unknown to this pcu\n",
		     nsei, osmo_cgi_ps_name(&dst_addr));
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_DST, NULL, msg);
	}

	/* Check if the incoming RIM PDU is parseable, if not we must report
	 * an error to the controlling BSS 3GPP TS 48.018, 8c.3.4 and 8c.3.4.2 */
	if (!pdu->decoded_present) {
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) errornous RIM PDU received -- rejected.\n", nsei);
		format_response_pdu_err(&resp_pdu, pdu);
		return 0;
	}

	/* Check if the RIM container inside the incoming RIM PDU has the correct
	 * application ID */
	if (!match_app_id(pdu, BSSGP_RAN_INF_APP_ID_NACC)) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) RIM PDU with unknown/wrong application ID received -- rejected.\n", nsei);
		format_response_pdu_err(&resp_pdu, pdu);
		return 0;
	}

	/* Handle incoming RIM container */
	switch (pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		LOGP(DRIM, LOGL_NOTICE, "BSSGP RIM (NSEI=%u) responding to RAN INFORMATION REQUEST ...\n", nsei);
		format_response_pdu(&resp_pdu, pdu, bts);
		bssgp_tx_rim(&resp_pdu, nsei);
		break;
	case BSSGP_IE_RI_RIM_CONTAINER:
		LOGP(DRIM, LOGL_NOTICE, "BSSGP RIM (NSEI=%u) responding to RAN INFORMATION not yet implemented!\n", nsei);
		break;
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
