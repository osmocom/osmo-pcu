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

#include "gprs_debug.h"
#include "gprs_pcu.h"

#define LOGPRIM(nsei, level, fmt, args...) \
	LOGP(DRIM, level, "(NSEI=%u) " fmt, nsei, ## args)

static inline void gprs_ra_id_ci_to_cgi_ps(struct osmo_cell_global_id_ps *cgi_ps,
					   const struct gprs_ra_id *raid, uint16_t cid)
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
static void mirror_rim_routing_info(struct bssgp_ran_information_pdu *to_pdu,
				    const struct bssgp_ran_information_pdu *from_pdu)
{
	memcpy(&to_pdu->routing_info_dest, &from_pdu->routing_info_src, sizeof(to_pdu->routing_info_dest));
	memcpy(&to_pdu->routing_info_src, &from_pdu->routing_info_dest, sizeof(to_pdu->routing_info_src));
}

/* Format a RAN INFORMATION ERROR PDU */
static void format_response_pdu_err(struct bssgp_ran_information_pdu *resp_pdu,
				    const struct bssgp_ran_information_pdu *req_pdu)
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
static const enum bssgp_ran_inf_app_id *get_app_id(const struct bssgp_ran_information_pdu *pdu)
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

/* Check if the application ID in the request PDU is of a certain type */
static bool match_app_id(const struct bssgp_ran_information_pdu *pdu, enum bssgp_ran_inf_app_id exp_app_id)
{
	const enum bssgp_ran_inf_app_id *app_id = get_app_id(pdu);
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

	OSMO_ASSERT (bp->oph.sap == SAP_BSSGP_RIM);

	/* At the moment we only support GERAN, so we block all other network
	 * types here. */
	if (pdu->routing_info_dest.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGPRIM(nsei, LOGL_ERROR,
			"Only GERAN supported, destination cell is not a GERAN cell -- rejected.\n");
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}

	/* Check if the RIM pdu is really addressed to this PCU. In case we
	 * receive a RIM PDU for a cell that is not parented by this PCU we
	 * are supposed to reject it with a BSSGP STATUS.
	 * see also: 3GPP TS 48.018, section 8c.3.1.2 */
	gprs_ra_id_ci_to_cgi_ps(&dst_addr, &pdu->routing_info_dest.geran.raid,
				pdu->routing_info_dest.geran.cid);
	bts = gprs_pcu_get_bts_by_cgi_ps(the_pcu, &dst_addr);
	if (!bts) {
		LOGPRIM(nsei, LOGL_ERROR, "Cell %s unknown to this pcu\n",
			osmo_cgi_ps_name(&dst_addr));
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_DST, NULL, msg);
	}

	/* Check if the incoming RIM PDU is parseable, if not we must report
	 * an error to the controlling BSS 3GPP TS 48.018, 8c.3.4 and 8c.3.4.2 */
	if (!pdu->decoded_present) {
		LOGPRIM(nsei, LOGL_ERROR, "Errornous RIM PDU received -- rejected.\n");
		format_response_pdu_err(&resp_pdu, pdu);
		return 0;
	}

	/* Check if the RIM container inside the incoming RIM PDU has the correct
	 * application ID */
	if (!match_app_id(pdu, BSSGP_RAN_INF_APP_ID_NACC)) {
		LOGPRIM(nsei, LOGL_ERROR, "RIM PDU with unknown/wrong application ID received -- rejected.\n");
		format_response_pdu_err(&resp_pdu, pdu);
		return 0;
	}

	/* Handle incoming RIM container */
	switch (pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		LOGPRIM(nsei, LOGL_NOTICE, "Responding to RAN INFORMATION REQUEST not yet implemented!\n");
		break;
	case BSSGP_IE_RI_RIM_CONTAINER:
		LOGPRIM(nsei, LOGL_NOTICE, "Responding to RAN INFORMATION not yet implemented!\n");
		break;
	case BSSGP_IE_RI_APP_ERROR_RIM_CONT:
	case BSSGP_IE_RI_ACK_RIM_CONTAINER:
	case BSSGP_IE_RI_ERROR_RIM_COINTAINER:
		LOGPRIM(nsei, LOGL_ERROR, "RIM PDU not handled by this application\n");
		return -EINVAL;
	default:
		/* This should never happen. If the RIM PDU is parsed correctly, then the rim_cont_iei will
		 * be set to one of the cases above and if parsing fails this switch statement is guarded
		 * by the check on decoded_present above */
		OSMO_ASSERT(false);
	}

	return 0;
}