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
#include "bts.h"
#include "gprs_ms.h"
#include "nacc_fsm.h"

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

/* Fill NACC application container with data (cell identifier, sysinfo) */
#define SI_HDR_LEN 2
static void fill_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *app_cont, const struct gprs_rlcmac_bts *bts)
{
	struct bssgp_bvc_ctx *bctx = the_pcu->bssgp.bctx;

	gprs_ra_id_ci_to_cgi_ps(&app_cont->reprt_cell, &bctx->ra_id, bctx->cell_id);
	app_cont->num_si = 0;

	/* Note: The BTS struct stores the system information including its pseudo header. The RIM application
	 * container defines the system information without pseudo header, so we need to chop it off. */

	if (bts->si1_is_set) {
		app_cont->si[app_cont->num_si] = bts->si1 + SI_HDR_LEN;
		app_cont->num_si++;
	}

	if (bts->si3_is_set) {
		app_cont->si[app_cont->num_si] = bts->si3 + SI_HDR_LEN;
		app_cont->num_si++;
	}

	if (bts->si13_is_set) {
		app_cont->si[app_cont->num_si] = bts->si13 + SI_HDR_LEN;
		app_cont->num_si++;
	}

	/* Note: It is possible that the resulting PDU will not contain any system information, even if this is
	 * an unlikely case since the BTS immediately updates the system information after startup. The
	 * specification permits to send zero system information, see also: 3GPP TS 48.018 section 11.3.63.2.1 */

	if (!bts->si1_is_set || !bts->si3_is_set || !bts->si13_is_set)
		LOGP(DNACC, LOGL_INFO, "TX RAN INFO RESPONSE (NACC) %s: Some SI are missing:%s%s%s\n",
		     osmo_cgi_ps_name(&app_cont->reprt_cell),
		     bts->si1_is_set ? "" : " SI1",
		     bts->si3_is_set ? "" : " SI3",
		     bts->si13_is_set ? "" : " SI13");
}

/* Format a RAN INFORMATION PDU that contains the requested system information */
static void format_response_pdu(struct bssgp_ran_information_pdu *resp_pdu,
				const struct bssgp_ran_information_pdu *req_pdu,
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

static int handle_ran_info_response_nacc(const struct bssgp_ran_inf_app_cont_nacc *nacc, struct gprs_rlcmac_bts *bts)
{
	struct si_cache_value val;
	struct si_cache_entry *entry;
	struct llist_head *tmp;
	int i;

	LOGP(DRIM, LOGL_INFO, "Rx RAN-INFO cell=%s type=%sBCCH num_si=%d\n",
	     osmo_cgi_ps_name(&nacc->reprt_cell),
	     nacc->type_psi ? "P" : "", nacc->num_si);

	val.type_psi = nacc->type_psi;
	val.si_len = 0;
	for (i = 0; i < nacc->num_si; i++) {
		size_t len = val.type_psi ? BSSGP_RIM_PSI_LEN : BSSGP_RIM_SI_LEN;
		memcpy(&val.si_buf[val.si_len], nacc->si[i], len);
		val.si_len += len;
	}
	entry = si_cache_add(bts->pcu->si_cache, &nacc->reprt_cell, &val);

	llist_for_each(tmp, bts_ms_list(bts)) {
		struct GprsMs *ms = llist_entry(tmp, typeof(*ms), list);
		if (!ms->nacc)
			continue;
		if (ms->nacc->fi->state != NACC_ST_WAIT_REQUEST_SI)
			continue;
		if (osmo_cgi_ps_cmp(&nacc->reprt_cell, &ms->nacc->cgi_ps) != 0)
			continue;
		osmo_fsm_inst_dispatch(ms->nacc->fi, NACC_EV_RX_SI, entry);
	}
	return 0;
}

static int handle_ran_info_response(const struct bssgp_ran_information_pdu *pdu, struct gprs_rlcmac_bts *bts)
{
	const struct bssgp_ran_inf_rim_cont *ran_info = &pdu->decoded.rim_cont;
	char ri_src_str[64];

	if (ran_info->app_err) {
		LOGP(DRIM, LOGL_ERROR,
		     "%s Rx RAN-INFO with an app error! cause: %s\n",
		     bssgp_rim_ri_name_buf(ri_src_str, sizeof(ri_src_str), &pdu->routing_info_src),
		     bssgp_nacc_cause_str(ran_info->u.app_err_cont_nacc.nacc_cause));
		return -1;
	}

	switch (pdu->decoded.rim_cont.app_id) {
	case BSSGP_RAN_INF_APP_ID_NACC:
		handle_ran_info_response_nacc(&ran_info->u.app_cont_nacc, bts);
		break;
	default:
		LOGP(DRIM, LOGL_ERROR, "%s Rx RAN-INFO with unknown/wrong application ID %s received\n",
		     bssgp_rim_ri_name_buf(ri_src_str, sizeof(ri_src_str), &pdu->routing_info_src),
		     bssgp_ran_inf_app_id_str(pdu->decoded.rim_cont.app_id));
		return -1;
	}
	return 0;
}

int handle_rim(struct osmo_bssgp_prim *bp)
{
	struct msgb *msg = bp->oph.msg;
	uint16_t nsei = msgb_nsei(msg);
	struct bssgp_ran_information_pdu *pdu = &bp->u.rim_pdu;
	struct bssgp_ran_information_pdu resp_pdu;
	struct osmo_cell_global_id_ps dst_addr;
	struct gprs_rlcmac_bts *bts;
	int rc;

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
		LOGPRIM(nsei, LOGL_ERROR, "Destination cell %s unknown to this pcu\n",
			osmo_cgi_ps_name(&dst_addr));
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_DST, NULL, msg);
	}

	/* Check if the incoming RIM PDU is parseable, if not we must report
	 * an error to the controlling BSS 3GPP TS 48.018, 8c.3.4 and 8c.3.4.2 */
	if (!pdu->decoded_present) {
		LOGPRIM(nsei, LOGL_ERROR, "Erroneous RIM PDU received for cell %s -- reject.\n",
			osmo_cgi_ps_name(&dst_addr));
		format_response_pdu_err(&resp_pdu, pdu);
		return 0;
	}

	/* Check if the RIM container inside the incoming RIM PDU has the correct
	 * application ID */
	if (!match_app_id(pdu, BSSGP_RAN_INF_APP_ID_NACC)) {
		LOGPRIM(nsei, LOGL_ERROR,
			"RIM PDU for cell %s with unknown/wrong application ID received -- reject.\n",
			osmo_cgi_ps_name(&dst_addr));
		format_response_pdu_err(&resp_pdu, pdu);
		return 0;
	}

	/* Handle incoming RIM container */
	switch (pdu->rim_cont_iei) {
	case BSSGP_IE_RI_REQ_RIM_CONTAINER:
		rc = osmo_cgi_ps_cmp(&dst_addr, &pdu->decoded.req_rim_cont.u.app_cont_nacc.reprt_cell);
		if (rc != 0) {
			LOGPRIM(nsei, LOGL_ERROR, "reporting cell in RIM application container %s "
				"does not match destination cell in RIM routing info %s -- rejected.\n",
				osmo_cgi_ps_name(&pdu->decoded.req_rim_cont.u.app_cont_nacc.reprt_cell),
				osmo_cgi_ps_name2(&dst_addr));
			format_response_pdu_err(&resp_pdu, pdu);
		} else {
			LOGPRIM(nsei, LOGL_INFO, "Responding to RAN INFORMATION REQUEST %s ...\n",
				osmo_cgi_ps_name(&pdu->decoded.req_rim_cont.u.app_cont_nacc.reprt_cell));
			format_response_pdu(&resp_pdu, pdu, bts);
		}
		bssgp_tx_rim(&resp_pdu, nsei);
		break;
	case BSSGP_IE_RI_RIM_CONTAINER:
		return handle_ran_info_response(pdu, bts);
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
