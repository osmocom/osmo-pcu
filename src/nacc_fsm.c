/* nacc_fsm.c
 *
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
 */

#include <unistd.h>

#include <talloc.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

#include <nacc_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>
#include <neigh_cache.h>

#define X(s) (1 << (s))

/* Infer CTRL id (seqnum) for a given tgt arfcn+bsic (bsic range: 0-63) */
#define arfcn_bsic_2_ctrl_id(arfcn, bsic) ((arfcn) * 100 + (bsic))

static const struct osmo_tdef_state_timeout nacc_fsm_timeouts[32] = {
	[NACC_ST_INITIAL] = {},
	[NACC_ST_WAIT_RESOLVE_RAC_CI] = { .T = PCU_TDEF_NEIGH_RESOLVE_TO },
	[NACC_ST_WAIT_REQUEST_SI] = { .T = PCU_TDEF_SI_RESOLVE_TO },
	[NACC_ST_TX_NEIGHBOUR_DATA] = {},
	[NACC_ST_TX_CELL_CHG_CONTINUE] = {},
	[NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK] = {}, /* Timeout through event controlled by tbf::poll_timeout() */
	[NACC_ST_DONE] = {},
};

/* Transition to a state, using the T timer defined in nacc_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */

#define nacc_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     nacc_fsm_timeouts, \
				     ((struct nacc_fsm_ctx*)(fi->priv))->ms->bts->pcu->T_defs, \
				     -1)

const struct value_string nacc_fsm_event_names[] = {
	{ NACC_EV_RX_CELL_CHG_NOTIFICATION, "RX_CELL_CHG_NOTIFICATION" },
	{ NACC_EV_RX_RAC_CI, "RX_RAC_CI" },
	{ NACC_EV_RX_SI, "RX_SI" },
	{ NACC_EV_CREATE_RLCMAC_MSG, "CREATE_RLCMAC_MSG" },
	{ NACC_EV_RX_CELL_CHG_CONTINUE_ACK, "RX_CELL_CHG_CONTINUE_ACK"},
	{ NACC_EV_TIMEOUT_CELL_CHG_CONTINUE, "TIMEOUT_CELL_CHG_CONTINUE" },
	{ 0, NULL }
};

/* TS 44 060 11.2.9e Packet Neighbour Cell Data */
static struct msgb *create_packet_neighbour_cell_data(struct nacc_fsm_ctx *ctx,
						      const struct gprs_rlcmac_tbf *tbf,
						      bool *all_si_info_sent)
{
	struct msgb *msg;
	int rc;
	RlcMacDownlink_t *mac_control_block;
	struct GprsMs *ms = tbf_ms(tbf);
	OSMO_ASSERT(tbf_is_tfi_assigned(tbf));
	uint8_t tfi_is_dl = tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF;
	uint8_t tfi = tbf_tfi(tbf);
	uint8_t container_id = 0;
	PNCDContainer_t container;
	size_t max_len, len_to_write;
	uint8_t *cont_buf;
	uint8_t si_type = ctx->si_info.type_psi ? 0x01 : 0x0;

	memset(&container, 0, sizeof(container));
	if (ctx->container_idx == 0) {
		container.UnionType = 1; /* with ID */
		container.u.PNCD_Container_With_ID.ARFCN = ctx->neigh_key.tgt_arfcn;
		container.u.PNCD_Container_With_ID.BSIC = ctx->neigh_key.tgt_bsic;
		cont_buf = &container.u.PNCD_Container_With_ID.CONTAINER[0];
		max_len = sizeof(container.u.PNCD_Container_With_ID.CONTAINER) - 1;
	} else {
		container.UnionType = 0; /* without ID */
		cont_buf = &container.u.PNCD_Container_Without_ID.CONTAINER[0];
		max_len = sizeof(container.u.PNCD_Container_Without_ID.CONTAINER) - 1;
	}

	len_to_write = ctx->si_info.si_len - ctx->si_info_bytes_sent;

	if (len_to_write == 0) {
		/* We sent all info on last message filing it exactly, we now send a zeroed one to finish */
		*all_si_info_sent = true;
		*cont_buf = (si_type << 5) | 0x00;
	} else if (len_to_write >= max_len) {
		/* We fill the rlcmac block, we'll need more messages */
		*all_si_info_sent = false;
		*cont_buf = (si_type << 5) |  0x1F;
		memcpy(cont_buf + 1, &ctx->si_info.si_buf[ctx->si_info_bytes_sent], max_len);
		ctx->si_info_bytes_sent += max_len;
	} else {
		/* Last block, we don't fill it exactly */
		*all_si_info_sent = true;
		*cont_buf = (si_type << 5) | (len_to_write & 0x1F);
		memcpy(cont_buf + 1, &ctx->si_info.si_buf[ctx->si_info_bytes_sent], len_to_write);
		ctx->si_info_bytes_sent += len_to_write;
	}

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "neighbour_cell_data");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	struct bitvec bv = {
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, DUMMY_VEC);

	mac_control_block = (RlcMacDownlink_t *)talloc_zero(ctx->ms, RlcMacDownlink_t);

	write_packet_neighbour_cell_data(mac_control_block,
					 tfi_is_dl, tfi, container_id,
					 ctx->container_idx, &container);
	LOGP(DNACC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Neighbour Cell Data +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Encoding of Packet Neighbour Cell Data failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DNACC, LOGL_DEBUG, "------------------------- TX : Packet Neighbour Cell Data -------------------------\n");
	rate_ctr_inc(rate_ctr_group_get_ctr(bts_rate_counters(ms->bts), CTR_PKT_NEIGH_CELL_DATA));
	talloc_free(mac_control_block);

	ctx->container_idx++;

	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

/* TS 44 060 11.2.2a Packet Cell Change Continue */
static struct msgb *create_packet_cell_chg_continue(const struct nacc_fsm_ctx *ctx,
						    const struct nacc_ev_create_rlcmac_msg_ctx *data,
						    uint32_t *new_poll_fn)
{
	struct msgb *msg;
	int rc;
	RlcMacDownlink_t *mac_control_block;
	struct gprs_rlcmac_tbf *tbf = data->tbf;
	struct GprsMs *ms = tbf_ms(tbf);
	unsigned int rrbp;

	rc = tbf_check_polling(tbf, data->pdch, data->fn, new_poll_fn, &rrbp);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Failed registering poll for Pkt Cell Chg Continue (%d)\n", rc);
		return NULL;
	}

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_cell_chg_continue");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	struct bitvec bv = {
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, DUMMY_VEC);

	mac_control_block = (RlcMacDownlink_t *)talloc_zero(ctx->ms, RlcMacDownlink_t);

	OSMO_ASSERT(tbf_is_tfi_assigned(tbf));
	uint8_t tfi_is_dl = tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF;
	uint8_t tfi = tbf_tfi(tbf);
	uint8_t container_id = 0;
	write_packet_cell_change_continue(mac_control_block, 1, rrbp, tfi_is_dl, tfi, ctx->neigh_key_present,
			ctx->neigh_key.tgt_arfcn, ctx->neigh_key.tgt_bsic, container_id);
	LOGP(DNACC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Cell Change Continue +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DTBF, LOGL_ERROR, "Encoding of Packet Cell Change Continue failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DNACC, LOGL_DEBUG, "------------------------- TX : Packet Cell Change Continue -------------------------\n");
	rate_ctr_inc(rate_ctr_group_get_ctr(bts_rate_counters(ms->bts), CTR_PKT_CELL_CHG_CONTINUE));
	talloc_free(mac_control_block);
	tbf_set_polling(tbf, data->pdch, *new_poll_fn, PDCH_ULC_POLL_CELL_CHG_CONTINUE);
	LOGPTBF(tbf, LOGL_DEBUG,
	     "Scheduled 'Packet Cell Change Continue' polling on PACCH (FN=%d, TS=%d)\n",
	     *new_poll_fn, data->pdch->ts_no);
	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

static int fill_rim_ran_info_req(const struct nacc_fsm_ctx *ctx, struct bssgp_ran_information_pdu *pdu)
{
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;

	*pdu = (struct bssgp_ran_information_pdu){
		.routing_info_dest = {
			.discr = BSSGP_RIM_ROUTING_INFO_GERAN,
			.geran = {
				.raid = {
					.mcc = ctx->cgi_ps.rai.lac.plmn.mcc,
					.mnc = ctx->cgi_ps.rai.lac.plmn.mnc,
					.mnc_3_digits = ctx->cgi_ps.rai.lac.plmn.mnc_3_digits,
					.lac = ctx->cgi_ps.rai.lac.lac,
					.rac = ctx->cgi_ps.rai.rac,
				},
				.cid = ctx->cgi_ps.cell_identity,
			},
		},
		.routing_info_src = {
			.discr = BSSGP_RIM_ROUTING_INFO_GERAN,
			.geran = {
				.raid = {
					.mcc = bts->cgi_ps.rai.lac.plmn.mcc,
					.mnc = bts->cgi_ps.rai.lac.plmn.mnc,
					.mnc_3_digits = bts->cgi_ps.rai.lac.plmn.mnc_3_digits,
					.lac = bts->cgi_ps.rai.lac.lac,
					.rac = bts->cgi_ps.rai.rac,
				},
				.cid = bts->cgi_ps.cell_identity,
			},
		},
		.rim_cont_iei = BSSGP_IE_RI_REQ_RIM_CONTAINER,
		.decoded_present = true,
		.decoded = {
			.req_rim_cont = {
				.app_id = BSSGP_RAN_INF_APP_ID_NACC,
				.seq_num = 1,
				.pdu_ind = {
					.ack_requested = 0,
					.pdu_type_ext = RIM_PDU_TYPE_SING_REP,
				},
				.prot_ver = 1,
				.son_trans_app_id = NULL,
				.son_trans_app_id_len = 0,
				.u = {
					.app_cont_nacc = {
						.reprt_cell = ctx->cgi_ps,
					},
				},
			},
		},
	};

	return 0;
}

static int fill_neigh_key_from_bts_pkt_cell_chg_not(struct nacc_fsm_ctx *ctx,
						    const struct gprs_rlcmac_bts *bts,
						    const Packet_Cell_Change_Notification_t *notif)
{
	const Target_Cell_GSM_Notif_t *notif_gsm;
	const Target_Cell_3G_Notif_t *notif_3g;
	const Target_Cell_4G_Notif_t *notif_4g;

	memset(&ctx->neigh_key, 0, sizeof(ctx->neigh_key));
	ctx->neigh_key_present = false;

	switch (notif->Target_Cell.UnionType) {
	case 0:	/* GSM */
		notif_gsm = &notif->Target_Cell.u.Target_Cell_GSM_Notif;
		LOGPFSML(ctx->fi, LOGL_NOTICE, "TargetCell: RAT=GSM, ARFCN=%u, BSIC=%u\n",
			 notif_gsm->ARFCN, notif_gsm->BSIC);

		ctx->neigh_key.local_lac = bts->cgi_ps.rai.lac.lac;
		ctx->neigh_key.local_ci = bts->cgi_ps.cell_identity;
		ctx->neigh_key.tgt_arfcn = notif_gsm->ARFCN;
		ctx->neigh_key.tgt_bsic = notif_gsm->BSIC;
		ctx->neigh_key_present = true;
		return 0;
	default:
		switch (notif->Target_Cell.u.Target_Other_RAT_Notif.UnionType) {
		case 0:	/* UTRAN */
			notif_3g = &notif->Target_Cell.u.Target_Other_RAT_Notif.u.Target_Cell_3G_Notif;
			if (notif_3g->Exist_FDD_Description) {
				LOGPFSML(ctx->fi, LOGL_NOTICE,
					 "TargetCell: RAT=UTRAN, FDD-ARFCN=%u => no system information provided.\n",
					 notif_3g->FDD_Target_Cell_Notif.FDD_ARFCN);
			} else if (notif_3g->Exist_TDD_Description) {
				LOGPFSML(ctx->fi, LOGL_NOTICE,
					 "TargetCell: RAT=UTRAN, TDD-ARFCN=%u => no system information provided.\n",
					 notif_3g->TDD_Target_Cell.TDD_ARFCN);
			}
			return 0;
		default:
			switch (notif->Target_Cell.u.Target_Other_RAT_Notif.u.Target_Other_RAT_2_Notif.UnionType) {
			case 0:	/* E-UTRAN (and older RAT) */
				notif_4g =
				    &notif->Target_Cell.u.Target_Other_RAT_Notif.u.Target_Other_RAT_2_Notif.u.Target_Cell_4G_Notif;
				notif_3g = &notif_4g->Target_Cell_3G_Notif;
				if (notif_4g->Exist_Arfcn) {
					LOGPFSML(ctx->fi, LOGL_NOTICE, "TargetCell: RAT=GSM, ARFCN=%u, BSIC=%u\n",
						 notif_4g->Arfcn, notif_4g->bsic);
					ctx->neigh_key.local_lac = bts->cgi_ps.rai.lac.lac;
					ctx->neigh_key.local_ci = bts->cgi_ps.cell_identity;
					ctx->neigh_key.tgt_arfcn = notif_4g->Arfcn;
					ctx->neigh_key.tgt_bsic = notif_4g->bsic;
					ctx->neigh_key_present = true;
					return 0;
				}
				if (notif_4g->Exist_3G_Target_Cell) {
					if (notif_3g->Exist_FDD_Description) {
						LOGPFSML(ctx->fi, LOGL_NOTICE,
							 "TargetCell: RAT=UTRAN, FDD-ARFCN=%u => no system information provided.\n",
							 notif_3g->FDD_Target_Cell_Notif.FDD_ARFCN);
					} else if (notif_3g->Exist_TDD_Description) {
						LOGPFSML(ctx->fi, LOGL_NOTICE,
							 "TargetCell: RAT=UTRAN, TDD-ARFCN=%u => no system information provided.\n",
							 notif_3g->TDD_Target_Cell.TDD_ARFCN);
					}
					return 0;
				}
				if (notif_4g->Exist_Eutran_Target_Cell) {
					LOGPFSML(ctx->fi, LOGL_NOTICE,
						 "TargetCell: RAT=E-UTRAN, EARFCN=%u, CI=%u => no system information provided.\n",
						 notif_4g->Target_EUTRAN_Cell.EARFCN,
						 notif_4g->Target_EUTRAN_Cell.Physical_Layer_Cell_Identity);
					return 0;
				}

				/* TODO: do something meaningful with an Eutran_Ccn_Measurement_Report, in case it is
				 * provided. */

				LOGPFSML(ctx->fi, LOGL_NOTICE, "TargetCell: (none, invalid)\n");
				return -EINVAL;
			default:
				LOGPFSML(ctx->fi, LOGL_NOTICE,
					 "TargetCell: RAT=CSG-UTRAN|CSG-EUTRAN, (not supported)\n");
				return -ENOTSUP;	/* TODO: Add support */
			}
		}
	}
}

#define SI_HDR_LEN 2
static void bts_fill_si_cache_value(const struct gprs_rlcmac_bts *bts, struct si_cache_value *val)
{
	val->type_psi = false;
	val->si_len = 0;
	if (bts->si1_is_set) {
		osmo_static_assert(sizeof(bts->si1) - SI_HDR_LEN == BSSGP_RIM_SI_LEN, _si1_header_size);
		memcpy(&val->si_buf[val->si_len], bts->si1 + SI_HDR_LEN, BSSGP_RIM_SI_LEN);
		val->si_len += BSSGP_RIM_SI_LEN;
	}
	if (bts->si3_is_set) {
		osmo_static_assert(sizeof(bts->si3) - SI_HDR_LEN == BSSGP_RIM_SI_LEN, _si3_header_size);
		memcpy(&val->si_buf[val->si_len], bts->si3 + SI_HDR_LEN, BSSGP_RIM_SI_LEN);
		val->si_len += BSSGP_RIM_SI_LEN;
	}
	if (bts->si13_is_set) {
		osmo_static_assert(sizeof(bts->si13) - SI_HDR_LEN == BSSGP_RIM_SI_LEN, _si13_header_size);
		memcpy(&val->si_buf[val->si_len], bts->si13 + SI_HDR_LEN, BSSGP_RIM_SI_LEN);
		val->si_len += BSSGP_RIM_SI_LEN;
	}
}

/* Called on event NACC_EV_RX_CELL_CHG_NOTIFICATION on states after
 * WAIT_RESOLVE_RAC_CI. Ignore duplicate messages, transition back if target
 * cell changed.
 */
static void handle_retrans_pkt_cell_chg_notif(struct nacc_fsm_ctx *ctx, const Packet_Cell_Change_Notification_t *notif)
{
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;
	struct neigh_cache_entry_key neigh_key;
	int rc;

	rc = fill_neigh_key_from_bts_pkt_cell_chg_not(ctx, bts, notif);
	if (rc < 0) {
		/* (see comment below) */
		if (ctx->fi->state != NACC_ST_TX_CELL_CHG_CONTINUE)
			nacc_fsm_state_chg(ctx->fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		return;
	} else if (!ctx->neigh_key_present) {
		/* In case no neighbour key information is present, (This would be the case for UTRAN or EUTRAN cells)
		 * then we will not provide any system information. Instead we will send the PacketCellChangeContinue
		 * message immediately. This also applies in the case of re-transmissions. See also: 3GPP TS 48.018,
		 * section 8c.6.1. */
		nacc_fsm_state_chg(ctx->fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		return;
	}

	/* If tgt cell changed, restart resolving it */
	if (!neigh_cache_entry_key_eq(&ctx->neigh_key, &neigh_key)) {
		ctx->neigh_key = neigh_key;
		nacc_fsm_state_chg(ctx->fi, NACC_ST_WAIT_RESOLVE_RAC_CI);
	}
	/* else: ignore it, it's a dup, carry on what we were doing */
}

////////////////
// FSM states //
////////////////

static void st_initial(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;
	Packet_Cell_Change_Notification_t *notif;
	int rc;

	switch (event) {
	case NACC_EV_RX_CELL_CHG_NOTIFICATION:
		notif = (Packet_Cell_Change_Notification_t *)data;
		rc = fill_neigh_key_from_bts_pkt_cell_chg_not(ctx, bts, notif);
		if (rc < 0)
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		else if (!ctx->neigh_key_present) {
			/* In case no neighbour key information is present, (This would be the case for UTRAN or EUTRAN
			 * cells) then we will not provide any system information. Instead we will send the
			 * PacketCellChangeContinue message immediately. See also: 3GPP TS 48.018, section 8c.6.1. */
			nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		} else
			nacc_fsm_state_chg(fi, NACC_ST_WAIT_RESOLVE_RAC_CI);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static int send_neigh_addr_req(struct nacc_fsm_ctx *ctx)
{
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;

	/* Using PCUIF over IPA Abis multiplex proto: */
	return pcu_tx_neigh_addr_res_req(bts, &ctx->neigh_key);
}

static void st_wait_resolve_rac_ci_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;
	struct gprs_pcu *pcu = bts->pcu;
	const struct osmo_cell_global_id_ps *cgi_ps;

	/* First try to find the value in the cache */
	cgi_ps = neigh_cache_lookup_value(pcu->neigh_cache, &ctx->neigh_key);
	if (cgi_ps) {
		ctx->cgi_ps = *cgi_ps;
		nacc_fsm_state_chg(fi, NACC_ST_WAIT_REQUEST_SI);
		return;
	}

	/* CGI-PS not in cache, resolve it using BSC Neighbor Resolution CTRL interface */
	LOGPFSML(fi, LOGL_DEBUG, "No CGI-PS found in cache, resolving " NEIGH_CACHE_ENTRY_KEY_FMT "...\n",
		 NEIGH_CACHE_ENTRY_KEY_ARGS(&ctx->neigh_key));

	if (send_neigh_addr_req(ctx) < 0)
		nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
}

static void st_wait_resolve_rac_ci(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	const Packet_Cell_Change_Notification_t *notif;

	switch (event) {
	case NACC_EV_RX_CELL_CHG_NOTIFICATION:
		notif = (const Packet_Cell_Change_Notification_t *)data;
		handle_retrans_pkt_cell_chg_notif(ctx, notif);
		break;
	case NACC_EV_RX_RAC_CI:
		/* data is NULL upon failure */
		if (data) {
			ctx->cgi_ps = *(struct osmo_cell_global_id_ps *)data;
			nacc_fsm_state_chg(fi, NACC_ST_WAIT_REQUEST_SI);
		} else {
			nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* At this point, we expect correct tgt cell info to be already in ctx->cgi_ps */
static void st_wait_request_si_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;
	struct gprs_pcu *pcu = bts->pcu;
	struct bssgp_ran_information_pdu pdu;
	const struct si_cache_value *si;
	struct gprs_rlcmac_bts *bts_i;
	int rc;

	/* First check if the CGI-PS addresses a cell managed by this PCU. If
	 * that's the case, we already have the info and there's no need to go
	 * the RIM way since we'd end up to this same PCU on the other end anyway.
	 */
	llist_for_each_entry(bts_i, &the_pcu->bts_list, list) {
		if (bts_i == bts) /* Makes no sense targeting the same cell */
			continue;
		if (osmo_cgi_ps_cmp(&ctx->cgi_ps, &bts_i->cgi_ps) != 0)
			continue;

		LOGPFSML(fi, LOGL_DEBUG, "neighbor CGI-PS %s addresses local BTS %d\n",
			 osmo_cgi_ps_name(&ctx->cgi_ps), bts_i->nr);
		bts_fill_si_cache_value(bts, &ctx->si_info);
		/* Tell the PCU scheduler we are ready to go, from here one we
		 * are polled/driven by the scheduler */
		nacc_fsm_state_chg(fi, NACC_ST_TX_NEIGHBOUR_DATA);
		return;
	}

	/* First check if we have SI info for the target cell in cache */
	si = si_cache_lookup_value(pcu->si_cache, &ctx->cgi_ps);
	if (si) {
		/* Copy info since cache can be deleted at any point */
		memcpy(&ctx->si_info, si, sizeof(ctx->si_info));
		/* Tell the PCU scheduler we are ready to go, from here one we
		 * are polled/driven by the scheduler */
		nacc_fsm_state_chg(fi, NACC_ST_TX_NEIGHBOUR_DATA);
		return;
	}

	/* SI info not in cache, resolve it using RIM procedure against SGSN */
	if (fill_rim_ran_info_req(ctx, &pdu) < 0) {
		nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		return;
	}

	LOGPFSML(fi, LOGL_INFO, "Tx RIM RAN-INFO to request SI of %s\n",
		 osmo_cgi_ps_name(&ctx->cgi_ps));
	rc = bssgp_tx_rim(&pdu, gprs_ns2_nse_nsei(ctx->ms->bts->nse));
	if (rc < 0) {
		LOGPFSML(fi, LOGL_ERROR, "Failed transmitting RIM RAN-INFO %s PDU: %d\n",
			 osmo_cgi_ps_name(&ctx->cgi_ps), rc);
		nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		return;
	}
}


static void st_wait_request_si(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	const Packet_Cell_Change_Notification_t *notif;
	struct si_cache_entry *entry;

	switch (event) {
	case NACC_EV_RX_CELL_CHG_NOTIFICATION:
		notif = (const Packet_Cell_Change_Notification_t *)data;
		handle_retrans_pkt_cell_chg_notif(ctx, notif);
		break;
	case NACC_EV_RX_SI:
		entry = (struct si_cache_entry *)data;
		/* Copy info since cache can be deleted at any point */
		memcpy(&ctx->si_info, &entry->value, sizeof(ctx->si_info));
		/* Tell the PCU scheduler we are ready to go, from here one we
		 * are polled/driven by the scheduler */
		nacc_fsm_state_chg(fi, NACC_ST_TX_NEIGHBOUR_DATA);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* At this point, we already received all required SI information to send stored
 * in struct nacc_fsm_ctx. We now wait for scheduler to ask us to construct
 * RLCMAC DL CTRL messages to move FSM states forward
 */
static void st_tx_neighbour_data_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	ctx->si_info_bytes_sent = 0;
	ctx->container_idx = 0;
}

static void st_tx_neighbour_data(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	const Packet_Cell_Change_Notification_t *notif;
	struct nacc_ev_create_rlcmac_msg_ctx *data_ctx;
	bool all_si_info_sent;

	switch (event) {
	case NACC_EV_RX_CELL_CHG_NOTIFICATION:
		notif = (const Packet_Cell_Change_Notification_t *)data;
		handle_retrans_pkt_cell_chg_notif(ctx, notif);
		break;
	case NACC_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct nacc_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_neighbour_cell_data(ctx, data_ctx->tbf, &all_si_info_sent);
		if (!data_ctx->msg) {
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
			return;
		}
		if (all_si_info_sent) /* DONE */
			nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

/* st_cell_chg_continue_on_enter:
 * At this point, we already sent all Pkt Cell Neighbour Change rlcmac
 * blocks, and we only need to wait to be scheduled again to send PKT
 * CELL CHANGE NOTIFICATION and then we are done
 */

static void st_cell_chg_continue(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	const Packet_Cell_Change_Notification_t *notif;
	struct nacc_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case NACC_EV_RX_CELL_CHG_NOTIFICATION:
		notif = (const Packet_Cell_Change_Notification_t *)data;
		handle_retrans_pkt_cell_chg_notif(ctx, notif);
		break;
	case NACC_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct nacc_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_cell_chg_continue(ctx, data_ctx, &ctx->continue_poll_fn);
		if (data_ctx->msg) {
			ctx->continue_poll_ts = data_ctx->pdch->ts_no;
			nacc_fsm_state_chg(fi, NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK);
		}
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_cell_chg_continue_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	const Packet_Cell_Change_Notification_t *notif;

	switch (event) {
	case NACC_EV_RX_CELL_CHG_NOTIFICATION:
		notif = (const Packet_Cell_Change_Notification_t *)data;
		handle_retrans_pkt_cell_chg_notif(ctx, notif);
		break;
	case NACC_EV_TIMEOUT_CELL_CHG_CONTINUE:
		nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		break;
	case NACC_EV_RX_CELL_CHG_CONTINUE_ACK:
		nacc_fsm_state_chg(fi, NACC_ST_DONE);
		break;
	default:
		OSMO_ASSERT(0);
	}
}


static void st_done_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void nacc_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)fi->priv;
	/* after cleanup() finishes, FSM termination calls osmo_fsm_inst_free,
	   so we need to avoid double-freeing it during ctx talloc free
	   destructor */
	talloc_reparent(ctx, ctx->ms, ctx->fi);
	ctx->fi = NULL;

	/* remove references from owning MS and free entire ctx */
	ctx->ms->nacc = NULL;
	talloc_free(ctx);
}

static int nacc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
	case PCU_TDEF_NEIGH_RESOLVE_TO:
	case PCU_TDEF_SI_RESOLVE_TO:
		nacc_fsm_state_chg(fi, NACC_ST_TX_CELL_CHG_CONTINUE);
		break;
	}
	return 0;
}

static struct osmo_fsm_state nacc_fsm_states[] = {
	[NACC_ST_INITIAL] = {
		.in_event_mask =
			X(NACC_EV_RX_CELL_CHG_NOTIFICATION),
		.out_state_mask =
			X(NACC_ST_WAIT_RESOLVE_RAC_CI) |
			X(NACC_ST_TX_CELL_CHG_CONTINUE),
		.name = "INITIAL",
		.action = st_initial,
	},
	[NACC_ST_WAIT_RESOLVE_RAC_CI] = {
		.in_event_mask =
			X(NACC_EV_RX_CELL_CHG_NOTIFICATION) |
			X(NACC_EV_RX_RAC_CI),
		.out_state_mask =
			X(NACC_ST_WAIT_RESOLVE_RAC_CI) |
			X(NACC_ST_WAIT_REQUEST_SI) |
			X(NACC_ST_TX_CELL_CHG_CONTINUE),
		.name = "WAIT_RESOLVE_RAC_CI",
		.onenter = st_wait_resolve_rac_ci_on_enter,
		.action = st_wait_resolve_rac_ci,
	},
	[NACC_ST_WAIT_REQUEST_SI] = {
		.in_event_mask =
			X(NACC_EV_RX_CELL_CHG_NOTIFICATION) |
			X(NACC_EV_RX_SI),
		.out_state_mask =
			X(NACC_ST_WAIT_RESOLVE_RAC_CI) |
			X(NACC_ST_TX_NEIGHBOUR_DATA) |
			X(NACC_ST_TX_CELL_CHG_CONTINUE),
		.name = "WAIT_REQUEST_SI",
		.onenter = st_wait_request_si_on_enter,
		.action = st_wait_request_si,
	},
	[NACC_ST_TX_NEIGHBOUR_DATA] = {
		.in_event_mask =
			X(NACC_EV_RX_CELL_CHG_NOTIFICATION) |
			X(NACC_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(NACC_ST_WAIT_RESOLVE_RAC_CI) |
			X(NACC_ST_TX_CELL_CHG_CONTINUE),
		.name = "TX_NEIGHBOUR_DATA",
		.onenter = st_tx_neighbour_data_on_enter,
		.action = st_tx_neighbour_data,
	},
	[NACC_ST_TX_CELL_CHG_CONTINUE] = {
		.in_event_mask =
			X(NACC_EV_RX_CELL_CHG_NOTIFICATION) |
			X(NACC_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(NACC_ST_WAIT_RESOLVE_RAC_CI) |
			X(NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK),
		.name = "TX_CELL_CHG_CONTINUE",
		.action = st_cell_chg_continue,
	},
	[NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK] = {
		.in_event_mask =
			X(NACC_EV_RX_CELL_CHG_NOTIFICATION) |
			X(NACC_EV_RX_CELL_CHG_CONTINUE_ACK) |
			X(NACC_EV_TIMEOUT_CELL_CHG_CONTINUE),
		.out_state_mask =
			X(NACC_ST_WAIT_RESOLVE_RAC_CI) |
			X(NACC_ST_TX_CELL_CHG_CONTINUE) |
			X(NACC_ST_DONE),
		.name = "WAIT_CELL_CHG_CONTINUE_ACK",
		.action = st_wait_cell_chg_continue_ack,
	},
	[NACC_ST_DONE] = {
		.in_event_mask = 0,
		.out_state_mask = 0,
		.name = "DONE",
		.onenter = st_done_on_enter,
	},
};

static struct osmo_fsm nacc_fsm = {
	.name = "NACC",
	.states = nacc_fsm_states,
	.num_states = ARRAY_SIZE(nacc_fsm_states),
	.timer_cb = nacc_fsm_timer_cb,
	.cleanup = nacc_fsm_cleanup,
	.log_subsys = DNACC,
	.event_names = nacc_fsm_event_names,
};

static __attribute__((constructor)) void nacc_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&nacc_fsm) == 0);
}

void nacc_fsm_ctrl_reply_cb(struct ctrl_handle *ctrl, struct ctrl_cmd *cmd, void *data)
{
	struct nacc_fsm_ctx *ctx = (struct nacc_fsm_ctx *)data;
	char *tmp = NULL, *tok, *saveptr;
	unsigned int exp_id;
	struct osmo_cell_global_id_ps cgi_ps;

	LOGPFSML(ctx->fi, LOGL_NOTICE, "Received CTRL message: type=%d %s %s: %s\n",
		 cmd->type, cmd->variable, cmd->id, osmo_escape_str(cmd->reply, -1));

	if (cmd->type != CTRL_TYPE_GET_REPLY || !cmd->reply) {
		osmo_fsm_inst_dispatch(ctx->fi, NACC_EV_RX_RAC_CI, NULL);
		return;
	}

	/* Validate it's the seqnum from our last GET cmd, and not from older
	 * one we may have requested in case MS decided to resend Pkt Cell
	 * Change Notify with a different tgt cell:
	 */
	exp_id = arfcn_bsic_2_ctrl_id(ctx->neigh_key.tgt_arfcn, ctx->neigh_key.tgt_bsic);
	if ((unsigned int)atoi(cmd->id) != exp_id) {
		LOGPFSML(ctx->fi, LOGL_INFO,
			 "Received CTRL message with id=%s doesn't match our expected last id=%d, ignoring\n",
			 cmd->id, exp_id);
		return;
	}

	/* TODO: Potentially validate cmd->variable contains same params as we
	   sent, and that cmd->id matches the original set. We may want to keep
	   the original cmd around by setting cmd->defer=1 when sending it. */

	tmp = talloc_strdup(cmd, cmd->reply);
	if (!tmp)
		goto free_ret;

	if (!(tok = strtok_r(tmp, "-", &saveptr)))
		goto free_ret;
	cgi_ps.rai.lac.plmn.mcc = atoi(tok);

	if (!(tok = strtok_r(NULL, "-", &saveptr)))
		goto free_ret;
	cgi_ps.rai.lac.plmn.mnc = atoi(tok);
	cgi_ps.rai.lac.plmn.mnc_3_digits = strlen(tok) > 2;

	if (!(tok = strtok_r(NULL, "-", &saveptr)))
		goto free_ret;
	cgi_ps.rai.lac.lac = atoi(tok);

	if (!(tok = strtok_r(NULL, "-", &saveptr)))
		goto free_ret;
	cgi_ps.rai.rac = atoi(tok);

	if (!(tok = strtok_r(NULL, "\0", &saveptr)))
		goto free_ret;
	cgi_ps.cell_identity = atoi(tok);

	/* Cache the cgi_ps so we can avoid requesting again same resolution for a while */
	neigh_cache_add(ctx->ms->bts->pcu->neigh_cache, &ctx->neigh_key, &cgi_ps);

	osmo_fsm_inst_dispatch(ctx->fi, NACC_EV_RX_RAC_CI, &cgi_ps);
	return;

free_ret:
	talloc_free(tmp);
	osmo_fsm_inst_dispatch(ctx->fi, NACC_EV_RX_RAC_CI, NULL);
	return;
}

static int nacc_fsm_ctx_talloc_destructor(struct nacc_fsm_ctx *ctx)
{
	if (ctx->fi) {
		osmo_fsm_inst_free(ctx->fi);
		ctx->fi = NULL;
	}

	return 0;
}

struct nacc_fsm_ctx *nacc_fsm_alloc(struct GprsMs* ms)
{
	struct nacc_fsm_ctx *ctx = talloc_zero(ms, struct nacc_fsm_ctx);
	char buf[64];

	talloc_set_destructor(ctx, nacc_fsm_ctx_talloc_destructor);

	ctx->ms = ms;

	snprintf(buf, sizeof(buf), "TLLI-0x%08x", ms_tlli(ms));
	ctx->fi = osmo_fsm_inst_alloc(&nacc_fsm, ctx, ctx, LOGL_INFO, buf);
	if (!ctx->fi)
		goto free_ret;

	return ctx;
free_ret:
	talloc_free(ctx);
	return NULL;
}

bool nacc_fsm_is_waiting_addr_resolution(const struct nacc_fsm_ctx *ctx,
					 const struct neigh_cache_entry_key *neigh_key)
{
	if (ctx->fi->state != NACC_ST_WAIT_RESOLVE_RAC_CI)
		return false;
	return neigh_cache_entry_key_eq(&ctx->neigh_key, neigh_key);
}

bool nacc_fsm_is_waiting_si_resolution(const struct nacc_fsm_ctx *ctx,
				       const struct osmo_cell_global_id_ps *cgi_ps)
{
	if (ctx->fi->state != NACC_ST_WAIT_REQUEST_SI)
		return false;
	return !osmo_cgi_ps_cmp(&ctx->cgi_ps, cgi_ps);
}

bool nacc_fsm_exp_ctrl_ack(const struct nacc_fsm_ctx *ctx, uint32_t fn, uint8_t ts)
{
	return ctx->fi->state == NACC_ST_WAIT_CELL_CHG_CONTINUE_ACK &&
	       ctx->continue_poll_fn == fn &&
	       ctx->continue_poll_ts == ts;
}

bool tbf_nacc_rts(const struct gprs_rlcmac_tbf *tbf, const struct gprs_rlcmac_pdch *pdch)
{
	if (!tbf_is_control_ts(tbf, pdch))
		return false;

	return tbf_is_tfi_assigned(tbf) && ms_nacc_rts(tbf_ms(tbf));
}
