/* ms_anr_fsm.c
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <unistd.h>
#include <talloc.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

#include <ms_anr_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>

#define X(s) (1 << (s))

/* We add safety timer to any FSM since ending up into some unexpected scenario
 * can keep the FSM alive and hence the TBF kept open forever */
static const struct osmo_tdef_state_timeout ms_anr_fsm_timeouts[32] = {
	[MS_ANR_ST_INITIAL] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_TX_PKT_MEAS_RESET1] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_WAIT_CTRL_ACK1] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_TX_PKT_MEAS_ORDER] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_WAIT_PKT_MEAS_REPORT] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_TX_PKT_MEAS_RESET2] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_WAIT_CTRL_ACK2] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
	[MS_ANR_ST_DONE] = { .T = PCU_TDEF_ANR_MS_TIMEOUT },
};

/* Transition to a state, using the T timer defined in assignment_fsm_timeouts.
 * The actual timeout value is in turn obtained from conn->T_defs.
 * Assumes local variable fi exists. */
#define ms_anr_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     ms_anr_fsm_timeouts, \
				     ((struct ms_anr_fsm_ctx*)(fi->priv))->ms->bts->pcu->T_defs, \
				     -1)

const struct value_string ms_anr_fsm_event_names[] = {
	{ MS_ANR_EV_START, "START" },
	{ MS_ANR_EV_CREATE_RLCMAC_MSG, "CREATE_RLCMAC_MSG" },
	{ MS_ANR_EV_RX_PKT_MEAS_REPORT, "RX_PKT_MEAS_REPORT" },
	{ MS_ANR_EV_RX_PKT_CTRL_ACK_MSG, "RX_PKT_CTRL_ACK_MSG" },
	{ MS_ANR_EV_RX_PKT_CTRL_ACK_TIMEOUT, "RX_PKT_CTRL_ACK_TIMEOUT" },
	{ 0, NULL }
};

/* TS 44 060 11.2.9b Packet Measurement Order */
static struct msgb *create_packet_meas_order(struct ms_anr_fsm_ctx *ctx,
					     const struct gprs_rlcmac_tbf *tbf,
					     uint8_t nco, uint8_t pmo_idx, uint8_t pmo_count,
					     const NC_Frequency_list_t *freq_li)
{
	struct msgb *msg;
	int rc;
	RlcMacDownlink_t *mac_control_block;
	struct GprsMs *ms = tbf_ms(tbf);
	bool tfi_asigned, tfi_is_dl;
	uint8_t tfi;
	bool exist_nc;
	uint8_t non_drx_period, nc_report_period_i, nc_report_period_t;

	if (tbf_is_tfi_assigned(tbf)) {
		tfi_asigned = true;
		tfi_is_dl = tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF;
		tfi = tbf_tfi(tbf);
	} else {
		tfi_asigned = false;
		tfi_is_dl = false;
		tfi = 0;
	}


	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_meas_order");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	struct bitvec bv = {
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, DUMMY_VEC);

	mac_control_block = (RlcMacDownlink_t *)talloc_zero(ctx->ms, RlcMacDownlink_t);

	/* First message, set NC Meas Params. As per spec:
	 * "If parameters for the NC measurements are not included, a previous
	 * Packet Measurement Order message belonging to the same set of messages
	 * shall still be valid." */
	exist_nc = pmo_idx == 0;
	non_drx_period = 2; /* default value, still need to check */
	nc_report_period_i = 5;//0;
	nc_report_period_t = 5;//0;


	write_packet_measurement_order(mac_control_block, 0, 0, tfi_asigned, tfi_is_dl,tfi, ms_tlli(ms),
				       pmo_idx, pmo_count, nco, exist_nc, non_drx_period,
				       nc_report_period_i, nc_report_period_t, freq_li);
	LOGP(DANR, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Measurement Order +++++++++++++++++++++++++\n");
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DANR, LOGL_ERROR, "Encoding of Packet Measurement Order Data failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DANR, LOGL_DEBUG, "------------------------- TX : Packet Measurement Order -------------------------\n");
	rate_ctr_inc(&bts_rate_counters(ms->bts)->ctr[CTR_PKT_MEAS_ORDER]);
	talloc_free(mac_control_block);

	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

#define MAX_REMOVE_FREQ_PER_MSG 16
#define MAX_ADD_FREQ_PER_MSG 5
static void build_nc_freq_list(struct ms_anr_fsm_ctx *ctx, NC_Frequency_list_t *freq_li,
			       const uint16_t *freq_to_remove, unsigned *freq_to_remove_idx, unsigned freq_to_remove_cnt,
			       const struct arfcn_bsic *freq_to_add, unsigned *freq_to_add_idx, unsigned freq_to_add_cnt)
{
	int i;
	unsigned to_remove_this_message;
	LOGP(DANR, LOGL_DEBUG, "Build NC Frequency List:\n");

	/* First, remove all ARFCNs from BS(GPRS): */
	if (*freq_to_remove_idx < freq_to_remove_cnt) {
		to_remove_this_message = OSMO_MIN(freq_to_remove_cnt - *freq_to_remove_idx, MAX_REMOVE_FREQ_PER_MSG);
		freq_li->Exist_REMOVED_FREQ = 1;
		freq_li->NR_OF_REMOVED_FREQ = to_remove_this_message; /* offset of 1 applied already by CSN1 encoder */
		for (i = 0; i < to_remove_this_message; i++) {
			LOGP(DANR, LOGL_DEBUG, "Remove_Frequency[%d] INDEX=%u\n", i, freq_to_remove[*freq_to_remove_idx]);
			freq_li->Removed_Freq_Index[i].REMOVED_FREQ_INDEX = freq_to_remove[(*freq_to_remove_idx)++];
		}
		/* We want in general to first remove all frequencies, and only once we
		 * are done removing, starting adding new ones */
		if (*freq_to_remove_idx < freq_to_remove_cnt) {
			freq_li->Count_Add_Frequency = 0;
			return;
		}
	} else {
		to_remove_this_message = 0;
		freq_li->Exist_REMOVED_FREQ = 0;
	}

	/* Then, add selected ones for ANR. ctx->cell_list has ARFCNs stored in ascending order */
	freq_li->Count_Add_Frequency = OSMO_MIN(freq_to_add_cnt - *freq_to_add_idx,
						MAX_ADD_FREQ_PER_MSG - to_remove_this_message/4);
	for (i = 0; i < freq_li->Count_Add_Frequency; i++) {
		freq_li->Add_Frequency[i].START_FREQUENCY = freq_to_add[*freq_to_add_idx].arfcn;
		freq_li->Add_Frequency[i].BSIC = freq_to_add[*freq_to_add_idx].bsic;
		freq_li->Add_Frequency[i].Exist_Cell_Selection = 0;
		freq_li->Add_Frequency[i].NR_OF_FREQUENCIES = 0; /* TODO: optimize here checking if we can fit more with DIFF */
		freq_li->Add_Frequency[i].FREQ_DIFF_LENGTH = 0;
		LOGP(DANR, LOGL_DEBUG, "Add_Frequency[%d] START_FREQ=%u BSIC=%u\n", i,
			freq_li->Add_Frequency[i].START_FREQUENCY,
			freq_li->Add_Frequency[i].BSIC);
		(*freq_to_add_idx)++;
	}
}

static int build_multipart_packet_meas_order(struct ms_anr_fsm_ctx *ctx)
{
	struct gprs_rlcmac_bts *bts = ctx->ms->bts;
	unsigned int i, j;
	/* TODO: decide early whether to use si2 or si5, and pick is related BA-IND */
	struct gsm_sysinfo_freq *bcch_freq_list = bts->si2_bcch_cell_list;
	unsigned int bcch_freq_list_len = ARRAY_SIZE(bts->si2_bcch_cell_list);
	unsigned int bcch_freq_list_cnt = 0; // Number of freqs in Neigh List */

	unsigned int freq_to_remove_cnt = 0, freq_to_add_cnt = 0;
	uint16_t freq_to_remove[1024]; /* freq list index */
	struct arfcn_bsic freq_to_add[1024];

	/* First calculate amount of REMOVE and ADD freq entries, to calculate
	 * required number of bits and hence number of RLCMAC messages */
	ctx->nc_measurement_list_len = 0;
	for (i = 0; i < bcch_freq_list_len; i++) {
		bool bcch_freq_marked = !!bcch_freq_list[i].mask;

		if (bcch_freq_marked) {
			/* Freqs from BCCH list occupy one slot in the Neighbour
			 * List, even if removed later by NC_FreqList in Pkt
			 * Meas Order */
			if (ctx->nc_measurement_list_len < ARRAY_SIZE(ctx->nc_measurement_list)) {
				ctx->nc_measurement_list[ctx->nc_measurement_list_len] = i;
				ctx->nc_measurement_list_len++;
			}

			/* Check if the ARFCN is in our target ANR subset,
			 * otherwise mark it from removal using Pkt Meas Order */
			bcch_freq_list_cnt++;
			bool found = false;
			for (j = 0; j < ctx->num_cells; j++) {
				/* early termination, arfcns are in ascending order */
				if (ctx->cell_list[j].arfcn > i)
					break;
				if (ctx->cell_list[j].arfcn == i) {
					found = true;
					break;
				}
			}
			if (!found) {
				freq_to_remove[freq_to_remove_cnt] = bcch_freq_list_cnt - 1;
				freq_to_remove_cnt++;
			}
		} else {
			for (j = 0; j < ctx->num_cells; j++) {
				/* early termination, arfcns are in ascending order */
				if (ctx->cell_list[j].arfcn > i)
					break;
				if (ctx->cell_list[j].arfcn == i) {
					freq_to_add[freq_to_add_cnt] = ctx->cell_list[j];
					freq_to_add_cnt++;
					/* Don't break here, there may be several ARFCN=N with different BSIC */
				}
			}
		}
	}

	LOGPFSML(ctx->fi, LOGL_DEBUG, "NC_freq_list to_remove=%u to_add=%u\n", freq_to_remove_cnt, freq_to_add_cnt);

	/* Added frequency through Pkt Meas Order NC Freq list are indexed after existing arfcns from BA(GPRS) */
	for (i = 0; i < freq_to_add_cnt; i++) {
		if (ctx->nc_measurement_list_len >= ARRAY_SIZE(ctx->nc_measurement_list))
			break;
		ctx->nc_measurement_list[ctx->nc_measurement_list_len] = freq_to_add[i].arfcn;
		ctx->nc_measurement_list_len++;
	}

	uint8_t pmo_index;
	uint8_t pmo_count = 0;
	unsigned int freq_to_remove_idx = 0, freq_to_add_idx = 0;
	NC_Frequency_list_t freq_li[8];
	do {
		OSMO_ASSERT(pmo_count < ARRAY_SIZE(freq_li)); /* TODO: print something here*/
		build_nc_freq_list(ctx, &freq_li[pmo_count],
				   freq_to_remove, &freq_to_remove_idx, freq_to_remove_cnt,
				   freq_to_add, &freq_to_add_idx, freq_to_add_cnt);
		pmo_count++;
	} while (freq_to_remove_idx < freq_to_remove_cnt || freq_to_add_idx < freq_to_add_cnt);

	/* Now build messages */
	for (pmo_index = 0; pmo_index < pmo_count; pmo_index++) {
		struct msgb *msg = create_packet_meas_order(ctx, ctx->tbf, NC_1, pmo_index, pmo_count - 1, &freq_li[pmo_index]);
		llist_add_tail(&msg->list, &ctx->meas_order_queue);
	}
	return 0;
}

/* TS 44 060 11.2.9b Packet Measurement Order */
static struct msgb *create_packet_meas_order_reset(struct ms_anr_fsm_ctx *ctx,
						   struct ms_anr_ev_create_rlcmac_msg_ctx *data,
						   uint32_t *new_poll_fn)
{
	struct msgb *msg;
	int rc;
	RlcMacDownlink_t *mac_control_block;
	struct gprs_rlcmac_tbf *tbf = ctx->tbf;
	struct GprsMs *ms = tbf_ms(tbf);
	bool tfi_asigned, tfi_is_dl;
	uint8_t tfi;
	uint8_t pmo_idx = 0, pmo_count = 0;
	uint8_t nco = NC_RESET;
	unsigned int rrbp;

	if (tbf_is_tfi_assigned(tbf)) {
		tfi_asigned = true;
		tfi_is_dl = tbf_direction(tbf) == GPRS_RLCMAC_DL_TBF;
		tfi = tbf_tfi(tbf);
	} else {
		tfi_asigned = false;
		tfi_is_dl = false;
		tfi = 0;
	}

	rc = tbf_check_polling(tbf, data->fn, data->ts, new_poll_fn, &rrbp);
	if (rc < 0) {
		LOGP(DANR, LOGL_ERROR, "Failed registering poll for Packet Measurement Order (reset) (%d)\n", rc);
		return NULL;
	}

	msg = msgb_alloc(GSM_MACBLOCK_LEN, "pkt_meas_order");
	if (!msg)
		return NULL;

	/* Initialize a bit vector that uses allocated msgb as the data buffer. */
	struct bitvec bv = {
		.data = msgb_put(msg, GSM_MACBLOCK_LEN),
		.data_len = GSM_MACBLOCK_LEN,
	};
	bitvec_unhex(&bv, DUMMY_VEC);

	mac_control_block = (RlcMacDownlink_t *)talloc_zero(ctx->ms, RlcMacDownlink_t);

	write_packet_measurement_order(mac_control_block, 1, rrbp, tfi_asigned, tfi_is_dl,tfi, ms_tlli(ms),
					    pmo_idx, pmo_count, nco, false, 0, 0, 0, NULL);
	LOGP(DANR, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Measurement Order (reset) FN=%" PRIu32 " +++++++++++++++++++++++++\n", data->fn);
	rc = encode_gsm_rlcmac_downlink(&bv, mac_control_block);
	if (rc < 0) {
		LOGP(DANR, LOGL_ERROR, "Encoding of Packet Measurement Order Data failed (%d)\n", rc);
		goto free_ret;
	}
	LOGP(DANR, LOGL_DEBUG, "------------------------- TX : Packet Measurement Order (reset) POLL_FN=%" PRIu32 "-------------------------\n", *new_poll_fn);
	rate_ctr_inc(&bts_rate_counters(ms->bts)->ctr[CTR_PKT_MEAS_ORDER]);
	talloc_free(mac_control_block);

	tbf_set_polling(tbf, *new_poll_fn, data->ts, PDCH_ULC_POLL_MEAS_ORDER);
	return msg;

free_ret:
	talloc_free(mac_control_block);
	msgb_free(msg);
	return NULL;
}

static void handle_meas_report(struct ms_anr_fsm_ctx *ctx, uint8_t *meas, const Packet_Measurement_Report_t *pmr)
{
	//TODO: transmit meas back to BSC
	const NC_Measurement_Report_t *ncr;
	int i, j;
	memset(meas, 0xff, ctx->num_cells);

	switch (pmr->UnionType) {
	case 0: break;
	case 1: /* EXT Reporting, should not happen */
	default:
		LOGPFSML(ctx->fi, LOGL_NOTICE, "EXT Reporting not supported!\n");
		osmo_fsm_inst_term(ctx->fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}

	ncr = &pmr->u.NC_Measurement_Report;
	LOGPFSML(ctx->fi, LOGL_NOTICE, "Rx MEAS REPORT %u neighbours\n", ncr->NUMBER_OF_NC_MEASUREMENTS);

	for (i = 0; i < ncr->NUMBER_OF_NC_MEASUREMENTS; i++) {
		const NC_Measurements_t *nc = &ncr->NC_Measurements[i];
		/* infer ARFCN from FREQUENCY_N using previously calculated data: */
		OSMO_ASSERT(nc->FREQUENCY_N < ARRAY_SIZE(ctx->nc_measurement_list));
		uint16_t arfcn = ctx->nc_measurement_list[nc->FREQUENCY_N];
		LOGPFSML(ctx->fi, LOGL_DEBUG, "Neigh arfcn_index=%u arfcn=%u bsic=%d %d dBm\n",
			 nc->FREQUENCY_N, arfcn, nc->Exist_BSIC_N ? nc->BSIC_N : -1, nc->RXLEV_N - 110);
		if (!nc->Exist_BSIC_N)
			continue; /* Skip measurement without BSIC, since there could be several cells with same ARFCN */
		for (j = 0; j < ctx->num_cells; j++) {
			if (ctx->cell_list[j].arfcn != arfcn || ctx->cell_list[j].bsic != nc->BSIC_N)
				continue;
			meas[j] = nc->RXLEV_N;
			break;
		}
		if (j == ctx->num_cells) {
			LOGPFSML(ctx->fi, LOGL_NOTICE,
				 "Neigh arfcn_index=%u arfcn=%u bsic=%u %d dBm not found in target cell list!\n",
				 nc->FREQUENCY_N, arfcn, nc->BSIC_N, nc->RXLEV_N - 110);
		}
	}
}

////////////////
// FSM states //
////////////////

static void st_initial(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	//struct gprs_rlcmac_bts *bts = ctx->ms->bts;
	const struct ms_anr_ev_start *start_data;

	switch (event) {
	case MS_ANR_EV_START:
		start_data = (const struct ms_anr_ev_start *)data;
		/* Copy over cell list on which to ask for measurements */
		OSMO_ASSERT(start_data->tbf);
		ctx->tbf = start_data->tbf;
		OSMO_ASSERT(start_data->num_cells <= ARRAY_SIZE(ctx->cell_list));
		ctx->num_cells = start_data->num_cells;
		if (start_data->num_cells)
			memcpy(ctx->cell_list, start_data->cell_list, start_data->num_cells * sizeof(start_data->cell_list[0]));
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_TX_PKT_MEAS_RESET1);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_tx_pkt_meas_reset1(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	struct ms_anr_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case MS_ANR_EV_CREATE_RLCMAC_MSG:
		/* Set NC to RESET and drop NC_Freq_list for MS to go back to
		   network defaults. */
		data_ctx = (struct ms_anr_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_meas_order_reset(ctx, data_ctx, &ctx->poll_fn);
		if (!data_ctx->msg) {
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
			return;
		}
		ctx->poll_ts = data_ctx->ts;
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_WAIT_CTRL_ACK1);
		break;
	case MS_ANR_EV_RX_PKT_MEAS_REPORT:
		/* Ignore Meas Report from previously (potentially unfinished) prcoedures */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_ctrl_ack1(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;

	switch (event) {
	case MS_ANR_EV_RX_PKT_CTRL_ACK_MSG:
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_TX_PKT_MEAS_ORDER);
		break;
	case MS_ANR_EV_RX_PKT_CTRL_ACK_TIMEOUT:
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_TX_PKT_MEAS_RESET1);
		break;
	case MS_ANR_EV_RX_PKT_MEAS_REPORT:
		/* Ignore Meas Report from previously (potentially unfinished) prcoedures */
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_tx_pkt_meas_order_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	build_multipart_packet_meas_order(ctx);
}

static void st_tx_pkt_meas_order(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	struct ms_anr_ev_create_rlcmac_msg_ctx *data_ctx;

	switch (event) {
	case MS_ANR_EV_CREATE_RLCMAC_MSG:
		data_ctx = (struct ms_anr_ev_create_rlcmac_msg_ctx *)data;
		/* Set NC to 1 to force MS to send us Meas Rep */
		data_ctx->msg = llist_first_entry(&ctx->meas_order_queue, struct msgb, list);
		if (!data_ctx->msg) {
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
			return;
		}
		llist_del(&data_ctx->msg->list);
		if (llist_empty(&ctx->meas_order_queue)) /* DONE */
			ms_anr_fsm_state_chg(fi, MS_ANR_ST_WAIT_PKT_MEAS_REPORT);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_rx_pkt_meas_report_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* DO NOTHING */
}


static void st_wait_rx_pkt_meas_report(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	uint8_t *meas = alloca(ctx->num_cells);
	struct ms_anr_ev_meas_compl ev_compl = {
		.cell_list = ctx->cell_list,
		.meas_list = meas,
		.num_cells = ctx->num_cells,
	};

	switch (event) {
	case MS_ANR_EV_RX_PKT_MEAS_REPORT:
		handle_meas_report(ctx, meas, (const Packet_Measurement_Report_t *)data);
		osmo_fsm_inst_dispatch(ctx->ms->bts->anr->fi, BTS_ANR_EV_MS_MEAS_COMPL, &ev_compl);
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_TX_PKT_MEAS_RESET2);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_tx_pkt_meas_reset2(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	struct ms_anr_ev_create_rlcmac_msg_ctx *data_ctx;
	uint8_t *meas = alloca(ctx->num_cells);
	struct ms_anr_ev_meas_compl ev_compl = {
		.cell_list = ctx->cell_list,
		.meas_list = meas,
		.num_cells = ctx->num_cells,
	};

	switch (event) {
	case MS_ANR_EV_CREATE_RLCMAC_MSG:
		/* Set NC to RESET and drop NC_Freq_list for MS to go back to
		   network defaults. */
		data_ctx = (struct ms_anr_ev_create_rlcmac_msg_ctx *)data;
		data_ctx->msg = create_packet_meas_order_reset(ctx, data_ctx, &ctx->poll_fn);
		if (!data_ctx->msg) {
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
			return;
		}
		ctx->poll_ts = data_ctx->ts;
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_WAIT_CTRL_ACK2);
		break;
	case MS_ANR_EV_RX_PKT_MEAS_REPORT:
		handle_meas_report(ctx, meas, (const Packet_Measurement_Report_t *)data);
		osmo_fsm_inst_dispatch(ctx->ms->bts->anr->fi, BTS_ANR_EV_MS_MEAS_COMPL, &ev_compl);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_wait_ctrl_ack2(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;
	uint8_t *meas = alloca(ctx->num_cells);
	struct ms_anr_ev_meas_compl ev_compl = {
		.cell_list = ctx->cell_list,
		.meas_list = meas,
		.num_cells = ctx->num_cells,
	};

	switch (event) {
	case MS_ANR_EV_RX_PKT_CTRL_ACK_MSG:
		ms_anr_fsm_state_chg(fi, MS_ANR_ST_DONE);
		break;
	case MS_ANR_EV_RX_PKT_CTRL_ACK_TIMEOUT:
		ms_anr_fsm_state_chg(fi, fi->state == MS_ANR_ST_WAIT_CTRL_ACK1 ?
						MS_ANR_ST_TX_PKT_MEAS_RESET1 :
						MS_ANR_ST_TX_PKT_MEAS_RESET2);
		break;
	case MS_ANR_EV_RX_PKT_MEAS_REPORT:
		/* We may keep receiving meas report from MS while waiting to
		 * receive the CTRL ACK: */
		handle_meas_report(ctx, meas, (const Packet_Measurement_Report_t *)data);
		osmo_fsm_inst_dispatch(ctx->ms->bts->anr->fi, BTS_ANR_EV_MS_MEAS_COMPL, &ev_compl);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_done_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void ms_anr_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ms_anr_fsm_ctx *ctx = (struct ms_anr_fsm_ctx *)fi->priv;

	/* after cleanup() finishes, FSM termination calls osmo_fsm_inst_free,
	   so we need to avoid double-freeing it during ctx talloc free
	   destructor */
	talloc_reparent(ctx, ctx->ms, ctx->fi);
	ctx->fi = NULL;

	/* remove references from owning MS and free entire ctx */
	ctx->ms->anr = NULL;

	if (cause != OSMO_FSM_TERM_REGULAR && cause != OSMO_FSM_TERM_REQUEST) {
		/* Signal to bts_anr_fsm that orchestrates us that we failed, so
		 * that it can schedule the procedure again */
		struct ms_anr_ev_abort ev_data = {
			.cell_list = &ctx->cell_list[0],
			.num_cells = ctx->num_cells,
		};
		osmo_fsm_inst_dispatch(ctx->ms->bts->anr->fi, BTS_ANR_EV_MS_MEAS_ABORTED, &ev_data);
	}

	talloc_free(ctx);
}

static int ms_anr_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
		case PCU_TDEF_ANR_MS_TIMEOUT:
			LOGPFSML(fi, LOGL_NOTICE, "ms_anr_fsm got stuck, freeing it. This probably indicates a bug somehwere (if not in state WAIT_PKT_MEAS_REPORT)\n");
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
			break;
		default:
			OSMO_ASSERT(0);
	}
	return 0;
}

static struct osmo_fsm_state ms_anr_fsm_states[] = {
	[MS_ANR_ST_INITIAL] = {
		.in_event_mask =
			X(MS_ANR_EV_START),
		.out_state_mask =
			X(MS_ANR_ST_TX_PKT_MEAS_RESET1),
		.name = "INITIAL",
		.action = st_initial,
	},
	[MS_ANR_ST_TX_PKT_MEAS_RESET1] = {
		.in_event_mask =
			X(MS_ANR_EV_CREATE_RLCMAC_MSG) |
			X(MS_ANR_EV_RX_PKT_MEAS_REPORT),
		.out_state_mask =
			X(MS_ANR_ST_WAIT_CTRL_ACK1),
		.name = "TX_PKT_MEAS_RESET1",
		.action = st_tx_pkt_meas_reset1,
	},
	[MS_ANR_ST_WAIT_CTRL_ACK1] = {
		.in_event_mask =
			X(MS_ANR_EV_RX_PKT_CTRL_ACK_MSG) |
			X(MS_ANR_EV_RX_PKT_CTRL_ACK_TIMEOUT) |
			X(MS_ANR_EV_RX_PKT_MEAS_REPORT),
		.out_state_mask =
			X(MS_ANR_ST_TX_PKT_MEAS_RESET1) |
			X(MS_ANR_ST_TX_PKT_MEAS_ORDER),
		.name = "WAIT_CTRL_ACK1",
		.action = st_wait_ctrl_ack1,
	},
	[MS_ANR_ST_TX_PKT_MEAS_ORDER] = {
		.in_event_mask =
			X(MS_ANR_EV_CREATE_RLCMAC_MSG),
		.out_state_mask =
			X(MS_ANR_ST_WAIT_PKT_MEAS_REPORT),
		.name = "TX_PKT_MEAS_ORDER",
		.onenter = st_tx_pkt_meas_order_on_enter,
		.action = st_tx_pkt_meas_order,
	},
	[MS_ANR_ST_WAIT_PKT_MEAS_REPORT] = {
		.in_event_mask =
			X(MS_ANR_EV_RX_PKT_MEAS_REPORT),
		.out_state_mask =
			X(MS_ANR_ST_TX_PKT_MEAS_RESET2),
		.name = "WAIT_PKT_MEAS_REPORT",
		.onenter = st_wait_rx_pkt_meas_report_on_enter,
		.action = st_wait_rx_pkt_meas_report,
	},
	[MS_ANR_ST_TX_PKT_MEAS_RESET2] = {
		.in_event_mask =
			X(MS_ANR_EV_CREATE_RLCMAC_MSG) |
			X(MS_ANR_EV_RX_PKT_MEAS_REPORT),
		.out_state_mask =
			X(MS_ANR_ST_WAIT_CTRL_ACK2),
		.name = "TX_PKT_MEAS_RESET2",
		.action = st_tx_pkt_meas_reset2,
	},
	[MS_ANR_ST_WAIT_CTRL_ACK2] = {
		.in_event_mask =
			X(MS_ANR_EV_RX_PKT_CTRL_ACK_MSG) |
			X(MS_ANR_EV_RX_PKT_CTRL_ACK_TIMEOUT) |
			X(MS_ANR_EV_RX_PKT_MEAS_REPORT),
		.out_state_mask =
			X(MS_ANR_ST_TX_PKT_MEAS_RESET2) |
			X(MS_ANR_ST_DONE),
		.name = "WAIT_CTRL_ACK2",
		.action = st_wait_ctrl_ack2,
	},
	[MS_ANR_ST_DONE] = {
		.in_event_mask = 0,
		.out_state_mask = 0,
		.name = "DONE",
		.onenter = st_done_on_enter,
	},
};

static struct osmo_fsm ms_anr_fsm = {
	.name = "MS_ANR",
	.states = ms_anr_fsm_states,
	.num_states = ARRAY_SIZE(ms_anr_fsm_states),
	.timer_cb = ms_anr_fsm_timer_cb,
	.cleanup = ms_anr_fsm_cleanup,
	.log_subsys = DANR,
	.event_names = ms_anr_fsm_event_names,
};

static __attribute__((constructor)) void ms_anr_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&ms_anr_fsm) == 0);
}

static int ms_anr_fsm_ctx_talloc_destructor(struct ms_anr_fsm_ctx *ctx)
{
	/* if ctx->fi != NULL it means we come directly from talloc_free(ctx)
	 * without having passed through ms_anr_fsm_cleanup() as part of
	 * osmo_fsm_inst_term(). In this case, clean up manually similarly to
	 * ms_anr_fsm_cleanup() and free the ctx->fi. */
	if (ctx->fi) {
		/* Signal to bts_anr_fsm that orchestrates us that we failed, so
		 * that it can schedule the procedure again */
		struct ms_anr_ev_abort ev_data = {
			.cell_list = &ctx->cell_list[0],
			.num_cells = ctx->num_cells,
		};
		osmo_fsm_inst_dispatch(ctx->ms->bts->anr->fi, BTS_ANR_EV_MS_MEAS_ABORTED, &ev_data);
		osmo_fsm_inst_free(ctx->fi);
		ctx->fi = NULL;
	}

	return 0;
}

struct ms_anr_fsm_ctx *ms_anr_fsm_alloc(struct GprsMs* ms)
{
	struct ms_anr_fsm_ctx *ctx = talloc_zero(ms, struct ms_anr_fsm_ctx);
	char buf[64];

	talloc_set_destructor(ctx, ms_anr_fsm_ctx_talloc_destructor);

	ctx->ms = ms;
	INIT_LLIST_HEAD(&ctx->meas_order_queue);

	snprintf(buf, sizeof(buf), "TLLI-0x%08x", ms_tlli(ms));
	ctx->fi = osmo_fsm_inst_alloc(&ms_anr_fsm, ctx, ctx, LOGL_INFO, buf);
	if (!ctx->fi)
		goto free_ret;

	return ctx;
free_ret:
	talloc_free(ctx);
	return NULL;
}

/* Used by bts_anr_fsm to abort ongoing procedure without need of being informed
 * back by BTS_ANR_EV_MS_MEAS_ABORTED */
void ms_anr_fsm_abort(struct ms_anr_fsm_ctx *ctx)
{
	osmo_fsm_inst_term(ctx->fi, OSMO_FSM_TERM_REQUEST, NULL);
}
