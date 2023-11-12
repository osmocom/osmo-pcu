/* pcu_vty_functions.cpp
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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
/* OsmoBTS VTY interface */


#include <stdint.h>
#include <stdlib.h>
#include "pcu_vty_functions.h"
#include "bts.h"
#include "gprs_ms.h"
#include "cxx_linuxlist.h"
#include <llc.h>
#include <pcu_l1_if.h>
#include <rlc.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <pdch.h>

extern "C" {
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
	#include <osmocom/core/linuxlist.h>
	#include <osmocom/core/utils.h>
	#include <osmocom/vty/vty.h>
	#include "coding_scheme.h"
}

static uint32_t tbf_state_flags(const struct gprs_rlcmac_tbf *tbf)
{
	const struct gprs_rlcmac_ul_tbf *ul_tbf = tbf_as_ul_tbf_const(tbf);
	const struct gprs_rlcmac_dl_tbf *dl_tbf = tbf_as_dl_tbf_const(tbf);
	if (ul_tbf)
		return ul_tbf->state_fsm.state_flags;
	return dl_tbf->state_fsm.state_flags;
}

static void tbf_print_vty_info(struct vty *vty, struct gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf = tbf_as_ul_tbf(tbf);
	gprs_rlcmac_dl_tbf *dl_tbf = tbf_as_dl_tbf(tbf);
	uint32_t state_flags = tbf_state_flags(tbf);
	struct GprsMs *ms = tbf_ms(tbf);
	const struct gprs_rlcmac_pdch *first_common_ts = ms_first_common_ts(ms);

	vty_out(vty, "TBF: TFI=%d TLLI=0x%08x (%s) TA=%u DIR=%s IMSI=%s%s", tbf->tfi(),
		tbf->tlli(), tbf->is_tlli_valid() ? "valid" : "invalid",
		tbf->ta(),
		tbf->direction == GPRS_RLCMAC_UL_TBF ? "UL" : "DL",
		tbf->imsi(), VTY_NEWLINE);
	vty_out(vty, " created=%lu state=%s flags=%08x [CCCH:%u, PACCH:%u] 1st_cTS=%" PRId8 " ctrl_TS=%d MS_CLASS=%d/%d%s",
		tbf->created_ts(), tbf->state_name(),
		state_flags,
		state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH),
		state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH),
		first_common_ts ? first_common_ts->ts_no : -1,
		tbf->control_ts ? tbf->control_ts->ts_no : -1,
		tbf->ms_class(),
		ms_egprs_ms_class(ms),
		VTY_NEWLINE);
	vty_out(vty, " TS_alloc=");
	for (int i = 0; i < 8; i++) {
		bool is_ctrl = tbf_is_control_ts(tbf, tbf->pdch[i]);
		if (tbf->pdch[i])
			vty_out(vty, "%d%s ", i, is_ctrl ? "!" : "");
	}
	if (tbf->trx != NULL)
		vty_out(vty, " TRX_ID=%d", tbf->trx->trx_no);
	vty_out(vty, " CS=%s", mcs_name(tbf->current_cs()));

	if (ul_tbf) {
		gprs_rlc_ul_window *win = static_cast<gprs_rlc_ul_window *>(ul_tbf->window());
		vty_out(vty, " WS=%u V(Q)=%d V(R)=%d",
			ul_tbf->window_size(), win->v_q(), win->v_r());
		vty_out(vty, "%s", VTY_NEWLINE);
		vty_out(vty, " TBF Statistics:%s", VTY_NEWLINE);
		if (ul_tbf->m_ul_gprs_ctrs)
			vty_out_rate_ctr_group(vty, " ", ul_tbf->m_ul_gprs_ctrs);
		if (ul_tbf->m_ul_egprs_ctrs)
			vty_out_rate_ctr_group(vty, " ", ul_tbf->m_ul_egprs_ctrs);
	}
	if (dl_tbf) {
		gprs_rlc_dl_window *win = static_cast<gprs_rlc_dl_window *>(dl_tbf->window());
		vty_out(vty, " WS=%u V(A)=%d V(S)=%d nBSN=%d%s",
			dl_tbf->window_size(), win->v_a(), win->v_s(), win->resend_needed(),
			win->window_stalled() ? " STALLED" : "");
		vty_out(vty, "%s", VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, " ", tbf->m_ctrs);
		if (dl_tbf->m_dl_gprs_ctrs)
			vty_out_rate_ctr_group(vty, " ", dl_tbf->m_dl_gprs_ctrs);
		if (dl_tbf->m_dl_egprs_ctrs)
			vty_out_rate_ctr_group(vty, " ", dl_tbf->m_dl_egprs_ctrs);
	}
	vty_out(vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
}

int pcu_vty_show_tbf_all(struct vty *vty, struct gprs_rlcmac_bts *bts, uint32_t flags)
{
	struct llist_item *iter;
	const struct gprs_rlcmac_trx *trx;
	struct gprs_rlcmac_tbf *tbf;
	const struct gprs_rlcmac_ul_tbf *ul_tbf;
	const struct gprs_rlcmac_dl_tbf *dl_tbf;
	size_t trx_no;

	vty_out(vty, "UL TBFs%s", VTY_NEWLINE);
	for (trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); trx_no++) {
		trx = &bts->trx[trx_no];
		llist_for_each_entry(iter, &trx->ul_tbfs, list) {
			tbf = (struct gprs_rlcmac_tbf *)iter->entry;
			ul_tbf = tbf_as_ul_tbf_const(tbf);
			if (ul_tbf->state_fsm.state_flags & flags)
				tbf_print_vty_info(vty, tbf);
		}
	}

	vty_out(vty, "%sDL TBFs%s", VTY_NEWLINE, VTY_NEWLINE);
	for (trx_no = 0; trx_no < ARRAY_SIZE(bts->trx); trx_no++) {
		trx = &bts->trx[trx_no];
		llist_for_each_entry(iter, &trx->dl_tbfs, list) {
			tbf = (struct gprs_rlcmac_tbf *)iter->entry;
			dl_tbf = tbf_as_dl_tbf_const(tbf);
			if (dl_tbf->state_fsm.state_flags & flags)
				tbf_print_vty_info(vty, tbf);
		}
	}

	return CMD_SUCCESS;
}

static int show_ms(struct vty *vty, GprsMs *ms)
{
	unsigned i;
	struct llist_item *i_tbf;
	uint8_t slots;

	vty_out(vty, "MS TLLI=%08x, IMSI=%s%s", ms_tlli(ms), ms_imsi(ms), VTY_NEWLINE);
	if (osmo_timer_pending(&ms->release_timer)) {
		struct timeval tv_now, tv_res1, tv_res2;
		osmo_gettimeofday(&tv_now, NULL);
		timersub(&tv_now, &ms->tv_idle_start, &tv_res1);
		osmo_timer_remaining(&ms->release_timer, &tv_now, &tv_res2);
		vty_out(vty, "  State:                  IDLE for %lus, release in %lus%s",
			tv_res1.tv_sec, tv_res2.tv_sec, VTY_NEWLINE);
	} else {
		vty_out(vty, "  State:                  ACTIVE%s", VTY_NEWLINE);
	}
	vty_out(vty, "  Mode:                   %s%s", mode_name(ms_mode(ms)), VTY_NEWLINE);
	vty_out(vty, "  MS class:               %d%s", ms_ms_class(ms), VTY_NEWLINE);
	vty_out(vty, "  EGPRS MS class:         %d%s", ms_egprs_ms_class(ms), VTY_NEWLINE);
	vty_out(vty, "  PACCH:                  ");
	slots = ms_current_pacch_slots(ms);
	for (int i = 0; i < 8; i++)
		if (slots & (1 << i))
			vty_out(vty, "TS%d ", i);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  DL LLC queue length:    %zd%s", llc_queue_size(ms_llc_queue(ms)),
		VTY_NEWLINE);
	vty_out(vty, "  DL LLC queue octets:    %zd%s", llc_queue_octets(ms_llc_queue(ms)),
		VTY_NEWLINE);
	vty_out(vty, "  DL Coding Scheme:       %s%s", mcs_name(ms_current_cs_dl(ms, ms_mode(ms))),
		VTY_NEWLINE);
	vty_out(vty, "  UL Coding Scheme:       %s%s", mcs_name(ms_current_cs_ul(ms)),
		VTY_NEWLINE);
	vty_out(vty, "  Timing advance (TA):    %d%s", ms_ta(ms), VTY_NEWLINE);
	if (ms->l1_meas.have_rssi)
		vty_out(vty, "  RSSI:                   %d dBm%s",
			ms->l1_meas.rssi, VTY_NEWLINE);
	if (ms->l1_meas.have_ber)
		vty_out(vty, "  Bit error rate:         %d %%%s",
			ms->l1_meas.ber, VTY_NEWLINE);
	if (ms->l1_meas.have_link_qual)
		vty_out(vty, "  Link quality:           %d dB%s",
			ms->l1_meas.link_qual, VTY_NEWLINE);
	if (ms->l1_meas.have_bto)
		vty_out(vty, "  Burst timing offset:    %d/4 bit%s",
			ms->l1_meas.bto, VTY_NEWLINE);
	if (ms->l1_meas.have_ms_rx_qual)
		vty_out(vty, "  Downlink NACK rate:     %d %%%s",
			ms_nack_rate_dl(ms), VTY_NEWLINE);
	if (ms->l1_meas.have_ms_rx_qual)
		vty_out(vty, "  MS Rx quality:          %d %%%s",
			ms->l1_meas.ms_rx_qual, VTY_NEWLINE);
	if (ms->l1_meas.have_ms_c_value)
		vty_out(vty, "  MS C value:             %d dB%s",
			ms->l1_meas.ms_c_value, VTY_NEWLINE);
	if (ms->l1_meas.have_ms_sign_var)
		vty_out(vty, "  MS SIGN variance:       %d dB%s",
			ms->l1_meas.ms_sign_var, VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(ms->l1_meas.ts); ++i) {
		if (ms->l1_meas.ts[i].have_ms_i_level)
			vty_out(vty, "  MS I level (slot %d):    %d dB%s",
				i, ms->l1_meas.ts[i].ms_i_level, VTY_NEWLINE);
	}
	if (ms_ul_tbf(ms))
		vty_out(vty, "  UL TBF:                 TFI=%d, state=%s%s",
			ms_ul_tbf(ms)->tfi(),
			ms_ul_tbf(ms)->state_name(),
			VTY_NEWLINE);
	if (ms_dl_tbf(ms)) {
		vty_out(vty, "  DL TBF:                 TFI=%d, state=%s%s",
			ms_dl_tbf(ms)->tfi(),
			ms_dl_tbf(ms)->state_name(),
			VTY_NEWLINE);
		vty_out(vty, "  Current DL Throughput:  %d Kbps%s",
			ms_dl_tbf(ms)->m_bw.dl_throughput,
			VTY_NEWLINE);
	}

	llist_for_each_entry(i_tbf, &ms->old_tbfs, list) {
		struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)i_tbf->entry;
		vty_out(vty, "  Old %s TBF: TFI=%d, state=%s%s",
			tbf_direction(tbf) == GPRS_RLCMAC_UL_TBF ?
			"UL" : "DL",
			tbf->tfi(),
			tbf->state_name(),
			VTY_NEWLINE);
	}
	vty_out_rate_ctr_group(vty, "  ", ms->ctrs);

	return CMD_SUCCESS;
}

int pcu_vty_show_ms_all(struct vty *vty, struct gprs_rlcmac_bts *bts)
{
	struct llist_head *tmp;

	llist_for_each(tmp, &bts->ms_list) {
		struct GprsMs *ms_iter = llist_entry(tmp, typeof(*ms_iter), list);
		show_ms(vty, ms_iter);
	}

	return CMD_SUCCESS;
}

int pcu_vty_show_ms_by_tlli(struct vty *vty, struct gprs_rlcmac_bts *bts,
	uint32_t tlli)
{
	struct GprsMs *ms = bts_get_ms_by_tlli(bts, tlli, GSM_RESERVED_TMSI);
	if (!ms) {
		vty_out(vty, "Unknown TLLI %08x.%s", tlli, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return show_ms(vty, ms);
}

int pcu_vty_show_ms_by_imsi(struct vty *vty, struct gprs_rlcmac_bts *bts,
	const char *imsi)
{
	struct GprsMs *ms = bts_get_ms_by_imsi(bts, imsi);
	if (!ms) {
		vty_out(vty, "Unknown IMSI '%s'.%s", imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return show_ms(vty, ms);
}

int pcu_vty_show_bts_pdch(struct vty *vty, const struct gprs_rlcmac_bts *bts)
{
	unsigned int trx_nr, ts_nr;

	vty_out(vty, "BTS%" PRIu8 " (%s)%s", bts->nr, bts->active ? "active" : "disabled", VTY_NEWLINE);
	for (trx_nr = 0; trx_nr < ARRAY_SIZE(bts->trx); trx_nr++) {
		const struct gprs_rlcmac_trx *trx = &bts->trx[trx_nr];

		for (ts_nr = 0; ts_nr < ARRAY_SIZE(trx->pdch); ts_nr++) {
			if (trx->pdch[ts_nr].is_enabled())
				break;
		}
		if (ts_nr == ARRAY_SIZE(trx->pdch))
			continue; /* no pdch active, skip */

		vty_out(vty, " TRX%u%s", trx->trx_no, VTY_NEWLINE);
		for (ts_nr = 0; ts_nr < ARRAY_SIZE(trx->pdch); ts_nr++) {
			const struct gprs_rlcmac_pdch *pdch = &trx->pdch[ts_nr];

			vty_out(vty, "  TS%u: PDCH %s, %u DL TBFs, %u UL TBFs%s", pdch->ts_no,
				pdch->is_enabled() ? "enabled" : "disabled",
				pdch->num_tbfs(GPRS_RLCMAC_DL_TBF),
				pdch->num_tbfs(GPRS_RLCMAC_UL_TBF), VTY_NEWLINE);
		}
	}
	return CMD_SUCCESS;
}
