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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
/* OsmoBTS VTY interface */


#include <stdint.h>
#include <stdlib.h>
#include "pcu_vty_functions.h"
#include "bts.h"
#include "gprs_ms_storage.h"
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

static void tbf_print_vty_info(struct vty *vty, gprs_rlcmac_tbf *tbf)
{
	gprs_rlcmac_ul_tbf *ul_tbf = as_ul_tbf(tbf);
	gprs_rlcmac_dl_tbf *dl_tbf = as_dl_tbf(tbf);

	vty_out(vty, "TBF: TFI=%d TLLI=0x%08x (%s) TA=%u DIR=%s IMSI=%s%s", tbf->tfi(),
		tbf->tlli(), tbf->is_tlli_valid() ? "valid" : "invalid",
		tbf->ta(),
		tbf->direction == GPRS_RLCMAC_UL_TBF ? "UL" : "DL",
		tbf->imsi(), VTY_NEWLINE);
	vty_out(vty, " created=%lu state=%08x [CCCH:%u, PACCH:%u] 1st_TS=%d 1st_cTS=%d ctrl_TS=%d MS_CLASS=%d/%d%s",
		tbf->created_ts(), tbf->state_flags,
		tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH),
		tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH),
		tbf->first_ts,
		tbf->first_common_ts, tbf->control_ts,
		tbf->ms_class(),
		tbf->ms() ? tbf->ms()->egprs_ms_class() : -1,
		VTY_NEWLINE);
	vty_out(vty, " TS_alloc=");
	for (int i = 0; i < 8; i++) {
		bool is_ctrl = tbf->is_control_ts(i);
		if (tbf->pdch[i])
			vty_out(vty, "%d%s ", i, is_ctrl ? "!" : "");
	}
	if (tbf->trx != NULL)
		vty_out(vty, " TRX_ID=%d", tbf->trx->trx_no);
	vty_out(vty, " CS=%s", mcs_name(tbf->current_cs()));

	if (ul_tbf) {
		gprs_rlc_ul_window *win = ul_tbf->window();
		vty_out(vty, " WS=%u V(Q)=%d V(R)=%d",
			ul_tbf->window_size(), win->v_q(), win->v_r());
		vty_out(vty, "%s", VTY_NEWLINE);
		vty_out(vty, " TBF Statistics:%s", VTY_NEWLINE);
		if(GPRS == tbf->ms()->mode()) {
			vty_out_rate_ctr_group(vty, " ", ul_tbf->m_ul_gprs_ctrs);
		} else {
			vty_out_rate_ctr_group(vty, " ", ul_tbf->m_ul_egprs_ctrs);
		}
	}
	if (dl_tbf) {
		gprs_rlc_dl_window *win = dl_tbf->window();
		vty_out(vty, " WS=%u V(A)=%d V(S)=%d nBSN=%d%s",
			dl_tbf->window_size(), win->v_a(), win->v_s(), win->resend_needed(),
			win->window_stalled() ? " STALLED" : "");
		vty_out(vty, "%s", VTY_NEWLINE);
		vty_out_rate_ctr_group(vty, " ", tbf->m_ctrs);
		if(GPRS == tbf->ms()->mode()) {
			vty_out_rate_ctr_group(vty, " ", dl_tbf->m_dl_gprs_ctrs);
		} else {
			vty_out_rate_ctr_group(vty, " ", dl_tbf->m_dl_egprs_ctrs);
		}
	}
	vty_out(vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
}

int pcu_vty_show_tbf_all(struct vty *vty, struct gprs_rlcmac_bts *bts_data, uint32_t flags)
{
	BTS *bts = bts_data->bts;
	LListHead<gprs_rlcmac_tbf> *iter;

	vty_out(vty, "UL TBFs%s", VTY_NEWLINE);
	llist_for_each(iter, &bts->ul_tbfs()) {
		if (iter->entry()->state_flags & flags)
			tbf_print_vty_info(vty, iter->entry());
	}

	vty_out(vty, "%sDL TBFs%s", VTY_NEWLINE, VTY_NEWLINE);
	llist_for_each(iter, &bts->dl_tbfs()) {
		if (iter->entry()->state_flags & flags)
			tbf_print_vty_info(vty, iter->entry());
	}

	return CMD_SUCCESS;
}

static int show_ms(struct vty *vty, GprsMs *ms)
{
	unsigned i;
	LListHead<gprs_rlcmac_tbf> *i_tbf;
	uint8_t slots;

	vty_out(vty, "MS TLLI=%08x, IMSI=%s%s", ms->tlli(), ms->imsi(), VTY_NEWLINE);
	vty_out(vty, "  Timing advance (TA):    %d%s", ms->ta(), VTY_NEWLINE);
	vty_out(vty, "  Coding scheme uplink:   %s%s", mcs_name(ms->current_cs_ul()),
		VTY_NEWLINE);
	vty_out(vty, "  Coding scheme downlink: %s%s", mcs_name(ms->current_cs_dl()),
		VTY_NEWLINE);
	vty_out(vty, "  Mode:                   %s%s", mode_name(ms->mode()), VTY_NEWLINE);
	vty_out(vty, "  MS class:               %d%s", ms->ms_class(), VTY_NEWLINE);
	vty_out(vty, "  EGPRS MS class:         %d%s", ms->egprs_ms_class(), VTY_NEWLINE);
	vty_out(vty, "  PACCH:                  ");
	slots = ms->current_pacch_slots();
	for (int i = 0; i < 8; i++)
		if (slots & (1 << i))
			vty_out(vty, "%d ", i);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  LLC queue length:       %zd%s", ms->llc_queue()->size(),
		VTY_NEWLINE);
	vty_out(vty, "  LLC queue octets:       %zd%s", ms->llc_queue()->octets(),
		VTY_NEWLINE);
	if (ms->l1_meas()->have_rssi)
		vty_out(vty, "  RSSI:                   %d dBm%s",
			ms->l1_meas()->rssi, VTY_NEWLINE);
	if (ms->l1_meas()->have_ber)
		vty_out(vty, "  Bit error rate:         %d %%%s",
			ms->l1_meas()->ber, VTY_NEWLINE);
	if (ms->l1_meas()->have_link_qual)
		vty_out(vty, "  Link quality:           %d dB%s",
			ms->l1_meas()->link_qual, VTY_NEWLINE);
	if (ms->l1_meas()->have_bto)
		vty_out(vty, "  Burst timing offset:    %d/4 bit%s",
			ms->l1_meas()->bto, VTY_NEWLINE);
	if (ms->l1_meas()->have_ms_rx_qual)
		vty_out(vty, "  Downlink NACK rate:     %d %%%s",
			ms->nack_rate_dl(), VTY_NEWLINE);
	if (ms->l1_meas()->have_ms_rx_qual)
		vty_out(vty, "  MS RX quality:          %d %%%s",
			ms->l1_meas()->ms_rx_qual, VTY_NEWLINE);
	if (ms->l1_meas()->have_ms_c_value)
		vty_out(vty, "  MS C value:             %d dB%s",
			ms->l1_meas()->ms_c_value, VTY_NEWLINE);
	if (ms->l1_meas()->have_ms_sign_var)
		vty_out(vty, "  MS SIGN variance:       %d dB%s",
			ms->l1_meas()->ms_sign_var, VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(ms->l1_meas()->ts); ++i) {
		if (ms->l1_meas()->ts[i].have_ms_i_level)
			vty_out(vty, "  MS I level (slot %d):    %d dB%s",
				i, ms->l1_meas()->ts[i].ms_i_level, VTY_NEWLINE);
	}
	vty_out(vty, "  RLC/MAC DL Control Msg: %d%s", ms->dl_ctrl_msg(),
		VTY_NEWLINE);
	if (ms->ul_tbf())
		vty_out(vty, "  Uplink TBF:             TFI=%d, state=%s%s",
			ms->ul_tbf()->tfi(),
			ms->ul_tbf()->state_name(),
			VTY_NEWLINE);
	if (ms->dl_tbf()) {
		vty_out(vty, "  Downlink TBF:           TFI=%d, state=%s%s",
			ms->dl_tbf()->tfi(),
			ms->dl_tbf()->state_name(),
			VTY_NEWLINE);
		vty_out(vty, "  Current DL Throughput:  %d Kbps %s",
			ms->dl_tbf()->m_bw.dl_throughput,
			VTY_NEWLINE);
	}

	llist_for_each(i_tbf, &ms->old_tbfs())
		vty_out(vty, "  Old %-19s TFI=%d, state=%s%s",
			i_tbf->entry()->direction == GPRS_RLCMAC_UL_TBF ?
			"Uplink TBF:" : "Downlink TBF:",
			i_tbf->entry()->tfi(),
			i_tbf->entry()->state_name(),
			VTY_NEWLINE);

	return CMD_SUCCESS;
}

int pcu_vty_show_ms_all(struct vty *vty, struct gprs_rlcmac_bts *bts_data)
{
	BTS *bts = bts_data->bts;
	LListHead<GprsMs> *ms_iter;

	llist_for_each(ms_iter, &bts->ms_store().ms_list())
		show_ms(vty, ms_iter->entry());

	return CMD_SUCCESS;
}

int pcu_vty_show_ms_by_tlli(struct vty *vty, struct gprs_rlcmac_bts *bts_data,
	uint32_t tlli)
{
	BTS *bts = bts_data->bts;
	GprsMs *ms = bts->ms_store().get_ms(tlli);
	if (!ms) {
		vty_out(vty, "Unknown TLLI %08x.%s", tlli, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return show_ms(vty, ms);
}

int pcu_vty_show_ms_by_imsi(struct vty *vty, struct gprs_rlcmac_bts *bts_data,
	const char *imsi)
{
	BTS *bts = bts_data->bts;
	GprsMs *ms = bts->ms_store().get_ms(0, 0, imsi);
	if (!ms) {
		vty_out(vty, "Unknown IMSI '%s'.%s", imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return show_ms(vty, ms);
}
