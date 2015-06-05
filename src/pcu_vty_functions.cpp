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

extern "C" {
#  include <osmocom/vty/command.h>
#  include <osmocom/vty/logging.h>
#  include <osmocom/vty/misc.h>
}

int pcu_vty_config_write_pcu_ext(struct vty *vty)
{
	return CMD_SUCCESS;
}

int pcu_vty_show_ms_all(struct vty *vty, struct gprs_rlcmac_bts *bts_data)
{
	BTS *bts = bts_data->bts;
	LListHead<GprsMs> *ms_iter;

	llist_for_each(ms_iter, &bts->ms_store().ms_list()) {
		GprsMs *ms = ms_iter->entry();

		vty_out(vty, "MS TLLI=%08x, TA=%d, CS-UL=%d, CS-DL=%d, IMSI=%s%s",
			ms->tlli(),
			ms->ta(), ms->current_cs_ul(), ms->current_cs_dl(),
			ms->imsi(),
			VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

static int show_ms(struct vty *vty, GprsMs *ms)
{
	vty_out(vty, "MS TLLI=%08x, IMSI=%s%s", ms->tlli(), ms->imsi(), VTY_NEWLINE);
	vty_out(vty, "  Timing advance (TA):    %d%s", ms->ta(), VTY_NEWLINE);
	vty_out(vty, "  Coding scheme uplink:   CS-%d%s", ms->current_cs_ul(),
		VTY_NEWLINE);
	vty_out(vty, "  Coding scheme downlink: CS-%d%s", ms->current_cs_dl(),
		VTY_NEWLINE);
	vty_out(vty, "  MS class:               %d%s", ms->ms_class(), VTY_NEWLINE);
	vty_out(vty, "  LLC queue length:       %d%s", ms->llc_queue()->size(),
		VTY_NEWLINE);
	if (ms->ul_tbf())
		vty_out(vty, "  Uplink TBF:             TFI=%d, state=%s%s",
			ms->ul_tbf()->tfi(),
			ms->ul_tbf()->state_name(),
			VTY_NEWLINE);
	if (ms->dl_tbf())
		vty_out(vty, "  Downlink TBF:           TFI=%d, state=%s%s",
			ms->dl_tbf()->tfi(),
			ms->dl_tbf()->state_name(),
			VTY_NEWLINE);

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
