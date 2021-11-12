/* gprs_ms_storage.cpp
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


#include "gprs_ms_storage.h"

#include "tbf.h"
#include "bts.h"

extern "C" {
	#include <osmocom/core/linuxlist.h>
	#include <osmocom/gsm/gsm48.h>
}

static void ms_storage_ms_idle_cb(struct GprsMs *ms)
{
	llist_del(&ms->list);
	if (ms->bts)
		bts_stat_item_add(ms->bts, STAT_MS_PRESENT, -1);
	if (ms_is_idle(ms))
		talloc_free(ms);
}

static void ms_storage_ms_active_cb(struct GprsMs *ms)
{
	/* Nothing to do */
}

static struct gpr_ms_callback ms_storage_ms_cb = {
	.ms_idle = ms_storage_ms_idle_cb,
	.ms_active = ms_storage_ms_active_cb,
};

GprsMsStorage::GprsMsStorage(struct gprs_rlcmac_bts *bts) :
	m_bts(bts)
{
	INIT_LLIST_HEAD(&m_list);
}

GprsMsStorage::~GprsMsStorage()
{
	cleanup();
}

void GprsMsStorage::cleanup()
{
	struct llist_head *pos, *tmp;

	llist_for_each_safe(pos, tmp, &m_list) {
		struct GprsMs *ms = llist_entry(pos, typeof(*ms), list);
		ms_set_callback(ms, NULL);
		ms_storage_ms_idle_cb(ms);
	}
}

GprsMs *GprsMsStorage::get_ms(uint32_t tlli, uint32_t old_tlli, const char *imsi) const
{
	struct llist_head *tmp;
	GprsMs *ms;

	if (tlli != GSM_RESERVED_TMSI || old_tlli != GSM_RESERVED_TMSI) {
		llist_for_each(tmp, &m_list) {
			ms = llist_entry(tmp, typeof(*ms), list);
			if (ms_check_tlli(ms, tlli))
				return ms;
			if (ms_check_tlli(ms, old_tlli))
				return ms;
		}
	}

	/* not found by TLLI */

	if (imsi && imsi[0] != '\0') {
		llist_for_each(tmp, &m_list) {
			ms = llist_entry(tmp, typeof(*ms), list);
			if (ms_imsi_is_valid(ms) && strcmp(imsi, ms_imsi(ms)) == 0)
				return ms;
		}
	}

	return NULL;
}

GprsMs *GprsMsStorage::create_ms()
{
	GprsMs *ms;

	ms = ms_alloc(m_bts, GSM_RESERVED_TMSI);

	ms_set_callback(ms, &ms_storage_ms_cb);
	llist_add(&ms->list, &m_list);
	if (m_bts)
		bts_stat_item_add(m_bts, STAT_MS_PRESENT, 1);

	return ms;
}
