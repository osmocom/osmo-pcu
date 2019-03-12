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
}

#define GPRS_UNDEFINED_IMSI "000"

GprsMsStorage::GprsMsStorage(BTS *bts) :
	m_bts(bts)
{
}

GprsMsStorage::~GprsMsStorage()
{
	cleanup();
}

void GprsMsStorage::cleanup()
{
	LListHead<GprsMs> *pos, *tmp;

	llist_for_each_safe(pos, tmp, &m_list) {
		GprsMs *ms = pos->entry();
		ms->set_callback(NULL);
		ms_idle(ms);
	}
}

void GprsMsStorage::ms_idle(class GprsMs *ms)
{
	llist_del(&ms->list());
	if (m_bts)
		m_bts->ms_present(m_bts->ms_present_get() - 1);
	if (ms->is_idle())
		delete ms;
}

void GprsMsStorage::ms_active(class GprsMs *ms)
{
	/* Nothing to do */
}

GprsMs *GprsMsStorage::get_ms(uint32_t tlli, uint32_t old_tlli, const char *imsi) const
{
	GprsMs *ms;
	LListHead<GprsMs> *pos;

	if (tlli || old_tlli) {
		llist_for_each(pos, &m_list) {
			ms = pos->entry();
			if (ms->check_tlli(tlli))
				return ms;
			if (ms->check_tlli(old_tlli))
				return ms;
		}
	}

	/* not found by TLLI */

	if (imsi && imsi[0] && strcmp(imsi, GPRS_UNDEFINED_IMSI) != 0) {
		llist_for_each(pos, &m_list) {
			ms = pos->entry();
			if (strcmp(imsi, ms->imsi()) == 0)
				return ms;
		}
	}

	return NULL;
}

GprsMs *GprsMsStorage::create_ms()
{
	GprsMs *ms;

	ms = new GprsMs(m_bts, 0);

	ms->set_callback(this);
	llist_add(&ms->list(), &m_list);
	if (m_bts)
		m_bts->ms_present(m_bts->ms_present_get() + 1);

	return ms;
}
