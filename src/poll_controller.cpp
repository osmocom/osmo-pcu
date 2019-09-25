/* poll_controller.h
 *
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <poll_controller.h>
#include <bts.h>
#include <tbf.h>
#include <tbf_ul.h>
#include <cxx_linuxlist.h>
#include <sba.h>

extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm_utils.h>
}

PollController::PollController(BTS& bts)
	: m_bts(bts)
{}

static inline bool elapsed_fn_check(unsigned max_delay, int frame_number, uint32_t from)
{
	uint32_t elapsed = (frame_number + GSM_MAX_FN - from) % GSM_MAX_FN;

	if (elapsed > max_delay && elapsed < 2715400)
		return true;

	return false;
}

void PollController::expireTimedout(int frame_number, unsigned max_delay)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_sba *sba, *sba2;
	LListHead<gprs_rlcmac_tbf> *pos;

	llist_for_each(pos, &m_bts.ul_tbfs()) {
		ul_tbf = as_ul_tbf(pos->entry());
		if (ul_tbf->poll_scheduled()) {
			if (elapsed_fn_check(max_delay, frame_number, ul_tbf->poll_fn))
				ul_tbf->poll_timeout();
		}
	}
	llist_for_each(pos, &m_bts.dl_tbfs()) {
		dl_tbf = as_dl_tbf(pos->entry());
		if (dl_tbf->poll_scheduled()) {
			if (elapsed_fn_check(max_delay, frame_number, dl_tbf->poll_fn))
				dl_tbf->poll_timeout();
		}
	}
	llist_for_each_entry_safe(sba, sba2, &m_bts.sba()->m_sbas, list) {
		if (elapsed_fn_check(max_delay, frame_number, sba->fn)) {
			/* sba will be freed here */
			m_bts.sba()->timeout(sba);
		}
	}

}
