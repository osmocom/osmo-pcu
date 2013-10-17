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
#include <tbf.h>

PollController::PollController(BTS& bts)
	: m_bts(bts)
{}

void PollController::expireTimedout(int frame_number)
{
	struct gprs_rlcmac_bts *bts = m_bts.bts_data();
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_sba *sba, *sba2;
	uint32_t elapsed;

	/* check for poll timeout */
	llist_for_each_entry(tbf, &gprs_rlcmac_ul_tbfs, list) {
		if (tbf->poll_state == GPRS_RLCMAC_POLL_SCHED) {
			elapsed = (frame_number + 2715648 - tbf->poll_fn)
								% 2715648;
			if (elapsed >= 20 && elapsed < 2715400)
				gprs_rlcmac_poll_timeout(bts, tbf);
		}
	}
	llist_for_each_entry(tbf, &gprs_rlcmac_dl_tbfs, list) {
		if (tbf->poll_state == GPRS_RLCMAC_POLL_SCHED) {
			elapsed = (frame_number + 2715648 - tbf->poll_fn)
								% 2715648;
			if (elapsed >= 20 && elapsed < 2715400)
				gprs_rlcmac_poll_timeout(bts, tbf);
		}
	}
	llist_for_each_entry_safe(sba, sba2, &gprs_rlcmac_sbas, list) {
		elapsed = (frame_number + 2715648 - sba->fn) % 2715648;
		if (elapsed >= 20 && elapsed < 2715400) {
			/* sba will be freed here */
			gprs_rlcmac_sba_timeout(sba);
		}
	}

}
