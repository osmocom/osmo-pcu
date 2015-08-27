/* poll_controller.h
 *
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

#pragma once

struct gprs_rlcmac_bts;

struct BTS;

/**
 * I belong to a BTS and I am responsible for finding TBFs and
 * SBAs that should have been polled and execute the timeout
 * action on them.
 */
class PollController {
public:
	PollController(BTS& bts);

	/* check for poll timeout */
	void expireTimedout(int frame_number, unsigned max_delay);

private:
	BTS& m_bts;

private:
	/* disable copying to avoid slicing */
	PollController(const PollController&);
	PollController& operator=(const PollController&);
};
