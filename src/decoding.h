/* decoding
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
#pragma once

#include <gsm_rlcmac.h>

#include <stdint.h>

class Decoding {
public:
	static int tlli_from_ul_data(const uint8_t *data, uint8_t len,
					uint32_t *tlli);
	static uint8_t get_ms_class_by_capability(MS_Radio_Access_capability_t *cap);

	static void extract_rbb(const uint8_t *rbb, char *extracted_rbb);
};
