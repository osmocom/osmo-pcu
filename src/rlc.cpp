/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include "tbf.h"

extern "C" {
#include <osmocom/core/utils.h>
}


uint8_t *gprs_rlc_data::prepare(size_t block_data_len)
{
	/* todo.. only set it once if it turns out to be a bottleneck */
	memset(block, 0x0, ARRAY_SIZE(block));
	memset(block, 0x2b, block_data_len);

	return block;
}

void gprs_rlc_v_b::reset()
{
	for (size_t i = 0; i < ARRAY_SIZE(m_v_b); ++i)
		mark_invalid(i);
}
