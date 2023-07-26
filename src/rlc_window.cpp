/* RLC Window (common for both UL/DL TBF), 3GPP TS 44.060
 *
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2023 sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include "gprs_debug.h"
#include "rlc_window.h"

extern "C" {
#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>
}

void gprs_rlc_window::set_sns(uint16_t sns)
{
	OSMO_ASSERT(sns >= RLC_GPRS_SNS);
	OSMO_ASSERT(sns <= RLC_MAX_SNS);
	/* check for 2^n */
	OSMO_ASSERT((sns & (-sns)) == sns);
	m_sns = sns;
}

void gprs_rlc_window::set_ws(uint16_t ws)
{
	LOGP(DRLCMAC, LOGL_INFO, "ws(%d)\n",
		ws);
	OSMO_ASSERT(ws >= RLC_GPRS_SNS/2);
	OSMO_ASSERT(ws <= RLC_MAX_SNS/2);
	m_ws = ws;
}