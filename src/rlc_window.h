/* RLC Window (common for both UL/DL TBF), 3GPP TS 44.060
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
#pragma once

#include <stdint.h>

#include "rlc.h"

#define RLC_GPRS_WS  64 /* max window size */
#define RLC_EGPRS_MIN_WS 64 /* min window size */
#define RLC_EGPRS_MAX_WS 1024 /* min window size */
#define RLC_EGPRS_MAX_BSN_DELTA 512
#define RLC_MAX_WS   RLC_EGPRS_MAX_WS

class gprs_rlc_window {
public:
	gprs_rlc_window();

	const uint16_t mod_sns(void) const;
	const uint16_t mod_sns(uint16_t bsn) const;
	const uint16_t sns(void) const;
	const uint16_t ws(void) const;

	void set_sns(uint16_t sns);
	void set_ws(uint16_t ws);

protected:
	uint16_t m_sns;
	uint16_t m_ws;
};


inline gprs_rlc_window::gprs_rlc_window(void)
	: m_sns(RLC_GPRS_SNS)
	, m_ws(RLC_GPRS_WS)
{
}

inline const uint16_t gprs_rlc_window::sns(void) const
{
	return m_sns;
}

inline const uint16_t gprs_rlc_window::ws(void) const
{
	return m_ws;
}

inline const uint16_t gprs_rlc_window::mod_sns(void) const
{
	return sns() - 1;
}

inline const uint16_t gprs_rlc_window::mod_sns(uint16_t bsn) const
{
	return bsn & mod_sns();
}
