/* gprs_debug.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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

#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/core/logging.h>

/* we used to have DBSSGP definded in each application, and applications telling
 * libosmogb which sub-system to use.  That creates problems and has been deprecated */
#define DBSSGP DLBSSGP

/* Debug Areas of the code */
enum {
	DCSN1,
	DL1IF,
	DRLCMAC,
	DRLCMACDATA,
	DRLCMACDL,
	DRLCMACUL,
	DRLCMACSCHED,
	DRLCMACMEAS,
	DTBF,
	DTBFDL,
	DTBFUL,
	DNS,
	DPCU,
	DNACC,
	DRIM,
	DE1,
	aDebug_LastEntry
};

extern const struct log_info gprs_log_info;

#ifdef __cplusplus
};
#endif
