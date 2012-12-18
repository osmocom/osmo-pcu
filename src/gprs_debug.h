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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
 
#ifndef GPRS_DEBUG_H
#define GPRS_DEBUG_H

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#ifdef __cplusplus
};
#endif
/* Debug Areas of the code */
enum {
	DCSN1,
	DL1IF,
	DRLCMAC,
	DRLCMACDATA,
	DRLCMACDL,
	DRLCMACUL,
	DRLCMACSCHED,
	DRLCMACBW,
	DBSSGP,
	DPCU,
	aDebug_LastEntry
};

/* context */
#define BSC_CTX_SUBSCR	1
#define BSC_CTX_NSVC	4
#define BSC_CTX_BVC		5

/* target */

enum {
	//DEBUG_FILTER_ALL = 1 << 0,
	LOG_FILTER_IMSI = 1 << 1,
	LOG_FILTER_NSVC = 1 << 2,
	LOG_FILTER_BVC  = 1 << 3,
};

/* we don't need a header dependency for this... */

struct gprs_nsvc;
struct bssgp_bvc_ctx;

void log_set_imsi_filter(struct log_target *target, const char *imsi);
void log_set_nsvc_filter(struct log_target *target,
			 struct gprs_nsvc *nsvc);
void log_set_bvc_filter(struct log_target *target,
			struct bssgp_bvc_ctx *bctx);

extern const struct log_info gprs_log_info;



#endif // GPRS_DEBUG_H
