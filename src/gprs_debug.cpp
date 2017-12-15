/* gprs_debug.cpp
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

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <gprs_debug.h>

/* default categories */

static const struct log_info_cat default_categories[] = {
 	{"DCSN1", "\033[1;31m", "Concrete Syntax Notation One (CSN1)", LOGL_INFO, 0},
 	{"DL1IF", "\033[1;32m", "GPRS PCU L1 interface (L1IF)", LOGL_INFO, 1},
	{"DRLCMAC", "\033[0;33m", "GPRS RLC/MAC layer (RLCMAC)", LOGL_NOTICE, 1},
	{"DRLCMACDATA", "\033[0;33m", "GPRS RLC/MAC layer Data (RLCMAC)", LOGL_NOTICE, 1},
	{"DRLCMACDL", "\033[1;33m", "GPRS RLC/MAC layer Downlink (RLCMAC)", LOGL_NOTICE, 1},
	{"DRLCMACUL", "\033[1;36m", "GPRS RLC/MAC layer Uplink (RLCMAC)", LOGL_NOTICE, 1},
	{"DRLCMACSCHED", "\033[0;36m", "GPRS RLC/MAC layer Scheduling (RLCMAC)", LOGL_NOTICE, 1},
	{"DRLCMACMEAS", "\033[1;31m", "GPRS RLC/MAC layer Measurements (RLCMAC)", LOGL_INFO, 1},
	{"DNS","\033[1;34m", "GPRS Network Service Protocol (NS)", LOGL_INFO , 1},
	{"DBSSGP","\033[1;34m", "GPRS BSS Gateway Protocol (BSSGP)", LOGL_INFO , 1},
	{"DPCU", "\033[1;35m", "GPRS Packet Control Unit (PCU)", LOGL_NOTICE, 1},
};

static int filter_fn(const struct log_context *ctx,
		     struct log_target *tar)
{
	const struct gprs_nsvc *nsvc = (const struct gprs_nsvc*)ctx->ctx[LOG_CTX_GB_NSVC];
	const struct gprs_nsvc *bvc = (const struct gprs_nsvc*)ctx->ctx[LOG_CTX_GB_BVC];

	/* Filter on the NS Virtual Connection */
	if ((tar->filter_map & (1 << LOG_FLT_GB_NSVC)) != 0
	    && nsvc && (nsvc == tar->filter_data[LOG_FLT_GB_NSVC]))
		return 1;

	/* Filter on the BVC */
	if ((tar->filter_map & (1 << LOG_FLT_GB_BVC)) != 0
	    && bvc && (bvc == tar->filter_data[LOG_FLT_GB_BVC]))
		return 1;

	return 0;
}

const struct log_info gprs_log_info = {
	filter_fn,
	(struct log_info_cat*)default_categories,
	ARRAY_SIZE(default_categories),
};
