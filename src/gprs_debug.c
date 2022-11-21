/* gprs_debug.c
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2019 Harald Welte <laforge@gnumonks.org>
 * Copyright (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <gprs_debug.h>

/* default categories */

static const struct log_info_cat default_categories[] = {
	[DCSN1] = {
		.name = "DCSN1",
		.color = "\033[1;31m",
		.description = "Concrete Syntax Notation One (CSN1)",
		.loglevel = LOGL_NOTICE,
		.enabled = 0,
	},
	[DL1IF] = {
		.name = "DL1IF",
		.color = "\033[1;32m",
		.description = "GPRS PCU L1 interface (L1IF)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRLCMAC] = {
		.name = "DRLCMAC",
		.color = "\033[0;33m",
		.description = "GPRS RLC/MAC layer (RLCMAC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRLCMACDATA] = {
		.name = "DRLCMACDATA",
		.color = "\033[0;33m",
		.description = "GPRS RLC/MAC layer Data (RLCMAC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRLCMACDL] = {
		.name = "DRLCMACDL",
		.color = "\033[1;33m",
		.description = "GPRS RLC/MAC layer Downlink (RLCMAC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRLCMACUL] = {
		.name = "DRLCMACUL",
		.color = "\033[1;36m",
		.description = "GPRS RLC/MAC layer Uplink (RLCMAC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRLCMACSCHED] = {
		.name = "DRLCMACSCHED",
		.color = "\033[0;36m",
		.description = "GPRS RLC/MAC layer Scheduling (RLCMAC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRLCMACMEAS] = {
		.name = "DRLCMACMEAS",
		.color = "\033[1;31m",
		.description = "GPRS RLC/MAC layer Measurements (RLCMAC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DTBF] = {
		.name = "DTBF",
		.color = "\033[1;34m",
		.description = "Temporary Block Flow (TBF)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DTBFDL] = {
		.name = "DTBFDL",
		.color = "\033[1;34m",
		.description = "Temporary Block Flow (TBF) Downlink",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DTBFUL] = {
		.name = "DTBFUL",
		.color = "\033[1;34m",
		.description = "Temporary Block Flow (TBF) Uplink",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DNS] = {
		.name = "DNS",
		.color = "\033[1;34m",
		.description = "GPRS Network Service Protocol (NS)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DPCU] = {
		.name = "DPCU",
		.color = "\033[1;35m",
		.description = "GPRS Packet Control Unit (PCU)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DNACC] = {
		.name = "DNACC",
		.color = "\033[1;37m",
		.description = "Network Assisted Cell Change (NACC)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
	[DRIM] = {
		.name = "DRIM",
		.color = "\033[1;38m",
		.description = "RAN Information Management (RIM)",
		.loglevel = LOGL_NOTICE,
		.enabled = 1,
	},
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
