/* alloc_algo.h
 *
 * Copyright (C) 2022 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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

#include <stdbool.h>
#include <stdint.h>

#include "tbf.h"

struct gprs_rlcmac_bts;
struct GprsMs;
struct gprs_rlcmac_tbf;

#ifdef __cplusplus
extern "C" {
#endif

struct alloc_resources_req {
	/* BTS where to allocate resources */
	struct gprs_rlcmac_bts *bts;
	/* MS for which to allocate resources */
	const struct GprsMs *ms;
	/* Direction of the TBF for which we are allocating resources */
	enum gprs_rlcmac_tbf_direction direction;
	/* Whether to allocate only a single (1) TS */
	bool single;
	/* Whether to allocate on a specific TRX (>=0) or not (-1) */
	int8_t use_trx;
};

struct alloc_resources_res {
	struct gprs_rlcmac_trx *trx;
	struct gprs_rlcmac_pdch *first_common_ts;
	uint8_t reserved_ul_slots;
	uint8_t reserved_dl_slots;
	uint8_t ass_slots_mask;
	bool upgrade_to_multislot;
	uint8_t tfi;
	int usf[8];
};

int alloc_algorithm_a(const struct alloc_resources_req *req,
		      struct alloc_resources_res *res);

int alloc_algorithm_b(const struct alloc_resources_req *req,
		      struct alloc_resources_res *res);

int alloc_algorithm_dynamic(const struct alloc_resources_req *req,
			    struct alloc_resources_res *res);
int gprs_alloc_max_dl_slots_per_ms(const struct gprs_rlcmac_bts *bts, uint8_t ms_class);

#ifdef __cplusplus
}
#endif
