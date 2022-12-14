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

struct gprs_rlcmac_bts;
struct gprs_rlcmac_tbf;

#ifdef __cplusplus
extern "C" {
#endif

int alloc_algorithm_a(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf, bool single,
		      int8_t use_trx);

int alloc_algorithm_b(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf, bool single,
		      int8_t use_trx);

int alloc_algorithm_dynamic(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf, bool single,
			    int8_t use_trx);
int gprs_alloc_max_dl_slots_per_ms(const struct gprs_rlcmac_bts *bts, uint8_t ms_class);

#ifdef __cplusplus
}
#endif
