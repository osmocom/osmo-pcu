/* pcu_vty_functions.h
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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

struct vty;
struct gprs_rlcmac_bts;

int pcu_vty_show_tbf_all(struct vty *vty, struct gprs_rlcmac_bts *bts, uint32_t flags);
int pcu_vty_show_ms_all(struct vty *vty, struct gprs_rlcmac_bts *bts);
int pcu_vty_show_ms_by_tlli(struct vty *vty, struct gprs_rlcmac_bts *bts,
	uint32_t tlli);
int pcu_vty_show_ms_by_imsi(struct vty *vty, struct gprs_rlcmac_bts *bts,
	const char *imsi);
int pcu_vty_show_bts_pdch(struct vty *vty, const struct gprs_rlcmac_bts *bts);
#ifdef __cplusplus
}
#endif
