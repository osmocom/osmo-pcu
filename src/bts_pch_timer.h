/*
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Oliver Smith
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
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <bts.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bts_pch_timer {
	struct llist_head entry;
	struct gprs_rlcmac_bts *bts;
	struct osmo_timer_list T3113;
	uint32_t ptmsi; /* GSM_RESERVED_TMSI if not available */
	char imsi[OSMO_IMSI_BUF_SIZE];
};

struct GprsMs;

void bts_pch_timer_start(struct gprs_rlcmac_bts *bts, const struct osmo_mobile_identity *mi_paging,
			 const char *imsi);
void bts_pch_timer_stop(struct gprs_rlcmac_bts *bts, const struct GprsMs *ms);
void bts_pch_timer_stop_all(struct gprs_rlcmac_bts *bts);
struct bts_pch_timer *bts_pch_timer_get_by_imsi(struct gprs_rlcmac_bts *bts, const char *imsi);

#ifdef __cplusplus
}
#endif
