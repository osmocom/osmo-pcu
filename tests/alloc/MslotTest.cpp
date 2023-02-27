/* MslotTest.cpp
 *
 * Copyright (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include "gprs_rlcmac.h"
#include "gprs_debug.h"
#include "tbf.h"
#include "bts.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>

extern "C" {
	#include "mslot_class.h"
#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

/* globals used by the code */
void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;

static inline void test_all_classes(struct gprs_rlcmac_trx *trx, bool clear_masks)
{
	int i, rc;
	uint8_t dl_slots = 0, ul_slots = 0;

	for (i = 0; i < 64; i++) {
		rc = find_multi_slots(trx, i, &ul_slots, &dl_slots);

		printf("    [%s] multislot class %3u - UL: " OSMO_BIT_SPEC " DL: " OSMO_BIT_SPEC " [%d]\n",
		       clear_masks ? "SEQ" : "ACC", i, OSMO_BIT_PRINT(ul_slots), OSMO_BIT_PRINT(dl_slots), rc);

		if (rc == -EINVAL)
			return;

		if (clear_masks) {
			dl_slots = 0;
			ul_slots = 0;
		}
	}
}

static inline void test_multislot_total_ascending(bool seq)
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct gprs_rlcmac_trx *trx;
	int i;

	printf("%s(): %s\n", __func__, seq ? "sequential" : "accumulative");

	trx = &bts->trx[0];

	for (i = 0; i < 8; i++) {
		printf("  Enabled PDCH %u for multislot tests...\n", i);
		trx->pdch[i].enable();

		test_all_classes(trx, seq);
	}
	talloc_free(bts);
}

static inline void test_multislot_total_descending(bool seq)
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct gprs_rlcmac_trx *trx;
	int i;

	printf("%s(): %s\n", __func__, seq ? "sequential" : "accumulative");

	trx = &bts->trx[0];

	for (i = 7; i >= 0; i--) {
		printf("  Enabled PDCH %u for multislot tests...\n", i);
		trx->pdch[i].enable();

		test_all_classes(trx, seq);
	}
	talloc_free(bts);
}

static inline void test_multislot_middle(bool seq)
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct gprs_rlcmac_trx *trx;

	printf("%s(): %s\n", __func__, seq ? "sequential" : "accumulative");

	trx = &bts->trx[0];

	trx->pdch[2].enable();
	trx->pdch[3].enable();
	trx->pdch[4].enable();

	test_all_classes(trx, seq);
	talloc_free(bts);
}

static inline void test_multislot_ends(bool seq)
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct gprs_rlcmac_trx *trx;

	printf("%s(): %s\n", __func__, seq ? "sequential" : "accumulative");

	trx = &bts->trx[0];

	trx->pdch[0].enable();
	trx->pdch[7].enable();

	test_all_classes(trx, seq);
	talloc_free(bts);
}

static inline void test_window_wrapper()
{
	uint16_t i;
	for (i = 0; i < 256 * 2 + 1; i++)
		printf("W[%03u] -> %3u %s\n",
		       i, mslot_wrap_window(i), mslot_wrap_window(i) < 256 ? "OK" : "FAIL");
}

int main(int argc, char **argv)
{
	tall_pcu_ctx = talloc_named_const(NULL, 1, "MslotTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);

	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);

	test_multislot_total_ascending(true);
	test_multislot_total_ascending(false);

	test_multislot_total_descending(true);
	test_multislot_total_descending(false);

	test_multislot_middle(true);
	test_multislot_middle(false);

	test_multislot_ends(true);
	test_multislot_ends(false);

	test_window_wrapper();

	talloc_free(the_pcu);

	return EXIT_SUCCESS;
}

/*
 * stubs that should not be reached
 */
extern "C" {
void l1if_pdch_req() { abort(); }
void l1if_connect_pdch() { abort(); }
void l1if_disconnect_pdch() { abort(); }
void l1if_close_pdch() { abort(); }
void l1if_open_pdch() { abort(); }
}
