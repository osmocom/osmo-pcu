/* AllocTest.cpp
 *
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include "gprs_rlcmac.h"
#include "gprs_debug.h"
#include "tbf.h"

#include <string.h>
#include <stdio.h>

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

/* globals used by the code */
void *tall_pcu_ctx;
struct gprs_rlcmac_bts *gprs_rlcmac_bts;
int16_t spoof_mnc = 0, spoof_mcc = 0;

static void test_alloc_a(gprs_rlcmac_tbf_direction dir, const int count)
{
	int tfi;
	uint8_t used_trx;
	struct gprs_rlcmac_bts bts;
	struct gprs_rlcmac_tbf *tbfs[33] = { 0, };

	printf("Testing alloc_a direction(%d)\n", dir);

	memset(&bts, 0, sizeof(bts));
	bts.alloc_algorithm = alloc_algorithm_a;
	gprs_rlcmac_bts = &bts;

	struct gprs_rlcmac_trx *trx = &bts.trx[0];
	trx->pdch[2].enable = 1;
	trx->pdch[3].enable = 1;

	/**
	 * Currently alloc_a will only allocate from the first
	 * PDCH and all possible usf's. We run out of usf's before
	 * we are out of tfi's. Observe this and make sure that at
	 * least this part is working okay.
	 */
	for (int i = 0; i < count; ++i) {
		struct gprs_rlcmac_tbf *tbf;

		tfi = tfi_find_free(&bts, dir, &used_trx, 0);
		OSMO_ASSERT(tfi >= 0);
		tbfs[i] = tbf_alloc(&bts, NULL, dir, tfi, used_trx, 0, 0);
	}

	/* Now check that there are still some TFIs */
	tfi = tfi_find_free(&bts, dir, &used_trx, 0);
	switch (dir) {
	case GPRS_RLCMAC_UL_TBF:
		OSMO_ASSERT(tfi >= 0);
		break;
	case GPRS_RLCMAC_DL_TBF:
		OSMO_ASSERT(tfi < 0);
		break;
	}
	OSMO_ASSERT(!tbf_alloc(&bts, NULL, dir, tfi, used_trx, 0, 0));

	for (int i = 0; i < ARRAY_SIZE(tbfs); ++i)
		if (tbfs[i])
			tbf_free(tbfs[i]);

	tfi = tfi_find_free(&bts, dir, &used_trx, 0);
	OSMO_ASSERT(tfi >= 0);

	tbfs[tfi] = tbf_alloc(&bts, NULL, dir, tfi, used_trx, 0, 0);
	OSMO_ASSERT(tbfs[tfi]);
	tbf_free(tbfs[tfi]);
}

static void test_alloc_a()
{
	test_alloc_a(GPRS_RLCMAC_DL_TBF, 32);
	test_alloc_a(GPRS_RLCMAC_UL_TBF, 7);
}

int main(int argc, char **argv)
{
	tall_pcu_ctx = talloc_named_const(NULL, 1, "moiji-mobile AllocTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_set_talloc_ctx(tall_pcu_ctx);
	osmo_init_logging(&gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	test_alloc_a();
	return EXIT_SUCCESS;
}

/*
 * stubs that should not be reached
 */
extern "C" {
void l1if_pdch_req() { abort(); }
void l1if_connect_pdch() { abort(); }
void l1if_close_pdch() { abort(); }
void l1if_open_pdch() { abort(); }
}
