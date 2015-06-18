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
#include "bts.h"

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
int16_t spoof_mnc = 0, spoof_mcc = 0;

static gprs_rlcmac_tbf *tbf_alloc(struct gprs_rlcmac_bts *bts,
		GprsMs *ms, gprs_rlcmac_tbf_direction dir,
		uint8_t tfi, uint8_t trx,
		uint8_t ms_class, uint8_t single_slot)
{
	if (dir == GPRS_RLCMAC_UL_TBF)
		return tbf_alloc_ul_tbf(bts, ms, tfi, trx, ms_class, single_slot);
	else
		return tbf_alloc_dl_tbf(bts, ms, tfi, trx, ms_class, single_slot);
}

static void test_alloc_a(gprs_rlcmac_tbf_direction dir, const int count)
{
	int tfi;
	uint8_t used_trx;
	BTS the_bts;
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_tbf *tbfs[33] = { 0, };

	printf("Testing alloc_a direction(%d)\n", dir);

	bts = the_bts.bts_data();
	bts->alloc_algorithm = alloc_algorithm_a;

	struct gprs_rlcmac_trx *trx = &bts->trx[0];
	trx->pdch[2].enable();
	trx->pdch[3].enable();

	/**
	 * Currently alloc_a will only allocate from the first
	 * PDCH and all possible usf's. We run out of usf's before
	 * we are out of tfi's. Observe this and make sure that at
	 * least this part is working okay.
	 */
	for (int i = 0; i < count; ++i) {
		tfi = the_bts.tfi_find_free(dir, &used_trx, 0);
		OSMO_ASSERT(tfi >= 0);
		tbfs[i] = tbf_alloc(bts, NULL, dir, tfi, used_trx, 0, 0);
	}

	/* Now check that there are still some TFIs */
	tfi = the_bts.tfi_find_free(dir, &used_trx, 0);
	switch (dir) {
	case GPRS_RLCMAC_UL_TBF:
		OSMO_ASSERT(tfi >= 0);
		break;
	case GPRS_RLCMAC_DL_TBF:
		OSMO_ASSERT(tfi < 0);
		break;
	}
	OSMO_ASSERT(!tbf_alloc(bts, NULL, dir, tfi, used_trx, 0, 0));

	for (size_t i = 0; i < ARRAY_SIZE(tbfs); ++i)
		if (tbfs[i])
			tbf_free(tbfs[i]);

	tfi = the_bts.tfi_find_free(dir, &used_trx, 0);
	OSMO_ASSERT(tfi >= 0);

	tbfs[tfi] = tbf_alloc(bts, NULL, dir, tfi, used_trx, 0, 0);
	OSMO_ASSERT(tbfs[tfi]);
	tbf_free(tbfs[tfi]);
}

static void test_alloc_a()
{
	test_alloc_a(GPRS_RLCMAC_DL_TBF, 32);
	test_alloc_a(GPRS_RLCMAC_UL_TBF, 7);
}

static void dump_assignment(struct gprs_rlcmac_tbf *tbf, const char *dir)
{
	for (size_t i = 0; i < ARRAY_SIZE(tbf->pdch); ++i)
		if (tbf->pdch[i])
			printf("PDCH[%d] is used for %s\n", i, dir);
	printf("PDCH[%d] is control_ts for %s\n", tbf->control_ts, dir);
	printf("PDCH[%d] is first common for %s\n", tbf->first_common_ts, dir);
}

static void test_alloc_b(int ms_class)
{
	printf("Going to test multislot assignment MS_CLASS=%d\n", ms_class);
	/*
	 * PDCH is on TS 6,7,8 and we start with a UL allocation and
	 * then follow two DL allocations (once single, once normal).
	 *
	 * Uplink assigned and still available..
	 */
	{
		BTS the_bts;
		struct gprs_rlcmac_bts *bts;
		struct gprs_rlcmac_trx *trx;
		int tfi;
		uint8_t trx_no;

		gprs_rlcmac_tbf *ul_tbf, *dl_tbf;

		printf("Testing UL then DL assignment.\n");

		bts = the_bts.bts_data();
		bts->alloc_algorithm = alloc_algorithm_b;

		trx = &bts->trx[0];
		trx->pdch[5].enable();
		trx->pdch[6].enable();
		trx->pdch[7].enable();

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		ul_tbf = tbf_alloc_ul_tbf(bts, NULL, tfi, trx_no, ms_class, 1);
		OSMO_ASSERT(ul_tbf);
		dump_assignment(ul_tbf, "UL");

		/* assume final ack has not been sent */
		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		dl_tbf = tbf_alloc_dl_tbf(bts, ul_tbf->ms(), tfi, trx_no, ms_class, 0);
		OSMO_ASSERT(dl_tbf);
		dump_assignment(dl_tbf, "DL");

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		tbf_free(dl_tbf);
		tbf_free(ul_tbf);
	}

	/**
	 * Test with the other order.. first DL and then UL
	 */
	{
		BTS the_bts;
		struct gprs_rlcmac_bts *bts;
		struct gprs_rlcmac_trx *trx;
		int tfi;
		uint8_t trx_no;

		gprs_rlcmac_ul_tbf *ul_tbf;
		gprs_rlcmac_dl_tbf *dl_tbf;

		printf("Testing DL then UL assignment followed by update\n");

		bts = the_bts.bts_data();
		bts->alloc_algorithm = alloc_algorithm_b;

		trx = &bts->trx[0];
		trx->pdch[5].enable();
		trx->pdch[6].enable();
		trx->pdch[7].enable();

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		dl_tbf = tbf_alloc_dl_tbf(bts, NULL, tfi, trx_no, ms_class, 1);
		dl_tbf->update_ms(0x23, GPRS_RLCMAC_DL_TBF);
		OSMO_ASSERT(dl_tbf);
		dump_assignment(dl_tbf, "DL");

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		ul_tbf = tbf_alloc_ul_tbf(bts, dl_tbf->ms(), tfi, trx_no, ms_class, 0);
		ul_tbf->update_ms(0x23, GPRS_RLCMAC_UL_TBF);
		ul_tbf->m_contention_resolution_done = 1;
		OSMO_ASSERT(ul_tbf);
		dump_assignment(ul_tbf, "UL");

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		/* now update the dl_tbf */
		dl_tbf->update();
		dump_assignment(dl_tbf, "DL");
		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		tbf_free(dl_tbf);
		tbf_free(ul_tbf);
	}

	/* Andreas osmocom-pcu example */
	{
		BTS the_bts;
		struct gprs_rlcmac_bts *bts;
		struct gprs_rlcmac_trx *trx;
		int tfi;
		uint8_t trx_no;

		gprs_rlcmac_tbf *ul_tbf, *dl_tbf;

		printf("Testing jolly example\n");

		bts = the_bts.bts_data();
		bts->alloc_algorithm = alloc_algorithm_b;

		trx = &bts->trx[0];
		trx->pdch[1].enable();
		trx->pdch[2].enable();
		trx->pdch[3].enable();
		trx->pdch[4].enable();

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		ul_tbf = tbf_alloc_ul_tbf(bts, NULL, tfi, trx_no, ms_class, 0);
		OSMO_ASSERT(ul_tbf);
		dump_assignment(ul_tbf, "UL");

		/* assume final ack has not been sent */
		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		dl_tbf = tbf_alloc_dl_tbf(bts, ul_tbf->ms(), tfi, trx_no, ms_class, 0);
		OSMO_ASSERT(dl_tbf);
		dump_assignment(dl_tbf, "DL");

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		tbf_free(dl_tbf);
		tbf_free(ul_tbf);
	}
}

#define ENABLE_PDCH(ts_no, enable_flag, trx)	\
		if (enable_flag)		\
			trx->pdch[ts_no].enable();

static void test_alloc_b(bool ts0, bool ts1, bool ts2, bool ts3, bool ts4, bool ts5, bool ts6, bool ts7, int ms_class)
{
	/* we can test the allocation failures differently */
	if (!ts0 && !ts1 && !ts2 && !ts3 && !ts4 && !ts5 && !ts6 && !ts7)
		return;

	printf("Mass test: TS0(%c%c%c%c%c%c%c%c)TS7 MS_Class=%d\n",
		ts0 ? 'O' : 'x',
		ts1 ? 'O' : 'x',
		ts2 ? 'O' : 'x',
		ts3 ? 'O' : 'x',
		ts4 ? 'O' : 'x',
		ts5 ? 'O' : 'x',
		ts6 ? 'O' : 'x',
		ts7 ? 'O' : 'x', ms_class);
	fflush(stdout);

	{
		BTS the_bts;
		struct gprs_rlcmac_bts *bts;
		struct gprs_rlcmac_trx *trx;
		int tfi;
		uint8_t trx_no;

		gprs_rlcmac_tbf *ul_tbf, *dl_tbf;

		bts = the_bts.bts_data();
		bts->alloc_algorithm = alloc_algorithm_b;

		trx = &bts->trx[0];
		ENABLE_PDCH(0, ts0, trx);
		ENABLE_PDCH(1, ts1, trx);
		ENABLE_PDCH(2, ts2, trx);
		ENABLE_PDCH(3, ts3, trx);
		ENABLE_PDCH(4, ts4, trx);
		ENABLE_PDCH(5, ts5, trx);
		ENABLE_PDCH(6, ts6, trx);
		ENABLE_PDCH(7, ts7, trx);

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);

		OSMO_ASSERT(tfi >= 0);
		ul_tbf = tbf_alloc_ul_tbf(bts, NULL, tfi, trx_no, ms_class, 1);
		OSMO_ASSERT(ul_tbf);

		/* assume final ack has not been sent */
		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		dl_tbf = tbf_alloc_dl_tbf(bts, ul_tbf->ms(), tfi, trx_no, ms_class, 0);
		OSMO_ASSERT(dl_tbf);

		/* verify that both are on the same ts */
		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		tbf_free(dl_tbf);
		tbf_free(ul_tbf);
	}

	/**
	 * Test with the other order.. first DL and then UL
	 */
	{
		BTS the_bts;
		struct gprs_rlcmac_bts *bts;
		struct gprs_rlcmac_trx *trx;
		int tfi;
		uint8_t trx_no;

		gprs_rlcmac_ul_tbf *ul_tbf;
		gprs_rlcmac_dl_tbf *dl_tbf;

		bts = the_bts.bts_data();
		bts->alloc_algorithm = alloc_algorithm_b;

		trx = &bts->trx[0];
		ENABLE_PDCH(0, ts0, trx);
		ENABLE_PDCH(1, ts1, trx);
		ENABLE_PDCH(2, ts2, trx);
		ENABLE_PDCH(3, ts3, trx);
		ENABLE_PDCH(4, ts4, trx);
		ENABLE_PDCH(5, ts5, trx);
		ENABLE_PDCH(6, ts6, trx);
		ENABLE_PDCH(7, ts7, trx);

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		dl_tbf = tbf_alloc_dl_tbf(bts, NULL, tfi, trx_no, ms_class, 1);
		OSMO_ASSERT(dl_tbf);
		dl_tbf->update_ms(0x23, GPRS_RLCMAC_DL_TBF);

		tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
		OSMO_ASSERT(tfi >= 0);
		ul_tbf = tbf_alloc_ul_tbf(bts, dl_tbf->ms(), tfi, trx_no, ms_class, 0);
		OSMO_ASSERT(ul_tbf);
		ul_tbf->update_ms(0x23, GPRS_RLCMAC_UL_TBF);
		ul_tbf->m_contention_resolution_done = 1;

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		/* now update the dl_tbf */
		dl_tbf->update();
		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		OSMO_ASSERT(ul_tbf->ms_class() == ms_class);
		OSMO_ASSERT(dl_tbf->ms_class() == ms_class);

		tbf_free(dl_tbf);
		tbf_free(ul_tbf);
	}
}

static void test_all_alloc_b()
{
	/* it is a bit crazy... */
 for (uint8_t ts0 = 0; ts0 < 2; ++ts0)
  for (uint8_t ts1 = 0; ts1 < 2; ++ts1)
    for (uint8_t ts2 = 0; ts2 < 2; ++ts2)
     for (uint8_t ts3 = 0; ts3 < 2; ++ts3)
      for (uint8_t ts4 = 0; ts4 < 2; ++ts4)
       for (uint8_t ts5 = 0; ts5 < 2; ++ts5)
        for (uint8_t ts6 = 0; ts6 < 2; ++ts6)
         for (uint8_t ts7 = 0; ts7 < 2; ++ts7)
	  for (int ms_class = 0; ms_class < 30; ++ms_class)
		test_alloc_b(ts0, ts1, ts2, ts3, ts4, ts5, ts6, ts7, ms_class);
}

static void test_alloc_b()
{
	for (int i = 0; i < 30; ++i)
		test_alloc_b(i);

	test_all_alloc_b();
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
	test_alloc_b();
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
