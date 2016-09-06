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
		uint8_t use_trx,
		uint8_t ms_class, uint8_t egprs_ms_class, uint8_t single_slot)
{
	if (dir == GPRS_RLCMAC_UL_TBF)
		return tbf_alloc_ul_tbf(bts, ms, use_trx,
			ms_class, egprs_ms_class, single_slot);
	else
		return tbf_alloc_dl_tbf(bts, ms, use_trx,
			ms_class, egprs_ms_class, single_slot);
}

static void check_tfi_usage(BTS *the_bts)
{
	int pdch_no;

	struct gprs_rlcmac_tbf *tfi_usage[8][8][2][32] = {{{{NULL}}}};
	LListHead<gprs_rlcmac_tbf> *tbf_lists[2] = {
		&the_bts->ul_tbfs(),
		&the_bts->dl_tbfs()
	};

	LListHead<gprs_rlcmac_tbf> *pos;
	gprs_rlcmac_tbf *tbf;
	unsigned list_idx;
	struct gprs_rlcmac_tbf **tbf_var;

	for (list_idx = 0; list_idx < ARRAY_SIZE(tbf_lists); list_idx += 1)
	{

		llist_for_each(pos, tbf_lists[list_idx]) {
			tbf = pos->entry();
			for (pdch_no = 0; pdch_no < 8; pdch_no += 1) {
				struct gprs_rlcmac_pdch *pdch = tbf->pdch[pdch_no];
				if (pdch == NULL)
					continue;

				tbf_var = &tfi_usage
					[tbf->trx->trx_no]
					[pdch_no]
					[tbf->direction]
					[tbf->tfi()];

				OSMO_ASSERT(*tbf_var == NULL);
				if (tbf->direction == GPRS_RLCMAC_DL_TBF) {
					OSMO_ASSERT(pdch->dl_tbf_by_tfi(
							tbf->tfi()) == tbf);
					OSMO_ASSERT(the_bts->dl_tbf_by_tfi(
							tbf->tfi(),
							tbf->trx->trx_no,
							pdch_no) == tbf);
				} else {
					OSMO_ASSERT(pdch->ul_tbf_by_tfi(
							tbf->tfi()) == tbf);
					OSMO_ASSERT(the_bts->ul_tbf_by_tfi(
							tbf->tfi(),
							tbf->trx->trx_no,
							pdch_no) == tbf);
				}
				*tbf_var = tbf;
				OSMO_ASSERT(pdch->assigned_tfi(tbf->direction) &
					(1 << tbf->tfi()));
			}
		}
	}
}

static void test_alloc_a(gprs_rlcmac_tbf_direction dir,
	uint8_t slots, const int count)
{
	int tfi;
	int i;
	uint8_t used_trx, tmp_trx;
	BTS the_bts;
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_tbf *tbfs[32*8+1] = { 0, };

	printf("Testing alloc_a direction(%d)\n", dir);

	bts = the_bts.bts_data();
	bts->alloc_algorithm = alloc_algorithm_a;

	struct gprs_rlcmac_trx *trx = &bts->trx[0];
	for (i = 0; i < 8; i += 1)
		if (slots & (1 << i))
			trx->pdch[i].enable();

	OSMO_ASSERT(count >= 0 && count <= (int)ARRAY_SIZE(tbfs));

	/**
	 * Currently alloc_a will only allocate from the first
	 * PDCH and all possible usf's. We run out of usf's before
	 * we are out of tfi's. Observe this and make sure that at
	 * least this part is working okay.
	 */
	for (i = 0; i < (int)ARRAY_SIZE(tbfs); ++i) {
		tbfs[i] = tbf_alloc(bts, NULL, dir, -1, 0, 0, 0);
		if (tbfs[i] == NULL)
			break;

		used_trx = tbfs[i]->trx->trx_no;
		tfi = the_bts.tfi_find_free(dir, &tmp_trx, used_trx);
		OSMO_ASSERT(tbfs[i]->tfi() != tfi);
	}

	check_tfi_usage(&the_bts);

	OSMO_ASSERT(i == count);

	for (i = 0; i < count; ++i)
		if (tbfs[i])
			tbf_free(tbfs[i]);

	tbfs[0] = tbf_alloc(bts, NULL, dir, -1, 0, 0, 0);
	OSMO_ASSERT(tbfs[0]);
	tbf_free(tbfs[0]);
}

static void test_alloc_a()
{
	/* slots 2 - 3 */
	test_alloc_a(GPRS_RLCMAC_DL_TBF, 0x0c, 32*2);
	test_alloc_a(GPRS_RLCMAC_UL_TBF, 0x0c, 14);

	/* slots 1 - 5 */
	test_alloc_a(GPRS_RLCMAC_DL_TBF, 0x1e, 32*4);
	test_alloc_a(GPRS_RLCMAC_UL_TBF, 0x1e, 28);
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
		uint8_t trx_no;

		gprs_rlcmac_tbf *ul_tbf, *dl_tbf;

		printf("Testing UL then DL assignment.\n");

		bts = the_bts.bts_data();
		bts->alloc_algorithm = alloc_algorithm_b;

		trx = &bts->trx[0];
		trx->pdch[5].enable();
		trx->pdch[6].enable();
		trx->pdch[7].enable();

		ul_tbf = tbf_alloc_ul_tbf(bts, NULL, -1, ms_class, 0, 1);
		OSMO_ASSERT(ul_tbf);
		OSMO_ASSERT(ul_tbf->ms());
		OSMO_ASSERT(ul_tbf->ms()->current_trx());
		trx_no = ul_tbf->ms()->current_trx()->trx_no;
		dump_assignment(ul_tbf, "UL");

		/* assume final ack has not been sent */
		dl_tbf = tbf_alloc_dl_tbf(bts, ul_tbf->ms(), trx_no, ms_class, 0, 0);
		OSMO_ASSERT(dl_tbf);
		dump_assignment(dl_tbf, "DL");

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		check_tfi_usage(&the_bts);

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

		dl_tbf = tbf_alloc_dl_tbf(bts, NULL, -1, ms_class, 0, 1);
		dl_tbf->update_ms(0x23, GPRS_RLCMAC_DL_TBF);
		OSMO_ASSERT(dl_tbf);
		OSMO_ASSERT(dl_tbf->ms());
		OSMO_ASSERT(dl_tbf->ms()->current_trx());
		trx_no = dl_tbf->ms()->current_trx()->trx_no;
		dump_assignment(dl_tbf, "DL");

		ul_tbf = tbf_alloc_ul_tbf(bts, dl_tbf->ms(), trx_no, ms_class, 0, 0);
		ul_tbf->update_ms(0x23, GPRS_RLCMAC_UL_TBF);
		ul_tbf->m_contention_resolution_done = 1;
		OSMO_ASSERT(ul_tbf);
		dump_assignment(ul_tbf, "UL");

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		/* now update the dl_tbf */
		dl_tbf->update();
		dump_assignment(dl_tbf, "DL");
		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		check_tfi_usage(&the_bts);

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
		ul_tbf = tbf_alloc_ul_tbf(bts, NULL, .1, ms_class, 0, 0);
		OSMO_ASSERT(ul_tbf);
		OSMO_ASSERT(ul_tbf->ms());
		OSMO_ASSERT(ul_tbf->ms()->current_trx());
		trx_no = ul_tbf->ms()->current_trx()->trx_no;
		dump_assignment(ul_tbf, "UL");

		/* assume final ack has not been sent */
		dl_tbf = tbf_alloc_dl_tbf(bts, ul_tbf->ms(), trx_no, ms_class, 0, 0);
		OSMO_ASSERT(dl_tbf);
		dump_assignment(dl_tbf, "DL");

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		check_tfi_usage(&the_bts);

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

		ul_tbf = tbf_alloc_ul_tbf(bts, NULL, -1, ms_class, 0, 1);
		OSMO_ASSERT(ul_tbf->ms());
		OSMO_ASSERT(ul_tbf->ms()->current_trx());
		trx_no = ul_tbf->ms()->current_trx()->trx_no;
		OSMO_ASSERT(ul_tbf);

		/* assume final ack has not been sent */
		dl_tbf = tbf_alloc_dl_tbf(bts, ul_tbf->ms(), trx_no, ms_class, 0, 0);
		OSMO_ASSERT(dl_tbf);

		/* verify that both are on the same ts */
		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		check_tfi_usage(&the_bts);

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

		dl_tbf = tbf_alloc_dl_tbf(bts, NULL, -1, ms_class, 0, 1);
		OSMO_ASSERT(dl_tbf);
		OSMO_ASSERT(dl_tbf->ms());
		OSMO_ASSERT(dl_tbf->ms()->current_trx());
		trx_no = dl_tbf->ms()->current_trx()->trx_no;
		dl_tbf->update_ms(0x23, GPRS_RLCMAC_DL_TBF);

		ul_tbf = tbf_alloc_ul_tbf(bts, dl_tbf->ms(), trx_no, ms_class, 0, 0);
		OSMO_ASSERT(ul_tbf);
		ul_tbf->update_ms(0x23, GPRS_RLCMAC_UL_TBF);
		ul_tbf->m_contention_resolution_done = 1;

		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		/* now update the dl_tbf */
		dl_tbf->update();
		OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

		OSMO_ASSERT(ul_tbf->ms_class() == ms_class);
		OSMO_ASSERT(dl_tbf->ms_class() == ms_class);

		check_tfi_usage(&the_bts);

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

typedef int (*algo_t)(struct gprs_rlcmac_bts *bts,
		struct GprsMs *ms,
		struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single,
		int use_trx);

static char get_dir_char(uint8_t mask, uint8_t tx, uint8_t rx, uint8_t busy)
{
	int offs = busy ? 32 : 0;
	return (mask & tx & rx) ? 'C' + offs :
		(mask & tx)     ? 'U' + offs :
		(mask & rx)     ? 'D' + offs :
				  '.';
}

enum test_mode {
	TEST_MODE_UL_ONLY,
	TEST_MODE_DL_ONLY,
	TEST_MODE_UL_AND_DL,
	TEST_MODE_DL_AND_UL,
	TEST_MODE_DL_AFTER_UL,
	TEST_MODE_UL_AFTER_DL,
};

static GprsMs *alloc_tbfs(BTS *the_bts, GprsMs *ms, unsigned ms_class,
	enum test_mode mode)
{
	struct gprs_rlcmac_bts *bts;
	uint8_t trx_no = -1;

	bts = the_bts->bts_data();

	gprs_rlcmac_tbf *tbf = NULL;

	if (ms && ms->current_trx())
		trx_no = ms->current_trx()->trx_no;

	GprsMs::Guard guard1(ms);

	/* Allocate what is needed first */
	switch (mode) {
	case TEST_MODE_UL_ONLY:
	case TEST_MODE_DL_AFTER_UL:
	case TEST_MODE_UL_AND_DL:
		if (ms && ms->ul_tbf())
			tbf_free(ms->ul_tbf());
		tbf = tbf_alloc_ul_tbf(bts, ms, trx_no, ms_class, 0, 0);
		if (tbf == NULL)
			return NULL;
		break;
	case TEST_MODE_DL_ONLY:
	case TEST_MODE_UL_AFTER_DL:
	case TEST_MODE_DL_AND_UL:
		if (ms && ms->dl_tbf())
			tbf_free(ms->dl_tbf());
		tbf = tbf_alloc_dl_tbf(bts, ms, trx_no, ms_class, 0, 0);
		if (tbf == NULL)
			return NULL;
	}

	OSMO_ASSERT(tbf);
	OSMO_ASSERT(tbf->ms());
	OSMO_ASSERT(ms == NULL || ms == tbf->ms());
	ms = tbf->ms();

	GprsMs::Guard guard2(ms);

	/* Continue with what is needed next */
	switch (mode) {
	case TEST_MODE_UL_ONLY:
	case TEST_MODE_DL_ONLY:
		/* We are done */
		break;

	case TEST_MODE_DL_AFTER_UL:
	case TEST_MODE_UL_AND_DL:
		ms = alloc_tbfs(the_bts, ms, ms_class, TEST_MODE_DL_ONLY);
		break;

	case TEST_MODE_UL_AFTER_DL:
	case TEST_MODE_DL_AND_UL:
		ms = alloc_tbfs(the_bts, ms, ms_class, TEST_MODE_UL_ONLY);
		break;
	}

	/* Optionally delete the TBF */
	switch (mode) {
	case TEST_MODE_DL_AFTER_UL:
	case TEST_MODE_UL_AFTER_DL:
		tbf_free(tbf);
		tbf = NULL;
		break;

	default:
		break;
	}

	if (!ms && tbf)
		tbf_free(tbf);

	return  guard2.is_idle() ? NULL : ms;
}

static unsigned alloc_many_tbfs(BTS *the_bts, unsigned min_class,
	unsigned max_class, enum test_mode mode)
{
	unsigned counter;
	unsigned ms_class = min_class;

	for (counter = 0; 1; counter += 1) {
		gprs_rlcmac_tbf *ul_tbf, *dl_tbf;
		uint8_t ul_slots = 0;
		uint8_t dl_slots = 0;
		uint8_t busy_slots = 0;
		unsigned i;
		int tfi = -1;
		int tfi2;
		uint8_t trx_no2;
		struct gprs_rlcmac_trx *trx;
		GprsMs *ms;
		enum gprs_rlcmac_tbf_direction dir;
		uint32_t tlli = counter + 0xc0000000;

		ms = the_bts->ms_by_tlli(tlli);

		ms = alloc_tbfs(the_bts, ms, ms_class, mode);
		if (!ms)
			break;

		ms->set_tlli(tlli);

		ul_tbf = ms->ul_tbf();
		dl_tbf = ms->dl_tbf();
		trx = ms->current_trx();

		OSMO_ASSERT(ul_tbf || dl_tbf);

		if (ul_tbf) {
			ul_slots = 1 << ul_tbf->first_common_ts;
			tfi = ul_tbf->tfi();
			dir = GPRS_RLCMAC_UL_TBF;
		} else {
			ul_slots = 1 << dl_tbf->first_common_ts;
			tfi = dl_tbf->tfi();
			dir = GPRS_RLCMAC_DL_TBF;
		}

		for (i = 0; dl_tbf && i < ARRAY_SIZE(dl_tbf->pdch); i += 1)
			if (dl_tbf->pdch[i])
				dl_slots |= 1 << i;

		for (i = 0; trx && i < ARRAY_SIZE(trx->pdch); i += 1) {
			struct gprs_rlcmac_pdch *pdch = &trx->pdch[i];

			if (ul_tbf && dl_tbf)
				continue;

			if (ul_tbf &&
				pdch->assigned_tfi(GPRS_RLCMAC_DL_TBF) != 0xffffffff)
				continue;

			if (dl_tbf &&
				pdch->assigned_tfi(GPRS_RLCMAC_UL_TBF) != 0xffffffff)
				continue;

			busy_slots |= 1 << i;
		}

		printf(" TBF[%d] class %d reserves %c%c%c%c%c%c%c%c\n",
			tfi, ms_class,
			get_dir_char(0x01, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x02, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x04, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x08, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x10, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x20, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x40, ul_slots, dl_slots, busy_slots),
			get_dir_char(0x80, ul_slots, dl_slots, busy_slots));

		if (tfi >= 0) {
			OSMO_ASSERT(ms->current_trx());
			tfi2 = the_bts->tfi_find_free(dir, &trx_no2,
				ms->current_trx()->trx_no);
			OSMO_ASSERT(tfi != tfi2);
			OSMO_ASSERT(tfi2 < 0 ||
				trx_no2 == ms->current_trx()->trx_no);
		}

		ms_class += 1;
		if (ms_class > max_class)
			ms_class = min_class;
	}

	return counter;
}

static void test_successive_allocation(algo_t algo, unsigned min_class,
	unsigned max_class, enum test_mode mode,
	unsigned expect_num, const char *text)
{
	BTS the_bts;
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_trx *trx;
	unsigned counter;

	printf("Going to test assignment with many TBF, %s\n", text);

	bts = the_bts.bts_data();
	bts->alloc_algorithm = algo;

	trx = &bts->trx[0];
	trx->pdch[3].enable();
	trx->pdch[4].enable();
	trx->pdch[5].enable();
	trx->pdch[6].enable();
	trx->pdch[7].enable();

	counter = alloc_many_tbfs(&the_bts, min_class, max_class, mode);

	printf("  Successfully allocated %d UL TBFs\n", counter);
	if (counter != expect_num)
		fprintf(stderr, "  Expected %d TBFs for %s\n", expect_num, text);

	OSMO_ASSERT(counter == expect_num);

	check_tfi_usage(&the_bts);
}

static void test_many_connections(algo_t algo, unsigned expect_num,
	const char *text)
{
	BTS the_bts;
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_trx *trx;
	int counter1, counter2 = -1;
	unsigned i;
	enum test_mode mode_seq[] = {
		TEST_MODE_DL_AFTER_UL,
		TEST_MODE_UL_ONLY,
		TEST_MODE_DL_AFTER_UL,
		TEST_MODE_DL_ONLY,
	};

	printf("Going to test assignment with many connections, %s\n", text);

	bts = the_bts.bts_data();
	bts->alloc_algorithm = algo;

	trx = &bts->trx[0];
	trx->pdch[3].enable();
	trx->pdch[4].enable();
	trx->pdch[5].enable();
	trx->pdch[6].enable();
	trx->pdch[7].enable();

	for (i = 0; i < ARRAY_SIZE(mode_seq); i += 1) {
		counter1 = alloc_many_tbfs(&the_bts, 1, 29, mode_seq[i]);
		fprintf(stderr, "  Allocated %d TBFs (previously %d)\n",
			counter1, counter2);

		check_tfi_usage(&the_bts);

		/* This will stop earlier due to USF shortage */
		if (mode_seq[i] == TEST_MODE_UL_ONLY)
			continue;

		if (counter2 >= 0) {
			if (counter1 < counter2)
				fprintf(stderr, "  Expected %d >= %d in %s\n",
					counter1, counter2, text);
			OSMO_ASSERT(counter1 >= counter2);
		}

		counter2 = counter1;
	}

	printf("  Successfully allocated %d TBFs\n", counter1);
	if (counter1 != (int)expect_num)
		fprintf(stderr, "  Expected %d TBFs for %s\n", expect_num, text);

	OSMO_ASSERT(expect_num == (unsigned)counter1);
}

static void test_successive_allocation()
{
	test_successive_allocation(alloc_algorithm_a, 1, 1, TEST_MODE_UL_AND_DL,
		35, "algorithm A (UL and DL)");
	test_successive_allocation(alloc_algorithm_b, 10, 10, TEST_MODE_UL_AND_DL,
		32, "algorithm B class 10 (UL and DL)");
	test_successive_allocation(alloc_algorithm_b, 12, 12, TEST_MODE_UL_AND_DL,
		32, "algorithm B class 12 (UL and DL)");
	test_successive_allocation(alloc_algorithm_b, 1, 12, TEST_MODE_UL_AND_DL,
		32, "algorithm B class 1-12 (UL and DL)");
	test_successive_allocation(alloc_algorithm_b, 1, 29, TEST_MODE_UL_AND_DL,
		32, "algorithm B class 1-29 (UL and DL)");
	test_successive_allocation(alloc_algorithm_dynamic, 1, 29, TEST_MODE_UL_AND_DL,
		35, "algorithm dynamic class 1-29 (UL and DL)");

	test_successive_allocation(alloc_algorithm_a, 1, 1, TEST_MODE_DL_AND_UL,
		35, "algorithm A (DL and UL)");
	test_successive_allocation(alloc_algorithm_b, 10, 10, TEST_MODE_DL_AND_UL,
		32, "algorithm B class 10 (DL and UL)");
	test_successive_allocation(alloc_algorithm_dynamic, 10, 10, TEST_MODE_DL_AND_UL,
		32, "algorithm dynamic class 10 (DL and UL)");

	test_successive_allocation(alloc_algorithm_a, 1, 1, TEST_MODE_DL_AFTER_UL,
		160, "algorithm A (DL after UL)");
	test_successive_allocation(alloc_algorithm_b, 10, 10, TEST_MODE_DL_AFTER_UL,
		32, "algorithm B class 10 (DL after UL)");
	test_successive_allocation(alloc_algorithm_dynamic, 10, 10, TEST_MODE_DL_AFTER_UL,
		95, "algorithm dynamic class 10 (DL after UL)");

	test_successive_allocation(alloc_algorithm_a, 1, 1, TEST_MODE_UL_AFTER_DL,
		35, "algorithm A (UL after DL)");
	test_successive_allocation(alloc_algorithm_b, 10, 10, TEST_MODE_UL_AFTER_DL,
		32, "algorithm B class 10 (UL after DL)");
	test_successive_allocation(alloc_algorithm_dynamic, 10, 10, TEST_MODE_UL_AFTER_DL,
		35, "algorithm dynamic class 10 (UL after DL)");

	test_successive_allocation(alloc_algorithm_a, 1, 1, TEST_MODE_UL_ONLY,
		35, "algorithm A (UL only)");
	test_successive_allocation(alloc_algorithm_b, 10, 10, TEST_MODE_UL_ONLY,
		32, "algorithm B class 10 (UL only)");
	test_successive_allocation(alloc_algorithm_dynamic, 10, 10, TEST_MODE_UL_ONLY,
		35, "algorithm dynamic class 10 (UL only)");

	test_successive_allocation(alloc_algorithm_a, 1, 1, TEST_MODE_DL_ONLY,
		160, "algorithm A (DL ONLY)");
	test_successive_allocation(alloc_algorithm_b, 10, 10, TEST_MODE_DL_ONLY,
		32, "algorithm B class 10 (DL ONLY)");
	test_successive_allocation(alloc_algorithm_dynamic, 10, 10, TEST_MODE_DL_ONLY,
		101, "algorithm dynamic class 10 (DL ONLY)");
}

static void test_many_connections()
{
	test_many_connections(alloc_algorithm_a, 160, "algorithm A");
	test_many_connections(alloc_algorithm_b, 32, "algorithm B");
	test_many_connections(alloc_algorithm_dynamic, 160, "algorithm dynamic");
}

static void test_2_consecutive_dl_tbfs()
{
	BTS the_bts;
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_trx *trx;
	uint8_t ms_class = 11;
	uint8_t egprs_ms_class = 11;
	gprs_rlcmac_tbf *dl_tbf1, *dl_tbf2;
	uint8_t numTs1 = 0, numTs2 = 0;

	printf("Testing DL TS allocation for Multi UEs\n");

	bts = the_bts.bts_data();
	bts->alloc_algorithm = alloc_algorithm_b;

	trx = &bts->trx[0];
	trx->pdch[4].enable();
	trx->pdch[5].enable();
	trx->pdch[6].enable();
	trx->pdch[7].enable();

	dl_tbf1 = tbf_alloc_dl_tbf(bts, NULL, 0, ms_class, egprs_ms_class, 0);
	OSMO_ASSERT(dl_tbf1);

	for (int i = 0; i < 8; i++) {
		if (dl_tbf1->pdch[i])
			numTs1++;
	}
	OSMO_ASSERT(numTs1 == 4);
	printf("TBF1: numTs(%d)\n", numTs1);

	dl_tbf2 = tbf_alloc_dl_tbf(bts, NULL, 0, ms_class, egprs_ms_class, 0);
	OSMO_ASSERT(dl_tbf2);

	for (int i = 0; i < 8; i++) {
		if (dl_tbf2->pdch[i])
			numTs2++;
	}

	/*
	 * TODO: currently 2nd DL TBF gets 3 TS
	 * This behaviour will be fixed in subsequent patch
	 */
	printf("TBF2: numTs(%d)\n", numTs2);
	OSMO_ASSERT(numTs2 == 3);

	tbf_free(dl_tbf1);
	tbf_free(dl_tbf2);
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
	if (getenv("LOGL_DEBUG"))
		log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	test_alloc_a();
	test_alloc_b();
	test_successive_allocation();
	test_many_connections();
	test_2_consecutive_dl_tbfs();
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
