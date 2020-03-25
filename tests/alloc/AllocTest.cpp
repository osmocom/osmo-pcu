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
#include "tbf_ul.h"
#include "bts.h"

#include <string.h>
#include <stdio.h>

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

static gprs_rlcmac_tbf *tbf_alloc(struct gprs_rlcmac_bts *bts,
		GprsMs *ms, gprs_rlcmac_tbf_direction dir,
		uint8_t use_trx, bool single_slot)
{
	OSMO_ASSERT(ms != NULL);

	if (dir == GPRS_RLCMAC_UL_TBF)
		return tbf_alloc_ul_tbf(bts, ms, use_trx, single_slot);
	else
		return tbf_alloc_dl_tbf(bts, ms, use_trx, single_slot);
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
	GprsMs *ms;
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
		ms = bts->bts->ms_alloc(0, 0);
		tbfs[i] = tbf_alloc(bts, ms, dir, -1, 0);
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

	ms = bts->bts->ms_alloc(0, 0);
	tbfs[0] = tbf_alloc(bts, ms, dir, -1, 0);
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

static void dump_assignment(struct gprs_rlcmac_tbf *tbf, const char *dir, bool verbose)
{
	if (!verbose)
		return;

	for (size_t i = 0; i < ARRAY_SIZE(tbf->pdch); ++i)
		if (tbf->pdch[i])
			printf("PDCH[%zu] is used for %s\n", i, dir);
	printf("PDCH[%d] is control_ts for %s\n", tbf->control_ts, dir);
	printf("PDCH[%d] is first common for %s\n", tbf->first_common_ts, dir);
}

#define ENABLE_PDCH(ts_no, enable_flag, trx)	\
		if (enable_flag)		\
			trx->pdch[ts_no].enable();

static inline void enable_ts_on_bts(struct gprs_rlcmac_bts *bts,
				    bool ts0, bool ts1, bool ts2, bool ts3, bool ts4, bool ts5, bool ts6, bool ts7)
{
	struct gprs_rlcmac_trx *trx = &bts->trx[0];

	ENABLE_PDCH(0, ts0, trx);
	ENABLE_PDCH(1, ts1, trx);
	ENABLE_PDCH(2, ts2, trx);
	ENABLE_PDCH(3, ts3, trx);
	ENABLE_PDCH(4, ts4, trx);
	ENABLE_PDCH(5, ts5, trx);
	ENABLE_PDCH(6, ts6, trx);
	ENABLE_PDCH(7, ts7, trx);
}

static inline bool test_alloc_b_ul_dl(bool ts0, bool ts1, bool ts2, bool ts3, bool ts4, bool ts5, bool ts6, bool ts7,
				      uint8_t ms_class, bool verbose)
{
	BTS the_bts;
	struct gprs_rlcmac_bts *bts = the_bts.bts_data();
	GprsMs *ms;
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_dl_tbf *dl_tbf;

	if (verbose)
		printf("Testing UL then DL assignment.\n");

	bts->alloc_algorithm = alloc_algorithm_b;

	enable_ts_on_bts(bts, ts0, ts1, ts2, ts3, ts4, ts5, ts6, ts7);

	ms = the_bts.ms_alloc(ms_class, 0);
	ul_tbf = tbf_alloc_ul_tbf(bts, ms, -1, true);
	if (!ul_tbf)
		return false;

	OSMO_ASSERT(ul_tbf->ms());
	OSMO_ASSERT(ul_tbf->ms()->current_trx());

	dump_assignment(ul_tbf, "UL", verbose);

	/* assume final ack has not been sent */
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, ms->current_trx()->trx_no, false);
	if (!dl_tbf)
		return false;

	dump_assignment(dl_tbf, "DL", verbose);

	OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

	check_tfi_usage(&the_bts);

	tbf_free(dl_tbf);
	tbf_free(ul_tbf);

	return true;
}

static inline bool test_alloc_b_dl_ul(bool ts0, bool ts1, bool ts2, bool ts3, bool ts4, bool ts5, bool ts6, bool ts7,
				      uint8_t ms_class, bool verbose)
{
	BTS the_bts;
	struct gprs_rlcmac_bts *bts = the_bts.bts_data();
	GprsMs *ms;
	gprs_rlcmac_ul_tbf *ul_tbf;
	gprs_rlcmac_dl_tbf *dl_tbf;

	if (verbose)
		printf("Testing DL then UL assignment followed by update\n");

	bts->alloc_algorithm = alloc_algorithm_b;

	enable_ts_on_bts(bts, ts0, ts1, ts2, ts3, ts4, ts5, ts6, ts7);

	ms = the_bts.ms_alloc(ms_class, 0);
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, -1, true);
	if (!dl_tbf)
		return false;

	dl_tbf->update_ms(0x23, GPRS_RLCMAC_DL_TBF);
	OSMO_ASSERT(dl_tbf->ms() == ms);
	OSMO_ASSERT(dl_tbf->ms()->current_trx());

	dump_assignment(dl_tbf, "DL", verbose);

	ul_tbf = tbf_alloc_ul_tbf(bts, ms, ms->current_trx()->trx_no, false);
	if (!ul_tbf)
		return false;

	ul_tbf->update_ms(0x23, GPRS_RLCMAC_UL_TBF);
	ul_tbf->m_contention_resolution_done = 1;

	dump_assignment(ul_tbf, "UL", verbose);

	OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

	/* now update the dl_tbf */
	dl_tbf->update();
	dump_assignment(dl_tbf, "DL", verbose);
	OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

	check_tfi_usage(&the_bts);

	tbf_free(dl_tbf);
	tbf_free(ul_tbf);

	return true;
}

static inline bool test_alloc_b_jolly(uint8_t ms_class)
{
	BTS the_bts;
	struct gprs_rlcmac_bts *bts = the_bts.bts_data();
	GprsMs *ms;
	int tfi;
	uint8_t trx_no;
	gprs_rlcmac_tbf *ul_tbf, *dl_tbf;

	printf("Testing jolly example\n");

	bts->alloc_algorithm = alloc_algorithm_b;

	enable_ts_on_bts(bts, false, true, true, true, true, false, false, false);

	tfi = the_bts.tfi_find_free(GPRS_RLCMAC_UL_TBF, &trx_no, -1);
	OSMO_ASSERT(tfi >= 0);
	ms = the_bts.ms_alloc(ms_class, 0);
	ul_tbf = tbf_alloc_ul_tbf(bts, ms, -1, false);
	if (!ul_tbf)
		return false;

	OSMO_ASSERT(ul_tbf->ms() == ms);
	OSMO_ASSERT(ul_tbf->ms()->current_trx());
	trx_no = ms->current_trx()->trx_no;
	dump_assignment(ul_tbf, "UL", true);

	/* assume final ack has not been sent */
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, trx_no, false);
	if (!dl_tbf)
		return false;

	dump_assignment(dl_tbf, "DL", true);

	OSMO_ASSERT(dl_tbf->first_common_ts == ul_tbf->first_common_ts);

	check_tfi_usage(&the_bts);

	tbf_free(dl_tbf);
	tbf_free(ul_tbf);

	return true;
}

static void test_alloc_b_for_ms(uint8_t ms_class)
{
	bool rc;

	printf("Going to test multislot assignment MS_CLASS=%d\n", ms_class);
	/*
	 * PDCH is on TS 6,7,8 and we start with a UL allocation and
	 * then follow two DL allocations (once single, once normal).
	 *
	 * Uplink assigned and still available..
	 */

	rc = test_alloc_b_ul_dl(false, false, false, false, false, true, true, true, ms_class, true);
	if (!rc)
		return;

	/**
	 * Test with the other order.. first DL and then UL
	 */
	rc = test_alloc_b_dl_ul(false, false, false, false, false, true, true, true, ms_class, true);
	if (!rc)
		return;

	/* Andreas osmocom-pcu example */
	test_alloc_b_jolly(ms_class);
}

static void test_alloc_mass(bool ts0, bool ts1, bool ts2, bool ts3, bool ts4, bool ts5, bool ts6, bool ts7, int ms_class)
{
	bool rc;

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

	rc = test_alloc_b_ul_dl(ts0, ts1, ts2, ts3, ts4, ts5, ts6, ts7, ms_class, false);
	if (!rc)
		return;

	/**
	 * Test with the other order.. first DL and then UL
	 */
	test_alloc_b_dl_ul(ts0, ts1, ts2, ts3, ts4, ts5, ts6, ts7, ms_class, false);
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
	  for (int ms_class = 0; ms_class < mslot_class_max(); ++ms_class)
		test_alloc_mass(ts0, ts1, ts2, ts3, ts4, ts5, ts6, ts7, ms_class);
}

static void test_alloc_b()
{
	for (int i = 0; i < mslot_class_max(); ++i)
		test_alloc_b_for_ms(i);

	test_all_alloc_b();
}

typedef int (*algo_t)(struct gprs_rlcmac_bts *bts, struct GprsMs *ms, struct gprs_rlcmac_tbf *tbf, bool single,
		      int8_t use_trx);

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

static inline char *test_mode_descr(enum test_mode t)
{
	switch (t) {
	case TEST_MODE_UL_ONLY: return (char*)"UL only";
	case TEST_MODE_DL_ONLY: return (char*)"DL only";
	case TEST_MODE_UL_AND_DL: return (char*)"UL and DL";
	case TEST_MODE_DL_AND_UL: return (char*)"DL and UL";
	case TEST_MODE_DL_AFTER_UL: return (char*)"DL after UL";
	case TEST_MODE_UL_AFTER_DL: return (char*)"UL after DL";
	default: return NULL;
	}
}

static GprsMs *alloc_tbfs(BTS *the_bts, GprsMs *ms, enum test_mode mode)
{
	struct gprs_rlcmac_bts *bts;
	uint8_t trx_no = -1;

	OSMO_ASSERT(ms != NULL);

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
		if (ms->ul_tbf())
			tbf_free(ms->ul_tbf());
		tbf = tbf_alloc_ul_tbf(bts, ms, trx_no, false);
		if (tbf == NULL)
			return NULL;
		break;
	case TEST_MODE_DL_ONLY:
	case TEST_MODE_UL_AFTER_DL:
	case TEST_MODE_DL_AND_UL:
		if (ms->dl_tbf())
			tbf_free(ms->dl_tbf());
		tbf = tbf_alloc_dl_tbf(bts, ms, trx_no, false);
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
		ms = alloc_tbfs(the_bts, ms, TEST_MODE_DL_ONLY);
		break;

	case TEST_MODE_UL_AFTER_DL:
	case TEST_MODE_DL_AND_UL:
		ms = alloc_tbfs(the_bts, ms, TEST_MODE_UL_ONLY);
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
		if (!ms)
			ms = the_bts->ms_alloc(0, 0);
		ms->set_ms_class(ms_class);
		ms = alloc_tbfs(the_bts, ms, mode);
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

		for (i = 0; ul_tbf && i < ARRAY_SIZE(ul_tbf->pdch); i += 1)
			if (ul_tbf->pdch[i])
				ul_slots |= 1 << i;

		for (i = 0; trx && i < ARRAY_SIZE(trx->pdch); i += 1) {
			struct gprs_rlcmac_pdch *pdch = &trx->pdch[i];

			if (ul_tbf && dl_tbf)
				continue;

			if (ul_tbf &&
				pdch->assigned_tfi(GPRS_RLCMAC_DL_TBF) != NO_FREE_TFI)
				continue;

			if (dl_tbf &&
				pdch->assigned_tfi(GPRS_RLCMAC_UL_TBF) != NO_FREE_TFI)
				continue;

			busy_slots |= 1 << i;
		}

		printf(" TBF[%d] class %d reserves " OSMO_BIT_SPEC "\n",
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

	printf("Going to test assignment with many TBF, algorithm %s class %u..%u (%s)\n",
	       text, min_class, max_class, test_mode_descr(mode));

	bts = the_bts.bts_data();
	bts->alloc_algorithm = algo;

	trx = &bts->trx[0];
	trx->pdch[3].enable();
	trx->pdch[4].enable();
	trx->pdch[5].enable();
	trx->pdch[6].enable();
	trx->pdch[7].enable();

	counter = alloc_many_tbfs(&the_bts, min_class, max_class, mode);

	printf("  Successfully allocated %u UL TBFs, algorithm %s class %u..%u (%s)\n",
	       counter, text, min_class, max_class, test_mode_descr(mode));
	if (counter != expect_num)
		fprintf(stderr, "  Expected %u TBFs (got %u), algorithm %s class %u..%u (%s)\n",
			expect_num, counter, text, min_class, max_class, test_mode_descr(mode));

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

	printf("Going to test assignment with many connections, algorithm %s\n", text);

	bts = the_bts.bts_data();
	bts->alloc_algorithm = algo;

	trx = &bts->trx[0];
	trx->pdch[3].enable();
	trx->pdch[4].enable();
	trx->pdch[5].enable();
	trx->pdch[6].enable();
	trx->pdch[7].enable();

	for (i = 0; i < ARRAY_SIZE(mode_seq); i += 1) {
		counter1 = alloc_many_tbfs(&the_bts, 1, mslot_class_max(), mode_seq[i]);
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
		fprintf(stderr, "  Expected %d TBFs (got %d) for algorithm %s\n", expect_num, counter1, text);

	OSMO_ASSERT(expect_num == (unsigned)counter1);
}

static inline void test_a_b_dyn(enum test_mode mode, uint8_t exp_A, uint8_t exp_B, uint8_t exp_dyn)
{
	test_successive_allocation(alloc_algorithm_a,        1,  1, mode, exp_A,   "A");
	test_successive_allocation(alloc_algorithm_b,       10, 10, mode, exp_B,   "B");
	test_successive_allocation(alloc_algorithm_dynamic, 10, 10, mode, exp_dyn, "dynamic");
}

static void test_successive_allocations()
{
	test_successive_allocation(alloc_algorithm_a,       1,  1, TEST_MODE_UL_AND_DL, 35, "A");
	test_successive_allocation(alloc_algorithm_b,      10, 10, TEST_MODE_UL_AND_DL, 32, "B");
	test_successive_allocation(alloc_algorithm_b,      12, 12, TEST_MODE_UL_AND_DL, 32, "B");

	test_successive_allocation(alloc_algorithm_b,       1,                12, TEST_MODE_UL_AND_DL, 32, "B");
	test_successive_allocation(alloc_algorithm_b,       1, mslot_class_max(), TEST_MODE_UL_AND_DL, 32, "B");
	test_successive_allocation(alloc_algorithm_dynamic, 1, mslot_class_max(), TEST_MODE_UL_AND_DL, 35, "dynamic");

	test_a_b_dyn(TEST_MODE_DL_AND_UL,    35, 32,  32);
	test_a_b_dyn(TEST_MODE_DL_AFTER_UL, 160, 32,  95);
	test_a_b_dyn(TEST_MODE_UL_AFTER_DL,  35, 32,  35);
	test_a_b_dyn(TEST_MODE_UL_ONLY,      35, 32,  35);
	test_a_b_dyn(TEST_MODE_DL_ONLY,     160, 32, 101);
}

static void test_2_consecutive_dl_tbfs()
{
	BTS the_bts;
	GprsMs *ms;
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

	ms = the_bts.ms_alloc(ms_class, egprs_ms_class);
	dl_tbf1 = tbf_alloc_dl_tbf(bts, ms, 0, false);
	OSMO_ASSERT(dl_tbf1);

	for (int i = 0; i < 8; i++) {
		if (dl_tbf1->pdch[i])
			numTs1++;
	}
	OSMO_ASSERT(numTs1 == 4);
	printf("TBF1: numTs(%d)\n", numTs1);

	ms = the_bts.ms_alloc(ms_class, egprs_ms_class);
	dl_tbf2 = tbf_alloc_dl_tbf(bts, ms, 0, false);
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

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DTBF, 1, LOGL_INFO);
	if (getenv("LOGL_DEBUG"))
		log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	test_alloc_a();
	test_alloc_b();
	test_successive_allocations();
	test_many_connections(alloc_algorithm_a, 160, "A");
	test_many_connections(alloc_algorithm_b, 32, "B");
	test_many_connections(alloc_algorithm_dynamic, 160, "dynamic");
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
