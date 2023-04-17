/* PDCH UL Controller test
 *
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

#include "gprs_ms.h"
#include "bts.h"
#include "sba.h"
#include "pdch_ul_controller.h"

/* globals used by the code */
void *tall_pcu_ctx;

static void print_ulc_nodes(struct pdch_ulc *ulc)
{
	struct rb_node *node;
	for (node = rb_first(&ulc->tree_root); node; node = rb_next(node)) {
		struct pdch_ulc_node *it = container_of(node, struct pdch_ulc_node, node);
		printf("FN=%" PRIu32 " type=%s\n",
		       it->fn, get_value_string(pdch_ul_node_names, it->type));
	}
}

static struct gprs_rlcmac_bts *setup_new_bts(void)
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	struct gprs_rlcmac_pdch *pdch = &bts->trx[0].pdch[0];
	pdch->enable();
	return bts;
}

static void test_reserve_multiple()
{
	printf("=== start: %s ===\n", __FUNCTION__);
	const uint32_t fn = 20;
	struct gprs_rlcmac_bts *bts = setup_new_bts();
	struct gprs_rlcmac_pdch *pdch = &bts->trx[0].pdch[0];
	struct gprs_rlcmac_tbf *tbf1 = (struct gprs_rlcmac_tbf*)0x1234; /*Dummy pointer */
	struct gprs_rlcmac_tbf *tbf2 = (struct gprs_rlcmac_tbf*)0x5678; /*Dummy pointer */
	struct gprs_rlcmac_sba *sba1, *sba2;
	pdch->last_rts_fn = fn; /* This is used by sba_alloc to set + reserve FN */
	sba1 = sba_alloc(bts, pdch, 0);
	pdch->last_rts_fn = fn_next_block(pdch->last_rts_fn);
	sba2 = sba_alloc(bts, pdch, 0);
	uint32_t tbf1_poll_fn1 = fn_next_block(sba2->fn);
	uint32_t tbf2_poll_fn1 = fn_next_block(tbf1_poll_fn1);
	uint32_t tbf1_poll_fn2 = fn_next_block(tbf2_poll_fn1);
	int rc;
	struct pdch_ulc_node *node;

	/* SBAs are reserved directly during allocation: */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, sba1->fn) == false);
	OSMO_ASSERT(pdch_ulc_get_sba(pdch->ulc, sba1->fn) == sba1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, sba2->fn) == false);
	OSMO_ASSERT(pdch_ulc_get_sba(pdch->ulc, sba2->fn) == sba2);

	rc = pdch_ulc_reserve_sba(pdch->ulc, sba1);
	OSMO_ASSERT(rc == -EEXIST);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, sba1->fn) == false);
	node = pdch_ulc_get_node(pdch->ulc, sba1->fn);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_SBA && node->sba.sba == sba1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, sba1->fn) == false);

	rc = pdch_ulc_reserve_sba(pdch->ulc, sba2);
	OSMO_ASSERT(rc == -EEXIST);
	OSMO_ASSERT(pdch_ulc_get_sba(pdch->ulc, sba1->fn) == sba1);
	OSMO_ASSERT(pdch_ulc_get_sba(pdch->ulc, sba2->fn) == sba2);
	node = pdch_ulc_get_node(pdch->ulc, sba2->fn);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_SBA && node->sba.sba == sba2);

	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, sba1->fn, tbf1, PDCH_ULC_POLL_UL_ASS);
	OSMO_ASSERT(rc == -EEXIST);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, sba1->fn) == NULL);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, sba2->fn, tbf1, PDCH_ULC_POLL_UL_ASS);
	OSMO_ASSERT(rc == -EEXIST);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, sba2->fn) == NULL);

	/* Now Reserve correctly TBF1 */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn1) == true);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, tbf1_poll_fn1, tbf1, PDCH_ULC_POLL_UL_ASS);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf1_poll_fn1) == tbf1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn1) == false);
	node = pdch_ulc_get_node(pdch->ulc, tbf1_poll_fn1);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_TBF_POLL && node->tbf_poll.poll_tbf == tbf1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn1) == false);

	/* Now reserve correctly TBF2 */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf2_poll_fn1) == true);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, tbf2_poll_fn1, tbf2, PDCH_ULC_POLL_UL_ASS);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf2_poll_fn1) == tbf2);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf2_poll_fn1) == false);
	node = pdch_ulc_get_node(pdch->ulc, tbf2_poll_fn1);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_TBF_POLL && node->tbf_poll.poll_tbf == tbf2);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf2_poll_fn1) == false);

	/* Now Reserve TBF1 for POLL again on a later FN, which is totally expected: */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn2) == true);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, tbf1_poll_fn2, tbf1, PDCH_ULC_POLL_UL_ASS);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf1_poll_fn2) == tbf1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn2) == false);
	node = pdch_ulc_get_node(pdch->ulc, tbf1_poll_fn2);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_TBF_POLL && node->tbf_poll.poll_tbf == tbf1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn2) == false);

	/* Now release them in different ways: */
	node = pdch_ulc_pop_node(pdch->ulc, sba2->fn);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_SBA && node->sba.sba == sba2);
	OSMO_ASSERT(pdch_ulc_get_sba(pdch->ulc, sba2->fn) == NULL);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, sba2->fn) == true);
	/* This will probably print a warning since in general SBAs are expected
	 * to be released from ULC during sba_free() time: */
	sba_free(sba2);

	pdch_ulc_expire_fn(pdch->ulc, sba1->fn);

	/* here the 2 tbf1 entries should be removed, so Ul Controller should
	   only have 1 entry for tbf2 after the call: */
	pdch_ulc_release_tbf(pdch->ulc, tbf1);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf1_poll_fn1) == NULL);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf1_poll_fn2) == NULL);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf2_poll_fn1) == tbf2);

	rc = pdch_ulc_release_fn(pdch->ulc, tbf1_poll_fn1);
	OSMO_ASSERT(rc == -ENOKEY);
	rc = pdch_ulc_release_fn(pdch->ulc, tbf1_poll_fn2);
	OSMO_ASSERT(rc == -ENOKEY);
	rc = pdch_ulc_release_fn(pdch->ulc, tbf2_poll_fn1);
	OSMO_ASSERT(rc == 0);

	/* Make sure the store is empty now: */
	OSMO_ASSERT(!rb_first(&pdch->ulc->tree_root));

	talloc_free(bts);
	printf("=== end: %s ===\n", __FUNCTION__);
}

int _alloc_algorithm_dummy(struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_tbf *tbf,
			   bool single, int8_t use_tbf)
{
	tbf->trx = &bts->trx[0];
	ms_set_first_common_ts(tbf_ms(tbf), &tbf->trx->pdch[0]);
	return 0;
}


static void test_fn_wrap_around()
{
	printf("=== start: %s ===\n", __FUNCTION__);
	const uint32_t start_fn = GSM_MAX_FN - 40;

	the_pcu->alloc_algorithm = _alloc_algorithm_dummy;

	struct gprs_rlcmac_bts *bts = setup_new_bts();
	struct GprsMs *ms = ms_alloc(bts);
	ms_confirm_tlli(ms, 0x12345678);
	struct gprs_rlcmac_tbf *tbf1 = dl_tbf_alloc(bts, ms, 0, true);
	struct gprs_rlcmac_pdch *pdch = &tbf1->trx->pdch[0];
	int rc;
	uint32_t fn, last_fn;

	fn = start_fn;
	while (fn < 40 || fn >= start_fn) {
		printf("*** RESERVE FN=%" PRIu32 ":\n", fn);
		rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, fn, tbf1, PDCH_ULC_POLL_UL_ASS);
		OSMO_ASSERT(rc == 0);
		print_ulc_nodes(pdch->ulc);
		fn = fn_next_block(fn);
	}
	last_fn = fn;

	/* Expiring fn_next_block(start_fn) should only expire first 2 entries here: */
	fn = fn_next_block(start_fn);
	printf("*** EXPIRE FN=%" PRIu32 ":\n", fn);
	pdch_ulc_expire_fn(pdch->ulc, fn);
	print_ulc_nodes(pdch->ulc);

	/* We should still be able to release FN=0 here, since it came later: */
	printf("*** RELEASE fn=%" PRIu32 ":\n", 0);
	rc = pdch_ulc_release_fn(pdch->ulc, 0);
	print_ulc_nodes(pdch->ulc);
	OSMO_ASSERT(rc == 0);

	/* Expiring last FN should expire all entries */
	printf("*** EXPIRE FN=%" PRIu32 ":\n", last_fn);
	pdch_ulc_expire_fn(pdch->ulc, last_fn);
	print_ulc_nodes(pdch->ulc);
	/* Make sure the store is empty now: */
	OSMO_ASSERT(!rb_first(&pdch->ulc->tree_root));

	talloc_free(bts);
	printf("=== end: %s ===\n", __FUNCTION__);
}

static void test_next_free_fn_sba()
{
	printf("=== start: %s ===\n", __FUNCTION__);
	struct gprs_rlcmac_bts *bts = setup_new_bts();
	struct gprs_rlcmac_pdch *pdch = &bts->trx[0].pdch[0];
	struct gprs_rlcmac_sba *sba1, *sba2, *sba3, *sba4;

	pdch->last_rts_fn = 52;
	printf("*** ALLOC 1 SBA FN=%" PRIu32 ":\n", pdch->last_rts_fn);
	sba1 = sba_alloc(bts, pdch, 0);
	print_ulc_nodes(pdch->ulc);

	pdch->last_rts_fn = 65;
	printf("*** ALLOC 3 SBA FN=%" PRIu32 ":\n", pdch->last_rts_fn);
	sba2 = sba_alloc(bts, pdch, 0);
	sba3 = sba_alloc(bts, pdch, 0);
	sba4 = sba_alloc(bts, pdch, 0);
	print_ulc_nodes(pdch->ulc);
	(void)sba1; (void)sba2; (void)sba3; (void)sba4;

	talloc_free(bts);
	printf("=== end: %s ===\n", __FUNCTION__);
}

static void test_next_free_fn_rrbp()
{
	printf("=== start: %s ===\n", __FUNCTION__);
	struct gprs_rlcmac_bts *bts = setup_new_bts();
	struct gprs_rlcmac_pdch *pdch = &bts->trx[0].pdch[0];
	struct gprs_rlcmac_sba *sba1;
	uint32_t poll_fn, curr_fn;
	unsigned int rrbp;
	int rc;

	rc = pdch_ulc_get_next_free_rrbp_fn(pdch->ulc, 26, &poll_fn, &rrbp);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(poll_fn == 26+13);
	OSMO_ASSERT(rrbp == RRBP_N_plus_13);


	pdch->last_rts_fn = 52;
	printf("*** ALLOC 1 SBA FN=%" PRIu32 ":\n", pdch->last_rts_fn);
	sba1 = sba_alloc(bts, pdch, 0); (void)sba1;
	print_ulc_nodes(pdch->ulc);
	curr_fn = sba1->fn - 13;
	rc = pdch_ulc_get_next_free_rrbp_fn(pdch->ulc, curr_fn, &poll_fn, &rrbp);
	OSMO_ASSERT(rc == 0);
	printf("***NEXT FREE RRBP FN=%" PRIu32 ":\n", poll_fn);
	OSMO_ASSERT(poll_fn == (curr_fn+17) || poll_fn == (curr_fn+18));
	OSMO_ASSERT(rrbp == RRBP_N_plus_17_18);

	pdch->last_rts_fn = fn_next_block(pdch->last_rts_fn);
	printf("*** ALLOC 1 SBA FN=%" PRIu32 ":\n", pdch->last_rts_fn);
	sba1 = sba_alloc(bts, pdch, 0); (void)sba1;
	print_ulc_nodes(pdch->ulc);
	rc = pdch_ulc_get_next_free_rrbp_fn(pdch->ulc, curr_fn, &poll_fn, &rrbp);
	OSMO_ASSERT(rc == 0);
	printf("***NEXT FREE RRBP FN=%" PRIu32 ":\n", poll_fn);
	OSMO_ASSERT(poll_fn == (curr_fn+21) || poll_fn == (curr_fn+22));
	OSMO_ASSERT(rrbp == RRBP_N_plus_21_22);

	pdch->last_rts_fn = fn_next_block(pdch->last_rts_fn);
	printf("*** ALLOC 1 SBA FN=%" PRIu32 ":\n", pdch->last_rts_fn);
	sba1 = sba_alloc(bts, pdch, 0); (void)sba1;
	print_ulc_nodes(pdch->ulc);
	rc = pdch_ulc_get_next_free_rrbp_fn(pdch->ulc, curr_fn, &poll_fn, &rrbp);
	OSMO_ASSERT(rc == 0);
	printf("***NEXT FREE RRBP FN=%" PRIu32 ":\n", poll_fn);
	OSMO_ASSERT(poll_fn == (curr_fn+26));
	OSMO_ASSERT(rrbp == RRBP_N_plus_26);

	pdch->last_rts_fn = fn_next_block(pdch->last_rts_fn);
	printf("*** ALLOC 1 SBA FN=%" PRIu32 ":\n", pdch->last_rts_fn);
	sba1 = sba_alloc(bts, pdch, 0); (void)sba1;
	print_ulc_nodes(pdch->ulc);
	rc = pdch_ulc_get_next_free_rrbp_fn(pdch->ulc, curr_fn, &poll_fn, &rrbp);
	OSMO_ASSERT(rc == -EBUSY);

	talloc_free(bts);
	printf("=== end: %s ===\n", __FUNCTION__);
}

int main(int argc, char **argv)
{
	tall_pcu_ctx = talloc_named_const(NULL, 1, "pdch_ulc test context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_parse_category_mask(osmo_stderr_target, "DPCU,1:DRLCMAC,1:DRLCMACUL,1");

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);

	test_reserve_multiple();
	test_fn_wrap_around();
	test_next_free_fn_sba();
	test_next_free_fn_rrbp();
	talloc_free(the_pcu);
	return EXIT_SUCCESS;
}

/*
 * stubs that should not be reached
 */
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;
extern "C" {
	void l1if_pdch_req() {
		abort();
	} void l1if_connect_pdch() {
		abort();
	} void l1if_disconnect_pdch() {
		abort();
	}
	void l1if_close_pdch() {
		abort();
	}
	void l1if_open_pdch() {
		abort();
	}
}
