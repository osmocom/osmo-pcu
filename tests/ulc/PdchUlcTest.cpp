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

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

#include "bts.h"
#include "sba.h"
#include "pdch_ul_controller.h"

/* globals used by the code */
void *tall_pcu_ctx;

static void test_reserve_multiple()
{
	printf("=== start: %s ===\n", __FUNCTION__);
	const uint32_t fn = 20;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
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

	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, sba1->fn, tbf1);
	OSMO_ASSERT(rc == -EEXIST);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, sba1->fn) == NULL);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, sba2->fn, tbf1);
	OSMO_ASSERT(rc == -EEXIST);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, sba2->fn) == NULL);

	/* Now Reserve correctly TBF1 */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn1) == true);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, tbf1_poll_fn1, tbf1);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf1_poll_fn1) == tbf1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn1) == false);
	node = pdch_ulc_get_node(pdch->ulc, tbf1_poll_fn1);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_TBF_POLL && node->tbf_poll.poll_tbf == tbf1);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn1) == false);

	/* Now reserve correctly TBF2 */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf2_poll_fn1) == true);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, tbf2_poll_fn1, tbf2);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(pdch_ulc_get_tbf_poll(pdch->ulc, tbf2_poll_fn1) == tbf2);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf2_poll_fn1) == false);
	node = pdch_ulc_get_node(pdch->ulc, tbf2_poll_fn1);
	OSMO_ASSERT(node->type == PDCH_ULC_NODE_TBF_POLL && node->tbf_poll.poll_tbf == tbf2);
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf2_poll_fn1) == false);

	/* Now Reserve TBF1 for POLL again on a later FN, which is totally expected: */
	OSMO_ASSERT(pdch_ulc_fn_is_free(pdch->ulc, tbf1_poll_fn2) == true);
	rc = pdch_ulc_reserve_tbf_poll(pdch->ulc, tbf1_poll_fn2, tbf1);
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
	}
	void l1if_close_pdch() {
		abort();
	}
	void l1if_open_pdch() {
		abort();
	}
}
