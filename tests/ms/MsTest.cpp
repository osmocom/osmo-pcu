/*
 * MsTest.cpp
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 *
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "tbf.h"
#include "tbf_ul.h"
#include "gprs_debug.h"
#include "gprs_ms.h"
#include "bts.h"

extern "C" {
#include "pcu_vty.h"

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vty.h>
}

#include <errno.h>
#include <unistd.h>

#include <new>

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;

static int ul_tbf_dtor(struct gprs_rlcmac_ul_tbf *tbf)
{
	tbf->~gprs_rlcmac_ul_tbf();
	return 0;
}

static int dl_tbf_dtor(struct gprs_rlcmac_dl_tbf *tbf)
{
	tbf->~gprs_rlcmac_dl_tbf();
	return 0;
}

static gprs_rlcmac_ul_tbf *alloc_ul_tbf(struct gprs_rlcmac_bts *bts, GprsMs *ms)
{
	gprs_rlcmac_ul_tbf *ul_tbf;
	ul_tbf = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_ul_tbf);
	talloc_set_destructor(ul_tbf, ul_tbf_dtor);
	new (ul_tbf) gprs_rlcmac_ul_tbf(bts, ms);
	return ul_tbf;
}

static gprs_rlcmac_dl_tbf *alloc_dl_tbf(struct gprs_rlcmac_bts *bts, GprsMs *ms)
{
	gprs_rlcmac_dl_tbf *dl_tbf;
	dl_tbf = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_dl_tbf);
	talloc_set_destructor(dl_tbf, dl_tbf_dtor);
	new (dl_tbf) gprs_rlcmac_dl_tbf(bts, ms);
	return dl_tbf;
}

static void test_ms_state()
{
	uint32_t tlli = 0xffeeddbb;
	gprs_rlcmac_dl_tbf *dl_tbf;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	GprsMs *ms;

	printf("=== start %s ===\n", __func__);

	ms = ms_alloc(bts);
	ms_set_tlli(ms, tlli);
	OSMO_ASSERT(ms_is_idle(ms));

	dl_tbf = alloc_dl_tbf(bts, ms);
	ul_tbf = alloc_ul_tbf(bts, ms);

	ms_attach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == ul_tbf);
	OSMO_ASSERT(ms_dl_tbf(ms) == NULL);

	ms_attach_tbf(ms, dl_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == ul_tbf);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf);

	OSMO_ASSERT(ms_tbf(ms, GPRS_RLCMAC_UL_TBF) == ul_tbf);
	OSMO_ASSERT(ms_tbf(ms, GPRS_RLCMAC_DL_TBF) == dl_tbf);

	ms_detach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf);

	ms_detach_tbf(ms, dl_tbf);
	/* The ms object is freed now */
	ms = NULL;

	talloc_free(dl_tbf);
	talloc_free(ul_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static enum {CB_UNKNOWN, CB_IS_IDLE, CB_IS_ACTIVE} last_cb = CB_UNKNOWN;
static void ms_idle_cb(struct GprsMs *ms)
{
	OSMO_ASSERT(ms_is_idle(ms));
	printf("  ms_idle() was called\n");
	last_cb = CB_IS_IDLE;
}
static void ms_active_cb(struct GprsMs *ms)
{
	OSMO_ASSERT(!ms_is_idle(ms));
	printf("  ms_active() was called\n");
	last_cb = CB_IS_ACTIVE;
}
static struct gpr_ms_callback ms_cb = {
	.ms_idle = ms_idle_cb,
	.ms_active = ms_active_cb
};
static void test_ms_callback()
{
	uint32_t tlli = 0xffeeddbb;
	gprs_rlcmac_dl_tbf *dl_tbf;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	GprsMs *ms;
	last_cb = CB_UNKNOWN;

	printf("=== start %s ===\n", __func__);

	ms = ms_alloc(bts);
	ms_set_tlli(ms, tlli);
	ms_set_callback(ms, &ms_cb);

	OSMO_ASSERT(ms_is_idle(ms));

	dl_tbf = alloc_dl_tbf(bts, ms);
	ul_tbf = alloc_ul_tbf(bts, ms);

	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	ms_attach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == ul_tbf);
	OSMO_ASSERT(ms_dl_tbf(ms) == NULL);
	OSMO_ASSERT(last_cb == CB_IS_ACTIVE);

	last_cb = CB_UNKNOWN;

	ms_attach_tbf(ms, dl_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == ul_tbf);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf);
	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	ms_detach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf);
	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	ms_detach_tbf(ms, dl_tbf);
	OSMO_ASSERT(ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == NULL);
	OSMO_ASSERT(last_cb == CB_IS_IDLE);

	last_cb = CB_UNKNOWN;
	talloc_free(ms);

	talloc_free(dl_tbf);
	talloc_free(ul_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static bool was_idle;
static void ms_replace_tbf_idle_cb(struct GprsMs *ms)
{
	OSMO_ASSERT(ms_is_idle(ms));
	printf("  ms_idle() was called\n");
	was_idle = true;
}
static void ms_replace_tbf_active_cb(struct GprsMs *ms)
{
	OSMO_ASSERT(!ms_is_idle(ms));
	printf("  ms_active() was called\n");
}
static struct gpr_ms_callback ms_replace_tbf_cb = {
	.ms_idle = ms_replace_tbf_idle_cb,
	.ms_active = ms_replace_tbf_active_cb
};
static void test_ms_replace_tbf()
{
	uint32_t tlli = 0xffeeddbb;
	gprs_rlcmac_dl_tbf *dl_tbf[2];
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	GprsMs *ms;

	printf("=== start %s ===\n", __func__);

	ms = ms_alloc(bts);
	ms_confirm_tlli(ms, tlli);
	ms_set_callback(ms, &ms_replace_tbf_cb);

	OSMO_ASSERT(ms_is_idle(ms));
	was_idle = false;

	dl_tbf[0] = alloc_dl_tbf(bts, ms);
	dl_tbf[1] = alloc_dl_tbf(bts, ms);
	ul_tbf = alloc_ul_tbf(bts, ms);

	ms_attach_tbf(ms, dl_tbf[0]);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf[0]);
	OSMO_ASSERT(llist_empty(&ms->old_tbfs));
	OSMO_ASSERT(!was_idle);

	ms_attach_tbf(ms, dl_tbf[1]);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf[1]);
	OSMO_ASSERT(!llist_empty(&ms->old_tbfs));
	OSMO_ASSERT(!was_idle);

	ms_attach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == ul_tbf);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf[1]);
	OSMO_ASSERT(!llist_empty(&ms->old_tbfs));
	OSMO_ASSERT(!was_idle);

	ms_detach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf[1]);
	OSMO_ASSERT(!llist_empty(&ms->old_tbfs));
	OSMO_ASSERT(!was_idle);

	ms_detach_tbf(ms, dl_tbf[0]);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == dl_tbf[1]);
	OSMO_ASSERT(llist_empty(&ms->old_tbfs));
	OSMO_ASSERT(!was_idle);

	ms_detach_tbf(ms, dl_tbf[1]);
	OSMO_ASSERT(ms_is_idle(ms));
	OSMO_ASSERT(ms_ul_tbf(ms) == NULL);
	OSMO_ASSERT(ms_dl_tbf(ms) == NULL);
	OSMO_ASSERT(llist_empty(&ms->old_tbfs));
	OSMO_ASSERT(was_idle);

	talloc_free(ms);

	talloc_free(dl_tbf[0]);
	talloc_free(dl_tbf[1]);
	talloc_free(ul_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static void test_ms_change_tlli()
{
	uint32_t start_tlli = 0xaa000000;
	uint32_t new_ms_tlli = 0xff001111;
	uint32_t other_sgsn_tlli = 0xff00eeee;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	GprsMs *ms;

	printf("=== start %s ===\n", __func__);

	ms = ms_alloc(bts);

	OSMO_ASSERT(ms_is_idle(ms));

	/* MS announces TLLI, SGSN uses it immediately */
	ms_set_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));

	ms_confirm_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));

	/* MS announces TLLI, SGSN uses it later */
	ms_set_tlli(ms, start_tlli);
	ms_confirm_tlli(ms, start_tlli);

	ms_set_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, start_tlli));

	ms_confirm_tlli(ms, start_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, start_tlli));

	ms_set_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, start_tlli));

	ms_confirm_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(!ms_check_tlli(ms, start_tlli));

	/* MS announces TLLI, SGSN uses it later after another new TLLI */
	ms_set_tlli(ms, start_tlli);
	ms_confirm_tlli(ms, start_tlli);

	ms_set_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, start_tlli));

	ms_confirm_tlli(ms, other_sgsn_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, other_sgsn_tlli));

	ms_set_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, other_sgsn_tlli));

	ms_confirm_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(!ms_check_tlli(ms, start_tlli));
	OSMO_ASSERT(!ms_check_tlli(ms, other_sgsn_tlli));

	/* SGSN uses the new TLLI before it is announced by the MS (shouldn't
	 * happen in normal use) */
	ms_set_tlli(ms, start_tlli);
	ms_confirm_tlli(ms, start_tlli);

	ms_confirm_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == start_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(ms_check_tlli(ms, start_tlli));

	ms_set_tlli(ms, new_ms_tlli);
	OSMO_ASSERT(ms_tlli(ms) == new_ms_tlli);
	OSMO_ASSERT(ms_check_tlli(ms, new_ms_tlli));
	OSMO_ASSERT(!ms_check_tlli(ms, start_tlli));

	talloc_free(ms);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static GprsMs *prepare_ms(struct gprs_rlcmac_bts *bts, uint32_t tlli, enum gprs_rlcmac_tbf_direction dir)
{
	GprsMs *ms = bts_get_ms_by_tlli(bts, tlli, GSM_RESERVED_TMSI);
	if (ms)
		return ms;

	ms = ms_alloc(bts);

	if (dir == GPRS_RLCMAC_UL_TBF)
		ms_set_tlli(ms, tlli);
	else
		ms_confirm_tlli(ms, tlli);

	return ms;
}

static void test_ms_storage()
{
	uint32_t tlli = 0xffeeddbb;
	const char *imsi1 = "001001987654321";
	const char *imsi2 = "001001987654322";

	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	GprsMs *ms, *ms_tmp;

	printf("=== start %s ===\n", __func__);

	ms = bts_get_ms_by_tlli(bts, tlli + 0, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms == NULL);

	ms = prepare_ms(bts, tlli + 0, GPRS_RLCMAC_UL_TBF);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms_tlli(ms) == tlli + 0);
	ms_set_imsi(ms, imsi1);
	OSMO_ASSERT(strcmp(ms_imsi(ms), imsi1) == 0);

	ms_tmp = bts_get_ms_by_tlli(bts, tlli + 0, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms == ms_tmp);
	OSMO_ASSERT(ms_tlli(ms) == tlli + 0);

	ms_tmp = bts_get_ms_by_imsi(bts, imsi1);
	OSMO_ASSERT(ms == ms_tmp);
	OSMO_ASSERT(strcmp(ms_imsi(ms), imsi1) == 0);
	ms_tmp = bts_get_ms_by_imsi(bts, imsi2);
	OSMO_ASSERT(ms_tmp == NULL);

	ms = prepare_ms(bts, tlli + 1, GPRS_RLCMAC_UL_TBF);
	OSMO_ASSERT(ms != NULL);
	OSMO_ASSERT(ms_tlli(ms) == tlli + 1);
	ms_set_imsi(ms, imsi2);
	OSMO_ASSERT(strcmp(ms_imsi(ms), imsi2) == 0);

	ms_tmp = bts_get_ms_by_tlli(bts, tlli + 1, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms == ms_tmp);
	OSMO_ASSERT(ms_tlli(ms) == tlli + 1);

	ms_tmp = bts_get_ms_by_imsi(bts, imsi1);
	OSMO_ASSERT(ms_tmp != NULL);
	OSMO_ASSERT(ms_tmp != ms);
	ms_tmp = bts_get_ms_by_imsi(bts, imsi2);
	OSMO_ASSERT(ms == ms_tmp);
	OSMO_ASSERT(strcmp(ms_imsi(ms), imsi2) == 0);

	/* delete ms */
	ms = bts_get_ms_by_tlli(bts, tlli + 0, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms != NULL);
	ul_tbf = alloc_ul_tbf(bts, ms);
	ms_attach_tbf(ms, ul_tbf);
	tbf_set_ms(ul_tbf, NULL);
	ms = bts_get_ms_by_tlli(bts, tlli + 0, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms == NULL);
	ms = bts_get_ms_by_tlli(bts, tlli + 1, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms != NULL);

	/* delete ms */
	ms = bts_get_ms_by_tlli(bts, tlli + 1, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms != NULL);
	tbf_set_ms(ul_tbf, ms);
	tbf_set_ms(ul_tbf, NULL);
	ms = bts_get_ms_by_tlli(bts, tlli + 1, GSM_RESERVED_TMSI);
	OSMO_ASSERT(ms == NULL);

	talloc_free(ms);
	talloc_free(ul_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static void test_ms_timeout()
{
	uint32_t tlli = 0xffeeddbb;
	gprs_rlcmac_dl_tbf *dl_tbf;
	gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	GprsMs *ms;
	last_cb = CB_UNKNOWN;

	printf("=== start %s ===\n", __func__);

	ms = ms_alloc(bts);
	ms_set_tlli(ms, tlli);
	ms_set_callback(ms, &ms_cb);
	ms_set_timeout(ms, 1);

	OSMO_ASSERT(ms_is_idle(ms));

	dl_tbf = alloc_dl_tbf(bts, ms);
	ul_tbf = alloc_ul_tbf(bts, ms);

	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	ms_attach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(last_cb == CB_IS_ACTIVE);

	last_cb = CB_UNKNOWN;

	ms_attach_tbf(ms, dl_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	ms_detach_tbf(ms, ul_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	ms_detach_tbf(ms, dl_tbf);
	OSMO_ASSERT(!ms_is_idle(ms));
	OSMO_ASSERT(last_cb == CB_UNKNOWN);

	usleep(1100000);
	osmo_timers_update();

	OSMO_ASSERT(ms_is_idle(ms));
	OSMO_ASSERT(last_cb == CB_IS_IDLE);

	last_cb = CB_UNKNOWN;
	talloc_free(ms);
	talloc_free(dl_tbf);
	talloc_free(ul_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static void test_ms_cs_selection()
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	uint32_t tlli = 0xffeeddbb;

	gprs_rlcmac_dl_tbf *dl_tbf;
	GprsMs *ms;

	printf("=== start %s ===\n", __func__);

	bts->initial_cs_dl = 4;
	bts->initial_cs_ul = 1;
	the_pcu->vty.cs_downgrade_threshold = 0;
	the_pcu->vty.cs_adj_lower_limit = 0;

	ms = ms_alloc(bts);
	ms_confirm_tlli(ms, tlli);

	OSMO_ASSERT(ms_is_idle(ms));

	dl_tbf = alloc_dl_tbf(bts, ms);
	ms_attach_tbf(ms, dl_tbf);

	OSMO_ASSERT(!ms_is_idle(ms));

	OSMO_ASSERT(mcs_chan_code(ms_current_cs_dl(ms, ms_mode(ms))) == 3);

	the_pcu->vty.cs_downgrade_threshold = 200;

	OSMO_ASSERT(mcs_chan_code(ms_current_cs_dl(ms, ms_mode(ms))) == 2);

	talloc_free(ms);
	talloc_free(dl_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

static void dump_ms(const GprsMs *ms, const char *pref)
{
	printf("%s MS DL %s/%s, UL %s/%s, mode %s, <%s>\n", pref,
	       mcs_name(ms_current_cs_dl(ms, ms_mode(ms))), mcs_name(ms_max_cs_dl(ms)),
	       mcs_name(ms_current_cs_ul(ms)), mcs_name(ms_max_cs_ul(ms)),
	       mode_name(ms_mode(ms)),
	       ms_is_idle(ms) ? "IDLE" : "ACTIVE");
}

static void test_ms_mcs_mode()
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	uint32_t tlli = 0xdeadbeef;

	gprs_rlcmac_dl_tbf *dl_tbf;
	GprsMs *ms1, *ms2;

	printf("=== start %s ===\n", __func__);

	ms1 = ms_alloc(bts);
	ms_confirm_tlli(ms1, tlli);
	dump_ms(ms1, "1: no BTS defaults  ");

	bts->initial_cs_dl = 4;
	bts->initial_cs_ul = 1;
	the_pcu->vty.cs_downgrade_threshold = 0;

	ms2 = ms_alloc(bts);
	ms_confirm_tlli(ms2, tlli + 1);
	dump_ms(ms2, "2: with BTS defaults");

	dl_tbf = alloc_dl_tbf(bts, ms2);
	ms_attach_tbf(ms2, dl_tbf);

	dump_ms(ms2, "2: after TBF attach ");

	ms_set_mode(ms1, EGPRS);
	dump_ms(ms1, "1: after mode set   ");

	ms_set_mode(ms2, EGPRS);
	dump_ms(ms2, "2: after mode set   ");

	ms_set_current_cs_dl(ms1, MCS7);
	dump_ms(ms1, "1: after MCS set    ");

	ms_set_current_cs_dl(ms2, MCS8);
	dump_ms(ms2, "2: after MCS set    ");

	ms_set_mode(ms1, EGPRS_GMSK);
	dump_ms(ms1, "1: after mode set   ");

	ms_set_mode(ms2, EGPRS_GMSK);
	dump_ms(ms2, "2: after mode set   ");

	// FIXME: following code triggers ASAN failure:
	// ms2->detach_tbf(dl_tbf);
	// dump_ms(ms2, "2: after TBF detach ");

	ms_set_mode(ms1, GPRS);
	dump_ms(ms1, "1: after mode set   ");

	ms_set_mode(ms2, GPRS);
	dump_ms(ms2, "2: after mode set   ");

	talloc_free(ms1);
	talloc_free(ms2);
	talloc_free(dl_tbf);
	talloc_free(bts);
	printf("=== end %s ===\n", __func__);
}

int main(int argc, char **argv)
{
	struct vty_app_info pcu_vty_info = {0};

	tall_pcu_ctx = talloc_named_const(NULL, 1, "MsTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_parse_category_mask(osmo_stderr_target, "DPCU,3:DRLCMAC,3");

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);

	vty_init(&pcu_vty_info);
	pcu_vty_init();

	osmo_tdef_set(the_pcu->T_defs, -2030, 0, OSMO_TDEF_S);

	test_ms_state();
	test_ms_callback();
	test_ms_replace_tbf();
	test_ms_change_tlli();
	test_ms_storage();
	test_ms_timeout();
	test_ms_cs_selection();
	test_ms_mcs_mode();

	talloc_free(the_pcu);

	if (getenv("TALLOC_REPORT_FULL"))
		talloc_report_full(tall_pcu_ctx, stderr);

	return EXIT_SUCCESS;
}

extern "C" {
void l1if_pdch_req() { abort(); }
void l1if_connect_pdch() { abort(); }
void l1if_disconnect_pdch() { abort(); }
void l1if_close_pdch() { abort(); }
void l1if_open_pdch() { abort(); }
}
