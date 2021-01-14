/* Copyright (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <cstdlib>
#include <cstring>
#include <assert.h>
#include "gprs_rlcmac.h"
#include "bts.h"
#include "tbf_dl.h"

extern "C" {
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
}

using namespace std;
gprs_rlcmac_dl_tbf *tbf1, *tbf2;
GprsMs *ms1, *ms2;
struct msgb *sched_app_info(struct gprs_rlcmac_tbf *tbf);

/* globals used by the code */
void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;

void test_enc_zero_len() {
	struct gsm_pcu_if_app_info_req req = {0, 0, {0}};

	fprintf(stderr, "--- %s ---\n",  __func__);
	assert(gprs_rlcmac_app_info_msg(&req) == NULL);
	fprintf(stderr, "\n");
}

void test_enc(const struct gsm_pcu_if_app_info_req *req)
{
	const char *exp = "03 fc 03 fc 00 00 00 00 00 00 00 00 00 00 00 00 "; /* shifted by two bits to the right */
	struct msgb *msg;
	char *msg_dump;

	fprintf(stderr, "--- %s ---\n",  __func__);
	msg = gprs_rlcmac_app_info_msg(req);
	msg_dump = msgb_hexdump_c(tall_pcu_ctx, msg);

	fprintf(stderr, "exp: %s\n", exp);
	fprintf(stderr, "msg: %s\n", msg_dump);
	assert(strcmp(msg_dump, exp) == 0);

	msgb_free(msg);
	talloc_free(msg_dump);
	fprintf(stderr, "\n");
}

void test_pcu_rx_no_subscr_with_active_tbf()
{
	struct gsm_pcu_if pcu_prim = {PCU_IF_MSG_APP_INFO_REQ, };

	fprintf(stderr, "--- %s ---\n",  __func__);
	pcu_rx(PCU_IF_MSG_APP_INFO_REQ, &pcu_prim);
	fprintf(stderr, "\n");
}

void prepare_bts_with_two_dl_tbf_subscr()
{
	struct gprs_rlcmac_bts *bts = the_pcu->bts;
	struct gprs_rlcmac_trx *trx;

	fprintf(stderr, "--- %s ---\n",  __func__);

	the_pcu->alloc_algorithm = alloc_algorithm_b;

	trx = bts->trx;
	trx->pdch[4].enable();
	trx->pdch[5].enable();
	trx->pdch[6].enable();
	trx->pdch[7].enable();

	ms1 = bts_alloc_ms(bts, 10, 11);
	tbf1 = tbf_alloc_dl_tbf(bts, ms1, 0, false);
	ms2 = bts_alloc_ms(bts, 12, 13);
	tbf2 = tbf_alloc_dl_tbf(bts, ms2, 0, false);

	fprintf(stderr, "\n");
}

void test_sched_app_info_ok(const struct gsm_pcu_if_app_info_req *req)
{
	struct gsm_pcu_if pcu_prim = {PCU_IF_MSG_APP_INFO_REQ, };
	struct msgb *msg;

	fprintf(stderr, "--- %s ---\n",  __func__);
	pcu_prim.u.app_info_req = *req;
	pcu_rx(PCU_IF_MSG_APP_INFO_REQ, &pcu_prim);

	msg = sched_app_info(tbf1);
	assert(msg);
	msgb_free(msg);

	msg = sched_app_info(tbf2);
	assert(msg);
	msgb_free(msg);

	fprintf(stderr, "\n");
}

void test_sched_app_info_missing_app_info_in_bts(const struct gsm_pcu_if_app_info_req *req)
{
	struct gprs_rlcmac_bts *bts = the_pcu->bts;
	struct gsm_pcu_if pcu_prim = {PCU_IF_MSG_APP_INFO_REQ, };

	fprintf(stderr, "--- %s ---\n",  __func__);
	pcu_prim.u.app_info_req = *req;
	pcu_rx(PCU_IF_MSG_APP_INFO_REQ, &pcu_prim);

	msgb_free(bts->app_info);
	bts->app_info = NULL;

	assert(sched_app_info(tbf1) == NULL);

	fprintf(stderr, "\n");
}

void test_pcu_rx_overwrite_app_info(const struct gsm_pcu_if_app_info_req *req)
{
	struct gsm_pcu_if pcu_prim = {PCU_IF_MSG_APP_INFO_REQ, };

	fprintf(stderr, "--- %s ---\n",  __func__);
	pcu_prim.u.app_info_req = *req;
	pcu_rx(PCU_IF_MSG_APP_INFO_REQ, &pcu_prim);
	pcu_rx(PCU_IF_MSG_APP_INFO_REQ, &pcu_prim);
	fprintf(stderr, "\n");
}

void cleanup()
{
	fprintf(stderr, "--- %s ---\n",  __func__);

	tbf_free(tbf1);
	tbf_free(tbf2);
	TALLOC_FREE(the_pcu->bts);
	/* FIXME: talloc report disabled, because bts_alloc_ms(bts, ) in prepare_bts_with_two_dl_tbf_subscr() causes leak */
	/* talloc_report_full(tall_pcu_ctx, stderr); */
	talloc_free(the_pcu);
	talloc_free(tall_pcu_ctx);
}

int main(int argc, char *argv[])
{
	struct gsm_pcu_if_app_info_req req = {0, 15, {0}};
	const uint8_t req_data[] = {0xff, 0x00, 0xff};
	memcpy(req.data, req_data, 3);

	tall_pcu_ctx = talloc_named_const(NULL, 1, "AppInfoTest");
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_parse_category_mask(osmo_stderr_target, "DL1IF,1:DRLCMAC,3:DRLCMACSCHED,1");

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);
	the_pcu->bts = bts_alloc(the_pcu);

	test_enc_zero_len();
	test_enc(&req);
	test_pcu_rx_no_subscr_with_active_tbf();

	prepare_bts_with_two_dl_tbf_subscr();
	test_sched_app_info_ok(&req);
	test_sched_app_info_missing_app_info_in_bts(&req);
	test_pcu_rx_overwrite_app_info(&req);

	cleanup();
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
