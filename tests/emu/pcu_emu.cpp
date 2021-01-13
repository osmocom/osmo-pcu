/* Code for a software PCU to test a SGSN.. */

/* (C) 2013 by Holger Hans Peter Freyther
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

extern "C" {
#include <osmocom/core/talloc.h>
#include <pcu_vty.h>
}

#include "gprs_tests.h"


#include <gprs_bssgp_pcu.h>
#include <gprs_rlcmac.h>
#include <bts.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

static size_t current_test;

/* Extern data to please the underlying code */
void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;

extern void test_replay_gprs_attach(struct gprs_bssgp_pcu *pcu);
extern void test_replay_gprs_data(struct gprs_bssgp_pcu *, struct msgb *, struct tlv_parsed *);

extern void test_pdp_activation_start(struct gprs_bssgp_pcu *pcu);
extern void test_pdp_activation_data(struct gprs_bssgp_pcu *, struct msgb *, struct tlv_parsed*);

struct gprs_test all_tests[] = {
	gprs_test("gprs_attach_with_tmsi",
			"A simple test that verifies that N(U) is "
			"increasing across various messages. This makes "
			"sure that no new LLE/LLME is created on the fly.",
			test_replay_gprs_attach,
			test_replay_gprs_data),
	gprs_test("gprs_full_attach_pdp_activation",
			"A simple test to do a GPRS attach and open a PDP "
			"context. Then goes to sleep and waits for you to ping "
			"the connection and hopefully re-produce a crash.",
			test_pdp_activation_start,
			test_pdp_activation_data),
};

static void init_main_bts()
{
	struct gprs_rlcmac_bts *bts = bts_main_data();
	bts->fc_interval = 100;
	bts->initial_cs_dl = bts->initial_cs_ul = 1;
	bts->cs_mask = 1 << 0; /* CS-1 always enabled by default */
	bts->n3101 = 10;
	bts->n3103 = 4;
	bts->n3105 = 8;
	bts->alpha = 0; /* a = 0.0 */
}

static void init_pcu(struct gprs_pcu *pcu)
{
	if (!pcu->alloc_algorithm)
		pcu->alloc_algorithm = alloc_algorithm_b;
}

static void bvci_unblocked(struct gprs_bssgp_pcu *pcu)
{
	printf("BVCI unblocked. We can begin with test cases.\n");
	all_tests[current_test].start(pcu);
}

static void bssgp_data(struct gprs_bssgp_pcu *pcu, struct msgb *msg, struct tlv_parsed *tp)
{
	all_tests[current_test].data(pcu, msg, tp);
}

void create_and_connect_bssgp(struct gprs_rlcmac_bts *bts,
			uint32_t sgsn_ip, uint16_t sgsn_port)
{
	struct gprs_bssgp_pcu *pcu;
	struct osmo_sockaddr local, remote;
	uint16_t nsvci = 20;
	uint16_t nsei = 20;

	local.u.sin.sin_family = AF_INET;
	local.u.sin.sin_addr.s_addr = 0;
	local.u.sin.sin_port = 0;

	remote.u.sin.sin_family = AF_INET;
	remote.u.sin.sin_addr.s_addr = htonl(sgsn_ip);
	remote.u.sin.sin_port = htons(sgsn_port);

	pcu = gprs_bssgp_init(bts, 20, 20, 901, 99, false, 1, 0, 0);
	gprs_ns_config(bts, nsei, &local, &remote, &nsvci, 1);

	pcu->on_unblock_ack = bvci_unblocked;
	pcu->on_dl_unit_data = bssgp_data;
}

int main(int argc, char **argv)
{
	struct gprs_pcu *pcu = gprs_pcu_alloc(tall_pcu_ctx);
	the_pcu = pcu; /* globally avaialable object */
	pcu->bts = bts_alloc(pcu);

	tall_pcu_ctx = talloc_named_const(NULL, 1, "moiji-mobile Emu-PCU context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);

	pcu->nsi = gprs_ns2_instantiate(tall_pcu_ctx, &gprs_ns_prim_cb, NULL);
	if (!pcu->nsi) {
		LOGP(DBSSGP, LOGL_ERROR, "Failed to create NS instance\n");
		abort();
	}

	vty_init(&pcu_vty_info);
	pcu_vty_init();

	current_test = 0;

	init_pcu(pcu);
	init_main_bts();
	bssgp_set_bssgp_callback(gprs_gp_send_cb, pcu->nsi);
	create_and_connect_bssgp(bts_data(pcu->bts), INADDR_LOOPBACK, 23000);

	for (;;)
		osmo_select_main(0);

	return EXIT_SUCCESS;
}


/*
 * Test handling..
 */
void gprs_test_success(struct gprs_bssgp_pcu *pcu)
{
	current_test += 1;
	if (current_test >= ARRAY_SIZE(all_tests)) {
		printf("All tests executed.\n");
		exit(EXIT_SUCCESS);
	}

	all_tests[current_test].start(pcu);
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
