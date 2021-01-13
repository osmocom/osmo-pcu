/* Frame number calculation test */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include "bts.h"
#include <string.h>
#include <stdio.h>

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

#define RFN_MODULUS 42432

/* globals used by the code */ void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;
bool spoof_mnc_3_digits = false;

static uint32_t calc_fn(BTS * bts, uint32_t rfn)
{
	uint32_t fn;
	fn = bts->rfn_to_fn(rfn);
	printf("rfn=%i ==> fn=%i\n", rfn, fn);
	return fn;
}

static void set_fn(BTS * bts, uint32_t fn)
{
	printf("\n");
	bts->set_current_frame_number(fn);
	printf("bts: fn=%i\n", fn);
}

static void run_test()
{
	BTS bts(the_pcu);
	uint32_t fn;

	printf("RFN_MODULUS=%i\n",RFN_MODULUS);
	printf("GSM_MAX_FN=%i\n",GSM_MAX_FN);


	/* Test with a collection of real world examples,
	 * all all of them are not critical and do not
	 * assume the occurence of any race contions */
	set_fn(&bts, 1320462);
	fn = calc_fn(&bts, 5066);
	OSMO_ASSERT(fn == 1320458);

	set_fn(&bts, 8246);
	fn = calc_fn(&bts, 8244);
	OSMO_ASSERT(fn == 8244);

	set_fn(&bts, 10270);
	fn = calc_fn(&bts, 10269);
	OSMO_ASSERT(fn == 10269);

	set_fn(&bts, 311276);
	fn = calc_fn(&bts, 14250);
	OSMO_ASSERT(fn == 311274);


	/* Now lets assume a case where the frame number
	 * just wrapped over a little bit above the
	 * modulo 42432 raster, but the rach request
	 * occurred before the wrapping */
	set_fn(&bts, RFN_MODULUS + 30);
	fn = calc_fn(&bts, RFN_MODULUS - 10);
	OSMO_ASSERT(fn == 42422);

	set_fn(&bts, RFN_MODULUS + 1);
	fn = calc_fn(&bts, RFN_MODULUS - 1);
	OSMO_ASSERT(fn == 42431);

	set_fn(&bts, RFN_MODULUS * 123 + 16);
	fn = calc_fn(&bts, RFN_MODULUS - 4);
	OSMO_ASSERT(fn == 5219132);

	set_fn(&bts, RFN_MODULUS * 123 + 451);
	fn = calc_fn(&bts, RFN_MODULUS - 175);
	OSMO_ASSERT(fn == 5218961);


	/* Lets check a special cornercase. We assume that
	 * the BTS just wrapped its internal frame number
	 * but we still get rach requests with high relative
	 * frame numbers. */
	set_fn(&bts, 0);
	fn = calc_fn(&bts, RFN_MODULUS - 13);
	OSMO_ASSERT(fn == 2715635);

	set_fn(&bts, 453);
	fn = calc_fn(&bts, RFN_MODULUS - 102);
	OSMO_ASSERT(fn == 2715546);

	set_fn(&bts, 10);
	fn = calc_fn(&bts, RFN_MODULUS - 10);
	OSMO_ASSERT(fn == 2715638);

	set_fn(&bts, 23);
	fn = calc_fn(&bts, RFN_MODULUS - 42);
	OSMO_ASSERT(fn == 2715606);


	/* Also check with some corner case
	 * values where Fn and RFn reach its
	 * maximum/minimum valid range */
	set_fn(&bts, GSM_MAX_FN);
	fn = calc_fn(&bts, RFN_MODULUS-1);
	OSMO_ASSERT(fn == GSM_MAX_FN-1);

	set_fn(&bts, 0);
	fn = calc_fn(&bts, RFN_MODULUS-1);
	OSMO_ASSERT(fn == GSM_MAX_FN-1);

	set_fn(&bts, GSM_MAX_FN);
	fn = calc_fn(&bts, 0);
	OSMO_ASSERT(fn == GSM_MAX_FN);

	set_fn(&bts, 0);
	fn = calc_fn(&bts, 0);
	OSMO_ASSERT(fn == 0);
}

int main(int argc, char **argv)
{
	tall_pcu_ctx = talloc_named_const(NULL, 1, "fn test context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);

	run_test();

	talloc_free(the_pcu);
	return EXIT_SUCCESS;
}

/*
 * stubs that should not be reached
 */
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
