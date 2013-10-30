/*
 * TbfTest.cpp
 *
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include "bts.h"
#include "tbf.h"
#include "gprs_debug.h"

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;

static void test_tbf_tlli_update()
{
	BTS the_bts;
	the_bts.bts_data()->alloc_algorithm = alloc_algorithm_a;
	the_bts.bts_data()->trx[0].pdch[2].enable();
	the_bts.bts_data()->trx[0].pdch[3].enable();

	/*
	 * Make a uplink and downlink allocation
	 */
	gprs_rlcmac_tbf *dl_tbf = tbf_alloc(the_bts.bts_data(),
						NULL, GPRS_RLCMAC_DL_TBF, 0,
						0, 0, 0);
	dl_tbf->update_tlli(0x2342);
	dl_tbf->tlli_mark_valid();
	dl_tbf->ta = 4;
	the_bts.timing_advance()->remember(0x2342, dl_tbf->ta);

	gprs_rlcmac_tbf *ul_tbf = tbf_alloc(the_bts.bts_data(),
						ul_tbf, GPRS_RLCMAC_UL_TBF, 0,
						0, 0, 0);
	ul_tbf->update_tlli(0x2342);
	ul_tbf->tlli_mark_valid();
	

	OSMO_ASSERT(the_bts.tbf_by_tlli(0x2342, GPRS_RLCMAC_DL_TBF) == dl_tbf);
	OSMO_ASSERT(the_bts.tbf_by_tlli(0x2342, GPRS_RLCMAC_UL_TBF) == ul_tbf);


	/*
	 * Now check.. that DL changes and that the timing advance
	 * has changed.
	 */
	dl_tbf->update_tlli(0x4232);
	OSMO_ASSERT(!the_bts.tbf_by_tlli(0x2342, GPRS_RLCMAC_DL_TBF));
	OSMO_ASSERT(!the_bts.tbf_by_tlli(0x2342, GPRS_RLCMAC_UL_TBF));

	
	OSMO_ASSERT(the_bts.tbf_by_tlli(0x4232, GPRS_RLCMAC_DL_TBF) == dl_tbf);
	OSMO_ASSERT(the_bts.tbf_by_tlli(0x4232, GPRS_RLCMAC_UL_TBF) == ul_tbf);
}

int main(int argc, char **argv)
{
	tall_pcu_ctx = talloc_named_const(NULL, 1, "moiji-mobile TbfTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_set_talloc_ctx(tall_pcu_ctx);
	osmo_init_logging(&gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	test_tbf_tlli_update();
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
