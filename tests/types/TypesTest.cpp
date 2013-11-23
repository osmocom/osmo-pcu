/*
 * TypesTest.cpp Test the primitive data types
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

static void test_llc(void)
{
	{
		uint8_t data[LLC_MAX_LEN] = {1, 2, 3, 4, };
		uint8_t out;
		gprs_llc llc;
		llc.init();

		OSMO_ASSERT(llc.chunk_size() == 0);
		OSMO_ASSERT(llc.remaining_space() == LLC_MAX_LEN);
		OSMO_ASSERT(llc.frame_length() == 0);

		llc.put_frame(data, 2);
		OSMO_ASSERT(llc.remaining_space() == LLC_MAX_LEN - 2);
		OSMO_ASSERT(llc.frame_length() == 2);
		OSMO_ASSERT(llc.chunk_size() == 2);
		OSMO_ASSERT(llc.frame[0] == 1);
		OSMO_ASSERT(llc.frame[1] == 2);

		llc.append_frame(&data[3], 1);
		OSMO_ASSERT(llc.remaining_space() == LLC_MAX_LEN - 3);
		OSMO_ASSERT(llc.frame_length() == 3);
		OSMO_ASSERT(llc.chunk_size() == 3);

		/* consume two bytes */
		llc.consume(&out, 1);
		OSMO_ASSERT(llc.remaining_space() == LLC_MAX_LEN - 3);
		OSMO_ASSERT(llc.frame_length() == 3);
		OSMO_ASSERT(llc.chunk_size() == 2);

		/* check that the bytes are as we expected */
		OSMO_ASSERT(llc.frame[0] == 1);
		OSMO_ASSERT(llc.frame[1] == 2);
		OSMO_ASSERT(llc.frame[2] == 4);

		/* now fill the frame */
		llc.append_frame(data, llc.remaining_space() - 1);
		OSMO_ASSERT(llc.fits_in_current_frame(1));
		OSMO_ASSERT(!llc.fits_in_current_frame(2));
	}	
}

static void test_rlc()
{
	{
		struct gprs_rlc_data rlc = { 0, };
		memset(rlc.block, 0x23, RLC_MAX_LEN);
		uint8_t *p = rlc.prepare(20);
		OSMO_ASSERT(p == rlc.block);
		for (int i = 0; i < 20; ++i)
			OSMO_ASSERT(p[i] == 0x2B);
		for (int i = 20; i < RLC_MAX_LEN; ++i)
			OSMO_ASSERT(p[i] == 0x0);
	}
}

static void test_rlc_v_b()
{
	{
		gprs_rlc_v_b vb;
		vb.reset();

		for (size_t i = 0; i < RLC_MAX_SNS/2; ++i)
			OSMO_ASSERT(vb.is_invalid(i));

		vb.mark_unacked(23);
		OSMO_ASSERT(vb.is_unacked(23));

		vb.mark_nacked(23);
		OSMO_ASSERT(vb.is_nacked(23));

		vb.mark_acked(23);
		OSMO_ASSERT(vb.is_acked(23));

		vb.mark_resend(23);
		OSMO_ASSERT(vb.is_resend(23));

		vb.mark_invalid(23);
		OSMO_ASSERT(vb.is_invalid(23));
	}
}

int main(int argc, char **argv)
{
	printf("Making some basic type testing.\n");
	test_llc();
	test_rlc();
	test_rlc_v_b();
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
