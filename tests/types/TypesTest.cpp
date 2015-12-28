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
#include "encoding.h"
#include "decoding.h"

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

#define OSMO_ASSERT_STR_EQ(a, b) \
	do { \
		if (strcmp(a, b)) { \
			printf("String mismatch:\nGot:\t%s\nWant:\t%s\n", a, b); \
			OSMO_ASSERT(false); \
		} \
	} while (0)

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

		for (size_t i = 0; i < RLC_MAX_SNS; ++i)
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

static void test_rlc_v_n()
{
	{
		gprs_rlc_v_n vn;
		vn.reset();

		OSMO_ASSERT(!vn.is_received(0x23));
		OSMO_ASSERT(vn.state(0x23) == GPRS_RLC_UL_BSN_INVALID);

		vn.mark_received(0x23);
		OSMO_ASSERT(vn.is_received(0x23));
		OSMO_ASSERT(vn.state(0x23) == GPRS_RLC_UL_BSN_RECEIVED);

		vn.mark_missing(0x23);
		OSMO_ASSERT(!vn.is_received(0x23));
		OSMO_ASSERT(vn.state(0x23) == GPRS_RLC_UL_BSN_MISSING);
	}
}

static void test_rlc_dl_ul_basic()
{
	{
		gprs_rlc_dl_window dl_win;
		OSMO_ASSERT(dl_win.window_empty());
		OSMO_ASSERT(!dl_win.window_stalled());
		OSMO_ASSERT(dl_win.distance() == 0);

		dl_win.increment_send();
		OSMO_ASSERT(!dl_win.window_empty());
		OSMO_ASSERT(!dl_win.window_stalled());
		OSMO_ASSERT(dl_win.distance() == 1);

		for (int i = 1; i < 64; ++i) {
			dl_win.increment_send();
			OSMO_ASSERT(!dl_win.window_empty());
			OSMO_ASSERT(dl_win.distance() == i + 1);
		}

		OSMO_ASSERT(dl_win.distance() == 64);
		OSMO_ASSERT(dl_win.window_stalled());

		dl_win.raise(1);
		OSMO_ASSERT(dl_win.distance() == 63);
		OSMO_ASSERT(!dl_win.window_stalled());
		for (int i = 62; i >= 0; --i) {
			dl_win.raise(1);
			OSMO_ASSERT(dl_win.distance() == i);
		}

		OSMO_ASSERT(dl_win.distance() == 0);
		OSMO_ASSERT(dl_win.window_empty());

		dl_win.increment_send();
		dl_win.increment_send();
		dl_win.increment_send();
		dl_win.increment_send();
		OSMO_ASSERT(dl_win.distance() == 4);

		for (int i = 0; i < 128; ++i) {
			dl_win.increment_send();
			dl_win.increment_send();
			dl_win.raise(2);
			OSMO_ASSERT(dl_win.distance() == 4);
		}
	}

	{
		gprs_rlc_ul_window ul_win;
		int count;
		const char *rbb;
		char win_rbb[65];
		uint8_t bin_rbb[8];
		win_rbb[64] = '\0';

		ul_win.m_v_n.reset();

		OSMO_ASSERT(ul_win.is_in_window(0));
		OSMO_ASSERT(ul_win.is_in_window(63));
		OSMO_ASSERT(!ul_win.is_in_window(64));

		OSMO_ASSERT(!ul_win.m_v_n.is_received(0));

		rbb = "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII";
		OSMO_ASSERT(ul_win.ssn() == 0);
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		Encoding::encode_rbb(win_rbb, bin_rbb);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(bin_rbb, win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);

		/* simulate to have received 0, 1 and 5 */
		OSMO_ASSERT(ul_win.is_in_window(0));
		ul_win.receive_bsn(0);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(ul_win.m_v_n.is_received(0));
		OSMO_ASSERT(ul_win.v_q() == 1);
		OSMO_ASSERT(ul_win.v_r() == 1);
		OSMO_ASSERT(count == 1);

		rbb = "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIR";
		OSMO_ASSERT(ul_win.ssn() == 1);
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		Encoding::encode_rbb(win_rbb, bin_rbb);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(bin_rbb, win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);

		OSMO_ASSERT(ul_win.is_in_window(1));
		ul_win.receive_bsn(1);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(ul_win.m_v_n.is_received(0));
		OSMO_ASSERT(ul_win.v_q() == 2);
		OSMO_ASSERT(ul_win.v_r() == 2);
		OSMO_ASSERT(count == 1);

		rbb = "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIRR";
		OSMO_ASSERT(ul_win.ssn() == 2);
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		Encoding::encode_rbb(win_rbb, bin_rbb);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(bin_rbb, win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);

		OSMO_ASSERT(ul_win.is_in_window(5));
		ul_win.receive_bsn(5);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(ul_win.m_v_n.is_received(0));
		OSMO_ASSERT(ul_win.v_q() == 2);
		OSMO_ASSERT(ul_win.v_r() == 6);
		OSMO_ASSERT(count == 0);

		rbb = "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIRRIIIR";
		OSMO_ASSERT(ul_win.ssn() == 6);
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		Encoding::encode_rbb(win_rbb, bin_rbb);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(bin_rbb, win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);

		OSMO_ASSERT(ul_win.is_in_window(65));
		OSMO_ASSERT(ul_win.is_in_window(2));
		OSMO_ASSERT(ul_win.m_v_n.is_received(5));
		ul_win.receive_bsn(65);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(count == 0);
		OSMO_ASSERT(ul_win.m_v_n.is_received(5));
		OSMO_ASSERT(ul_win.v_q() == 2);
		OSMO_ASSERT(ul_win.v_r() == 66);

		rbb = "IIIRIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIR";
		OSMO_ASSERT(ul_win.ssn() == 66);
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		Encoding::encode_rbb(win_rbb, bin_rbb);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(bin_rbb, win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);

		OSMO_ASSERT(ul_win.is_in_window(2));
		OSMO_ASSERT(!ul_win.is_in_window(66));
		ul_win.receive_bsn(2);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(count == 1);
		OSMO_ASSERT(ul_win.v_q() == 3);
		OSMO_ASSERT(ul_win.v_r() == 66);

		OSMO_ASSERT(ul_win.is_in_window(66));
		ul_win.receive_bsn(66);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(count == 0);
		OSMO_ASSERT(ul_win.v_q() == 3);
		OSMO_ASSERT(ul_win.v_r() == 67);

		for (int i = 3; i <= 67; ++i) {
			ul_win.receive_bsn(i);
			ul_win.raise_v_q();
		}

		OSMO_ASSERT(ul_win.v_q() == 68);
		OSMO_ASSERT(ul_win.v_r() == 68);

		ul_win.receive_bsn(68);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(ul_win.v_q() == 69);
		OSMO_ASSERT(ul_win.v_r() == 69);
		OSMO_ASSERT(count == 1);

		/* now test the wrapping */
		OSMO_ASSERT(ul_win.is_in_window(4));
		OSMO_ASSERT(!ul_win.is_in_window(5));
		ul_win.receive_bsn(4);
		count = ul_win.raise_v_q();
		OSMO_ASSERT(count == 0);
	}

	{
		uint16_t lost = 0, recv = 0;
		char show_rbb[65];
		BTS dummy_bts;
		gprs_rlc_dl_window dl_win;

		dl_win.m_v_b.reset();

		OSMO_ASSERT(dl_win.window_empty());
		OSMO_ASSERT(!dl_win.window_stalled());
		OSMO_ASSERT(dl_win.distance() == 0);

		dl_win.increment_send();
		OSMO_ASSERT(!dl_win.window_empty());
		OSMO_ASSERT(!dl_win.window_stalled());
		OSMO_ASSERT(dl_win.distance() == 1);

		for (int i = 0; i < 35; ++i) {
			dl_win.increment_send();
			OSMO_ASSERT(!dl_win.window_empty());
			OSMO_ASSERT(dl_win.distance() == i + 2);
		}

		uint8_t rbb_cmp[8] = { 0x00, 0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0xff };
		Decoding::extract_rbb(rbb_cmp, show_rbb);
		printf("show_rbb: %s\n", show_rbb);

		dl_win.update(&dummy_bts, show_rbb, 35, &lost, &recv);
		OSMO_ASSERT(lost == 0);
		OSMO_ASSERT(recv == 35);

	}
}

int main(int argc, char **argv)
{
	osmo_init_logging(&gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	printf("Making some basic type testing.\n");
	test_llc();
	test_rlc();
	test_rlc_v_b();
	test_rlc_v_n();
	test_rlc_dl_ul_basic();
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
