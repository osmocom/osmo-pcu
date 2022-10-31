/*
 * TypesTest.cpp Test the primitive data types
 *
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2019 by Sysmocom s.f.m.c. GmbH
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
#include "tbf_ul.h"
#include "tbf_dl.h"
#include "pcu_utils.h"
#include "gprs_debug.h"
#include "encoding.h"
#include "decoding.h"
#include "gprs_rlcmac.h"
#include "egprs_rlc_compression.h"

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/fsm.h>
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
bool spoof_mnc_3_digits = false;

static void test_llc(void)
{
	{
		uint8_t data[LLC_MAX_LEN] = {1, 2, 3, 4, };
		uint8_t out;
		gprs_llc llc;
		llc_init(&llc);

		OSMO_ASSERT(llc_chunk_size(&llc) == 0);
		OSMO_ASSERT(llc_remaining_space(&llc) == LLC_MAX_LEN);
		OSMO_ASSERT(llc_frame_length(&llc) == 0);

		llc_put_frame(&llc, data, 2);
		OSMO_ASSERT(llc_remaining_space(&llc) == LLC_MAX_LEN - 2);
		OSMO_ASSERT(llc_frame_length(&llc) == 2);
		OSMO_ASSERT(llc_chunk_size(&llc) == 2);
		OSMO_ASSERT(llc.frame[0] == 1);
		OSMO_ASSERT(llc.frame[1] == 2);

		llc_append_frame(&llc, &data[3], 1);
		OSMO_ASSERT(llc_remaining_space(&llc) == LLC_MAX_LEN - 3);
		OSMO_ASSERT(llc_frame_length(&llc) == 3);
		OSMO_ASSERT(llc_chunk_size(&llc) == 3);

		/* consume two bytes */
		llc_consume_data(&llc, &out, 1);
		OSMO_ASSERT(llc_remaining_space(&llc) == LLC_MAX_LEN - 3);
		OSMO_ASSERT(llc_frame_length(&llc) == 3);
		OSMO_ASSERT(llc_chunk_size(&llc) == 2);

		/* check that the bytes are as we expected */
		OSMO_ASSERT(llc.frame[0] == 1);
		OSMO_ASSERT(llc.frame[1] == 2);
		OSMO_ASSERT(llc.frame[2] == 4);

		/* now fill the frame */
		llc_append_frame(&llc, data, llc_remaining_space(&llc) - 1);
		OSMO_ASSERT(llc_fits_in_current_frame(&llc, 1));
		OSMO_ASSERT(!llc_fits_in_current_frame(&llc, 2));
	}
}

static void test_rlc()
{
	{
		struct gprs_rlc_data rlc = { 0, };
		memset(rlc.block, 0x23, RLC_MAX_LEN);
		uint8_t *p = prepare(&rlc, 20);
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
		uint8_t bin_rbb[RLC_GPRS_WS/8];
		bitvec bits;
		win_rbb[64] = '\0';
		bits.data = bin_rbb;
		bits.data_len = sizeof(bin_rbb);
		bits.cur_bit = 0;

		ul_win.m_v_n.reset();

		OSMO_ASSERT(ul_win.is_in_window(0));
		OSMO_ASSERT(ul_win.is_in_window(63));
		OSMO_ASSERT(!ul_win.is_in_window(64));

		OSMO_ASSERT(!ul_win.m_v_n.is_received(0));

		rbb = "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII";
		OSMO_ASSERT(ul_win.ssn() == 0);
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		bits.cur_bit = 0;
		Encoding::encode_rbb(win_rbb, &bits);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(&bits, win_rbb);
		//printf("win_rbb: %s\n", win_rbb);
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
		bits.cur_bit = 0;
		Encoding::encode_rbb(win_rbb, &bits);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(&bits, win_rbb);
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
		bits.cur_bit = 0;
		Encoding::encode_rbb(win_rbb, &bits);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(&bits, win_rbb);
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
		bits.cur_bit = 0;
		Encoding::encode_rbb(win_rbb, &bits);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(&bits, win_rbb);
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
		bits.cur_bit = 0;
		Encoding::encode_rbb(win_rbb, &bits);
		printf("rbb: %s\n", osmo_hexdump(bin_rbb, sizeof(bin_rbb)));
		Decoding::extract_rbb(&bits, win_rbb);
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

		/*
		 * SSN wrap around case
		 * Should not expect any BSN as nacked.
		 */
		rbb = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
		for (int i = 0; i < 128; ++i) {
			ul_win.receive_bsn(i);
			ul_win.raise_v_q();
		}
		ul_win.receive_bsn(0);
		ul_win.raise_v_q();
		ul_win.receive_bsn(1);
		ul_win.raise_v_q();
		ul_win.update_rbb(win_rbb);
		OSMO_ASSERT_STR_EQ(win_rbb, rbb);
		OSMO_ASSERT(ul_win.ssn() == 2);
	}

	{
		uint16_t lost = 0, recv = 0;
		char show_rbb[65];
		uint8_t bits_data[8];
		struct gprs_rlcmac_bts *dummy_bts = bts_alloc(the_pcu, 0);
		gprs_rlc_dl_window dl_win;
		bitvec bits;
		int bsn_begin, bsn_end, num_blocks;
		Ack_Nack_Description_t desc;

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
		bits.data = bits_data;
		bits.data_len = sizeof(bits_data);
		bits.cur_bit = 0;

		memcpy(desc.RECEIVED_BLOCK_BITMAP, rbb_cmp,
			sizeof(desc.RECEIVED_BLOCK_BITMAP));
		desc.FINAL_ACK_INDICATION = 0;
		desc.STARTING_SEQUENCE_NUMBER = 35;

		num_blocks = Decoding::decode_gprs_acknack_bits(
			&desc, &bits,
			&bsn_begin, &bsn_end, &dl_win);
		Decoding::extract_rbb(&bits, show_rbb);
		printf("show_rbb: %s\n", show_rbb);

		dl_win.update(dummy_bts, &bits, 0, &lost, &recv);
		OSMO_ASSERT(lost == 0);
		OSMO_ASSERT(recv == 35);
		OSMO_ASSERT(bsn_begin == 0);
		OSMO_ASSERT(bsn_end == 35);
		OSMO_ASSERT(num_blocks == 35);

		dl_win.raise(dl_win.move_window());

		for (int i = 0; i < 8; ++i) {
			dl_win.increment_send();
			OSMO_ASSERT(!dl_win.window_empty());
			OSMO_ASSERT(dl_win.distance() == 2 + i);
		}

		uint8_t rbb_cmp2[8] = { 0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0xff, 0x31 };
		bits.data = bits_data;
		bits.data_len = sizeof(bits_data);
		bits.cur_bit = 0;

		memcpy(desc.RECEIVED_BLOCK_BITMAP, rbb_cmp2,
			sizeof(desc.RECEIVED_BLOCK_BITMAP));
		desc.FINAL_ACK_INDICATION = 0;
		desc.STARTING_SEQUENCE_NUMBER = 35 + 8;

		num_blocks = Decoding::decode_gprs_acknack_bits(
			&desc, &bits,
			&bsn_begin, &bsn_end, &dl_win);
		Decoding::extract_rbb(&bits, show_rbb);
		printf("show_rbb: %s\n", show_rbb);

		lost = recv = 0;
		dl_win.update(dummy_bts, &bits, 0, &lost, &recv);
		OSMO_ASSERT(lost == 5);
		OSMO_ASSERT(recv == 3);
		OSMO_ASSERT(bitvec_get_bit_pos(&bits, 0) == 0);
		OSMO_ASSERT(bitvec_get_bit_pos(&bits, 7) == 1);
		OSMO_ASSERT(bsn_begin == 35);
		OSMO_ASSERT(bsn_end == 43);
		OSMO_ASSERT(num_blocks == 8);
		talloc_free(dummy_bts);
	}
}

struct crbb_test {
	bool has_crbb;
	bitvec *crbb;
	uint8_t length;
	bool color_code;
};

static void extract_egprs_ul_ack_nack(
		struct gprs_rlcmac_ul_tbf *tbf,
		struct bitvec *dest,
		uint16_t *ssn,
		struct crbb_test *crbb_test,
		struct bitvec **urbb,
		bool is_final)
{
	uint8_t bytelength;

	/* Start of Ack/Nack Description struct */
	uint8_t startbit_ack_nack = 0;

	bool has_length = false;
	uint8_t length = 0;

	bool bow = false;
	uint8_t urbb_length = 0;
	dest->cur_bit = 0;

	/* ignore the first 8 bit */
	bitvec_get_uint(dest, 8);

	/* uplink ack/nack message content */
	OSMO_ASSERT(bitvec_get_uint(dest, 6) == 0b001001);

	/* ignore page mode*/
	bitvec_get_uint(dest, 2);

	/* fix 00 */
	OSMO_ASSERT(bitvec_get_uint(dest, 2) == 0);

	OSMO_ASSERT(bitvec_get_uint(dest, 5) == tbf->tfi());

	/* egprs ack/nack */
	OSMO_ASSERT(bitvec_get_uint(dest, 1) == 1);

	/* fix 00 */
	OSMO_ASSERT(bitvec_get_uint(dest, 2) == 0);

	/* ignore Channel Coding Command */
	bitvec_get_uint(dest, 4);

	/* we always allow resegmentation */
	OSMO_ASSERT(bitvec_get_uint(dest, 1) == 1);

	/* ignore pre emptive transmission */
	bitvec_get_uint(dest, 1);

	/* ignore PRR retransmission request */
	bitvec_get_uint(dest, 1);

	/* ignore ARAC retransmission request */
	bitvec_get_uint(dest, 1);

	if (bitvec_get_uint(dest, 1)) {
		OSMO_ASSERT((uint32_t) bitvec_get_uint(dest, 32) == tbf->tlli());
	}

	/* ignore TBF_EST */
	bitvec_get_uint(dest, 1);

	/* Timing Advance */
	if (bitvec_get_uint(dest, 1)) {
		/* Timing Advance Value */
		if (bitvec_get_uint(dest, 1))
			bitvec_get_uint(dest, 6);

		/* Timing Advance Index*/
		if (bitvec_get_uint(dest, 1))
			bitvec_get_uint(dest, 6);
		/* Timing Advance Timeslot Number */
		bitvec_get_uint(dest, 3);
	}

	/* Packet Extended Timing Advance */
	if (bitvec_get_uint(dest, 1))
		bitvec_get_uint(dest, 2);

	/* Power Control Parameters */
	if (bitvec_get_uint(dest, 1)) {
		/* Alpha */
		bitvec_get_uint(dest, 4);
		for (int i=0; i<8 ; i++) {
			/* Gamma */
			if (bitvec_get_uint(dest, 1))
				bitvec_get_uint(dest, 5);
		}
	}

	/* Extension Bits */
	if (bitvec_get_uint(dest, 1)) {
		int length = bitvec_get_uint(dest, 6);
		bitvec_get_uint(dest, length);
	}

	/* Beging of the EGPRS Ack/Nack */
	has_length = bitvec_get_uint(dest, 1);
	if (has_length) {
		length = bitvec_get_uint(dest, 8);
	} else {
		/* remaining bits is the length */
		length = dest->data_len * 8 - dest->cur_bit;
	}
	startbit_ack_nack = dest->cur_bit;

	OSMO_ASSERT(bitvec_get_uint(dest, 1) == is_final);

	/* bow Begin Of Window */
	bow = bitvec_get_uint(dest, 1);
	/* TODO: check if bow is always present in our implementation */

	/* eow End Of Window */
	/* TODO: eow checking */
	bitvec_get_uint(dest, 1);

	*ssn = bitvec_get_uint(dest, 11);
	if (bow) {
		OSMO_ASSERT(*ssn == static_cast<gprs_rlc_ul_window *>(tbf->window())->v_q() + 1);
	}

	crbb_test->has_crbb = bitvec_get_uint(dest, 1);
	if (crbb_test->has_crbb) {
		crbb_test->length = bitvec_get_uint(dest, 7);
		crbb_test->color_code = bitvec_get_uint(dest, 1);
		if (crbb_test->length % 8)
			bytelength = crbb_test->length * 8 + 1;
		else
			bytelength = crbb_test->length * 8;

		crbb_test->crbb = bitvec_alloc(bytelength, tall_pcu_ctx);
		for (int i=0; i<crbb_test->length; i++)
			bitvec_set_bit(crbb_test->crbb, bitvec_get_bit_pos(dest, dest->cur_bit + i));

		dest->cur_bit += crbb_test->length;
	}

	OSMO_ASSERT(dest->cur_bit < dest->data_len * 8);
	urbb_length = length - (dest->cur_bit - startbit_ack_nack);

	if (urbb_length > 0) {
		if (urbb_length % 8)
			bytelength = urbb_length / 8 + 1;
		else
			bytelength = urbb_length / 8;

		*urbb = bitvec_alloc(bytelength, tall_pcu_ctx);
		for (int i=urbb_length; i>0; i--) {
			bitvec_set_bit(*urbb, bitvec_get_bit_pos(dest, dest->cur_bit + i - 1));
		}
	}
}

static void check_egprs_bitmap(struct gprs_rlcmac_ul_tbf *tbf, uint16_t ssn, struct crbb_test *crbb_test, bitvec *urbb, unsigned int *rbb_size)
{
	gprs_rlc_ul_window *win = static_cast<gprs_rlc_ul_window *>(tbf->window());
	uint8_t rbb_should[RLC_EGPRS_MAX_WS] = {0};
	bitvec rbb_should_bv;
	rbb_should_bv.data = rbb_should;
	rbb_should_bv.data_len = RLC_EGPRS_MAX_WS;
	rbb_should_bv.cur_bit = 0;

	/* rbb starting at ssn without mod */
	bitvec *rbb_ssn_bv = bitvec_alloc(RLC_EGPRS_MAX_WS, tall_pcu_ctx);

	/* even any ssn is allowed, pcu should only use v_q() at least for now */
	OSMO_ASSERT(ssn == (win->v_q() + 1));

	if (crbb_test->has_crbb) {
		OSMO_ASSERT(0 == egprs_compress::decompress_crbb(
				    crbb_test->length,
				    crbb_test->color_code,
				    crbb_test->crbb->data,
				    rbb_ssn_bv));
	}

	if (urbb && urbb->cur_bit > 0) {
		for (unsigned int i=0; i<urbb->cur_bit; i++) {
			bitvec_set_bit(rbb_ssn_bv, bitvec_get_bit_pos(urbb, i));
		}
	}

	/* check our rbb is equal the decompressed */
	rbb_should_bv.cur_bit = win->update_egprs_rbb(rbb_should);

	bool failed = false;
	for (unsigned int i=0; i < rbb_ssn_bv->cur_bit; i++) {
		if (bitvec_get_bit_pos(&rbb_should_bv, i) !=
			    bitvec_get_bit_pos(rbb_ssn_bv, i))
			failed = true;
	}
	if (failed) {
		fprintf(stderr, "SSN %d\n", ssn);
		for (int i=win->v_q(); i<win->ws(); i++) {
			fprintf(stderr, "bsn %d is %s\n", i, win->is_received( i) ? "received" : "MISS");
		}
		char to_dump[256] = { 0 };
		bitvec_to_string_r(&rbb_should_bv, to_dump);
		fprintf(stderr, "should: %s\n", to_dump);
		memset(to_dump, 0x0, 256);
		bitvec_to_string_r(rbb_ssn_bv, to_dump);
		fprintf(stderr, "is    : %s\n", to_dump);
		OSMO_ASSERT(false);
	}

	if (rbb_size)
		*rbb_size = rbb_ssn_bv->cur_bit;
}

static void free_egprs_ul_ack_nack(bitvec **rbb, struct crbb_test *crbb_test)
{
	if (*rbb) {
		bitvec_free(*rbb);
		*rbb = NULL;
	}

	if (crbb_test->crbb) {
		bitvec_free(crbb_test->crbb);
		crbb_test->crbb = NULL;
	}
}

static void test_egprs_ul_ack_nack()
{
	bitvec *dest = bitvec_alloc(23, tall_pcu_ctx);

	fprintf(stderr, "############## test_egprs_ul_ack_nack\n");

	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	the_pcu->alloc_algorithm = alloc_algorithm_a;
	bts->trx[0].pdch[4].enable();

	GprsMs *ms = bts_alloc_ms(bts, 1, 1);
	struct gprs_rlcmac_ul_tbf *tbf = ul_tbf_alloc(bts, ms, 0, true);
	struct crbb_test crbb_test = {0};
	bitvec *rbb = NULL;
	unsigned int rbb_size;
	uint16_t ssn = 0;
	gprs_rlc_ul_window *win = static_cast<gprs_rlc_ul_window *>(tbf->window());

	fprintf(stderr, "************** Test with empty window\n");
	win->reset_state();
	win->set_ws(256);

	write_packet_uplink_ack(dest, tbf, false, 0);
	extract_egprs_ul_ack_nack(tbf, dest, &ssn, &crbb_test, &rbb, false);
	check_egprs_bitmap(tbf, ssn, &crbb_test, rbb, &rbb_size);
	free_egprs_ul_ack_nack(&rbb, &crbb_test);
	OSMO_ASSERT(rbb_size == 0);

	fprintf(stderr, "************** Test with 1 lost packet\n");
	win->reset_state();
	win->set_ws(256);
	win->receive_bsn(1);

	write_packet_uplink_ack(dest, tbf, false, 0);
	extract_egprs_ul_ack_nack(tbf, dest, &ssn, &crbb_test, &rbb, false);
	check_egprs_bitmap(tbf, ssn, &crbb_test, rbb, &rbb_size);
	free_egprs_ul_ack_nack(&rbb, &crbb_test);
	OSMO_ASSERT(rbb_size == 1);

	fprintf(stderr, "************** Test with compressed window\n");
	win->reset_state();
	win->set_ws(128);
	win->receive_bsn(127);

	write_packet_uplink_ack(dest, tbf, false, 0);
	extract_egprs_ul_ack_nack(tbf, dest, &ssn, &crbb_test, &rbb, false);
	check_egprs_bitmap(tbf, ssn, &crbb_test, rbb, &rbb_size);
	free_egprs_ul_ack_nack(&rbb, &crbb_test);

	fprintf(stderr, "************** Provoke an uncompressed ACK without EOW\n");
	win->reset_state();
	win->set_ws(384);
	for (uint16_t i=1; i<384/2; i++)
		win->receive_bsn(i*2);

	write_packet_uplink_ack(dest, tbf, false, 0);
	extract_egprs_ul_ack_nack(tbf, dest, &ssn, &crbb_test, &rbb, false);
	check_egprs_bitmap(tbf, ssn, &crbb_test, rbb, &rbb_size);
	free_egprs_ul_ack_nack(&rbb, &crbb_test);
	talloc_free(bts);
}

static void check_imm_ass(struct gprs_rlcmac_tbf *tbf, bool dl, enum ph_burst_type bt, const uint8_t *exp, uint8_t len,
			  const char *kind)
{
	uint8_t alpha = 7, gamma = 8, ta = 35, usf = 1, sz = sizeof(DUMMY_VEC) / 2, plen;
	bitvec *immediate_assignment = bitvec_alloc(sz, tall_pcu_ctx);
	struct msgb *m = msgb_alloc(80, "test");
	bool poll = true;
	uint16_t ra = 13;
	uint32_t ref_fn = 24, fn = 11;
	int8_t ta_idx = 0;

	/* HACK: tbf can be NULL, so we cannot use tbf->trx here */
	struct gprs_rlcmac_trx trx = { };
	trx.pdch[5].trx = &trx;
	trx.pdch[5].ts_no = 5;
	trx.pdch[5].tsc = 1;
	trx.arfcn = 877;

	bitvec_unhex(immediate_assignment, DUMMY_VEC);
	plen = Encoding::write_immediate_assignment(&trx.pdch[5], tbf,
						    immediate_assignment,
						    dl, ra, ref_fn, ta, usf,
						    poll, fn, alpha, gamma, ta_idx, bt);
	printf("[%u] %s Immediate Assignment <%s>:\n\t%s\n", plen, dl ? "DL" : "UL", kind,
	       osmo_hexdump(immediate_assignment->data, sz));

	memcpy(msgb_put(m, sz), immediate_assignment->data, sz);
	if (!msgb_eq_data_print(m, exp, len))
		printf("%s(%s, %s) failed!\n", __func__, dl ? "DL" : "UL", kind);

	msgb_free(m);
}

void test_immediate_assign_dl()
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	the_pcu->alloc_algorithm = alloc_algorithm_a;
	bts->trx[0].pdch[2].enable();
	bts->trx[0].pdch[3].enable();
	GprsMs *ms = bts_alloc_ms(bts, 1, 0);

	struct gprs_rlcmac_tbf *tbf = dl_tbf_alloc(bts, ms, 0, false);
	static uint8_t res[] = { 0x06,
				 0x3f, /* Immediate Assignment Message Type (GSM48_MT_RR_IMM_ASS) */
				 0x30, /* §10.5.2.26 Page Mode and §10.5.2.25b Dedicated mode/TBF */
				 0x0d, 0x23, 0x6d, /* §10.5.2.25a Packet Channel Description */
				 /* ETSI TS 44.018 §10.5.2.30 Request Reference */
				 0x7f, /* RA */
				 0x03, 0x18, /* T1'-T3 */
				 0x23, /* TA */
				 0x00, /* 0-length §10.5.2.21 Mobile Allocation */
				 /* ETSI TS 44.018 §10.5.2.16 IA Rest Octets */
				 0xdf, 0xff, 0xff, 0xff, 0xf8, 0x17, 0x47, 0x08, 0x0b, 0x5b, 0x2b, 0x2b, };

	check_imm_ass(tbf, true, GSM_L1_BURST_TYPE_ACCESS_2, res, sizeof(res), "ia_rest_downlink");
	talloc_free(bts);
}

void test_immediate_assign_ul0m()
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	the_pcu->alloc_algorithm = alloc_algorithm_a;
	bts->trx[0].pdch[4].enable();
	bts->trx[0].pdch[5].enable();

	GprsMs *ms = bts_alloc_ms(bts, 1, 0);
	struct gprs_rlcmac_tbf *tbf = ul_tbf_alloc(bts, ms, 0, false);
	static uint8_t res[] = { 0x06,
				 0x3f, /* Immediate Assignment Message Type (GSM48_MT_RR_IMM_ASS) */
				 0x10, /* §10.5.2.26 Page Mode and §10.5.2.25b Dedicated mode/TBF */
				 0x0d, 0x23, 0x6d, /* §10.5.2.25a Packet Channel Description */
				 /* ETSI TS 44.018 §10.5.2.30 Request Reference */
				 0x0d, /* RA */
				 0x03, 0x18, /* T1'-T3 */
				 0x23, /* TA */
				 0x00, /* 0-length §10.5.2.21 Mobile Allocation */
				 /* ETSI TS 44.018 §10.5.2.16 IA Rest Octets */
				 0xc8, 0x02, 0x1b, 0xa2, 0x0b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, };

	check_imm_ass(tbf, false, GSM_L1_BURST_TYPE_ACCESS_0, res, sizeof(res), "ia_rest_uplink(MBA)");
	talloc_free(bts);
}

void test_immediate_assign_ul0s()
{
	static uint8_t res[] = { 0x06,
				 0x3f, /* Immediate Assignment Message Type (GSM48_MT_RR_IMM_ASS) */
				 0x10, /* §10.5.2.26 Page Mode and §10.5.2.25b Dedicated mode/TBF */
				 0x0d, 0x23, 0x6d, /* §10.5.2.25a Packet Channel Description */
				 /* ETSI TS 44.018 §10.5.2.30 Request Reference */
				 0x0d, /* RA */
				 0x03, 0x18, /* T1'-T3 */
				 0x23, /* TA */
				 0x00, /* 0-length §10.5.2.21 Mobile Allocation */
				 /* ETSI TS 44.018 §10.5.2.16 IA Rest Octets */
				 0xc5, 0xd0, 0x80, 0xb5, 0xab, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, };

	check_imm_ass(NULL, false, GSM_L1_BURST_TYPE_ACCESS_0, res, sizeof(res), "ia_rest_uplink(SBA)");
}

void test_immediate_assign_ul1s()
{
	struct gprs_rlcmac_bts *bts = bts_alloc(the_pcu, 0);
	the_pcu->alloc_algorithm = alloc_algorithm_a;
	bts->trx[0].pdch[1].enable();
	bts->trx[0].pdch[2].enable();

	GprsMs *ms = bts_alloc_ms(bts, 1, 1);
	struct gprs_rlcmac_tbf *tbf = ul_tbf_alloc(bts, ms, 0, false);
	static uint8_t res[] = { 0x06,
				 0x3f, /* Immediate Assignment Message Type (GSM48_MT_RR_IMM_ASS) */
				 0x10, /* §10.5.2.26 Page Mode and §10.5.2.25b Dedicated mode/TBF */
				 0x0d, 0x23, 0x6d, /* §10.5.2.25a Packet Channel Description */
				 /* ETSI TS 44.018 §10.5.2.30 Request Reference */
				 0x7f, /* RA */
				 0x03, 0x18, /* T1'-T3 */
				 0x23, /* TA */
				 0x00, /* 0-length §10.5.2.21 Mobile Allocation */
				 /* ETSI TS 44.018 §10.5.2.16 IA Rest Octets */
				 0x46, 0xa0, 0x08, 0x00, 0x17, 0x44, 0x0b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, };

	check_imm_ass(tbf, false, GSM_L1_BURST_TYPE_ACCESS_1, res, sizeof(res), "ia_rest_egprs_uplink(SBA)");
	talloc_free(bts);
}

void test_immediate_assign_ul1m()
{
	static uint8_t res[] = { 0x06,
				 0x3f, /* Immediate Assignment Message Type (GSM48_MT_RR_IMM_ASS) */
				 0x10, /* §10.5.2.26 Page Mode and §10.5.2.25b Dedicated mode/TBF */
				 0x0d, 0x23, 0x6d, /* §10.5.2.25a Packet Channel Description */
				 /* ETSI TS 44.018 §10.5.2.30 Request Reference */
				 0x7f, /* RA */
				 0x03, 0x18, /* T1'-T3 */
				 0x23, /* TA */
				 0x00, /* 0-length §10.5.2.21 Mobile Allocation */
				 /* ETSI TS 44.018 §10.5.2.16 IA Rest Octets */
				 0x46, 0x97, 0x40, 0x0b, 0x58, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, };

	check_imm_ass(NULL, false, GSM_L1_BURST_TYPE_ACCESS_1, res, sizeof(res), "ia_rest_egprs_uplink(MBA)");
}

void test_immediate_assign_rej()
{
	uint8_t plen;
	bitvec *immediate_assignment_rej = bitvec_alloc(22, tall_pcu_ctx);

	bitvec_unhex(immediate_assignment_rej, DUMMY_VEC);
	plen = Encoding::write_immediate_assignment_reject(
		immediate_assignment_rej, 112, 100,
		GSM_L1_BURST_TYPE_ACCESS_1, 20);

	printf("assignment reject: %s\n",
		osmo_hexdump(immediate_assignment_rej->data, 22));

	OSMO_ASSERT(plen == 19);
	/* RA value */
	OSMO_ASSERT(immediate_assignment_rej->data[3] == 0x7f);
	/* Extended RA value */
	OSMO_ASSERT(immediate_assignment_rej->data[19] == 0xc0);

	bitvec_unhex(immediate_assignment_rej, DUMMY_VEC);

	plen = Encoding::write_immediate_assignment_reject(
		immediate_assignment_rej, 112, 100,
		GSM_L1_BURST_TYPE_ACCESS_0, 20);

	printf("assignment reject: %s\n",
		osmo_hexdump(immediate_assignment_rej->data, 22));

	OSMO_ASSERT(plen == 19);
	/* RA value */
	OSMO_ASSERT(immediate_assignment_rej->data[3] == 0x70);

}

static void test_lsb()
{
	uint8_t u = 0;

	printf("Testing LBS utility...\n");

	do {
		uint8_t x = pcu_lsb(u); /* equivalent of (1 << ffs(u)) / 2 */
		printf("%2X " OSMO_BIT_SPEC ": {%d} %3d\n",
		       u, OSMO_BIT_PRINT(u), pcu_bitcount(u), x);
		u++;
	} while (u);
}

int main(int argc, char **argv)
{
	tall_pcu_ctx = talloc_named_const(NULL, 1, "types test context");
	if (!tall_pcu_ctx)
		abort();

	msgb_talloc_ctx_init(tall_pcu_ctx, 0);
	osmo_init_logging2(tall_pcu_ctx, &gprs_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);

	log_set_category_filter(osmo_stderr_target, DTBF, 1, LOGL_INFO);
	log_set_category_filter(osmo_stderr_target, DTBFUL, 1, LOGL_INFO);
	osmo_fsm_log_addr(false);

	the_pcu = gprs_pcu_alloc(tall_pcu_ctx);

	printf("Making some basic type testing.\n");

	test_llc();
	test_rlc();
	test_rlc_v_b();
	test_rlc_v_n();
	test_rlc_dl_ul_basic();
	test_immediate_assign_dl();
	test_immediate_assign_ul0m();
	test_immediate_assign_ul0s();
	test_immediate_assign_ul1m();
	test_immediate_assign_ul1s();
	test_immediate_assign_rej();
	test_lsb();
	test_egprs_ul_ack_nack();

	talloc_free(the_pcu);

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
