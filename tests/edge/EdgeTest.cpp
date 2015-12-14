/*
 * EdgeTest.cpp
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

#include "gprs_debug.h"
#include "gprs_coding_scheme.h"
#include "decoding.h"
#include "rlc.h"

extern "C" {
#include "pcu_vty.h"

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/vty.h>
}

#include <errno.h>

void *tall_pcu_ctx;
int16_t spoof_mnc = 0, spoof_mcc = 0;

static void check_coding_scheme(GprsCodingScheme& cs, GprsCodingScheme::Mode mode)
{
	volatile unsigned expected_size;
	GprsCodingScheme new_cs;

	OSMO_ASSERT(cs.isValid());
	OSMO_ASSERT(cs.isCompatible(mode));

	/* Check static getBySizeUL() */
	expected_size = cs.maxBytesUL();
	if (cs.spareBitsUL() > 0)
		expected_size += 1;
	OSMO_ASSERT(expected_size == cs.sizeUL());
	OSMO_ASSERT(cs == GprsCodingScheme::getBySizeUL(expected_size));

	/* Check static sizeUL() */
	expected_size = cs.maxBytesDL();
	if (cs.spareBitsDL() > 0)
		expected_size += 1;
	OSMO_ASSERT(expected_size == cs.sizeDL());

	/* Check data block sizes */
	OSMO_ASSERT(cs.maxDataBlockBytes() * cs.numDataBlocks() < cs.maxBytesDL());
	OSMO_ASSERT(cs.maxDataBlockBytes() * cs.numDataBlocks() < cs.maxBytesUL());

	/* Check inc/dec */
	new_cs = cs;
	new_cs.inc(mode);
	OSMO_ASSERT(new_cs.isCompatible(mode));
	if (new_cs != cs) {
		new_cs.dec(mode);
		OSMO_ASSERT(new_cs.isCompatible(mode));
		OSMO_ASSERT(new_cs == cs);
	}
	new_cs.dec(mode);
	OSMO_ASSERT(new_cs.isCompatible(mode));
	if (new_cs != cs) {
		new_cs.inc(mode);
		OSMO_ASSERT(new_cs.isCompatible(mode));
		OSMO_ASSERT(new_cs == cs);
	}
}

static void test_coding_scheme()
{
	unsigned i;
	unsigned last_size_UL;
	unsigned last_size_DL;
	GprsCodingScheme::Scheme gprs_schemes[] = {
		GprsCodingScheme::CS1,
		GprsCodingScheme::CS2,
		GprsCodingScheme::CS3,
		GprsCodingScheme::CS4
	};
	struct {
		GprsCodingScheme::Scheme s;
		bool is_gmsk;
	} egprs_schemes[] = {
		{GprsCodingScheme::MCS1, true},
		{GprsCodingScheme::MCS2, true},
		{GprsCodingScheme::MCS3, true},
		{GprsCodingScheme::MCS4, true},
		{GprsCodingScheme::MCS5, false},
		{GprsCodingScheme::MCS6, false},
		{GprsCodingScheme::MCS7, false},
		{GprsCodingScheme::MCS8, false},
		{GprsCodingScheme::MCS9, false},
	};

	printf("=== start %s ===\n", __func__);

	GprsCodingScheme cs;
	OSMO_ASSERT(!cs);
	OSMO_ASSERT(cs == GprsCodingScheme::UNKNOWN);
	OSMO_ASSERT(!cs.isCompatible(GprsCodingScheme::GPRS));
	OSMO_ASSERT(!cs.isCompatible(GprsCodingScheme::EGPRS_GMSK));
	OSMO_ASSERT(!cs.isCompatible(GprsCodingScheme::EGPRS));

	last_size_UL = 0;
	last_size_DL = 0;

	for (i = 0; i < ARRAY_SIZE(gprs_schemes); i++) {
		GprsCodingScheme current_cs(gprs_schemes[i]);
		OSMO_ASSERT(current_cs.isGprs());
		OSMO_ASSERT(!current_cs.isEgprs());
		OSMO_ASSERT(!current_cs.isEgprsGmsk());
		OSMO_ASSERT(current_cs == gprs_schemes[i]);
		OSMO_ASSERT(current_cs == GprsCodingScheme(gprs_schemes[i]));

		/* Check strong monotonicity */
		OSMO_ASSERT(current_cs.maxBytesUL() > last_size_UL);
		OSMO_ASSERT(current_cs.maxBytesDL() > last_size_DL);
		last_size_UL = current_cs.maxBytesUL();
		last_size_DL = current_cs.maxBytesDL();

		/* Check header types */
		OSMO_ASSERT(current_cs.headerTypeData() ==
			GprsCodingScheme::HEADER_GPRS_DATA);
		OSMO_ASSERT(current_cs.headerTypeControl() ==
			GprsCodingScheme::HEADER_GPRS_CONTROL);

		check_coding_scheme(current_cs, GprsCodingScheme::GPRS);
	}
	OSMO_ASSERT(i == 4);

	last_size_UL = 0;
	last_size_DL = 0;

	for (i = 0; i < ARRAY_SIZE(egprs_schemes); i++) {
		GprsCodingScheme current_cs(egprs_schemes[i].s);
		OSMO_ASSERT(!current_cs.isGprs());
		OSMO_ASSERT(current_cs.isEgprs());
		OSMO_ASSERT(!!current_cs.isEgprsGmsk() == !!egprs_schemes[i].is_gmsk);
		OSMO_ASSERT(current_cs == egprs_schemes[i].s);
		OSMO_ASSERT(current_cs == GprsCodingScheme(egprs_schemes[i].s));

		/* Check strong monotonicity */
		OSMO_ASSERT(current_cs.maxBytesUL() > last_size_UL);
		OSMO_ASSERT(current_cs.maxBytesDL() > last_size_DL);
		last_size_UL = current_cs.maxBytesUL();
		last_size_DL = current_cs.maxBytesDL();

		if (egprs_schemes[i].is_gmsk)
			check_coding_scheme(current_cs, GprsCodingScheme::EGPRS_GMSK);
		check_coding_scheme(current_cs, GprsCodingScheme::EGPRS);
	}
	OSMO_ASSERT(i == 9);

	printf("=== end %s ===\n", __func__);
}

static void test_rlc_decoder()
{
	struct gprs_rlc_ul_data_block_info rdbi = {0};
	GprsCodingScheme cs;
	uint8_t data[74];
	Decoding::RlcData chunks[16];
	volatile int num_chunks = 0;
	uint32_t tlli, tlli2;
	unsigned int offs;


	printf("=== start %s ===\n", __func__);

	/* TS 44.060, B.1 */
	cs = GprsCodingScheme::CS4;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = (11 << 2) | (1 << 1) | (0 << 0);
	data[offs++] = (26 << 2) | (1 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 3);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 2);
	OSMO_ASSERT(chunks[0].length == 11);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 13);
	OSMO_ASSERT(chunks[1].length == 26);
	OSMO_ASSERT(chunks[1].is_complete);
	OSMO_ASSERT(chunks[2].offset == 39);
	OSMO_ASSERT(chunks[2].length == cs.maxDataBlockBytes() - 39);
	OSMO_ASSERT(!chunks[2].is_complete);

	/* TS 44.060, B.2 */
	cs = GprsCodingScheme::CS1;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = (0 << 2) | (0 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 1);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 1);
	OSMO_ASSERT(chunks[0].length == 19);
	OSMO_ASSERT(!chunks[0].is_complete);

	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = (1 << 2) | (1 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 2);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 1);
	OSMO_ASSERT(chunks[0].length == 1);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 2);
	OSMO_ASSERT(chunks[1].length == 18);
	OSMO_ASSERT(!chunks[1].is_complete);

	/* TS 44.060, B.3 */
	cs = GprsCodingScheme::CS1;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = (7 << 2) | (1 << 1) | (0 << 0);
	data[offs++] = (11 << 2) | (0 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 2);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 2);
	OSMO_ASSERT(chunks[0].length == 7);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 9);
	OSMO_ASSERT(chunks[1].length == 11);
	OSMO_ASSERT(chunks[1].is_complete);

	/* TS 44.060, B.4 */
	cs = GprsCodingScheme::CS1;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 1;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 1);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 0);
	OSMO_ASSERT(chunks[0].length == 20);
	OSMO_ASSERT(!chunks[0].is_complete);

	/* TS 44.060, B.6 */
	cs = GprsCodingScheme::CS1;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 1;
	rdbi.ti = 0;
	rdbi.cv = 0;
	tlli = 0;
	offs = 0;
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 1);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 0);
	OSMO_ASSERT(chunks[0].length == 20);
	OSMO_ASSERT(chunks[0].is_complete);

	/* TS 44.060, B.8.1 */
	cs = GprsCodingScheme::MCS4;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = (11 << 1) | (0 << 0);
	data[offs++] = (26 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 3);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 2);
	OSMO_ASSERT(chunks[0].length == 11);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 13);
	OSMO_ASSERT(chunks[1].length == 26);
	OSMO_ASSERT(chunks[1].is_complete);
	OSMO_ASSERT(chunks[2].offset == 39);
	OSMO_ASSERT(chunks[2].length == 5);
	OSMO_ASSERT(!chunks[2].is_complete);

	/* TS 44.060, B.8.2 */

	/* Note that the spec confuses the byte numbering here, since it
	 * includes the FBI/E header bits into the N2 octet count which
	 * is not consistent with Section 10.3a.1 & 10.3a.2. */

	cs = GprsCodingScheme::MCS2;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = (15 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 2);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 1);
	OSMO_ASSERT(chunks[0].length == 15);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 16);
	OSMO_ASSERT(chunks[1].length == 12);
	OSMO_ASSERT(!chunks[1].is_complete);

	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 15;
	tlli = 0;
	offs = 0;
	data[offs++] = ( 0 << 1) | (0 << 0);
	data[offs++] = ( 7 << 1) | (0 << 0);
	data[offs++] = (18 << 1) | (1 << 0); /* Differs from spec's N2-11 = 17 */
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 3);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 3);
	OSMO_ASSERT(chunks[0].length == 0);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 3);
	OSMO_ASSERT(chunks[1].length == 7);
	OSMO_ASSERT(chunks[1].is_complete);
	OSMO_ASSERT(chunks[2].offset == 10);
	OSMO_ASSERT(chunks[2].length == 18);
	OSMO_ASSERT(chunks[2].is_complete);

	rdbi.e = 0;
	rdbi.ti = 0;
	rdbi.cv = 0;
	tlli = 0;
	offs = 0;
	data[offs++] = ( 6 << 1) | (0 << 0);
	data[offs++] = (12 << 1) | (0 << 0);
	data[offs++] = (127 << 1) | (1 << 0);
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 2);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 3);
	OSMO_ASSERT(chunks[0].length == 6);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 9);
	OSMO_ASSERT(chunks[1].length == 12);
	OSMO_ASSERT(chunks[1].is_complete);

	/* TS 44.060, B.8.3 */

	/* Note that the spec confuses the byte numbering here, too (see above) */

	cs = GprsCodingScheme::MCS2;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 1;
	rdbi.ti = 0;
	rdbi.cv = 0;
	tlli = 0;
	offs = 0;
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 1);
	OSMO_ASSERT(tlli == 0);
	OSMO_ASSERT(chunks[0].offset == 0);
	OSMO_ASSERT(chunks[0].length == 28);
	OSMO_ASSERT(chunks[0].is_complete);

	/* CS-1, TLLI, last block, single chunk until the end of the block */
	cs = GprsCodingScheme::CS1;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 1;
	rdbi.ti = 1;
	rdbi.cv = 0;
	tlli = 0;
	tlli2 = 0xffeeddcc;
	offs = 0;
	data[offs++] = tlli2 >> 24;
	data[offs++] = tlli2 >> 16;
	data[offs++] = tlli2 >>  8;
	data[offs++] = tlli2 >>  0;
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 1);
	OSMO_ASSERT(tlli == tlli2);
	OSMO_ASSERT(chunks[0].offset == 4);
	OSMO_ASSERT(chunks[0].length == 16);
	OSMO_ASSERT(chunks[0].is_complete);

	/* Like TS 44.060, B.2, first RLC block but with TLLI */
	cs = GprsCodingScheme::CS1;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 1;
	rdbi.cv = 15;
	tlli = 0;
	tlli2 = 0xffeeddbb;
	offs = 0;
	data[offs++] = (0 << 2) | (0 << 1) | (1 << 0);
	data[offs++] = tlli2 >> 24;
	data[offs++] = tlli2 >> 16;
	data[offs++] = tlli2 >>  8;
	data[offs++] = tlli2 >>  0;
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 1);
	OSMO_ASSERT(tlli == tlli2);
	OSMO_ASSERT(chunks[0].offset == 5);
	OSMO_ASSERT(chunks[0].length == 15);
	OSMO_ASSERT(!chunks[0].is_complete);

	/* Like TS 44.060, B.8.1 but with TLLI */
	cs = GprsCodingScheme::MCS4;
	rdbi.data_len = cs.maxDataBlockBytes();
	rdbi.e = 0;
	rdbi.ti = 1;
	rdbi.cv = 15;
	tlli = 0;
	tlli2 = 0xffeeddaa;
	offs = 0;
	data[offs++] = (11 << 1) | (0 << 0);
	data[offs++] = (26 << 1) | (1 << 0);
	/* Little endian */
	data[offs++] = tlli2 >>  0;
	data[offs++] = tlli2 >>  8;
	data[offs++] = tlli2 >> 16;
	data[offs++] = tlli2 >> 24;
	num_chunks = Decoding::rlc_data_from_ul_data(&rdbi, cs, data,
		chunks, ARRAY_SIZE(chunks), &tlli);
	OSMO_ASSERT(num_chunks == 3);
	OSMO_ASSERT(tlli == tlli2);
	OSMO_ASSERT(chunks[0].offset == 6);
	OSMO_ASSERT(chunks[0].length == 11);
	OSMO_ASSERT(chunks[0].is_complete);
	OSMO_ASSERT(chunks[1].offset == 17);
	OSMO_ASSERT(chunks[1].length == 26);
	OSMO_ASSERT(chunks[1].is_complete);
	OSMO_ASSERT(chunks[2].offset == 43);
	OSMO_ASSERT(chunks[2].length == 1);
	OSMO_ASSERT(!chunks[2].is_complete);

	printf("=== end %s ===\n", __func__);
}


static const struct log_info_cat default_categories[] = {
	{"DCSN1", "\033[1;31m", "Concrete Syntax Notation One (CSN1)", LOGL_INFO, 0},
	{"DL1IF", "\033[1;32m", "GPRS PCU L1 interface (L1IF)", LOGL_DEBUG, 1},
	{"DRLCMAC", "\033[0;33m", "GPRS RLC/MAC layer (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACDATA", "\033[0;33m", "GPRS RLC/MAC layer Data (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACDL", "\033[1;33m", "GPRS RLC/MAC layer Downlink (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACUL", "\033[1;36m", "GPRS RLC/MAC layer Uplink (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACSCHED", "\033[0;36m", "GPRS RLC/MAC layer Scheduling (RLCMAC)", LOGL_DEBUG, 1},
	{"DRLCMACMEAS", "\033[1;31m", "GPRS RLC/MAC layer Measurements (RLCMAC)", LOGL_INFO, 1},
	{"DNS","\033[1;34m", "GPRS Network Service Protocol (NS)", LOGL_INFO , 1},
	{"DBSSGP","\033[1;34m", "GPRS BSS Gateway Protocol (BSSGP)", LOGL_INFO , 1},
	{"DPCU", "\033[1;35m", "GPRS Packet Control Unit (PCU)", LOGL_NOTICE, 1},
};

static int filter_fn(const struct log_context *ctx,
	struct log_target *tar)
{
	return 1;
}

const struct log_info debug_log_info = {
	filter_fn,
	(struct log_info_cat*)default_categories,
	ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	struct vty_app_info pcu_vty_info = {0};

	tall_pcu_ctx = talloc_named_const(NULL, 1, "EdgeTest context");
	if (!tall_pcu_ctx)
		abort();

	msgb_set_talloc_ctx(tall_pcu_ctx);
	osmo_init_logging(&debug_log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	vty_init(&pcu_vty_info);
	pcu_vty_init(&debug_log_info);

	test_coding_scheme();
	test_rlc_decoder();

	if (getenv("TALLOC_REPORT_FULL"))
		talloc_report_full(tall_pcu_ctx, stderr);
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