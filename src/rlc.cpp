/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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
 */

#include "bts.h"
#include "gprs_debug.h"
#include <rlc.h>

#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

extern "C" {
#include <osmocom/core/utils.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>

#include "coding_scheme.h"
}


uint8_t *prepare(struct gprs_rlc_data *rlc, size_t block_data_len)
{
	/* todo.. only set it once if it turns out to be a bottleneck */
	memset(rlc->block, 0x0, sizeof(rlc->block));
	memset(rlc->block, 0x2b, block_data_len);

	/* Initial value of puncturing scheme */
	rlc->next_ps = EGPRS_PS_1;

	return rlc->block;
}

static void gprs_rlc_data_header_init(struct gprs_rlc_data_info *rlc,
	enum CodingScheme cs, bool with_padding, unsigned int header_bits,
	const unsigned int spb)
{
	unsigned int i;
	unsigned int padding_bits = with_padding ? mcs_opt_padding_bits(cs) : 0;

	rlc->cs = cs;
	rlc->r = 0;
	rlc->si = 0;
	rlc->tfi = 0;
	rlc->cps = 0;
	rlc->rsb = 0;
	rlc->usf = 0;
	rlc->es_p = 0;
	rlc->rrbp = 0;
	rlc->pr = 0;
	rlc->num_data_blocks = num_data_blocks(mcs_header_type(cs));
	rlc->with_padding = with_padding;

	OSMO_ASSERT(rlc->num_data_blocks <= ARRAY_SIZE(rlc->block_info));

	for (i = 0; i < rlc->num_data_blocks; i++) {
		gprs_rlc_data_block_info_init(&rlc->block_info[i], cs,
			with_padding, spb);

		rlc->data_offs_bits[i] =
			header_bits + padding_bits +
			(i+1) * num_data_block_header_bits(mcs_header_type(cs)) +
			i * 8 * rlc->block_info[0].data_len;
	}
}

void gprs_rlc_data_info_init_dl(struct gprs_rlc_data_info *rlc,
	enum CodingScheme cs, bool with_padding, const unsigned int spb)
{
	OSMO_ASSERT(mcs_is_valid(cs));
	return gprs_rlc_data_header_init(rlc, cs, with_padding,
					 num_data_header_bits_DL(mcs_header_type(cs)), spb);
}

void gprs_rlc_data_info_init_ul(struct gprs_rlc_data_info *rlc,
	enum CodingScheme cs, bool with_padding)
{
	OSMO_ASSERT(mcs_is_valid(cs));
	/*
	 * last parameter is sent as 0 since common function used
	 * for both DL and UL
	 */
	return gprs_rlc_data_header_init(rlc, cs, with_padding,
					 num_data_header_bits_UL(mcs_header_type(cs)), 0);
}

void gprs_rlc_data_block_info_init(struct gprs_rlc_data_block_info *rdbi,
	enum CodingScheme cs, bool with_padding, const unsigned int spb)
{
	unsigned int data_len = mcs_max_data_block_bytes(cs);
	if (with_padding)
		data_len -= mcs_opt_padding_bits(cs) / 8;

	rdbi->data_len = data_len;
	rdbi->bsn = 0;
	rdbi->ti  = 0;
	rdbi->e   = 1;
	rdbi->cv  = 15;
	rdbi->pi  = 0;
	rdbi->spb = spb;
}

unsigned int gprs_rlc_mcs_cps(enum CodingScheme cs,
	enum egprs_puncturing_values punct,
	enum egprs_puncturing_values punct2, bool with_padding)
{
	/* validate that punct and punct2 are as expected */
	switch (cs) {
	case MCS9:
	case MCS8:
	case MCS7:
		if (punct2 == EGPRS_PS_INVALID) {
			LOGP(DRLCMACDL, LOGL_ERROR,
			     "Invalid punct2 value for coding scheme %d: %d\n",
			     cs, punct2);
			return -1;
		}
		/* fall through */
	case MCS6:
	case MCS5:
	case MCS4:
	case MCS3:
	case MCS2:
	case MCS1:
		if (punct == EGPRS_PS_INVALID) {
			LOGP(DRLCMACDL, LOGL_ERROR,
			     "Invalid punct value for coding scheme %d: %d\n",
			     cs, punct);
			return -1;
		}
		break;
	default:
		return -1;
	}

	/* See 3GPP TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1 */
	switch (cs) {
	case MCS1: return 0b1011 +
		punct % EGPRS_MAX_PS_NUM_2;
	case MCS2: return 0b1001 +
		punct % EGPRS_MAX_PS_NUM_2;
	case MCS3: return (with_padding ? 0b0110 : 0b0011) +
		punct % EGPRS_MAX_PS_NUM_3;
	case MCS4: return 0b0000 +
		punct % EGPRS_MAX_PS_NUM_3;
	case MCS5: return  0b100 +
		punct % EGPRS_MAX_PS_NUM_2;
	case MCS6: return (with_padding ? 0b010 : 0b000) +
		punct % EGPRS_MAX_PS_NUM_2;
	case MCS7: return 0b10100 +
		3 * (punct % EGPRS_MAX_PS_NUM_3) +
		punct2 % EGPRS_MAX_PS_NUM_3;
	case MCS8: return 0b01011 +
		3 * (punct % EGPRS_MAX_PS_NUM_3) +
		punct2 % EGPRS_MAX_PS_NUM_3;
	case MCS9: return 0b00000 +
		4 * (punct % EGPRS_MAX_PS_NUM_3) +
		punct2 % EGPRS_MAX_PS_NUM_3;
	default: ;
	}

	return -1;
}

void gprs_rlc_mcs_cps_decode(unsigned int cps,
	enum CodingScheme cs, int *punct, int *punct2, int *with_padding)
{
	*punct2 = -1;
	*with_padding = 0;

	switch (cs) {
	case MCS1:
		cps -= 0b1011; *punct = cps % 2; break;
	case MCS2:
		cps -= 0b1001; *punct = cps % 2; break;
	case MCS3:
		cps -= 0b0011; *punct = cps % 3; *with_padding = cps >= 3; break;
	case MCS4:
		cps -= 0b0000; *punct = cps % 3; break;
	case MCS5:
		cps -= 0b100; *punct = cps % 2; break;
	case MCS6:
		cps -= 0b000; *punct = cps % 2; *with_padding = cps >= 2; break;
	case MCS7:
		cps -= 0b10100; *punct = cps / 3; *punct2 = cps % 3; break;
	case MCS8:
		cps -= 0b01011; *punct = cps / 3; *punct2 = cps % 3; break;
	case MCS9:
		cps -= 0b00000; *punct = cps / 4; *punct2 = cps % 3; break;
	default: ;
	}
}

/*
 * Finds the PS value for retransmission with MCS change,
 * retransmission with no MCS change, fresh transmission cases.
 * The return value shall be used for current transmission only
 * 44.060 9.3.2.1 defines the PS selection for MCS change case
 * cs_current is the output of MCS selection algorithm for retx
 * cs is coding scheme of previous transmission of RLC data block
 */
enum egprs_puncturing_values gprs_get_punct_scheme(
	enum egprs_puncturing_values punct,
	const enum CodingScheme &cs,
	const enum CodingScheme &cs_current,
	const enum egprs_rlcmac_dl_spb spb)
{

	/*
	 * 10.4.8b of TS 44.060
	 * If it is second segment of the block
	 * dont change the puncturing scheme
	 */
	if (spb == EGPRS_RLCMAC_DL_SEC_SEG)
		return punct;

	/* TS  44.060 9.3.2.1.1 */
	if ((cs == MCS9) &&
	(cs_current == MCS6)) {
		if ((punct == EGPRS_PS_1) || (punct == EGPRS_PS_3))
			return EGPRS_PS_1;
		else if (punct == EGPRS_PS_2)
			return EGPRS_PS_2;
	} else if ((cs == MCS6) &&
	(cs_current == MCS9)) {
		if (punct == EGPRS_PS_1)
			return EGPRS_PS_3;
		else if (punct == EGPRS_PS_2)
			return EGPRS_PS_2;
	} else if ((cs == MCS7) &&
	(cs_current == MCS5))
		return EGPRS_PS_1;
	else if ((cs == MCS5) &&
	(cs_current == MCS7))
		return EGPRS_PS_2;
	else if (cs != cs_current)
		return EGPRS_PS_1;
	/* TS  44.060 9.3.2.1.1 ends here */
	/*
	 * Below else will handle fresh transmission, retransmission with no
	 * MCS change case
	 */
	else
		return punct;
	return EGPRS_PS_INVALID;
}

/*
 * This function calculates puncturing scheme for retransmission of a RLC
 * block with same MCS. The computed value shall be used for next transmission
 * of the same RLC block
 * TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1
 */
void gprs_update_punct_scheme(enum egprs_puncturing_values *punct,
	const enum CodingScheme &cs)
{
	switch (cs) {
	case MCS1 :
	case MCS2 :
	case MCS5 :
	case MCS6 :
		*punct = ((enum egprs_puncturing_values)((*punct + 1) %
			EGPRS_MAX_PS_NUM_2));
		break;
	case MCS3 :
	case MCS4 :
	case MCS7 :
	case MCS8 :
	case MCS9 :
		*punct = ((enum egprs_puncturing_values)((*punct + 1) %
			EGPRS_MAX_PS_NUM_3));
		break;
	default:
		break;
	}
}
