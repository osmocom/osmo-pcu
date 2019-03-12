/* gprs_coding_scheme.cpp
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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


#include "gprs_coding_scheme.h"

#define MAX_NUM_ARQ           2     /* max. number of ARQ */
#define MAX_NUM_MCS           9     /* max. number of MCS */

/*
 * 44.060 Table 8.1.1.1 and Table 8.1.1.2
 * It has 3 level indexing. 0th level is ARQ type
 * 1st level is Original MCS( index 0 corresponds to MCS1 and so on)
 * 2nd level is MS MCS (index 0 corresponds to MCS1 and so on)
 */
static enum CodingScheme egprs_mcs_retx_tbl[MAX_NUM_ARQ]
			[MAX_NUM_MCS][MAX_NUM_MCS] = {
		{
			{MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1},
			{MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2},
			{MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3},
			{MCS1, MCS1, MCS1, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4},
			{MCS2, MCS2, MCS2, MCS2, MCS5, MCS5, MCS7, MCS7, MCS7},
			{MCS3, MCS3, MCS3, MCS3, MCS3, MCS6, MCS6, MCS6, MCS9},
			{MCS2, MCS2, MCS2, MCS2, MCS5, MCS5, MCS7, MCS7, MCS7},
			{MCS3, MCS3, MCS3, MCS3, MCS3, MCS6, MCS6, MCS8, MCS8},
			{MCS3, MCS3, MCS3, MCS3, MCS3, MCS6, MCS6, MCS6, MCS9}
		},
		{
			{MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1, MCS1},
			{MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2, MCS2},
			{MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3, MCS3},
			{MCS4, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4, MCS4},
			{MCS5, MCS5, MCS5, MCS5, MCS5, MCS5, MCS7, MCS7, MCS7},
			{MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS9},
			{MCS5, MCS5, MCS5, MCS5, MCS5, MCS5, MCS7, MCS7, MCS7},
			{MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS8, MCS8},
			{MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS6, MCS9}
		}
	};

enum Family {
	FAMILY_INVALID,
	FAMILY_A,
	FAMILY_B,
	FAMILY_C,
};

CodingScheme GprsCodingScheme::get_retx_mcs(const GprsCodingScheme mcs,
							const GprsCodingScheme demanded_mcs,
							const unsigned arq_type)
{
	return egprs_mcs_retx_tbl[arq_type][mcs_chan_code(mcs)][mcs_chan_code(demanded_mcs)];
}

static struct {
	struct {
		uint8_t bytes;
		uint8_t ext_bits;
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_bytes;
	uint8_t optional_padding_bits;
	enum HeaderType data_hdr;
	enum Family family;
} mcs_info[NUM_SCHEMES] = {
	{{0, 0},   {0, 0},    0,  0,
		HEADER_INVALID, FAMILY_INVALID},
	{{23, 0},  {23, 0},  20,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},
	{{33, 7},  {33, 7},  30,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},
	{{39, 3},  {39, 3},  36,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},
	{{53, 7},  {53, 7},  50,  0,
		HEADER_GPRS_DATA, FAMILY_INVALID},

	{{26, 1},  {26, 1},  22,  0,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_C},
	{{32, 1},  {32, 1},  28,  0,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_B},
	{{41, 1},  {41, 1},  37, 48,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_A},
	{{48, 1},  {48, 1},  44,  0,
		HEADER_EGPRS_DATA_TYPE_3, FAMILY_C},

	{{60, 7},  {59, 6},  56,  0,
		HEADER_EGPRS_DATA_TYPE_2, FAMILY_B},
	{{78, 7},  {77, 6},  74, 48,
		HEADER_EGPRS_DATA_TYPE_2, FAMILY_A},
	{{118, 2}, {117, 4}, 56,  0,
		HEADER_EGPRS_DATA_TYPE_1, FAMILY_B},
	{{142, 2}, {141, 4}, 68,  0,
		HEADER_EGPRS_DATA_TYPE_1, FAMILY_A},
	{{154, 2}, {153, 4}, 74,  0,
		HEADER_EGPRS_DATA_TYPE_1, FAMILY_A},
};

GprsCodingScheme GprsCodingScheme::getBySizeUL(unsigned size)
{
	switch (size) {
		case 23: return GprsCodingScheme(CS1);
		case 27: return GprsCodingScheme(MCS1);
		case 33: return GprsCodingScheme(MCS2);
		case 34: return GprsCodingScheme(CS2);
		case 40: return GprsCodingScheme(CS3);
		case 42: return GprsCodingScheme(MCS3);
		case 49: return GprsCodingScheme(MCS4);
		case 54: return GprsCodingScheme(CS4);
		case 61: return GprsCodingScheme(MCS5);
		case 79: return GprsCodingScheme(MCS6);
		case 119: return GprsCodingScheme(MCS7);
		case 143: return GprsCodingScheme(MCS8);
		case 155: return GprsCodingScheme(MCS9);
	}

	return GprsCodingScheme(UNKNOWN);
}

uint8_t GprsCodingScheme::sizeUL() const
{
	return mcs_info[m_scheme].uplink.bytes + (spareBitsUL() ? 1 : 0);
}

uint8_t GprsCodingScheme::usedSizeUL() const
{
	if (mcs_info[m_scheme].data_hdr == HEADER_GPRS_DATA)
		return mcs_info[m_scheme].uplink.bytes;
	else
		return sizeUL();
}

uint8_t GprsCodingScheme::maxBytesUL() const
{
	return mcs_info[m_scheme].uplink.bytes;
}

uint8_t GprsCodingScheme::spareBitsUL() const
{
	return mcs_info[m_scheme].uplink.ext_bits;
}

uint8_t GprsCodingScheme::sizeDL() const
{
	return mcs_info[m_scheme].downlink.bytes + (spareBitsDL() ? 1 : 0);
}

uint8_t GprsCodingScheme::usedSizeDL() const
{
	if (mcs_info[m_scheme].data_hdr == HEADER_GPRS_DATA)
		return mcs_info[m_scheme].downlink.bytes;
	else
		return sizeDL();
}

uint8_t GprsCodingScheme::maxBytesDL() const
{
	return mcs_info[m_scheme].downlink.bytes;
}

uint8_t GprsCodingScheme::spareBitsDL() const
{
	return mcs_info[m_scheme].downlink.ext_bits;
}

uint8_t GprsCodingScheme::maxDataBlockBytes() const
{
	return mcs_info[m_scheme].data_bytes;
}

uint8_t GprsCodingScheme::optionalPaddingBits() const
{
	return mcs_info[m_scheme].optional_padding_bits;
}

enum HeaderType GprsCodingScheme::headerTypeData() const
{
	return mcs_info[m_scheme].data_hdr;
}

void GprsCodingScheme::inc(enum mcs_kind mode)
{
	if (!isCompatible(mode))
		/* This should not happen. TODO: Use assert? */
		return;

	CodingScheme new_cs(CodingScheme(m_scheme + 1));
	if (!GprsCodingScheme(new_cs).isCompatible(mode))
		/* Clipping, do not change the value */
		return;

	m_scheme = new_cs;
}

void GprsCodingScheme::dec(enum mcs_kind mode)
{
	if (!isCompatible(mode))
		/* This should not happen. TODO: Use assert? */
		return;

	CodingScheme new_cs(CodingScheme(m_scheme - 1));
	if (!GprsCodingScheme(new_cs).isCompatible(mode))
		/* Clipping, do not change the value */
		return;

	m_scheme = new_cs;
}

void GprsCodingScheme::inc()
{
	if (mcs_is_gprs(m_scheme) && m_scheme == CS4)
		return;

	if (mcs_is_edge(m_scheme) && m_scheme == MCS9)
		return;

	if (!isValid())
		return;

	m_scheme = CodingScheme(m_scheme + 1);
}

void GprsCodingScheme::dec()
{
	if (mcs_is_gprs(m_scheme) && m_scheme == CS1)
		return;

	if (mcs_is_edge(m_scheme) && m_scheme == MCS1)
		return;

	if (!isValid())
		return;

	m_scheme = CodingScheme(m_scheme - 1);
}

bool GprsCodingScheme::isFamilyCompatible(GprsCodingScheme o) const
{
	if (*this == o)
		return true;

	if (mcs_info[m_scheme].family == FAMILY_INVALID)
		return false;

	return mcs_info[m_scheme].family == mcs_info[o.m_scheme].family;
}

void GprsCodingScheme::decToSingleBlock(bool *needStuffing)
{
	switch (m_scheme) {
	case MCS7: *needStuffing = false; m_scheme = MCS5; break;
	case MCS8: *needStuffing =  true; m_scheme = MCS6; break;
	case MCS9: *needStuffing = false; m_scheme = MCS6; break;
	default:   *needStuffing = false; break;
	}
}
