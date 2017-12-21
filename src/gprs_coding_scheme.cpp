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

/*
 * 44.060 Table 8.1.1.1 and Table 8.1.1.2
 * It has 3 level indexing. 0th level is ARQ type
 * 1st level is Original MCS( index 0 corresponds to MCS1 and so on)
 * 2nd level is MS MCS (index 0 corresponds to MCS1 and so on)
 */
enum GprsCodingScheme::Scheme GprsCodingScheme::egprs_mcs_retx_tbl[MAX_NUM_ARQ]
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

static struct {
	struct {
		uint8_t bytes;
		uint8_t ext_bits;
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_bytes;
	uint8_t optional_padding_bits;
	const char *name;
	GprsCodingScheme::HeaderType data_hdr;
	GprsCodingScheme::Family family;
} mcs_info[GprsCodingScheme::NUM_SCHEMES] = {
	{{0, 0},   {0, 0},    0,  0, "UNKNOWN",
		GprsCodingScheme::HEADER_INVALID, GprsCodingScheme::FAMILY_INVALID},
	{{23, 0},  {23, 0},  20,  0, "CS-1",
		GprsCodingScheme::HEADER_GPRS_DATA, GprsCodingScheme::FAMILY_INVALID},
	{{33, 7},  {33, 7},  30,  0, "CS-2",
		GprsCodingScheme::HEADER_GPRS_DATA, GprsCodingScheme::FAMILY_INVALID},
	{{39, 3},  {39, 3},  36,  0, "CS-3",
		GprsCodingScheme::HEADER_GPRS_DATA, GprsCodingScheme::FAMILY_INVALID},
	{{53, 7},  {53, 7},  50,  0, "CS-4",
		GprsCodingScheme::HEADER_GPRS_DATA, GprsCodingScheme::FAMILY_INVALID},

	{{26, 1},  {26, 1},  22,  0, "MCS-1",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3, GprsCodingScheme::FAMILY_C},
	{{32, 1},  {32, 1},  28,  0, "MCS-2",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3, GprsCodingScheme::FAMILY_B},
	{{41, 1},  {41, 1},  37, 48, "MCS-3",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3, GprsCodingScheme::FAMILY_A},
	{{48, 1},  {48, 1},  44,  0, "MCS-4",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3, GprsCodingScheme::FAMILY_C},

	{{60, 7},  {59, 6},  56,  0, "MCS-5",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2, GprsCodingScheme::FAMILY_B},
	{{78, 7},  {77, 6},  74, 48, "MCS-6",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2, GprsCodingScheme::FAMILY_A},
	{{118, 2}, {117, 4}, 56,  0, "MCS-7",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1, GprsCodingScheme::FAMILY_B},
	{{142, 2}, {141, 4}, 68,  0, "MCS-8",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1, GprsCodingScheme::FAMILY_A},
	{{154, 2}, {153, 4}, 74,  0, "MCS-9",
		GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1, GprsCodingScheme::FAMILY_A},
};

static struct {
	struct {
		uint8_t data_header_bits;
	} uplink, downlink;
	uint8_t data_block_header_bits;
	uint8_t num_blocks;
	const char *name;
} hdr_type_info[GprsCodingScheme::NUM_HEADER_TYPES] = {
	{{0},       {0},       0, 0, "INVALID"},
	{{1*8 + 0}, {1*8 + 0}, 0, 0, "CONTROL"},
	{{3*8 + 0}, {3*8 + 0}, 0, 1, "GPRS_DATA"},
	{{5*8 + 6}, {5*8 + 0}, 2, 2, "EGPRS_DATA_TYPE1"},
	{{4*8 + 5}, {3*8 + 4}, 2, 1, "EGPRS_DATA_TYPE2"},
	{{3*8 + 7}, {3*8 + 7}, 2, 1, "EGPRS_DATA_TYPE3"},
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

uint8_t GprsCodingScheme::numDataBlocks() const
{
	return hdr_type_info[headerTypeData()].num_blocks;
}

uint8_t GprsCodingScheme::numDataHeaderBitsUL() const
{
	return hdr_type_info[headerTypeData()].uplink.data_header_bits;
}

uint8_t GprsCodingScheme::numDataHeaderBitsDL() const
{
	return hdr_type_info[headerTypeData()].downlink.data_header_bits;
}

uint8_t GprsCodingScheme::numDataBlockHeaderBits() const
{
	return hdr_type_info[headerTypeData()].data_block_header_bits;
}

const char *GprsCodingScheme::name() const
{
	return mcs_info[m_scheme].name;
}

GprsCodingScheme::HeaderType GprsCodingScheme::headerTypeData() const
{
	return mcs_info[m_scheme].data_hdr;
}

GprsCodingScheme::Family GprsCodingScheme::family() const
{
	return mcs_info[m_scheme].family;
}

void GprsCodingScheme::inc(Mode mode)
{
	if (!isCompatible(mode))
		/* This should not happen. TODO: Use assert? */
		return;

	Scheme new_cs(Scheme(m_scheme + 1));
	if (!GprsCodingScheme(new_cs).isCompatible(mode))
		/* Clipping, do not change the value */
		return;

	m_scheme = new_cs;
}

void GprsCodingScheme::dec(Mode mode)
{
	if (!isCompatible(mode))
		/* This should not happen. TODO: Use assert? */
		return;

	Scheme new_cs(Scheme(m_scheme - 1));
	if (!GprsCodingScheme(new_cs).isCompatible(mode))
		/* Clipping, do not change the value */
		return;

	m_scheme = new_cs;
}

void GprsCodingScheme::inc()
{
	if (isGprs() && m_scheme == CS4)
		return;

	if (isEgprs() && m_scheme == MCS9)
		return;

	if (!isValid())
		return;

	m_scheme = Scheme(m_scheme + 1);
}

void GprsCodingScheme::dec()
{
	if (isGprs() && m_scheme == CS1)
		return;

	if (isEgprs() && m_scheme == MCS1)
		return;

	if (!isValid())
		return;

	m_scheme = Scheme(m_scheme - 1);
}

const char *GprsCodingScheme::modeName(Mode mode)
{
	switch (mode) {
	case GPRS:       return "GPRS";
	case EGPRS_GMSK: return "EGPRS_GMSK-only";
	case EGPRS:      return "EGPRS";
	default:         return "???";
	}
}

bool GprsCodingScheme::isFamilyCompatible(GprsCodingScheme o) const
{
	if (*this == o)
		return true;

	if (family() == FAMILY_INVALID)
		return false;

	return family() == o.family();
}

bool GprsCodingScheme::isCombinable(GprsCodingScheme o) const
{
	return numDataBlocks() == o.numDataBlocks();
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
