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

static struct {
	struct {
		unsigned int bytes;
		unsigned int ext_bits;
	} uplink, downlink;
	unsigned int data_bytes;
	unsigned int num_blocks;
	const char *name;
	GprsCodingScheme::HeaderType data_hdr;
} mcs_info[GprsCodingScheme::NUM_SCHEMES] = {
	{{0, 0},    {0, 0},    0, 0, "UNKNOWN", GprsCodingScheme::HEADER_INVALID},
	{{23, 0},   {23, 0},  20, 1, "CS-1", GprsCodingScheme::HEADER_GPRS_DATA},
	{{33, 7},   {33, 7},  30, 1, "CS-2", GprsCodingScheme::HEADER_GPRS_DATA},
	{{39, 3},   {39, 3},  36, 1, "CS-3", GprsCodingScheme::HEADER_GPRS_DATA},
	{{53, 7},   {53, 7},  50, 1, "CS-4", GprsCodingScheme::HEADER_GPRS_DATA},

	{{26, 1},   {26, 1},  22, 1, "MCS-1", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3},
	{{32, 1},   {32, 1},  28, 1, "MCS-2", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3},
	{{41, 1},   {41, 1},  37, 1, "MCS-3", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3},
	{{48, 1},   {48, 1},  44, 1, "MCS-4", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3},

	{{60, 7},   {59, 6},  56, 1, "MCS-5", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2},
	{{78, 7},   {77, 6},  74, 1, "MCS-6", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2},
	{{118, 2},  {117, 4}, 56, 2, "MCS-7", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1},
	{{142, 2},  {141, 4}, 68, 2, "MCS-8", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1},
	{{154, 2},  {153, 4}, 74, 2, "MCS-9", GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1},
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

unsigned int GprsCodingScheme::sizeUL() const
{
	return maxBytesUL() + (spareBitsUL() ? 1 : 0);
}

unsigned int GprsCodingScheme::maxBytesUL() const
{
	return mcs_info[m_scheme].uplink.bytes;
}

unsigned int GprsCodingScheme::spareBitsUL() const
{
	return mcs_info[m_scheme].uplink.ext_bits;
}

unsigned int GprsCodingScheme::sizeDL() const
{
	return maxBytesDL() + (spareBitsDL() ? 1 : 0);
}

unsigned int GprsCodingScheme::maxBytesDL() const
{
	return mcs_info[m_scheme].downlink.bytes;
}

unsigned int GprsCodingScheme::spareBitsDL() const
{
	return mcs_info[m_scheme].downlink.ext_bits;
}

unsigned int GprsCodingScheme::maxDataBlockBytes() const
{
	return mcs_info[m_scheme].data_bytes;
}

unsigned int GprsCodingScheme::numDataBlocks() const
{
	return mcs_info[m_scheme].num_blocks;
}

const char *GprsCodingScheme::name() const
{
	return mcs_info[m_scheme].name;
}

GprsCodingScheme::HeaderType GprsCodingScheme::headerTypeData() const
{
	return mcs_info[m_scheme].data_hdr;
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
