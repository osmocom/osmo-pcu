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
		unsigned bytes;
		unsigned ext_bits;
	} uplink, downlink;
	const char *name;
} mcs_info[GprsCodingScheme::NUM_SCHEMES] = {
	{{0, 0},    {0, 0},   "UNKNOWN"},
	{{23, 0},   {23, 0},  "CS-1"},
	{{33, 7},   {33, 7},  "CS-2"},
	{{39, 3},   {39, 3},  "CS-3"},
	{{53, 7},   {53, 7},  "CS-4"},

	{{26, 1},   {26, 1},  "MCS-1"},
	{{32, 1},   {32, 1},  "MCS-2"},
	{{41, 1},   {41, 1},  "MCS-3"},
	{{48, 1},   {48, 1},  "MCS-4"},

	{{60, 7},   {59, 6},  "MCS-5"},
	{{78, 7},   {77, 6},  "MCS-6"},
	{{118, 2},  {117, 4}, "MCS-7"},
	{{142, 2},  {141, 4}, "MCS-8"},
	{{154, 2},  {153, 4}, "MCS-9"},
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

const char *GprsCodingScheme::name() const
{
	return mcs_info[m_scheme].name;
}
