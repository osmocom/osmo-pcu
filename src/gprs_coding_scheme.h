/* gprs_coding_scheme.h
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

#pragma once

#include <stdint.h>
#include <stddef.h>


class GprsCodingScheme {
public:

#define MAX_NUM_ARQ           2      /* max. number of ARQ */
#define MAX_NUM_MCS           9     /* max. number of MCS */
#define EGPRS_ARQ1            0x0
#define EGPRS_ARQ2            0x1

	enum Scheme {
		UNKNOWN,
		CS1, CS2, CS3, CS4,
		MCS1, MCS2, MCS3, MCS4,
		MCS5, MCS6, MCS7, MCS8, MCS9,
		NUM_SCHEMES
	};

	enum Mode {
		GPRS,
		EGPRS_GMSK,
		EGPRS,
	};

	enum HeaderType {
		HEADER_INVALID,
		HEADER_GPRS_CONTROL,
		HEADER_GPRS_DATA,
		HEADER_EGPRS_DATA_TYPE_1,
		HEADER_EGPRS_DATA_TYPE_2,
		HEADER_EGPRS_DATA_TYPE_3,
		NUM_HEADER_TYPES
	};

	enum Family {
		FAMILY_INVALID,
		FAMILY_A,
		FAMILY_B,
		FAMILY_C,
	};

	GprsCodingScheme(Scheme s = UNKNOWN);

	operator bool() const {return m_scheme != UNKNOWN;}
	operator Scheme() const {return m_scheme;}
	unsigned int to_num() const;

	GprsCodingScheme& operator =(Scheme s);
	GprsCodingScheme& operator =(GprsCodingScheme o);

	bool isValid()   const {return UNKNOWN <= m_scheme && m_scheme <= MCS9;}
	bool isGprs()   const {return CS1 <= m_scheme && m_scheme <= CS4;}
	bool isEgprs()  const {return m_scheme >= MCS1;}
	bool isEgprsGmsk()  const {return isEgprs() && m_scheme <= MCS4;}
	bool isCompatible(Mode mode) const;
	bool isCompatible(GprsCodingScheme o) const;
	bool isFamilyCompatible(GprsCodingScheme o) const;
	bool isCombinable(GprsCodingScheme o) const;

	void inc(Mode mode);
	void dec(Mode mode);
	void inc();
	void dec();
	void decToSingleBlock(bool *needStuffing);

	unsigned int sizeUL() const;
	unsigned int sizeDL() const;
	unsigned int usedSizeUL() const;
	unsigned int usedSizeDL() const;
	unsigned int maxBytesUL() const;
	unsigned int maxBytesDL() const;
	unsigned int spareBitsUL() const;
	unsigned int spareBitsDL() const;
	unsigned int maxDataBlockBytes() const;
	unsigned int numDataBlocks() const;
	unsigned int numDataHeaderBitsUL() const;
	unsigned int numDataHeaderBitsDL() const;
	unsigned int numDataBlockHeaderBits() const;
	unsigned int optionalPaddingBits() const;
	const char *name() const;
	HeaderType headerTypeData() const;
	HeaderType headerTypeControl() const;
	Family family() const;

	static GprsCodingScheme getBySizeUL(unsigned size);
	static GprsCodingScheme getGprsByNum(unsigned num);
	static GprsCodingScheme getEgprsByNum(unsigned num);

	static const char *modeName(Mode mode);
	static enum Scheme egprs_mcs_retx_tbl[MAX_NUM_ARQ]
			[MAX_NUM_MCS][MAX_NUM_MCS];
private:
	GprsCodingScheme(int s); /* fail on use */
	GprsCodingScheme& operator =(int s); /* fail on use */
	enum Scheme m_scheme;
};

inline unsigned int GprsCodingScheme::to_num() const
{
	if (isGprs())
		return (m_scheme - CS1) + 1;

	if (isEgprs())
		return (m_scheme - MCS1) + 1;

	return 0;
}

inline bool GprsCodingScheme::isCompatible(Mode mode) const
{
	switch (mode) {
	case GPRS: return isGprs();
	case EGPRS_GMSK: return isEgprsGmsk();
	case EGPRS: return isEgprs();
	}

	return false;
}

inline bool GprsCodingScheme::isCompatible(GprsCodingScheme o) const
{
	return (isGprs() && o.isGprs()) || (isEgprs() && o.isEgprs());
}

inline GprsCodingScheme::HeaderType GprsCodingScheme::headerTypeControl() const
{
	return HEADER_GPRS_CONTROL;
}

inline GprsCodingScheme::GprsCodingScheme(Scheme s)
	: m_scheme(s)
{
	if (!isValid())
		m_scheme = UNKNOWN;
}

inline GprsCodingScheme& GprsCodingScheme::operator =(Scheme s)
{
	m_scheme = s;

	if (!isValid())
		m_scheme = UNKNOWN;

	return *this;
}

inline GprsCodingScheme& GprsCodingScheme::operator =(GprsCodingScheme o)
{
	m_scheme = o.m_scheme;
	return *this;
}

inline GprsCodingScheme GprsCodingScheme::getGprsByNum(unsigned num)
{
	if (num < 1 || num > 4)
		return GprsCodingScheme();

	return GprsCodingScheme(Scheme(CS1 + (num - 1)));
}

inline GprsCodingScheme GprsCodingScheme::getEgprsByNum(unsigned num)
{
	if (num < 1 || num > 9)
		return GprsCodingScheme();

	return GprsCodingScheme(Scheme(MCS1 + (num - 1)));
}

/* The coding schemes form a partial ordering */
inline bool operator ==(GprsCodingScheme a, GprsCodingScheme b)
{
	return GprsCodingScheme::Scheme(a) == GprsCodingScheme::Scheme(b);
}

inline bool operator !=(GprsCodingScheme a, GprsCodingScheme b)
{
	return !(a == b);
}

inline bool operator <(GprsCodingScheme a, GprsCodingScheme b)
{
	return a.isCompatible(b) &&
		GprsCodingScheme::Scheme(a) < GprsCodingScheme::Scheme(b);
}

inline bool operator >(GprsCodingScheme a, GprsCodingScheme b)
{
	return b < a;
}

inline bool operator <=(GprsCodingScheme a, GprsCodingScheme b)
{
	return a == b || a < b;
}

inline bool operator >=(GprsCodingScheme a, GprsCodingScheme b)
{
	return a == b || a > b;
}

