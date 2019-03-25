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

extern "C" {
	#include <osmocom/core/utils.h>
	#include "coding_scheme.h"
}

class GprsCodingScheme {
public:

#define EGPRS_ARQ1            0x0
#define EGPRS_ARQ2            0x1

	GprsCodingScheme(CodingScheme s = UNKNOWN);

	operator bool() const {return m_scheme != UNKNOWN;}
	operator CodingScheme() const {return m_scheme;}
	uint8_t to_num() const;

	GprsCodingScheme& operator =(CodingScheme s);
	bool operator == (CodingScheme s) const;
	GprsCodingScheme& operator =(GprsCodingScheme o);

	bool isValid()   const {return UNKNOWN <= m_scheme && m_scheme <= MCS9;}

	bool isCompatible(enum mcs_kind mode) const;
	bool isCompatible(GprsCodingScheme o) const;
	bool isFamilyCompatible(GprsCodingScheme o) const;

	void inc(enum mcs_kind mode);
	void dec(enum mcs_kind mode);
	void inc();
	void dec();
	void decToSingleBlock(bool *needStuffing);

	uint8_t sizeUL() const;
	uint8_t sizeDL() const;
	uint8_t usedSizeUL() const;
	uint8_t usedSizeDL() const;
	uint8_t maxBytesUL() const;
	uint8_t maxBytesDL() const;
	uint8_t spareBitsUL() const;
	uint8_t spareBitsDL() const;
	uint8_t maxDataBlockBytes() const;
	uint8_t optionalPaddingBits() const;

	enum HeaderType headerTypeData() const;

	static GprsCodingScheme getBySizeUL(unsigned size);
	static GprsCodingScheme getGprsByNum(unsigned num);
	static GprsCodingScheme getEgprsByNum(unsigned num);

	static CodingScheme get_retx_mcs(const GprsCodingScheme mcs,
				const GprsCodingScheme retx_mcs,
				const unsigned arq_type);
private:
	GprsCodingScheme(int s); /* fail on use */
	GprsCodingScheme& operator =(int s); /* fail on use */
	enum CodingScheme m_scheme;
};

inline uint8_t GprsCodingScheme::to_num() const
{
	if (mcs_is_gprs(m_scheme))
		return (m_scheme - CS1) + 1;

	if (mcs_is_edge(m_scheme))
		return (m_scheme - MCS1) + 1;

	return 0;
}

inline bool GprsCodingScheme::isCompatible(enum mcs_kind mode) const
{
	switch (mode) {
	case GPRS: return mcs_is_gprs(m_scheme);
	case EGPRS_GMSK: return mcs_is_edge_gmsk(m_scheme);
	case EGPRS: return mcs_is_edge(m_scheme);
	}

	return false;
}

inline bool GprsCodingScheme::isCompatible(GprsCodingScheme o) const
{
	return (mcs_is_gprs(m_scheme) && mcs_is_gprs(o)) || (mcs_is_edge(m_scheme) && mcs_is_edge(o));
}

inline GprsCodingScheme::GprsCodingScheme(CodingScheme s)
	: m_scheme(s)
{
	if (!isValid())
		m_scheme = UNKNOWN;
}

inline GprsCodingScheme& GprsCodingScheme::operator =(CodingScheme s)
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

	return GprsCodingScheme(CodingScheme(CS1 + (num - 1)));
}

inline GprsCodingScheme GprsCodingScheme::getEgprsByNum(unsigned num)
{
	if (num < 1 || num > 9)
		return GprsCodingScheme();

	return GprsCodingScheme(CodingScheme(MCS1 + (num - 1)));
}

/* The coding schemes form a partial ordering */
inline bool GprsCodingScheme::operator == (CodingScheme scheme) const
{
	return this->m_scheme == scheme;
}

inline bool operator !=(GprsCodingScheme a, GprsCodingScheme b)
{
	return !(a == b);
}

inline bool operator <(GprsCodingScheme a, GprsCodingScheme b)
{
	return a.isCompatible(b) && a.to_num() < b.to_num();
}
