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
	};

	GprsCodingScheme(Scheme s = UNKNOWN);

	operator bool() const {return m_scheme != UNKNOWN;}
	operator int()  const {return (int)m_scheme;}
	void operator =(Scheme s);
	void operator =(GprsCodingScheme o);
	bool isValid()   const {return UNKNOWN <= m_scheme && m_scheme <= MCS9;}
	bool isGprs()   const {return CS1 <= m_scheme && m_scheme <= CS4;}
	bool isEgprs()  const {return m_scheme >= MCS1;}
	bool isEgprsGmsk()  const {return isEgprs() && m_scheme <= MCS4;}
	bool isCompatible(Mode mode) const;

	void inc(Mode mode);
	void dec(Mode mode);

	unsigned int sizeUL() const;
	unsigned int sizeDL() const;
	unsigned int maxBytesUL() const;
	unsigned int maxBytesDL() const;
	unsigned int spareBitsUL() const;
	unsigned int spareBitsDL() const;
	const char *name() const;
	HeaderType headerTypeData() const;
	HeaderType headerTypeControl() const;

	static GprsCodingScheme getBySizeUL(unsigned size);

private:
	enum Scheme m_scheme;
};

inline bool GprsCodingScheme::isCompatible(Mode mode) const
{
	switch (mode) {
	case GPRS: return isGprs();
	case EGPRS_GMSK: return isEgprsGmsk();
	case EGPRS: return isEgprs();
	}

	return false;
}

inline void GprsCodingScheme::inc(Mode mode)
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

inline void GprsCodingScheme::dec(Mode mode)
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

inline void GprsCodingScheme::operator =(Scheme s)
{
	m_scheme = s;

	if (!isValid())
		m_scheme = UNKNOWN;
}

inline void GprsCodingScheme::operator =(GprsCodingScheme o)
{
	m_scheme = o.m_scheme;
}
