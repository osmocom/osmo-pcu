/* coding_scheme.h
 *
 * Copyright (C) 2015-2019 by sysmocom s.f.m.c. GmbH
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

enum CodingScheme {
	UNKNOWN,
	/* GPRS Coding Schemes: */
	CS1, CS2, CS3, CS4,
	/* EDGE/EGPRS Modulation and Coding Schemes: */
	MCS1, MCS2, MCS3, MCS4, MCS5, MCS6, MCS7, MCS8, MCS9,
	NUM_SCHEMES
};
