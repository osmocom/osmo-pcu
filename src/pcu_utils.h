/*
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
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

inline int msecs_to_frames(int msecs) {
	return (msecs * (1024 * 1000 / 4615)) / 1024;
}

inline void csecs_to_timeval(unsigned csecs, struct timeval *tv) {
	tv->tv_sec  = csecs / 100;
	tv->tv_usec = (csecs % 100) * 10000;
}

template <typename T>
inline unsigned int pcu_bitcount(T x)
{
	unsigned int count = 0;
	for (count = 0; x; count += 1)
		x &= x - 1;

	return count;
}

template <typename T>
inline T pcu_lsb(T x)
{
	return x & -x;
}
