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
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <osmocom/gsm/gsm_utils.h>
#ifdef __cplusplus
}
#endif

#include <time.h>
#include <stdint.h>

#define FN_UNSET 0xFFFFFFFF

static inline int msecs_to_frames(int msecs) {
	return (msecs * (1024 * 1000 / 4615)) / 1024;
}

static inline uint32_t next_fn(uint32_t fn, uint32_t offset)
{
	return (fn + offset) % GSM_MAX_FN;
}

static inline void csecs_to_timespec(unsigned csecs, struct timespec *ts) {
	ts->tv_sec  = csecs / 100;
	ts->tv_nsec = (csecs % 100) * 10000000;
}

static inline uint32_t rts_next_fn(uint32_t rts_fn, uint8_t block_nr)
{
	uint32_t fn = rts_fn + 4;
	if ((block_nr % 3) == 2)
		fn++;
	fn = fn % GSM_MAX_FN;
	return fn;
}

static inline unsigned fn2bn(unsigned fn)
{
	return (fn % 52) / 4;
}

static inline bool fn_valid(uint32_t fn)
{
	uint32_t f = fn % 13;
	return f == 0 || f == 4 || f == 8;
}

static inline unsigned fn_next_block(unsigned fn)
{
	unsigned bn = fn2bn(fn) + 1;
	fn = fn - (fn % 52);
	fn += bn * 4 + bn / 3;
	return fn % GSM_MAX_FN;
}

#ifdef __cplusplus
template <typename T>
inline unsigned int pcu_bitcount(T x)
{
	unsigned int count = 0;
	for (count = 0; x; count += 1)
		x &= x - 1;

	return count;
}
#endif

static inline uint8_t pcu_lsb(uint8_t x)
{
	return x & -x;
}

/* Used to store a C++ class in a llist used by C code */
struct llist_item {
	struct llist_head list; /* item used by llist */
	void *entry;
};

struct arfcn_bsic {
	uint16_t arfcn;
	uint8_t bsic;
};
