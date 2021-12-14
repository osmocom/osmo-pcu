/* gprs_codel.cpp
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
 */

#include "gprs_codel.h"
#include "gprs_debug.h"

#include <osmocom/core/utils.h>
#include <osmocom/core/timer_compat.h>

#include <stdint.h>
#include <stdlib.h>
#include <math.h>

static void control_law(struct gprs_codel *state, struct timespec *delta)
{
	/* 256 / sqrt(x), limited to 255 */
	static uint8_t inv_sqrt_tab[] = {255,
		255, 181, 147, 128, 114, 104, 96, 90, 85, 80, 77, 73, 71, 68,
		66, 64, 62, 60, 58, 57, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46,
		45, 45, 44, 43, 43, 42, 42, 41, 40, 40, 39, 39, 39, 38, 38, 37,
		37, 36, 36, 36, 35, 35, 35, 34, 34, 34, 33, 33, 33, 33, 32, 32,
		32, 32, 31, 31, 31, 31, 30, 30, 30, 30, 29, 29, 29, 29, 29, 28,
		28, 28, 28, 28, 28, 27, 27, 27, 27, 27, 27, 26, 26, 26, 26, 26,
		26, 26, 25, 25, 25, 25, 25, 25, 25, 25, 24, 24, 24, 24, 24, 24,
		24, 24, 24, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 22, 22, 22,
		22, 22, 22, 22, 22, 22, 22, 22, 22, 21, 21, 21, 21, 21, 21, 21,
		21, 21, 21, 21, 21, 21, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
		20, 20, 20, 20, 20, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19,
		19, 19, 19, 19, 19, 19, 19, 18, 18, 18, 18, 18, 18, 18, 18, 18,
		18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 17, 17, 17, 17,
		17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
		17, 17, 17, 17
	};
	uint_fast32_t delta_usecs;
	uint_fast32_t inv_sqrt;
	div_t q;

	if (state->count >= ARRAY_SIZE(inv_sqrt_tab))
		inv_sqrt = 16;
	else
		inv_sqrt = inv_sqrt_tab[state->count];

	/* delta = state->interval / sqrt(count) */
	delta_usecs = state->interval.tv_sec * 1000000 + state->interval.tv_nsec/1000;
	delta_usecs = delta_usecs * inv_sqrt / 256;

	q = div(delta_usecs, 1000000);
	delta->tv_sec = q.quot;
	delta->tv_nsec = q.rem * 1000;
}

void gprs_codel_init(struct gprs_codel *state)
{
	static const struct gprs_codel init_state = {0};

	*state = init_state;
	gprs_codel_set_interval(state, -1);
	gprs_codel_set_maxpacket(state, -1);
}

void gprs_codel_set_interval(struct gprs_codel *state, int interval_ms)
{
	div_t q;

	if (interval_ms <= 0)
		interval_ms = GPRS_CODEL_DEFAULT_INTERVAL_MS;

	q = div(interval_ms, 1000);
	state->interval.tv_sec = q.quot;
	state->interval.tv_nsec = q.rem * 1000000;

	/* target ~ 5% of interval */
	q = div(interval_ms * 13 / 256, 1000);
	state->target.tv_sec = q.quot;
	state->target.tv_nsec = q.rem * 1000000;
}

void gprs_codel_set_maxpacket(struct gprs_codel *state, int maxpacket)
{

	if (maxpacket < 0)
		maxpacket = GPRS_CODEL_DEFAULT_MAXPACKET;

	state->maxpacket = maxpacket;
}

/*
 * This is an broken up variant of the algorithm being described in
 * http://queue.acm.org/appendices/codel.html
 */
int gprs_codel_control(struct gprs_codel *state, const struct timespec *recv,
	const struct timespec *now, int bytes)
{
	struct timespec sojourn_time;
	struct timespec delta;

	if (recv == NULL)
		goto stop_dropping;

	timespecsub(now, recv, &sojourn_time);

	if (timespeccmp(&sojourn_time, &state->target, <))
		goto stop_dropping;

	if (bytes >= 0 && (unsigned)bytes <= state->maxpacket)
		goto stop_dropping;

	if (!timespecisset(&state->first_above_time)) {
		timespecadd(now, &state->interval, &state->first_above_time);
		goto not_ok_to_drop;
	}

	if (timespeccmp(now, &state->first_above_time, <))
		goto not_ok_to_drop;

	/* Ok to drop */

	if (!state->dropping) {
		int recently = 0;
		int in_drop_cycle = 0;
		if (timespecisset(&state->drop_next)) {
			timespecsub(now, &state->drop_next, &delta);
			in_drop_cycle = timespeccmp(&delta, &state->interval, <);
			recently = in_drop_cycle;
		}
		if (!recently) {
			timespecsub(now, &state->first_above_time, &delta);
			recently = !timespeccmp(&delta, &state->interval, <);
		};
		if (!recently)
			return 0;

		state->dropping = 1;

		if (in_drop_cycle && state->count > 2)
			state->count -= 2;
		else
			state->count = 1;

		state->drop_next = *now;
	} else {
		if (timespeccmp(now, &state->drop_next, <))
			return 0;

		state->count += 1;
	}

	control_law(state, &delta);
	timespecadd(&state->drop_next, &delta, &state->drop_next);

#if 1
	LOGP(DRLCMAC, LOGL_INFO,
		"CoDel decided to drop packet, window = %d.%03dms, count = %d\n",
		(int)delta.tv_sec, (int)(delta.tv_nsec / 1000000), state->count);
#endif
	return 1;

stop_dropping:
	timespecclear(&state->first_above_time);
not_ok_to_drop:
	state->dropping = 0;
	return 0;
}
