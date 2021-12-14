/* gprs_codel.h
 *
 * This is an implementation of the CoDel algorithm based on the reference
 * pseudocode (see http://queue.acm.org/appendices/codel.html).
 * Instead of abstracting the queue itself, the following implementation
 * provides a time stamp based automaton. The main work is done by a single
 * decision function which updates the state and tells whether to pass or to
 * drop a packet after it has been taken from the queue.
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

#pragma once

#include <time.h>

/* Spec default values */
#define GPRS_CODEL_DEFAULT_INTERVAL_MS 100
#define GPRS_CODEL_DEFAULT_MAXPACKET 512

#ifdef __cplusplus
extern "C" {
#endif

struct gprs_codel {
	int dropping;
	unsigned count;
	struct timespec first_above_time;
	struct timespec drop_next;
	struct timespec target;
	struct timespec interval;
	unsigned maxpacket;
};

/*!
 * \brief Decide about packet drop and update CoDel state
 *
 * This function takes timing information and decides whether the packet in
 * question should be dropped in order to keep related queue in a 'good' state.
 * The function is meant to be called when the packet is dequeued.
 *
 * The CoDel state is updated by this function.
 *
 * \param state	 A pointer to the CoDel state of this queue
 * \param recv	 The time when the packet has entered the queue,
 *		 use NULL if dequeueing was not possible because the queue is
 *		 empty
 * \param now	 The current (dequeueing) time
 * \param bytes	 The number of bytes currently stored in the queue (-1 if
 *		 unknown)
 *
 * \return != 0 if the packet should be dropped, 0 otherwise
 */
int gprs_codel_control(struct gprs_codel *state, const struct timespec *recv,
	const struct timespec *now, int bytes);

/*!
 * \brief Initialise CoDel state
 *
 * This function initialises the CoDel state object. It sets the interval time
 * to the default value (GPRS_CODEL_DEFAULT_INTERVAL_MS).
 *
 * \param state		A pointer to the CoDel state of this queue
 */
void gprs_codel_init(struct gprs_codel *state);

/*!
 * \brief Set interval time
 *
 * This function changes the interval time.
 * The target time is derived from the interval time as proposed in the spec
 * (5% of interval time).
 *
 * \param state		A pointer to the CoDel state of this queue
 * \param interval_ms	The initial interval in ms to be used (<= 0 selects the
 *			default value)
 */
void gprs_codel_set_interval(struct gprs_codel *state, int interval_ms);

/*!
 * \brief Set max packet size
 *
 * This function changes the maxpacket value. If no more than this number of
 * bytes are still stored in the queue, no dropping will be done.
 *
 * \param state		A pointer to the CoDel state of this queue
 * \param maxpacket	The value in bytes
 */
void gprs_codel_set_maxpacket(struct gprs_codel *state, int maxpacket);

#ifdef __cplusplus
}
#endif
