/* gsm_timer.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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
 
/* These store the amount of frame number that we wait until next timer expires. */
static int nearest;
static int *nearest_p;

/*! \addtogroup gsm_timer
 *  @{
 */

/*! \file gsm_timer.cpp
 */

#include <assert.h>
#include <string.h>
#include <limits.h>
#include <gsm_timer.h>
#include <pcu_l1_if.h>

static struct rb_root timer_root = RB_ROOT;

static void __add_gsm_timer(struct osmo_gsm_timer_list *timer)
{
	struct rb_node **new_node = &(timer_root.rb_node);
	struct rb_node *parent = NULL;

	while (*new_node) {
		struct osmo_gsm_timer_list *this_timer;

		this_timer = container_of(*new_node, struct osmo_gsm_timer_list, node);

		parent = *new_node;
		if (timer->fn < this_timer->fn)
			new_node = &((*new_node)->rb_left);
		else
			new_node = &((*new_node)->rb_right);
		}

		rb_link_node(&timer->node, parent, new_node);
		rb_insert_color(&timer->node, &timer_root);
}

/*! \brief add a new timer to the timer management
 *  \param[in] timer the timer that should be added
 */
void osmo_gsm_timer_add(struct osmo_gsm_timer_list *timer)
{
	osmo_gsm_timer_del(timer);
	timer->active = 1;
	INIT_LLIST_HEAD(&timer->list);
	__add_gsm_timer(timer);
}

/*! \brief schedule a gsm timer at a given future relative time
 *  \param[in] timer the to-be-added timer
 *  \param[in] number of frames from now
 *
 * This function can be used to (re-)schedule a given timer at a
 * specified number of frames in the future.  It will
 * internally add it to the timer management data structures, thus
 * osmo_timer_add() is automatically called.
 */
void
osmo_gsm_timer_schedule(struct osmo_gsm_timer_list *timer, int fn)
{
	int current_fn;

	current_fn = get_current_fn();
	timer->fn = current_fn + fn;
	osmo_gsm_timer_add(timer);
}

/*! \brief delete a gsm timer from timer management
 *  \param[in] timer the to-be-deleted timer
 *
 * This function can be used to delete a previously added/scheduled
 * timer from the timer management code.
 */
void osmo_gsm_timer_del(struct osmo_gsm_timer_list *timer)
{
	if (timer->active) {
		timer->active = 0;
		rb_erase(&timer->node, &timer_root);
		/* make sure this is not already scheduled for removal. */
		if (!llist_empty(&timer->list))
			llist_del_init(&timer->list);
	}
}

/*! \brief check if given timer is still pending
 *  \param[in] timer the to-be-checked timer
 *  \return 1 if pending, 0 otherwise
 *
 * This function can be used to determine whether a given timer
 * has alredy expired (returns 0) or is still pending (returns 1)
 */
int osmo_gsm_timer_pending(struct osmo_gsm_timer_list *timer)
{
	return timer->active;
}

/*
 * if we have a nearest frame number return the delta between the current
 * FN and the FN of the nearest timer.
 * If the nearest timer timed out return NULL and then we will
 * dispatch everything after the select
 */
int *osmo_gsm_timers_nearest(void)
{
	/* nearest_p is exactly what we need already: NULL if nothing is
	 * waiting, {0,0} if we must dispatch immediately, and the correct
	 * delay if we need to wait */
	return nearest_p;
}

static void update_nearest(int *cand, int *current)
{
	if (*cand != LONG_MAX) {
		if (*cand > *current)
			nearest = *cand - *current;
		else {
			/* loop again inmediately */
			nearest = 0;
		}
		nearest_p = &nearest;
	} else {
		nearest_p = NULL;
	}
}

/*
 * Find the nearest FN and update s_nearest_time
 */
void osmo_gsm_timers_prepare(void)
{
	struct rb_node *node;
	int current_fn;

	current_fn = get_current_fn();

	node = rb_first(&timer_root);
	if (node) {
		struct osmo_gsm_timer_list *this_timer;
		this_timer = container_of(node, struct osmo_gsm_timer_list, node);
		update_nearest(&this_timer->fn, &current_fn);
	} else {
		nearest_p = NULL;
	}
}

/*
 * fire all timers... and remove them
 */
int osmo_gsm_timers_update(void)
{
	int current_fn;
	struct rb_node *node;
	struct llist_head timer_eviction_list;
	struct osmo_gsm_timer_list *this_timer;
	int work = 0;

	current_fn = get_current_fn();

	INIT_LLIST_HEAD(&timer_eviction_list);
	for (node = rb_first(&timer_root); node; node = rb_next(node)) {
		this_timer = container_of(node, struct osmo_gsm_timer_list, node);

		if (this_timer->fn > current_fn)
			break;

		llist_add(&this_timer->list, &timer_eviction_list);
	}

	/*
	 * The callbacks might mess with our list and in this case
	 * even llist_for_each_entry_safe is not safe to use. To allow
	 * osmo_gsm_timer_del to be called from within the callback we need
	 * to restart the iteration for each element scheduled for removal.
	 *
	 * The problematic scenario is the following: Given two timers A
	 * and B that have expired at the same time. Thus, they are both
	 * in the eviction list in this order: A, then B. If we remove
	 * timer B from the A's callback, we continue with B in the next
	 * iteration step, leading to an access-after-release.
	 */
restart:
	llist_for_each_entry(this_timer, &timer_eviction_list, list) {
		osmo_gsm_timer_del(this_timer);
		this_timer->cb(this_timer->data);
		work = 1;
		goto restart;
	}

	return work;
}

int osmo_gsm_timers_check(void)
{
	struct rb_node *node;
	int i = 0;

	for (node = rb_first(&timer_root); node; node = rb_next(node)) {
		i++;
	}
	return i;
}

/*! }@ */

