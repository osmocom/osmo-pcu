/* gsm_timer.h
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

/*! \defgroup timer GSM timers
 *  @{
 */

/*! \file gsm_timer.h
 *  \brief GSM timer handling routines
 */
#ifndef GSM_TIMER_H
#define GSM_TIMER_H

extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/linuxrbtree.h>
}
/**
 * Timer management:
 *      - Create a struct osmo_gsm_timer_list
 *      - Fill out timeout and use add_gsm_timer or
 *        use schedule_gsm_timer to schedule a timer in
 *        x frames from now...
 *      - Use del_gsm_timer to remove the timer
 *
 *  Internally:
 *      - We hook into select.c to give a frame number of the
 *        nearest timer. On already passed timers we give
 *        it a 0 to immediately fire after the select.
 *      - update_gsm_timers will call the callbacks and remove
 *        the timers.
 *
 */
/*! \brief A structure representing a single instance of a gsm timer */
struct osmo_gsm_timer_list {
	struct rb_node node;	  /*!< \brief rb-tree node header */
	struct llist_head list;   /*!< \brief internal list header */
	int fn;                   /*!< \brief expiration frame number */
	unsigned int active  : 1; /*!< \brief is it active? */

	void (*cb)(void*);	  /*!< \brief call-back called at timeout */
	void *data;		  /*!< \brief user data for callback */
};

/**
 * timer management
 */

void osmo_gsm_timer_add(struct osmo_gsm_timer_list *timer);

void osmo_gsm_timer_schedule(struct osmo_gsm_timer_list *timer, int fn);

void osmo_gsm_timer_del(struct osmo_gsm_timer_list *timer);

int osmo_gsm_timer_pending(struct osmo_gsm_timer_list *timer);


/*
 * internal timer list management
 */
int *osmo_gsm_timers_nearest(void);
void osmo_gsm_timers_prepare(void);
int osmo_gsm_timers_update(void);
int osmo_gsm_timers_check(void);

/*! }@ */

#endif // GSM_TIMER_H
