/* si_cache.c
 *
 * Copyright (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <string.h>
#include <talloc.h>
#include <inttypes.h>

#include <osmocom/core/utils.h>

#include <neigh_cache.h>
#include <gprs_debug.h>

#define KEEP_TIME_DEFAULT_SEC 5

/*TODO: add a timer to the_pcu T_defs, pass value to struct neigh_cache instead of KEEP_TIME_DEFAULT_SEC */

static inline bool neigh_cache_entry_key_eq(const struct neigh_cache_entry_key *a,
					    const struct neigh_cache_entry_key *b)
{
	return a->local_lac == b->local_lac &&
	       a->local_ci == b->local_ci &&
	       a->tgt_arfcn == b->tgt_arfcn &&
	       a->tgt_bsic == b->tgt_bsic;
}

static void neigh_cache_schedule_cleanup(struct neigh_cache *cache);
static void neigh_cache_cleanup_cb(void *data)
{
	struct timespec now, threshold;
	struct neigh_cache *cache = (struct neigh_cache *)data;
	struct neigh_cache_entry *it, *tmp;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	/* Instead of adding keep_time_intval to each, substract it from now once */
	timespecsub(&now, &cache->keep_time_intval, &threshold);

	llist_for_each_entry_safe(it, tmp, &cache->list, list) {
		if (timespeccmp(&threshold, &it->update_ts, <))
			break;
		LOGP(DNACC, LOGL_DEBUG,
		     "neigh_cache: Removing entry " NEIGH_CACHE_ENTRY_KEY_FMT " => %s\n",
		     NEIGH_CACHE_ENTRY_KEY_ARGS(&it->key), osmo_cgi_ps_name(&it->value));
		llist_del(&it->list);
		talloc_free(it);
	}

	neigh_cache_schedule_cleanup(cache);
}

static void neigh_cache_schedule_cleanup(struct neigh_cache *cache)
{
	struct neigh_cache_entry *it;
	struct timespec now, threshold, result;

	/* First item is the one with oldest update_ts */
	it = llist_first_entry_or_null(&cache->list, struct neigh_cache_entry, list);
	if (!it)
		return;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	timespecadd(&it->update_ts, &cache->keep_time_intval, &threshold);

	if (timespeccmp(&now, &threshold, >=)) {
		/* Too late, let's flush asynchonously so newly added isn't
		 * immediatelly freed before return. */
		result = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	} else {
		timespecsub(&threshold, &now, &result);
	}
	osmo_timer_schedule(&cache->cleanup_timer, result.tv_sec, result.tv_nsec*1000);
}

struct neigh_cache *neigh_cache_alloc(void *ctx)
{
	struct neigh_cache *cache = talloc_zero(ctx, struct neigh_cache);
	OSMO_ASSERT(cache);
	INIT_LLIST_HEAD(&cache->list);
	osmo_timer_setup(&cache->cleanup_timer, neigh_cache_cleanup_cb, cache);
	cache->keep_time_intval = (struct timespec){ .tv_sec = KEEP_TIME_DEFAULT_SEC, .tv_nsec = 0};
	return cache;

}
struct neigh_cache_entry *neigh_cache_add(struct neigh_cache *cache,
					  const struct neigh_cache_entry_key *key,
					  const struct osmo_cell_global_id_ps *value)
{
	struct neigh_cache_entry *it;

	/* First check if it already exists. If so, simply update timer+value */
	it = neigh_cache_lookup_entry(cache, key);
	if (!it) {
		LOGP(DNACC, LOGL_DEBUG,
		     "neigh_cache: Inserting new entry " NEIGH_CACHE_ENTRY_KEY_FMT " => %s\n",
		     NEIGH_CACHE_ENTRY_KEY_ARGS(key), osmo_cgi_ps_name(value));
		it = talloc_zero(cache, struct neigh_cache_entry);
		OSMO_ASSERT(it);
		memcpy(&it->key, key, sizeof(it->key));
	} else {
		LOGP(DNACC, LOGL_DEBUG,
		     "neigh_cache: Updating entry " NEIGH_CACHE_ENTRY_KEY_FMT " => (%s -> %s)\n",
		     NEIGH_CACHE_ENTRY_KEY_ARGS(key), osmo_cgi_ps_name(&it->value), osmo_cgi_ps_name2(value));
		/* remove item, we'll add it to the end to have them sorted by last update */
		llist_del(&it->list);
	}

	memcpy(&it->value, value, sizeof(it->value));
	OSMO_ASSERT(osmo_clock_gettime(CLOCK_MONOTONIC, &it->update_ts) == 0);
	llist_add_tail(&it->list, &cache->list);
	neigh_cache_schedule_cleanup(cache);
	return it;
}

struct neigh_cache_entry *neigh_cache_lookup_entry(struct neigh_cache *cache,
						   const struct neigh_cache_entry_key *key)
{
	struct neigh_cache_entry *tmp;
	llist_for_each_entry(tmp, &cache->list, list) {
		if (neigh_cache_entry_key_eq(&tmp->key, key))
			return tmp;
	}
	return NULL;
}

const struct osmo_cell_global_id_ps *neigh_cache_lookup_value(struct neigh_cache *cache,
							      const struct neigh_cache_entry_key *key)
{
	struct neigh_cache_entry *it = neigh_cache_lookup_entry(cache, key);
	if (it)
		return &it->value;
	return NULL;
}

void neigh_cache_free(struct neigh_cache *cache)
{
	struct neigh_cache_entry *it, *tmp;
	if (!cache)
		return;

	llist_for_each_entry_safe(it, tmp, &cache->list, list) {
		llist_del(&it->list);
		talloc_free(it);
	}
	osmo_timer_del(&cache->cleanup_timer);
	talloc_free(cache);
}


////////////////////
// SI CACHE
///////////////////

/*TODO: add a timer to the_pcu T_defs, pass value to struct neigh_cache instead of KEEP_TIME_DEFAULT_SEC */

static void si_cache_schedule_cleanup(struct si_cache *cache);
static void si_cache_cleanup_cb(void *data)
{
	struct timespec now, threshold;
	struct si_cache *cache = (struct si_cache *)data;
	struct si_cache_entry *it, *tmp;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	/* Instead of adding keep_time_intval to each, substract it from now once */
	timespecsub(&now, &cache->keep_time_intval, &threshold);

	llist_for_each_entry_safe(it, tmp, &cache->list, list) {
		if (timespeccmp(&threshold, &it->update_ts, <))
			break;
		LOGP(DNACC, LOGL_DEBUG, "si_cache: Removing entry %s\n",
		     osmo_cgi_ps_name(&it->key));
		llist_del(&it->list);
		talloc_free(it);
	}

	si_cache_schedule_cleanup(cache);
}

static void si_cache_schedule_cleanup(struct si_cache *cache)
{
	struct si_cache_entry *it;
	struct timespec now, threshold, result;

	/* First item is the one with oldest update_ts */
	it = llist_first_entry_or_null(&cache->list, struct si_cache_entry, list);
	if (!it)
		return;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);

	timespecadd(&it->update_ts, &cache->keep_time_intval, &threshold);

	if (timespeccmp(&now, &threshold, >=)) {
		/* Too late, let's flush asynchonously so newly added isn't
		 * immediatelly freed before return. */
		result = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
	} else {
		timespecsub(&threshold, &now, &result);
	}
	osmo_timer_schedule(&cache->cleanup_timer, result.tv_sec, result.tv_nsec*1000);
}

struct si_cache *si_cache_alloc(void *ctx)
{
	struct si_cache *cache = talloc_zero(ctx, struct si_cache);
	OSMO_ASSERT(cache);
	INIT_LLIST_HEAD(&cache->list);
	osmo_timer_setup(&cache->cleanup_timer, si_cache_cleanup_cb, cache);
	cache->keep_time_intval = (struct timespec){ .tv_sec = KEEP_TIME_DEFAULT_SEC, .tv_nsec = 0};
	return cache;
}
struct si_cache_entry *si_cache_add(struct si_cache *cache,
				    const struct osmo_cell_global_id_ps *key,
				    const struct si_cache_value *value)
{
	struct si_cache_entry *it;

	/* First check if it already exists. If so, simply update timer+value */
	it = si_cache_lookup_entry(cache, key);
	if (!it) {
		LOGP(DNACC, LOGL_DEBUG, "si_cache: Inserting new entry %s\n",
		     osmo_cgi_ps_name(key));
		it = talloc_zero(cache, struct si_cache_entry);
		OSMO_ASSERT(it);
		memcpy(&it->key, key, sizeof(it->key));
	} else {
		LOGP(DNACC, LOGL_DEBUG, "si_cache: Updating entry %s\n",
		     osmo_cgi_ps_name(&it->key));
		/* remove item, we'll add it to the end to have them sorted by last update */
		llist_del(&it->list);
	}

	memcpy(&it->value, value, sizeof(it->value));
	OSMO_ASSERT(osmo_clock_gettime(CLOCK_MONOTONIC, &it->update_ts) == 0);
	llist_add_tail(&it->list, &cache->list);
	si_cache_schedule_cleanup(cache);
	return it;
}

struct si_cache_entry *si_cache_lookup_entry(struct si_cache *cache,
					     const struct osmo_cell_global_id_ps *key)
{
	struct si_cache_entry *tmp;
	llist_for_each_entry(tmp, &cache->list, list) {
		if (osmo_cgi_ps_cmp(&tmp->key, key) == 0)
			return tmp;
	}
	return NULL;
}

const struct si_cache_value *si_cache_lookup_value(struct si_cache *cache,
						   const struct osmo_cell_global_id_ps *key)
{
	struct si_cache_entry *it = si_cache_lookup_entry(cache, key);
	if (it)
		return &it->value;
	return NULL;
}

void si_cache_free(struct si_cache *cache)
{
	struct si_cache_entry *it, *tmp;
	if (!cache)
		return;

	llist_for_each_entry_safe(it, tmp, &cache->list, list) {
		llist_del(&it->list);
		talloc_free(it);
	}
	osmo_timer_del(&cache->cleanup_timer);
	talloc_free(cache);
}
