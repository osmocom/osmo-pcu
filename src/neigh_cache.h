/* neigh_cache.h
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
 */
#pragma once

#include <stdint.h>
#include <inttypes.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

////////////////////
// NEIGH CACHE
///////////////////

/* ARFC+BSIC -> CGI PS cache */
struct neigh_cache {
	struct llist_head list; /* list of neigh_cache_entry items */
	struct osmo_timer_list cleanup_timer; /* Timer removing too-old entries */
	struct timespec keep_time_intval;
};

struct neigh_cache_entry_key {
	uint16_t local_lac;
	uint16_t local_ci;
	uint16_t tgt_arfcn;
	uint8_t tgt_bsic;
};
#define NEIGH_CACHE_ENTRY_KEY_FMT "%" PRIu16 "-%" PRIu16 "-%" PRIu16 "-%" PRIu8
#define NEIGH_CACHE_ENTRY_KEY_ARGS(key) (key)->local_lac, (key)->local_ci, (key)->tgt_arfcn, (key)->tgt_bsic

static inline bool neigh_cache_entry_key_eq(const struct neigh_cache_entry_key *a,
					    const struct neigh_cache_entry_key *b)
{
	return a->local_lac == b->local_lac &&
	       a->local_ci == b->local_ci &&
	       a->tgt_arfcn == b->tgt_arfcn &&
	       a->tgt_bsic == b->tgt_bsic;
}

struct neigh_cache_entry {
	struct llist_head list; /* to be included in neigh_cache->list */
	struct timespec update_ts;
	struct neigh_cache_entry_key key;
	struct osmo_cell_global_id_ps value;
};

struct neigh_cache *neigh_cache_alloc(void *ctx, unsigned int keep_time_sec);
void neigh_cache_set_keep_time_interval(struct neigh_cache *cache, unsigned int keep_time_sec);
struct neigh_cache_entry *neigh_cache_add(struct neigh_cache *cache,
					  const struct neigh_cache_entry_key *key,
					  const struct osmo_cell_global_id_ps *value);
const struct osmo_cell_global_id_ps *neigh_cache_lookup_value(struct neigh_cache *cache,
							      const struct neigh_cache_entry_key *key);
void neigh_cache_free(struct neigh_cache *cache);


////////////////////
// SI CACHE
///////////////////

/* CGI-PS-> SI cache */
struct si_cache {
	struct llist_head list; /* list of si_cache_entry items */
	struct osmo_timer_list cleanup_timer; /* Timer removing too-old entries */
	struct timespec keep_time_intval;
};

struct si_cache_value {
	uint8_t si_buf[BSSGP_RIM_PSI_LEN * 127]; /* 3GPP TS 48.018 11.3.63.2.1 */
	size_t si_len;
	bool type_psi;
};

struct si_cache_entry {
	struct llist_head list; /* to be included in si_cache->list */
	struct timespec update_ts;
	struct osmo_cell_global_id_ps key;
	struct si_cache_value value;
};

struct si_cache *si_cache_alloc(void *ctx, unsigned int keep_time_sec);
void si_cache_set_keep_time_interval(struct si_cache *cache, unsigned int keep_time_sec);
struct si_cache_entry *si_cache_add(struct si_cache *cache,
				    const struct osmo_cell_global_id_ps *key,
				    const struct si_cache_value *value);
struct si_cache_entry *si_cache_lookup_entry(struct si_cache *cache,
					     const struct osmo_cell_global_id_ps *key);
const struct si_cache_value *si_cache_lookup_value(struct si_cache *cache,
						   const struct osmo_cell_global_id_ps *key);
void si_cache_free(struct si_cache *cache);
