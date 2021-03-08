/* pdch_ul_controller.c
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
 * along with it program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <unistd.h>
#include <talloc.h>

#include "pdch_ul_controller.h"
#include "bts.h"
#include "sba.h"
#include "pdch.h"

/* TS 44.060 Table 10.4.5.1 states maximum RRBP is N + 26. Give extra space for time diff between Tx and Rx? */
#define MAX_FN_RESERVED (27 + 50)

const struct value_string pdch_ul_node_names[] = {
	{ PDCH_ULC_NODE_TBF_USF, "USF" },
	{ PDCH_ULC_NODE_TBF_POLL, "POLL" },
	{ PDCH_ULC_NODE_SBA, "SBA" },
	{ 0, NULL }
};

struct pdch_ulc *pdch_ulc_alloc(struct gprs_rlcmac_pdch *pdch, void *ctx)
{
	struct pdch_ulc* ulc;
	ulc = talloc_zero(ctx, struct pdch_ulc);
	if (!ulc)
		return ulc;

	ulc->pdch = pdch;
	ulc->pool_ctx = talloc_pool(ulc, sizeof(struct pdch_ulc_node) * MAX_FN_RESERVED);
	return ulc;
}

struct pdch_ulc_node *pdch_ulc_get_node(struct pdch_ulc *ulc, uint32_t fn)
{
	struct rb_node *node;
	struct pdch_ulc_node *it;
	for (node = rb_first(&ulc->tree_root); node; node = rb_next(node)) {
		it = container_of(node, struct pdch_ulc_node, node);
		if (it->fn == fn)
			return it;
		if (it->fn > fn)
			break;
	}
	return NULL;
}
struct pdch_ulc_node *pdch_ulc_pop_node(struct pdch_ulc *ulc, uint32_t fn)
{
	struct pdch_ulc_node *item = pdch_ulc_get_node(ulc, fn);
	if (!item)
		return NULL;
	rb_erase(&item->node, &ulc->tree_root);
	return item;
}

struct gprs_rlcmac_sba *pdch_ulc_get_sba(struct pdch_ulc *ulc, uint32_t fn)
{
	struct pdch_ulc_node *item = pdch_ulc_get_node(ulc, fn);
	if (!item || item->type != PDCH_ULC_NODE_SBA)
		return NULL;
	return item->sba.sba;
}

bool pdch_ulc_fn_is_free(struct pdch_ulc *ulc, uint32_t fn)
{
	return !pdch_ulc_get_node(ulc, fn);
}

static struct pdch_ulc_node *_alloc_node(struct pdch_ulc *ulc, uint32_t fn)
{
	struct pdch_ulc_node *node;
	node = talloc_zero(ulc->pool_ctx, struct pdch_ulc_node);
	node->fn = fn;
	return node;
}

static int pdch_ulc_add_node(struct pdch_ulc *ulc, struct pdch_ulc_node *item)
{
	struct rb_node **n = &(ulc->tree_root.rb_node);
	struct rb_node *parent = NULL;

	while (*n) {
		struct pdch_ulc_node *it;

		it = container_of(*n, struct pdch_ulc_node, node);

		parent = *n;
		if (item->fn < it->fn) {
			n = &((*n)->rb_left);
		} else if (item->fn > it->fn) {
			n = &((*n)->rb_right);
		} else {
			LOGPDCH(ulc->pdch, DRLCMAC, LOGL_ERROR,
				"Trying to reserve already reserved FN %u\n",
				item->fn);
			return -EEXIST;
		}
	}

	rb_link_node(&item->node, parent, n);
	rb_insert_color(&item->node, &ulc->tree_root);
	return 0;
}

int pdch_ulc_reserve_tbf_usf(struct pdch_ulc *ulc, uint32_t fn, struct gprs_rlcmac_ul_tbf *ul_tbf)
{
	return 0; /* TODO: implement */
}

int pdch_ulc_reserve_tbf_poll(struct pdch_ulc *ulc, uint32_t fn, struct gprs_rlcmac_tbf *tbf)
{
	return 0; /* TODO: implement */
}

int pdch_ulc_reserve_sba(struct pdch_ulc *ulc, struct gprs_rlcmac_sba *sba)
{
	struct pdch_ulc_node *item = _alloc_node(ulc, sba->fn);
	item->type = PDCH_ULC_NODE_SBA;
	item->sba.sba = sba;
	return pdch_ulc_add_node(ulc, item);
}

int pdch_ulc_release_fn(struct pdch_ulc *ulc, uint32_t fn)
{
	struct pdch_ulc_node *item = pdch_ulc_get_node(ulc, fn);
	if (!item)
		return -ENOKEY;
	rb_erase(&item->node, &ulc->tree_root);
	talloc_free(item);
	return 0;
}

void pdch_ulc_expire_fn(struct pdch_ulc *ulc, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;
	struct pdch_ulc_node *item;

	struct rb_node *first;
	while((first = rb_first(&ulc->tree_root))) {
		item = container_of(first, struct pdch_ulc_node, node);
		if (item->fn > fn)
			break;
		if (item->fn < fn) {
			/* Sanity check: */
			LOGPDCH(ulc->pdch, DRLCMAC, LOGL_ERROR,
				"Expiring FN=%" PRIu32 " but previous FN=%" PRIu32 " is still reserved!\n",
				fn, item->fn);
		}
		rb_erase(&item->node, &ulc->tree_root);

		switch (item->type) {
		case PDCH_ULC_NODE_TBF_USF:
			/* TODO: increase N3...*/
			break;
		case PDCH_ULC_NODE_TBF_POLL:
			/* TODO: increase N3...*/
			break;
		case PDCH_ULC_NODE_SBA:
			sba = item->sba.sba;
			LOGPDCH(sba->pdch, DRLCMAC, LOGL_NOTICE,
				"Timeout for registered SBA (FN=%u, TA=%u)\n",
				sba->fn, sba->ta);
			sba_timeout(sba);
			break;
		}

		talloc_free(item);
	}
}
