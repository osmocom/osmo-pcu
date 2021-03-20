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
#include "pcu_utils.h"

/* TS 44.060 Table 10.4.5.1 states maximum RRBP is N + 26. Give extra space for time diff between Tx and Rx? */
#define MAX_FN_RESERVED (27 + 50)

const struct value_string pdch_ul_node_names[] = {
	{ PDCH_ULC_NODE_TBF_USF, "USF" },
	{ PDCH_ULC_NODE_TBF_POLL, "POLL" },
	{ PDCH_ULC_NODE_SBA, "SBA" },
	{ 0, NULL }
};

#define GSM_MAX_FN_THRESH (GSM_MAX_FN >> 1)
/* 0: equal, -1: fn1 BEFORE fn2, 1: fn1 AFTER fn2 */
static inline int fn_cmp(uint32_t fn1, uint32_t fn2)
{
	if (fn1 == fn2)
		return 0;
	/* FN1 goes before FN2: */
	if ((fn1 < fn2 && (fn2 - fn1) < GSM_MAX_FN_THRESH) ||
	    (fn1 > fn2 && (fn1 - fn2) > GSM_MAX_FN_THRESH))
		return -1;
	/* FN1 goes after FN2: */
	return 1;
}

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
	int res;
	for (node = rb_first(&ulc->tree_root); node; node = rb_next(node)) {
		it = container_of(node, struct pdch_ulc_node, node);
		res = fn_cmp(it->fn, fn);
		if (res == 0) /* it->fn == fn */
			return it;
		if (res > 0) /* it->fn AFTER fn */
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

struct gprs_rlcmac_tbf *pdch_ulc_get_tbf_poll(struct pdch_ulc *ulc, uint32_t fn)
{
	struct pdch_ulc_node *item = pdch_ulc_get_node(ulc, fn);
	if (!item || item->type != PDCH_ULC_NODE_TBF_POLL)
		return NULL;
	return item->tbf_poll.poll_tbf;
}

bool pdch_ulc_fn_is_free(struct pdch_ulc *ulc, uint32_t fn)
{
	return !pdch_ulc_get_node(ulc, fn);
}

int pdch_ulc_get_next_free_rrbp_fn(struct pdch_ulc *ulc, uint32_t fn, uint32_t *poll_fn, unsigned int *rrbp)
{
	/* TODO: support other RRBP offsets, see TS 44.060 able 10.4.5.1 */
	uint32_t new_poll_fn = next_fn(fn, 13);
	if (!pdch_ulc_fn_is_free(ulc, new_poll_fn)) {
		LOGPDCH(ulc->pdch, DRLCMAC, LOGL_ERROR, "Polling is already scheduled "
			"for single block allocation at FN=%u\n", fn);
		return -EBUSY;
	}

	*poll_fn = new_poll_fn;
	*rrbp = 0;

	return 0;
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
		int res;

		it = container_of(*n, struct pdch_ulc_node, node);

		parent = *n;
		res = fn_cmp(item->fn, it->fn);
		if (res < 0) { /* item->fn "BEFORE" it->fn */
			n = &((*n)->rb_left);
		} else if (res > 0) { /* item->fn "AFTER" it->fn */
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
	struct pdch_ulc_node *item = _alloc_node(ulc, fn);
	item->type = PDCH_ULC_NODE_TBF_POLL;
	item->tbf_poll.poll_tbf = tbf;
	return pdch_ulc_add_node(ulc, item);
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

void pdch_ulc_release_tbf(struct pdch_ulc *ulc, const struct gprs_rlcmac_tbf *tbf)
{
	bool tree_modified;
	do {
		struct rb_node *node;
		struct pdch_ulc_node *item;
		const struct gprs_rlcmac_tbf *item_tbf;

		tree_modified = false;
		for (node = rb_first(&ulc->tree_root); node; node = rb_next(node)) {
			item = container_of(node, struct pdch_ulc_node, node);
			switch (item->type) {
			case PDCH_ULC_NODE_SBA:
				continue;
			case PDCH_ULC_NODE_TBF_POLL:
				item_tbf = item->tbf_poll.poll_tbf;
				break;
			case PDCH_ULC_NODE_TBF_USF:
				item_tbf = (struct gprs_rlcmac_tbf *)item->tbf_usf.ul_tbf;
				break;
			default:
				OSMO_ASSERT(0);
			}
			if (item_tbf != tbf)
				continue;
			/* One entry found, remove it from tree and restart
			 * search from start (to avoid traverse continue from
			 * no-more existant node */
			tree_modified = true;
			rb_erase(&item->node, &ulc->tree_root);
			talloc_free(item);
			break;
		}
	} while (tree_modified);
}

void pdch_ulc_expire_fn(struct pdch_ulc *ulc, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;
	struct pdch_ulc_node *item;
	int res;

	struct rb_node *first;
	while((first = rb_first(&ulc->tree_root))) {
		item = container_of(first, struct pdch_ulc_node, node);
		res = fn_cmp(item->fn, fn);
		if (res > 0) /* item->fn AFTER fn */
			break;
		if (res < 0) { /* item->fn BEFORE fn */
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
			LOGPDCH(ulc->pdch, DRLCMAC, LOGL_NOTICE,
				"Timeout for registered POLL (FN=%u): %s\n",
				item->fn, tbf_name(item->tbf_poll.poll_tbf));
			tbf_poll_timeout(item->tbf_poll.poll_tbf);
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
