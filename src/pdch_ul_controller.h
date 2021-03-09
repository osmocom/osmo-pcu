/* pdch_ul_controller.h
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
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/utils.h>

struct gprs_rlcmac_pdch;
struct gprs_rlcmac_tbf;
struct gprs_rlcmac_ul_tbf;
struct gprs_rlcmac_sba;

struct pdch_ulc {
	struct gprs_rlcmac_pdch *pdch; /* back pointer */
	uint32_t last_fn; /* last FN rx from TDMA clock */
	struct rb_root tree_root;
	void *pool_ctx; /* talloc pool of struct pdch_ulc_node  */
};

enum PdchUlcNode {
	PDCH_ULC_NODE_TBF_USF,
	PDCH_ULC_NODE_TBF_POLL,
	PDCH_ULC_NODE_SBA,
};
extern const struct value_string pdch_ul_node_names[];

struct pdch_ulc_node {
	struct rb_node node;	  /*! entry in pdch_ulc->tree_root */
	uint32_t fn;
	enum PdchUlcNode type;
	union {
		struct {
			struct gprs_rlcmac_ul_tbf *ul_tbf;
		} tbf_usf;
		struct {
			struct gprs_rlcmac_tbf *poll_tbf;
		} tbf_poll;
		struct {
			struct gprs_rlcmac_sba *sba;
		} sba;
	};
};


struct pdch_ulc *pdch_ulc_alloc(struct gprs_rlcmac_pdch *pdch, void *ctx);

int pdch_ulc_reserve_tbf_usf(struct pdch_ulc *ulc, uint32_t fn, struct gprs_rlcmac_ul_tbf *ul_tbf);
int pdch_ulc_reserve_tbf_poll(struct pdch_ulc *ulc, uint32_t fn, struct gprs_rlcmac_tbf *tbf);
int pdch_ulc_reserve_sba(struct pdch_ulc *ulc, struct gprs_rlcmac_sba *sba);

bool pdch_ulc_fn_is_free(struct pdch_ulc *ulc, uint32_t fn);

int pdch_ulc_get_next_free_rrbp_fn(struct pdch_ulc *ulc, uint32_t fn, uint32_t *poll_fn, unsigned int *rrbp);

struct pdch_ulc_node *pdch_ulc_get_node(struct pdch_ulc *ulc, uint32_t fn);
struct pdch_ulc_node *pdch_ulc_pop_node(struct pdch_ulc *ulc, uint32_t fn);
struct gprs_rlcmac_sba *pdch_ulc_get_sba(struct pdch_ulc *ulc, uint32_t fn);

void pdch_ulc_release_tbf(struct pdch_ulc *ulc, const struct gprs_rlcmac_tbf *tbf);

int pdch_ulc_release_fn(struct pdch_ulc *ulc, uint32_t fn);

void pdch_ulc_expire_fn(struct pdch_ulc *ulc, uint32_t fn);
