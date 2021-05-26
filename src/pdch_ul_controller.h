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

/* RRBP offsets, see TS 44.060 able 10.4.5.1 */
enum rrbp_field {
	RRBP_N_plus_13 = 0x0,
	RRBP_N_plus_17_18 = 0x1,
	RRBP_N_plus_21_22 = 0x2,
	RRBP_N_plus_26 = 0x3,
};

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

enum pdch_ulc_tbf_poll_reason {
	PDCH_ULC_POLL_UL_ASS, /* Expect CTRL ACK for UL ASS we transmit */
	PDCH_ULC_POLL_DL_ASS, /* Expect CTRL ACK for DL ASS we transmit */
	PDCH_ULC_POLL_UL_ACK, /* Expect CTRL ACK (or PKT RES REQ on final UL ACK/NACK) for UL ACK/NACK we transmit */
	PDCH_ULC_POLL_DL_ACK, /* Expect DL ACK/NACK requested by RRBP */
	PDCH_ULC_POLL_CELL_CHG_CONTINUE, /* Expect CTRL ACK for Pkt cell Change Continue we transmit */
	PDCH_ULC_POLL_MEAS_ORDER, /* Expect CTRL ACK for Pkt Measurement Order we transmit */
};
extern const struct value_string pdch_ulc_tbf_poll_reason_names[];

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
			enum pdch_ulc_tbf_poll_reason reason;
		} tbf_poll;
		struct {
			struct gprs_rlcmac_sba *sba;
		} sba;
	};
};


struct pdch_ulc *pdch_ulc_alloc(struct gprs_rlcmac_pdch *pdch, void *ctx);

int pdch_ulc_reserve_tbf_usf(struct pdch_ulc *ulc, uint32_t fn, struct gprs_rlcmac_ul_tbf *ul_tbf);
int pdch_ulc_reserve_tbf_poll(struct pdch_ulc *ulc, uint32_t fn, struct gprs_rlcmac_tbf *tbf, enum pdch_ulc_tbf_poll_reason reason);
int pdch_ulc_reserve_sba(struct pdch_ulc *ulc, struct gprs_rlcmac_sba *sba);

bool pdch_ulc_fn_is_free(struct pdch_ulc *ulc, uint32_t fn);

int pdch_ulc_get_next_free_rrbp_fn(struct pdch_ulc *ulc, uint32_t fn, uint32_t *poll_fn, unsigned int *rrbp);
uint32_t pdch_ulc_get_next_free_fn(struct pdch_ulc *ulc, uint32_t start_fn);

struct pdch_ulc_node *pdch_ulc_get_node(struct pdch_ulc *ulc, uint32_t fn);
struct pdch_ulc_node *pdch_ulc_pop_node(struct pdch_ulc *ulc, uint32_t fn);
struct gprs_rlcmac_sba *pdch_ulc_get_sba(struct pdch_ulc *ulc, uint32_t fn);
struct gprs_rlcmac_tbf *pdch_ulc_get_tbf_poll(struct pdch_ulc *ulc, uint32_t fn);

void pdch_ulc_release_node(struct pdch_ulc *ulc, struct pdch_ulc_node *item);
void pdch_ulc_release_tbf(struct pdch_ulc *ulc, const struct gprs_rlcmac_tbf *tbf);
int pdch_ulc_release_fn(struct pdch_ulc *ulc, uint32_t fn);

void pdch_ulc_expire_fn(struct pdch_ulc *ulc, uint32_t fn);
