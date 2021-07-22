/* tbf_fsm.c
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

#include <unistd.h>

#include <talloc.h>

#include <tbf_fsm.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_ms.h>
#include <encoding.h>
#include <bts.h>

#define X(s) (1 << (s))

const struct osmo_tdef_state_timeout tbf_fsm_timeouts[32] = {
	[TBF_ST_NULL] = {},
	[TBF_ST_ASSIGN] = { },
	[TBF_ST_FLOW] = { },
	[TBF_ST_FINISHED] = {},
	[TBF_ST_WAIT_RELEASE] = {},
	[TBF_ST_RELEASING] = {},
};

const struct value_string tbf_fsm_event_names[] = {
	{ TBF_EV_ASSIGN_ADD_CCCH, "ASSIGN_ADD_CCCH" },
	{ TBF_EV_ASSIGN_ADD_PACCH, "ASSIGN_ADD_PACCH" },
	{ TBF_EV_ASSIGN_DEL_CCCH, "ASSIGN_DEL_CCCH" },
	{ 0, NULL }
};

static void mod_ass_type(struct tbf_fsm_ctx *ctx, uint8_t t, bool set)
{
	const char *ch = "UNKNOWN";
	bool prev_set = ctx->state_flags & (1 << t);

	switch (t) {
	case GPRS_RLCMAC_FLAG_CCCH:
		ch = "CCCH";
		break;
	case GPRS_RLCMAC_FLAG_PACCH:
		ch = "PACCH";
		break;
	default:
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			"attempted to %sset unexpected ass. type %d - FIXME!\n",
			set ? "" : "un", t);
		return;
	}

	if (set && prev_set) {
		LOGPTBF(ctx->tbf, LOGL_ERROR,
			"attempted to set ass. type %s which is already set.\n", ch);
	} else if (!set && !prev_set) {
			return;
	}

	LOGPTBF(ctx->tbf, LOGL_INFO, "%sset ass. type %s [prev CCCH:%u, PACCH:%u]\n",
		set ? "" : "un", ch,
		!!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)),
		!!(ctx->state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)));

	if (set) {
		ctx->state_flags |= (1 << t);
	} else {
		ctx->state_flags &= GPRS_RLCMAC_FLAG_TO_MASK; /* keep to flags */
		ctx->state_flags &= ~(1 << t);
	}
}


static void st_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		tbf_fsm_state_chg(fi, tbf_direction(ctx->tbf) == GPRS_RLCMAC_DL_TBF ?
					TBF_ST_ASSIGN : TBF_ST_FLOW);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		tbf_fsm_state_chg(fi, TBF_ST_ASSIGN);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void st_assign(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_ASSIGN_ADD_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, true);
		break;
	case TBF_EV_ASSIGN_ADD_PACCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_PACCH, true);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void tbf_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	/* TODO: needed ?
	 * struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	 */
}

static int tbf_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->T) {
		default:
			break;
	}
	return 0;
}

static struct osmo_fsm_state tbf_fsm_states[] = {
	[TBF_ST_NULL] = {
		.in_event_mask =
			X(TBF_EV_ASSIGN_ADD_CCCH) |
			X(TBF_EV_ASSIGN_ADD_PACCH),
		.out_state_mask =
			X(TBF_ST_ASSIGN) |
			X(TBF_ST_FLOW) |
			X(TBF_ST_RELEASING),
		.name = "NULL",
		.action = st_null,
	},
	[TBF_ST_ASSIGN] = {
		.in_event_mask =
			X(TBF_EV_ASSIGN_ADD_CCCH) |
			X(TBF_EV_ASSIGN_ADD_PACCH),
		.out_state_mask =
			X(TBF_ST_FLOW) |
			X(TBF_ST_FINISHED) |
			X(TBF_ST_RELEASING),
		.name = "ASSIGN",
		.action = st_assign,
	},
	[TBF_ST_FLOW] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_FINISHED) |
			X(TBF_ST_WAIT_RELEASE) |
			X(TBF_ST_RELEASING),
		.name = "FLOW",
	},
	[TBF_ST_FINISHED] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_WAIT_RELEASE),
		.name = "FINISHED",
	},
	[TBF_ST_WAIT_RELEASE] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_RELEASING),
		.name = "WAIT_RELEASE",
	},
	[TBF_ST_RELEASING] = {
		.in_event_mask =
			0,
		.out_state_mask =
			0,
		.name = "RELEASING",
	},
};

void tbf_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct tbf_fsm_ctx *ctx = (struct tbf_fsm_ctx *)fi->priv;
	switch (event) {
	case TBF_EV_ASSIGN_DEL_CCCH:
		mod_ass_type(ctx, GPRS_RLCMAC_FLAG_CCCH, false);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

struct osmo_fsm tbf_fsm = {
	.name = "TBF",
	.states = tbf_fsm_states,
	.num_states = ARRAY_SIZE(tbf_fsm_states),
	.timer_cb = tbf_fsm_timer_cb,
	.cleanup = tbf_fsm_cleanup,
	.log_subsys = DTBF,
	.event_names = tbf_fsm_event_names,
	.allstate_action = tbf_fsm_allstate_action,
	.allstate_event_mask = X(TBF_EV_ASSIGN_DEL_CCCH),
};

static __attribute__((constructor)) void tbf_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_fsm) == 0);
}
