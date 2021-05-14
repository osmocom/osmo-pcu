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
	{ TBF_EV_FOOBAR, "FOOBAR" },
	{ 0, NULL }
};

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
			0,
		.out_state_mask =
			X(TBF_ST_ASSIGN) |
			X(TBF_ST_FLOW) |
			X(TBF_ST_RELEASING),
		.name = "NULL",
		//.action = st_null,
	},
	[TBF_ST_ASSIGN] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_FLOW) |
			X(TBF_ST_FINISHED) |
			X(TBF_ST_RELEASING),
		.name = "ASSIGN",
		//.onenter = st_assign_on_enter,
		//.action = st_assign,
	},
	[TBF_ST_FLOW] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_FINISHED) |
			X(TBF_ST_WAIT_RELEASE) |
			X(TBF_ST_RELEASING),
		.name = "FLOW",
		//.onenter = st_flow_on_enter,
		//.action = st_flow,
	},
	[TBF_ST_FINISHED] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_WAIT_RELEASE),
		.name = "FINISHED",
		//.onenter = st_finished_on_enter,
		//.action = st_finished,
	},
	[TBF_ST_WAIT_RELEASE] = {
		.in_event_mask =
			0,
		.out_state_mask =
			X(TBF_ST_RELEASING),
		.name = "WAIT_RELEASE",
		//.action = st_wait_release,
	},
	[TBF_ST_RELEASING] = {
		.in_event_mask =
			0,
		.out_state_mask =
			0,
		.name = "RELEASING",
		//.action = st_releasing,
	},
};

struct osmo_fsm tbf_fsm = {
	.name = "TBF",
	.states = tbf_fsm_states,
	.num_states = ARRAY_SIZE(tbf_fsm_states),
	.timer_cb = tbf_fsm_timer_cb,
	.cleanup = tbf_fsm_cleanup,
	.log_subsys = DTBF,
	.event_names = tbf_fsm_event_names,
};

static __attribute__((constructor)) void tbf_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&tbf_fsm) == 0);
}
