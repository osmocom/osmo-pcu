/*
 * (C) 2022 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <er_ccu_if.h>
#include <er_ccu_descr.h>
#include <string.h>
#include <errno.h>

#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/abis.h>
#include <osmocom/trau/trau_sync.h>
#include <osmocom/trau/trau_pcu_ericsson.h>
#include <bts.h>
#include <gprs_debug.h>
#include <pcu_l1_if.h>

#define E1_TS_BYTES 160
#define DEBUG_BITS_MAX 1280
#define DEBUG_BYTES_MAX 40

#define LOGPCCU(ccu_descr, level, tag, fmt, args...) \
	LOGP(DE1, level, "E1TS(%u:%u:%u) %s:" fmt, \
	     ccu_descr->e1_conn_pars->e1_nr, ccu_descr->e1_conn_pars->e1_ts, \
	     ccu_descr->e1_conn_pars->e1_ts_ss == E1_SUBSLOT_FULL ? 0 : ccu_descr->e1_conn_pars->e1_ts_ss, tag, \
	     ## args)

struct e1_ts_descr {
	uint8_t usecount;
	bool i460_ts_initialized;
	struct osmo_i460_timeslot i460_ts;
};

struct e1_line_descr {
	struct e1_ts_descr e1_ts[NUM_E1_TS - 1];
};

static struct e1_line_descr e1_lines[32];
static void *tall_ccu_ctx = NULL;

static const struct e1inp_line_ops dummy_e1_line_ops = {
	.sign_link_up = NULL,
	.sign_link_down = NULL,
	.sign_link = NULL,
};

/* called by trau frame synchronizer: feed received MAC blocks into PCU */
static void sync_frame_out_cb(void *user_data, const ubit_t *bits, unsigned int num_bits)
{
	struct er_ccu_descr *ccu_descr = user_data;

	if (!bits || num_bits == 0)
		return;

	LOGPCCU(ccu_descr, LOGL_DEBUG, "I.460-RX", "receiving %u TRAU frame bits from subslot (synchronized): %s...\n",
		num_bits, osmo_ubit_dump(bits, num_bits > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : num_bits));

	ccu_descr->er_ccu_rx_cb(ccu_descr, bits, num_bits);
}

/* called by I.460 de-multiplexer: feed output of I.460 demux into TRAU frame sync */
static void e1_i460_demux_bits_cb(struct osmo_i460_subchan *schan, void *user_data, const ubit_t *bits,
				  unsigned int num_bits)
{
	struct er_ccu_descr *ccu_descr = user_data;

	LOGPCCU(ccu_descr, LOGL_DEBUG, "I.460-RX", "receiving %u TRAU frame bits from subslot: %s...\n", num_bits,
		osmo_ubit_dump(bits, num_bits > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : num_bits));

	OSMO_ASSERT(ccu_descr->link.trau_sync_fi);
	osmo_trau_sync_rx_ubits(ccu_descr->link.trau_sync_fi, bits, num_bits);

}

/* called by I.460 de-multiplexer: ensure that sync indications are sent when mux buffer runs empty */
static void e1_i460_mux_empty_cb(struct osmo_i460_subchan *schan2, void *user_data)
{
	struct er_ccu_descr *ccu_descr = user_data;

	LOGPCCU(ccu_descr, LOGL_DEBUG, "I.460-TX", "demux buffer empty\n");
	ccu_descr->er_ccu_empty_cb(ccu_descr);
}

/* handle outgoing E1 traffic */
static void e1_send_ts_frame(struct e1inp_ts *ts)
{
	void *ctx = tall_ccu_ctx;
	struct e1_ts_descr *ts_descr;
	struct msgb *msg;
	uint8_t *ptr;

	/* The line number and ts number that arrives here should be clean. */
	OSMO_ASSERT(ts->line->num < ARRAY_SIZE(e1_lines));

	ts_descr = &e1_lines[ts->line->num].e1_ts[ts->num];

	/* Do not send anything in case the E1 timeslot is not ready. */
	if (ts_descr->usecount == 0)
		return;

	/* Get E1 frame from I.460 multiplexer */
	msg = msgb_alloc_c(ctx, E1_TS_BYTES, "E1-TX-timeslot-bytes");
	ptr = msgb_put(msg, E1_TS_BYTES);
	osmo_i460_mux_out(&ts_descr->i460_ts, ptr, E1_TS_BYTES);

	LOGPITS(ts, DE1, LOGL_DEBUG, "E1-TX: sending %u bytes: %s...\n",
	     msgb_length(msg), osmo_hexdump_nospc(msgb_data(msg),
						  msgb_length(msg) >
						  DEBUG_BYTES_MAX ? DEBUG_BYTES_MAX : msgb_length(msg)));

	/* Hand data over to the E1 stack */
	msgb_enqueue(&ts->raw.tx_queue, msg);
}

/* Callback function to handle incoming E1 traffic */
static void e1_recv_cb(struct e1inp_ts *ts, struct msgb *msg)
{
	struct e1_ts_descr *ts_descr;

	if (msg->len != E1_TS_BYTES) {
		LOGPITS(ts, DE1, LOGL_ERROR,
		     "E1-RX: receiving bad, expected length is %u, actual length is %u!\n",
		     E1_TS_BYTES, msg->len);
		msgb_free(msg);
		return;
	}

	LOGPITS(ts, DE1, LOGL_DEBUG, "E1-RX: receiving %u bytes: %s ...\n",
		msg->len, osmo_hexdump_nospc(msg->data, msg->len));

	/* Note: The line number and ts number that arrives here should be clean. */
	OSMO_ASSERT(ts->line->num < ARRAY_SIZE(e1_lines));
	ts_descr = &e1_lines[ts->line->num].e1_ts[ts->num];

	/* Hand data over to the I640 demultiplexer. */
	osmo_i460_demux_in(&ts_descr->i460_ts, msg->data, msg->len);

	/* Trigger sending of pending E1 traffic */
	e1_send_ts_frame(ts);

	/* e1inp_rx_ts(), the caller of this callback does not free() msgb. */
	msgb_free(msg);
}

static struct e1_ts_descr *ts_descr_from_ccu_descr(struct er_ccu_descr *ccu_descr)
{
	/* Make sure E1 line number is valid */
	if (ccu_descr->e1_conn_pars->e1_nr >= ARRAY_SIZE(e1_lines)) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "Invalid E1 line number!\n");
		return NULL;
	}

	/* Make sure E1 timeslot number is valid */
	if (ccu_descr->e1_conn_pars->e1_ts < 1 || ccu_descr->e1_conn_pars->e1_ts > NUM_E1_TS - 1) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "Invalid E1 timeslot number!\n");
		return NULL;
	}

	/* Timeslots are only initialized once and will stay open after that. */
	return &e1_lines[ccu_descr->e1_conn_pars->e1_nr].e1_ts[ccu_descr->e1_conn_pars->e1_ts];
}

/* Configure an I.460 subslot and add it to the CCU descriptor */
static int add_i460_subslot(void *ctx, struct er_ccu_descr *ccu_descr)
{
	struct e1_ts_descr *ts_descr;
	enum osmo_tray_sync_pat_id sync_pattern;

	if (ccu_descr->link.schan) {
		/* NOTE: This is a serious error: subslots should be removed when l1if_close_trx() is called by the
		 * PCU. This log line points towards a problem with the PDCH management inside the PCU! */
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "I.460 subslot is already configured -- will not touch it!\n");
		return -EINVAL;
	}

	ts_descr = ts_descr_from_ccu_descr(ccu_descr);
	if (!ts_descr)
		return -EINVAL;
	if (ts_descr->usecount == 0) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "E1 timeslot not ready!\n");
		return -EINVAL;
	}

	/* Set up I.460 subchannel and connect it to the MUX on the E1 timeslot */
	if (ccu_descr->e1_conn_pars->e1_ts_ss == E1_SUBSLOT_FULL) {
		LOGPCCU(ccu_descr, LOGL_INFO, "SETUP", "using 64k subslots\n");
		ccu_descr->link.scd.rate = OSMO_I460_RATE_64k;
		ccu_descr->link.scd.demux.num_bits = E1_TS_BYTES * 8;
		ccu_descr->link.scd.bit_offset = 0;
		sync_pattern = OSMO_TRAU_SYNCP_64_ER_CCU;
	} else {
		LOGPCCU(ccu_descr, LOGL_INFO, "SETUP", "using 16k subslots\n");
		if (ccu_descr->e1_conn_pars->e1_ts_ss > 3) {
			LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "Invalid I.460 subslot number!\n");
			return -EINVAL;
		}
		ccu_descr->link.scd.rate = OSMO_I460_RATE_16k;
		ccu_descr->link.scd.demux.num_bits = E1_TS_BYTES / 4 * 8;
		ccu_descr->link.scd.bit_offset = ccu_descr->e1_conn_pars->e1_ts_ss * 2;
		sync_pattern = OSMO_TRAU_SYNCP_16_ER_CCU;
	}

	ccu_descr->link.scd.demux.out_cb_bits = e1_i460_demux_bits_cb;
	ccu_descr->link.scd.demux.out_cb_bytes = NULL;
	ccu_descr->link.scd.demux.user_data = ccu_descr;
	ccu_descr->link.scd.mux.in_cb_queue_empty = e1_i460_mux_empty_cb;
	ccu_descr->link.scd.mux.user_data = ccu_descr;

	LOGPCCU(ccu_descr, LOGL_INFO, "SETUP", "adding I.460 subchannel: bit_offset=%u, num_bits=%zu\n",
		ccu_descr->link.scd.bit_offset, ccu_descr->link.scd.demux.num_bits);
	ccu_descr->link.schan = osmo_i460_subchan_add(ctx, &ts_descr->i460_ts, &ccu_descr->link.scd);
	if (!ccu_descr->link.schan) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "adding I.460 subchannel: failed!\n");
		return -EINVAL;
	}

	/* Configure TRAU synchronizer */
	ccu_descr->link.trau_sync_fi = osmo_trau_sync_alloc(tall_ccu_ctx, "trau-sync", sync_frame_out_cb, sync_pattern, ccu_descr);
	if (!ccu_descr->link.trau_sync_fi) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "adding I.460 TRAU frame sync: failed!\n");
		return -EINVAL;
	}

	/* Ericsson uses a different synchronization pattern for MCS9 TRAU frames */
	if (sync_pattern == OSMO_TRAU_SYNCP_64_ER_CCU)
		osmo_trau_sync_set_secondary_pat(ccu_descr->link.trau_sync_fi, OSMO_TRAU_SYNCP_64_ER_CCU_MCS9, 1);

	return 0;
}

/* Remove an I.460 subslot from the CCU descriptor */
static void del_i460_subslot(struct er_ccu_descr *ccu_descr)
{
	if (ccu_descr->link.schan)
		osmo_i460_subchan_del(ccu_descr->link.schan);
	ccu_descr->link.schan = NULL;
	if (ccu_descr->link.trau_sync_fi)
		osmo_fsm_inst_term(ccu_descr->link.trau_sync_fi, OSMO_FSM_TERM_REGULAR, NULL);
	ccu_descr->link.trau_sync_fi = NULL;

	memset(&ccu_descr->link.scd, 0, sizeof(ccu_descr->link.scd));
}

/* Configure an E1 timeslot according to the description in the ccu_descr */
static int open_e1_timeslot(struct er_ccu_descr *ccu_descr)
{
	struct e1inp_line *e1_line;
	struct e1_ts_descr *ts_descr;
	int rc;

	/* Find timeslot descriptor and check if the timeslot is already open. */
	ts_descr = ts_descr_from_ccu_descr(ccu_descr);
	if (!ts_descr)
		return -EINVAL;
	if (ts_descr->usecount > 0) {
		LOGPCCU(ccu_descr, LOGL_DEBUG, "SETUP", "E1 timeslot already open -- using it as it is!\n");
		ts_descr->usecount++;
		return 0;
	}

	/* Find and set up E1 line */
	e1_line = e1inp_line_find(ccu_descr->e1_conn_pars->e1_nr);
	if (!e1_line) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "no such E1 line!\n");
		return -EINVAL;
	}
	e1inp_line_bind_ops(e1_line, &dummy_e1_line_ops);

	/* Set up E1 timeslot */
	rc = e1inp_ts_config_raw(&e1_line->ts[ccu_descr->e1_conn_pars->e1_ts - 1], e1_line, e1_recv_cb);
	if (rc < 0) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "configuration of timeslot failed!\n");
		return -EINVAL;
	}
	rc = e1inp_line_update(e1_line);
	if (rc < 0) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "line update failed!\n");
		return -EINVAL;
	}

	/* Make sure the i460 mux is ready */
	if (!ts_descr->i460_ts_initialized) {
		osmo_i460_ts_init(&ts_descr->i460_ts);
		ts_descr->i460_ts_initialized = true;
	}

	ts_descr->usecount++;
	OSMO_ASSERT(ts_descr->usecount == 1);

	return 0;
}

/* Configure an E1 timeslot according to the description in the ccu_descr */
static int close_e1_timeslot(struct er_ccu_descr *ccu_descr)
{
	struct e1inp_line *e1_line;
	struct e1_ts_descr *ts_descr;
	int rc;

	/* Find timeslot descriptor and check if the timeslot is still used by another subslot. */
	ts_descr = ts_descr_from_ccu_descr(ccu_descr);
	if (!ts_descr)
		return -EINVAL;
	if (ts_descr->usecount > 1) {
		LOGPCCU(ccu_descr, LOGL_DEBUG, "SETUP",
			"E1 timeslot still in used by another subslot, leaving it open!\n");
		ts_descr->usecount--;
		return 0;
	} else if (ts_descr->usecount == 0) {
		/* This should not be as it means we close the timeslot too often. */
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "E1 timeslot already closed, leaving it as it is...\n");
		return -EINVAL;
	}

	/* Find E1 line */
	e1_line = e1inp_line_find(ccu_descr->e1_conn_pars->e1_nr);
	if (!e1_line) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "no such E1 line!\n");
		return -EINVAL;
	}

	/* Release E1 timeslot */
	rc = e1inp_ts_config_none(&e1_line->ts[ccu_descr->e1_conn_pars->e1_ts - 1], e1_line);
	if (rc < 0) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "failed to disable E1 timeslot!\n");
		return -EINVAL;
	}
	rc = e1inp_line_update(e1_line);
	if (rc < 0) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "failed to update E1 line!\n");
		return -EINVAL;
	}

	ts_descr->usecount--;
	OSMO_ASSERT(ts_descr->usecount == 0);

	return 0;
}

int er_ccu_if_open(struct er_ccu_descr *ccu_descr)
{
	if (ccu_descr->link.ccu_connected) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP",
			"cannot connect CCU since it is already connected -- ignored!\n");
		return 0;
	}

	if (open_e1_timeslot(ccu_descr) < 0)
		return -EINVAL;

	if (add_i460_subslot(tall_ccu_ctx, ccu_descr) < 0)
		return -EINVAL;

	ccu_descr->link.ccu_connected = true;
	LOGPCCU(ccu_descr, LOGL_DEBUG, "SETUP", "CCU connected.\n");
	return 0;
}

void er_ccu_if_close(struct er_ccu_descr *ccu_descr)
{
	if (!ccu_descr->link.ccu_connected) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP",
			"cannot disconnect CCU since it is already disconnected -- ignored!\n");
		return;
	}

	del_i460_subslot(ccu_descr);
	close_e1_timeslot(ccu_descr);

	ccu_descr->link.ccu_connected = false;
	LOGPCCU(ccu_descr, LOGL_DEBUG, "SETUP", "CCU disconnected.\n");
}

void er_ccu_if_tx(struct er_ccu_descr *ccu_descr, const ubit_t *bits, unsigned int num_bits)
{
	struct msgb *msg;
	uint8_t *ptr;

	if (!ccu_descr->link.ccu_connected) {
		LOGPCCU(ccu_descr, LOGL_ERROR, "SETUP", "cannot TX block, CCU is disconnected -- ignored!\n");
		return;
	}

	msg = msgb_alloc_c(tall_ccu_ctx, num_bits, "E1-I.460-PCU-IND-frame");
	ptr = msgb_put(msg, num_bits);
	memcpy(ptr, bits, num_bits);
	LOGPCCU(ccu_descr, LOGL_DEBUG, "I.460-TX", "sending %u bits: %s...\n", msgb_length(msg),
		osmo_ubit_dump(msgb_data(msg), msgb_length(msg) > DEBUG_BITS_MAX ? DEBUG_BITS_MAX : msgb_length(msg)));
	osmo_i460_mux_enqueue(ccu_descr->link.schan, msg);
}

void er_ccu_if_init(void *ctx)
{
	libosmo_abis_init(ctx);
	e1inp_vty_init();

	tall_ccu_ctx = talloc_new(ctx);
	memset(e1_lines, 0, sizeof(e1_lines));
}
