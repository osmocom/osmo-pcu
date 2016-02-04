/* Copied from tbf.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include <bts.h>
#include <tbf.h>
#include <rlc.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>
#include <gprs_bssgp_pcu.h>
#include <gprs_codel.h>
#include <decoding.h>
#include <encoding.h>

#include "pcu_utils.h"

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
}

#include <errno.h>
#include <string.h>
#include <math.h>

/* After sending these frames, we poll for ack/nack. */
#define POLL_ACK_AFTER_FRAMES 20

extern "C" {
int bssgp_tx_llc_discarded(struct bssgp_bvc_ctx *bctx, uint32_t tlli,
                           uint8_t num_frames, uint32_t num_octets);
}

static inline void tbf_update_ms_class(struct gprs_rlcmac_tbf *tbf,
					const uint8_t ms_class)
{
	if (!tbf->ms_class() && ms_class)
		tbf->set_ms_class(ms_class);
}

static void llc_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_dl_tbf *tbf = (struct gprs_rlcmac_dl_tbf *)_tbf;

	if (tbf->state_is_not(GPRS_RLCMAC_FLOW))
		return;

	LOGP(DRLCMAC, LOGL_DEBUG,
		"%s LLC receive timeout, requesting DL ACK\n", tbf_name(tbf));

	tbf->request_dl_ack();
}

void gprs_rlcmac_dl_tbf::cleanup()
{
	osmo_timer_del(&m_llc_timer);
}

void gprs_rlcmac_dl_tbf::start_llc_timer()
{
	if (bts_data()->llc_idle_ack_csec > 0) {
		struct timeval tv;

		/* TODO: this ought to be within a constructor */
		m_llc_timer.data = this;
		m_llc_timer.cb = &llc_timer_cb;

		csecs_to_timeval(bts_data()->llc_idle_ack_csec, &tv);
		osmo_timer_schedule(&m_llc_timer, tv.tv_sec, tv.tv_usec);
	}
}

int gprs_rlcmac_dl_tbf::append_data(const uint8_t ms_class,
				const uint16_t pdu_delay_csec,
				const uint8_t *data, const uint16_t len)
{
	LOGP(DRLCMAC, LOGL_INFO, "%s append\n", tbf_name(this));
	gprs_llc_queue::MetaInfo info;
	struct msgb *llc_msg = msgb_alloc(len, "llc_pdu_queue");
	if (!llc_msg)
		return -ENOMEM;

	gprs_llc_queue::calc_pdu_lifetime(bts, pdu_delay_csec, &info.expire_time);
	gettimeofday(&info.recv_time, NULL);
	memcpy(msgb_put(llc_msg, len), data, len);
	llc_queue()->enqueue(llc_msg, &info);
	tbf_update_ms_class(this, ms_class);
	start_llc_timer();

	if (state_is(GPRS_RLCMAC_WAIT_RELEASE)) {
		LOGP(DRLCMAC, LOGL_DEBUG,
			"%s in WAIT RELEASE state "
			"(T3193), so reuse TBF\n", tbf_name(this));
		tbf_update_ms_class(this, ms_class);
		establish_dl_tbf_on_pacch();
	}

	return 0;
}

static int tbf_new_dl_assignment(struct gprs_rlcmac_bts *bts,
				const char *imsi,
				const uint32_t tlli, const uint32_t tlli_old,
				const uint8_t ms_class,
				const uint8_t egprs_ms_class,
				struct gprs_rlcmac_dl_tbf **tbf)
{
	uint8_t ss;
	int8_t use_trx;
	uint16_t ta = 0;
	struct gprs_rlcmac_ul_tbf *ul_tbf = NULL, *old_ul_tbf;
	struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;
	GprsMs *ms;

	/* check for uplink data, so we copy our informations */
#warning "Do the same look up for IMSI, TLLI and OLD_TLLI"
#warning "Refactor the below lines... into a new method"
	ms = bts->bts->ms_store().get_ms(tlli, tlli_old, imsi);
	if (ms) {
		ul_tbf = ms->ul_tbf();
		ta = ms->ta();
	}
	/* TODO: if (!ms) create MS before tbf_alloc is called? */

	if (ul_tbf && ul_tbf->m_contention_resolution_done
	 && !ul_tbf->m_final_ack_sent) {
		use_trx = ul_tbf->trx->trx_no;
		ss = 0;
		old_ul_tbf = ul_tbf;
	} else {
		use_trx = -1;
		ss = 1; /* PCH assignment only allows one timeslot */
		old_ul_tbf = NULL;
	}

	// Create new TBF (any TRX)
#warning "Copy and paste with alloc_ul_tbf"
	/* set number of downlink slots according to multislot class */
	dl_tbf = tbf_alloc_dl_tbf(bts, ms, use_trx, ms_class, egprs_ms_class, ss);

	if (!dl_tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource\n");
		return -EBUSY;
	}
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);
	dl_tbf->ms()->set_ta(ta);

	LOGP(DRLCMAC, LOGL_DEBUG, "%s [DOWNLINK] START\n", tbf_name(dl_tbf));

	/* Store IMSI for later look-up and PCH retransmission */
	dl_tbf->assign_imsi(imsi);

	/* trigger downlink assignment and set state to ASSIGN.
	 * we don't use old_downlink, so the possible uplink is used
	 * to trigger downlink assignment. if there is no uplink,
	 * AGCH is used. */
	dl_tbf->bts->trigger_dl_ass(dl_tbf, old_ul_tbf);
	*tbf = dl_tbf;
	return 0;
}

/**
 * TODO: split into unit test-able parts...
 */
int gprs_rlcmac_dl_tbf::handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const uint32_t tlli_old, const char *imsi,
		uint8_t ms_class, uint8_t egprs_ms_class,
		const uint16_t delay_csec,
		const uint8_t *data, const uint16_t len)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;
	int rc;
	GprsMs *ms, *ms_old;

	/* check for existing TBF */
	ms = bts->bts->ms_store().get_ms(tlli, tlli_old, imsi);
	if (ms) {
		dl_tbf = ms->dl_tbf();

		/* If we known the GPRS/EGPRS MS class, use it */
		if (ms->ms_class() || ms->egprs_ms_class()) {
			ms_class = ms->ms_class();
			egprs_ms_class = ms->egprs_ms_class();
		}
	}

	if (ms && strlen(ms->imsi()) == 0) {
		ms_old = bts->bts->ms_store().get_ms(0, 0, imsi);
		if (ms_old && ms_old != ms) {
			/* The TLLI has changed (RAU), so there are two MS
			 * objects for the same MS */
			LOGP(DRLCMAC, LOGL_NOTICE,
				"There is a new MS object for the same MS: "
				"(0x%08x, '%s') -> (0x%08x, '%s')\n",
				ms_old->tlli(), ms_old->imsi(),
				ms->tlli(), ms->imsi());

			GprsMs::Guard guard_old(ms_old);

			if (!dl_tbf && ms_old->dl_tbf()) {
				LOGP(DRLCMAC, LOGL_NOTICE,
					"%s IMSI %s: "
					"moving DL TBF to new MS object\n",
					dl_tbf->name(), imsi);
				dl_tbf = ms_old->dl_tbf();
				/* Move the DL TBF to the new MS */
				dl_tbf->set_ms(ms);
			}
			/* Clean up the old MS object */
			/* TODO: Put this into a separate function, use timer? */
			if (ms_old->ul_tbf() && ms_old->ul_tbf()->T == 0)
				tbf_free(ms_old->ul_tbf());
			if (ms_old->dl_tbf() && ms_old->dl_tbf()->T == 0)
				tbf_free(ms_old->dl_tbf());

			ms->merge_old_ms(ms_old);
		}
	}

	if (!dl_tbf) {
		rc = tbf_new_dl_assignment(bts, imsi, tlli, tlli_old,
			ms_class, egprs_ms_class, &dl_tbf);
		if (rc < 0)
			return rc;
	}

	/* TODO: ms_class vs. egprs_ms_class is not handled here */
	rc = dl_tbf->append_data(ms_class, delay_csec, data, len);
	dl_tbf->update_ms(tlli, GPRS_RLCMAC_DL_TBF);
	dl_tbf->assign_imsi(imsi);

	return rc;
}

struct msgb *gprs_rlcmac_dl_tbf::llc_dequeue(bssgp_bvc_ctx *bctx)
{
	struct msgb *msg;
	struct timeval tv_now, tv_now2;
	uint32_t octets = 0, frames = 0;
	struct timeval hyst_delta = {0, 0};
	const unsigned keep_small_thresh = 60;
	const gprs_llc_queue::MetaInfo *info;

	if (bts_data()->llc_discard_csec)
		csecs_to_timeval(bts_data()->llc_discard_csec, &hyst_delta);

	gettimeofday(&tv_now, NULL);
	timeradd(&tv_now, &hyst_delta, &tv_now2);

	while ((msg = llc_queue()->dequeue(&info))) {
		const struct timeval *tv_disc = &info->expire_time;
		const struct timeval *tv_recv = &info->recv_time;

		gprs_bssgp_update_queue_delay(tv_recv, &tv_now);

		if (ms() && ms()->codel_state()) {
			int bytes = llc_queue()->octets();
			if (gprs_codel_control(ms()->codel_state(),
					tv_recv, &tv_now, bytes))
				goto drop_frame;
		}

		/* Is the age below the low water mark? */
		if (!gprs_llc_queue::is_frame_expired(&tv_now2, tv_disc))
			break;

		/* Is the age below the high water mark */
		if (!gprs_llc_queue::is_frame_expired(&tv_now, tv_disc)) {
			/* Has the previous message not been dropped? */
			if (frames == 0)
				break;

			/* Hysteresis mode, try to discard LLC messages until
			 * the low water mark has been reached */

			/* Check whether to abort the hysteresis mode */

			/* Is the frame small, perhaps only a TCP ACK? */
			if (msg->len <= keep_small_thresh)
				break;

			/* Is it a GMM message? */
			if (!gprs_llc::is_user_data_frame(msg->data, msg->len))
				break;
		}

		bts->llc_timedout_frame();
drop_frame:
		frames++;
		octets += msg->len;
		msgb_free(msg);
		bts->llc_dropped_frame();
		continue;
	}

	if (frames) {
		LOGP(DRLCMACDL, LOGL_NOTICE, "%s Discarding LLC PDU "
			"because lifetime limit reached, "
			"count=%u new_queue_size=%zu\n",
			tbf_name(this), frames, llc_queue()->size());
		if (frames > 0xff)
			frames = 0xff;
		if (octets > 0xffffff)
			octets = 0xffffff;
		if (bctx)
			bssgp_tx_llc_discarded(bctx, tlli(), frames, octets);
	}

	return msg;
}

bool gprs_rlcmac_dl_tbf::restart_bsn_cycle()
{
	/* If V(S) == V(A) and finished state, we would have received
	 * acknowledgement of all transmitted block.  In this case we would
	 * have transmitted the final block, and received ack from MS. But in
	 * this case we did not receive the final ack indication from MS.  This
	 * should never happen if MS works correctly.
	 */
	if (m_window.window_empty()) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- MS acked all blocks\n");
		return false;
	}

	/* cycle through all unacked blocks */
	int resend = m_window.mark_for_resend();

	/* At this point there should be at least one unacked block
	 * to be resent. If not, this is an software error. */
	if (resend == 0) {
		LOGP(DRLCMACDL, LOGL_ERROR, "Software error: "
			"There are no unacknowledged blocks, but V(A) "
			" != V(S). PLEASE FIX!\n");
		return false;
	}

	return true;
}

int gprs_rlcmac_dl_tbf::take_next_bsn(uint32_t fn,
	int previous_bsn, bool *may_combine)
{
	int bsn;
	int data_len2, force_data_len = -1;
	GprsCodingScheme cs2;
	GprsCodingScheme force_cs;

	bsn = m_window.resend_needed();

	if (previous_bsn >= 0) {
		force_cs = m_rlc.block(previous_bsn)->cs;
		if (!force_cs.isEgprs())
			return -1;
		force_data_len = m_rlc.block(previous_bsn)->len;
	}

	if (bsn >= 0) {
		if (previous_bsn == bsn)
			return -1;

		if (previous_bsn >= 0 &&
			m_window.mod_sns(bsn - previous_bsn) > RLC_EGPRS_MAX_BSN_DELTA)
			return -1;

		cs2 = m_rlc.block(bsn)->cs;
		data_len2 = m_rlc.block(bsn)->len;
		if (force_data_len > 0 && force_data_len != data_len2)
			return -1;
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Resending BSN %d\n", bsn);
		/* re-send block with negative aknowlegement */
		m_window.m_v_b.mark_unacked(bsn);
		bts->rlc_resent();
	} else if (state_is(GPRS_RLCMAC_FINISHED)) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
			"because all blocks have been transmitted.\n",
			m_window.v_a());
		bts->rlc_restarted();
		if (restart_bsn_cycle())
			return take_next_bsn(fn, previous_bsn, may_combine);
	} else if (dl_window_stalled()) {
		LOGP(DRLCMACDL, LOGL_NOTICE, "- Restarting at BSN %d, "
			"because the window is stalled.\n",
			m_window.v_a());
		bts->rlc_stalled();
		if (restart_bsn_cycle())
			return take_next_bsn(fn, previous_bsn, may_combine);
	} else if (have_data()) {
		/* New blocks may be send */
		cs2 = force_cs ? force_cs : current_cs();
		LOGP(DRLCMACDL, LOGL_DEBUG,
			"- Sending new data block at BSN %d, CS=%s\n",
			m_window.v_s(), cs2.name());

		bsn = create_new_bsn(fn, cs2);
	} else if (!m_window.window_empty()) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
			"because all blocks have been transmitted (FLOW).\n",
			m_window.v_a());
		bts->rlc_restarted();
		if (restart_bsn_cycle())
			return take_next_bsn(fn, previous_bsn, may_combine);
	} else {
		/* Nothing left to send, create dummy LLC commands */
		LOGP(DRLCMACDL, LOGL_DEBUG,
			"- Sending new dummy block at BSN %d, CS=%s\n",
			m_window.v_s(), current_cs().name());
		bsn = create_new_bsn(fn, current_cs());
		/* Don't send a second block, so don't set cs2 */
	}

	if (bsn < 0) {
		/* we just send final block again */
		LOGP(DRLCMACDL, LOGL_DEBUG,
			"- Nothing else to send, Re-transmit final block!\n");
		bsn = m_window.v_s_mod(-1);
		bts->rlc_resent();
	}

	*may_combine = cs2.numDataBlocks() > 1;

	return bsn;
}

/*
 * Create DL data block
 * The messages are fragmented and forwarded as data blocks.
 */
struct msgb *gprs_rlcmac_dl_tbf::create_dl_acked_block(uint32_t fn, uint8_t ts)
{
	int bsn, bsn2 = -1;
	bool may_combine;

	LOGP(DRLCMACDL, LOGL_DEBUG, "%s downlink (V(A)==%d .. "
		"V(S)==%d)\n", tbf_name(this),
		m_window.v_a(), m_window.v_s());

	bsn = take_next_bsn(fn, -1, &may_combine);
	if (bsn < 0)
		return NULL;

	if (may_combine)
		bsn2 = take_next_bsn(fn, bsn, &may_combine);

	return create_dl_acked_block(fn, ts, bsn, bsn2);
}

void gprs_rlcmac_dl_tbf::schedule_next_frame()
{
	struct msgb *msg;

	if (m_llc.frame_length() != 0)
		return;

	/* dequeue next LLC frame, if any */
	msg = llc_dequeue(gprs_bssgp_pcu_current_bctx());
	if (!msg)
		return;

	LOGP(DRLCMACDL, LOGL_INFO,
		"- Dequeue next LLC for %s (len=%d)\n",
		tbf_name(this), msg->len);

	m_llc.put_frame(msg->data, msg->len);
	bts->llc_frame_sched();
	msgb_free(msg);
	m_last_dl_drained_fn = -1;
}

int gprs_rlcmac_dl_tbf::create_new_bsn(const uint32_t fn, GprsCodingScheme cs)
{
	uint8_t *data;
	gprs_rlc_data *rlc_data;
	const uint16_t bsn = m_window.v_s();
	gprs_rlc_data_block_info *rdbi;
	int num_chunks = 0;
	int write_offset = 0;
	Encoding::AppendResult ar;

	if (m_llc.frame_length() == 0)
		schedule_next_frame();

	OSMO_ASSERT(cs.isValid());

	/* length of usable data block (single data unit w/o header) */
	const uint8_t block_data_len = cs.maxDataBlockBytes();

	/* now we still have untransmitted LLC data, so we fill mac block */
	rlc_data = m_rlc.block(bsn);
	data = rlc_data->prepare(block_data_len);
	rlc_data->cs = cs;
	rlc_data->len = block_data_len;

	rdbi = &(rlc_data->block_info);
	memset(rdbi, 0, sizeof(*rdbi));
	rdbi->data_len = block_data_len;

	rdbi->cv = 15; /* Final Block Indicator, set late, if true */
	rdbi->bsn = bsn; /* Block Sequence Number */
	rdbi->e = 1; /* Extension bit, maybe set later (1: no extension) */

	do {
		bool is_final;

		if (m_llc.frame_length() == 0) {
			int space = block_data_len - write_offset;
			/* A header will need to by added, so we just need
			 * space-1 octets */
			m_llc.put_dummy_frame(space - 1);

			/* The data just drained, store the current fn */
			if (m_last_dl_drained_fn < 0)
				m_last_dl_drained_fn = fn;

			/* It is not clear, when the next real data will
			 * arrive, so request a DL ack/nack now */
			request_dl_ack();

			LOGP(DRLCMACDL, LOGL_DEBUG,
				"-- Empty chunk, "
				"added LLC dummy command of size %d, "
				"drained_since=%d\n",
				m_llc.frame_length(), frames_since_last_drain(fn));
		}

		is_final = llc_queue()->size() == 0 && !keep_open(fn);

		ar = Encoding::rlc_data_to_dl_append(rdbi, cs,
			&m_llc, &write_offset, &num_chunks, data, is_final);

		if (ar == Encoding::AR_NEED_MORE_BLOCKS)
			break;

		LOGP(DRLCMACDL, LOGL_INFO, "Complete DL frame for %s"
			"len=%d\n", tbf_name(this), m_llc.frame_length());
		gprs_rlcmac_dl_bw(this, m_llc.frame_length());
		m_llc.reset();

		if (is_final) {
			request_dl_ack();
			set_state(GPRS_RLCMAC_FINISHED);
		}

		/* dequeue next LLC frame, if any */
		schedule_next_frame();
	} while (ar == Encoding::AR_COMPLETED_SPACE_LEFT);

	LOGP(DRLCMACDL, LOGL_DEBUG, "data block (BSN %d, %s): %s\n",
		bsn, rlc_data->cs.name(),
		osmo_hexdump(rlc_data->block, block_data_len));
	/* raise send state and set ack state array */
	m_window.m_v_b.mark_unacked(bsn);
	m_window.increment_send();

	return bsn;
}

struct msgb *gprs_rlcmac_dl_tbf::create_dl_acked_block(
				const uint32_t fn, const uint8_t ts,
				int index, int index2)
{
	uint8_t *msg_data;
	struct msgb *dl_msg;
	unsigned msg_len;
	bool need_poll;
	/* TODO: support MCS-7 - MCS-9, where data_block_idx can be 1 */
	unsigned int data_block_idx = 0;
	unsigned int rrbp;
	uint32_t new_poll_fn;
	int rc;
	bool is_final = false;
	gprs_rlc_data_info rlc;
	GprsCodingScheme cs;
	int bsns[ARRAY_SIZE(rlc.block_info)];
	unsigned num_bsns;
	int punct[ARRAY_SIZE(rlc.block_info)];
	bool need_padding = false;

	/*
	 * TODO: This is an experimental work-around to put 2 BSN into
	 * MSC-7 to MCS-9 encoded messages. It just sends the same BSN
	 * twice in the block. The cs should be derived from the TBF's
	 * current CS such that both BSNs (that must be compatible) can
	 * be put into the data area, even if the resulting CS is higher than
	 * the current limit.
	 */
	cs = m_rlc.block(index)->cs;
	bsns[0] = index;
	num_bsns = 1;

	if (index2 >= 0) {
		bsns[num_bsns] = index2;
		num_bsns += 1;
	}

#if 0
	if (num_bsns == 1)
		cs.decToSingleBlock(&need_padding);
#endif

	gprs_rlc_data_info_init_dl(&rlc, cs, need_padding);

	rlc.usf = 7; /* will be set at scheduler */
	rlc.pr = 0; /* FIXME: power reduction */
	rlc.tfi = m_tfi; /* TFI */

	/* return data block(s) as message */
	msg_len = cs.sizeDL();
	dl_msg = msgb_alloc(msg_len, "rlcmac_dl_data");
	if (!dl_msg)
		return NULL;

	msg_data = msgb_put(dl_msg, msg_len);

	/* Copy block(s) to RLC message */
	for (data_block_idx = 0; data_block_idx < rlc.num_data_blocks;
		data_block_idx++)
	{
		int bsn;
		GprsCodingScheme cs_enc;
		uint8_t *block_data;
		gprs_rlc_data_block_info *rdbi, *block_info;

		/* Check if there are more blocks than BSNs */
		if (data_block_idx < num_bsns)
			bsn = bsns[data_block_idx];
		else
			bsn = bsns[0];

		cs_enc = m_rlc.block(bsn)->cs;

		/* get data and header from current block */
		block_data = m_rlc.block(bsn)->block;

		/* TODO: Use real puncturing values */
		punct[data_block_idx] = data_block_idx;

		rdbi = &rlc.block_info[data_block_idx];
		block_info = &m_rlc.block(bsn)->block_info;

		if(rdbi->data_len != m_rlc.block(bsn)->len) {
			LOGP(DRLCMACDL, LOGL_ERROR,
				"ERROR: Expected len = %d for %s instead of "
				"%d in data unit %d (BSN %d, %s)\n",
				rdbi->data_len, cs.name(), m_rlc.block(bsn)->len,
				data_block_idx, bsn, cs_enc.name());
			OSMO_ASSERT(rdbi->data_len == m_rlc.block(bsn)->len);
		}
		rdbi->e   = block_info->e;
		rdbi->cv  = block_info->cv;
		rdbi->bsn = bsn;
		is_final = is_final || rdbi->cv == 0;

		LOGP(DRLCMACDL, LOGL_DEBUG, "- Copying data unit %d (BSN %d)\n",
			data_block_idx, bsn);

		Encoding::rlc_copy_from_aligned_buffer(&rlc, data_block_idx,
			msg_data, block_data);
	}

	OSMO_ASSERT(ARRAY_SIZE(punct) >= 2);
	rlc.cps = gprs_rlc_mcs_cps(cs, punct[0], punct[1], need_padding);

	/* If the TBF has just started, relate frames_since_last_poll to the
	 * current fn */
	if (m_last_dl_poll_fn < 0)
		m_last_dl_poll_fn = fn;

	need_poll = state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);

	/* poll after POLL_ACK_AFTER_FRAMES frames, or when final block is tx.
	 */
	if (m_tx_counter >= POLL_ACK_AFTER_FRAMES || m_dl_ack_requested ||
			need_poll) {
		if (m_dl_ack_requested) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because is was requested explicitly "
				"(e.g. first final block sent).\n");
		} else if (need_poll) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because polling timed out.\n");
		} else {
			LOGP(DRLCMACDL, LOGL_DEBUG, "- Scheduling Ack/Nack "
				"polling, because %d blocks sent.\n",
				POLL_ACK_AFTER_FRAMES);
		}

		rc = check_polling(fn, ts, &new_poll_fn, &rrbp);
		if (rc >= 0) {
			set_polling(new_poll_fn, ts);

			LOGP(DRLCMACDL, LOGL_DEBUG, "Polling scheduled in this "
				"TS %d\n", ts);
			m_tx_counter = 0;
			/* start timer whenever we send the final block */
			if (is_final)
				tbf_timer_start(this, 3191, bts_data()->t3191, 0);

			/* Clear poll timeout flag */
			state_flags &= ~(1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);

			/* Clear request flag */
			m_dl_ack_requested = false;

			/* set polling in header */
			rlc.rrbp = rrbp;
			rlc.es_p = 1; /* Polling */

			m_last_dl_poll_fn = poll_fn;

			LOGP(DRLCMACDL, LOGL_INFO,
				"%s Scheduled Ack/Nack polling on FN=%d, TS=%d\n",
				name(), poll_fn, poll_ts);
		}
	}

	Encoding::rlc_write_dl_data_header(&rlc, msg_data);

	LOGP(DRLCMACDL, LOGL_DEBUG, "msg block (BSN %d, %s%s): %s\n",
		index, cs.name(),
		need_padding ? ", padded" : "",
		msgb_hexdump(dl_msg));

	/* Increment TX-counter */
	m_tx_counter++;

	bts->rlc_sent();

	return dl_msg;
}

static uint16_t bitnum_to_bsn(int bitnum, uint16_t ssn)
{
	return ssn - 1 - bitnum;
}

int gprs_rlcmac_dl_tbf::analyse_errors(char *show_rbb, uint8_t ssn,
	ana_result *res)
{
	gprs_rlc_data *rlc_data;
	uint16_t lost = 0, received = 0, skipped = 0;
	char info[RLC_MAX_WS + 1];
	memset(info, '.', m_window.ws());
	info[m_window.ws()] = 0;
	uint16_t bsn = 0;
	unsigned received_bytes = 0, lost_bytes = 0;
	unsigned received_packets = 0, lost_packets = 0;
	unsigned num_blocks = strlen(show_rbb);

	/* SSN - 1 is in range V(A)..V(S)-1 */
	for (unsigned int bitpos = 0; bitpos < num_blocks; bitpos++) {
		bool is_received;
		int index = num_blocks - 1 - bitpos;

		is_received = (index >= 0 && show_rbb[index] == 'R');

		bsn = m_window.mod_sns(bitnum_to_bsn(bitpos, ssn));

		if (bsn == m_window.mod_sns(m_window.v_a() - 1)) {
			info[bitpos] = '$';
			break;
		}

		rlc_data = m_rlc.block(bsn);
		if (!rlc_data) {
			info[bitpos] = '0';
			continue;
		}

		/* Get general statistics */
		if (is_received && !m_window.m_v_b.is_acked(bsn)) {
			received_packets += 1;
			received_bytes += rlc_data->len;
		} else if (!is_received && !m_window.m_v_b.is_nacked(bsn)) {
			lost_packets += 1;
			lost_bytes += rlc_data->len;
		}

		/* Get statistics for current CS */

		if (rlc_data->cs != current_cs()) {
			/* This block has already been encoded with a different
			 * CS, so it doesn't help us to decide, whether the
			 * current CS is ok. Ignore it. */
			info[bitpos] = 'x';
			skipped += 1;
			continue;
		}

		if (is_received) {
			if (!m_window.m_v_b.is_acked(bsn)) {
				received += 1;
				info[bitpos] = 'R';
			} else {
				info[bitpos] = 'r';
			}
		} else {
			info[bitpos] = 'L';
			lost += 1;
		}
	}

	LOGP(DRLCMACDL, LOGL_DEBUG, "%s DL analysis, range=%d:%d, lost=%d, recv=%d, "
		"skipped=%d, bsn=%d, info='%s'\n",
		name(), m_window.v_a(), m_window.v_s(), lost, received,
		skipped, bsn, info);

	res->received_packets = received_packets;
	res->lost_packets = lost_packets;
	res->received_bytes = received_bytes;
	res->lost_bytes = lost_bytes;

	if (lost + received <= 1)
		return -1;

	return lost * 100 / (lost + received);
}

int gprs_rlcmac_dl_tbf::update_window(unsigned first_bsn,
	const struct bitvec *rbb)
{
	int16_t dist; /* must be signed */
	uint16_t lost = 0, received = 0;
	char show_v_b[RLC_MAX_SNS + 1];
	char show_rbb[RLC_MAX_SNS + 1];
	int error_rate;
	struct ana_result ana_res;
	unsigned num_blocks = rbb->cur_bit;
	unsigned behind_last_bsn = m_window.mod_sns(first_bsn + num_blocks);

	Decoding::extract_rbb(rbb, show_rbb);
	/* show received array in debug */
	LOGP(DRLCMACDL, LOGL_DEBUG, "- ack:  (BSN=%d)\"%s\""
		"(BSN=%d)  R=ACK I=NACK\n", first_bsn,
		show_rbb, m_window.mod_sns(behind_last_bsn - 1));

	/* apply received array to receive state (first_bsn..behind_last_bsn-1) */
	if (num_blocks > 0) {
		/* calculate distance of ssn from V(S) */
		dist = m_window.mod_sns(m_window.v_s() - behind_last_bsn);
		/* check if distance is less than distance V(A)..V(S) */
		if (dist >= m_window.distance()) {
			/* this might happpen, if the downlink assignment
			 * was not received by ms and the ack refers
			 * to previous TBF
			 * FIXME: we should implement polling for
			 * control ack!*/
			LOGP(DRLCMACDL, LOGL_NOTICE, "- ack range is out of "
				"V(A)..V(S) range %s Free TBF!\n", tbf_name(this));
			return 1; /* indicate to free TBF */
		}
	}

	error_rate = analyse_errors(show_rbb, behind_last_bsn, &ana_res);

	if (bts_data()->cs_adj_enabled && ms())
		ms()->update_error_rate(this, error_rate);

	m_window.update(bts, rbb, first_bsn, &lost, &received);

	/* report lost and received packets */
	gprs_rlcmac_received_lost(this, received, lost);

	/* Used to measure the leak rate */
	gprs_bssgp_update_bytes_received(ana_res.received_bytes,
		ana_res.received_packets + ana_res.lost_packets);

	/* raise V(A), if possible */
	m_window.raise(m_window.move_window());

	/* show receive state array in debug (V(A)..V(S)-1) */
	m_window.show_state(show_v_b);
	LOGP(DRLCMACDL, LOGL_DEBUG, "- V(B): (V(A)=%d)\"%s\""
		"(V(S)-1=%d)  A=Acked N=Nacked U=Unacked "
		"X=Resend-Unacked I=Invalid\n",
		m_window.v_a(), show_v_b,
		m_window.v_s_mod(-1));
	return 0;
}

int gprs_rlcmac_dl_tbf::update_window(const uint8_t ssn, const uint8_t *rbb)
{
	int16_t dist; /* must be signed */
	uint16_t lost = 0, received = 0;
	char show_rbb[65];
	char show_v_b[RLC_MAX_SNS + 1];
	int error_rate;
	struct ana_result ana_res;

	Decoding::extract_rbb(rbb, show_rbb);
	/* show received array in debug (bit 64..1) */
	LOGP(DRLCMACDL, LOGL_DEBUG, "- ack:  (BSN=%d)\"%s\""
		"(BSN=%d)  R=ACK I=NACK\n", m_window.mod_sns(ssn - 64),
		show_rbb, m_window.mod_sns(ssn - 1));

	/* apply received array to receive state (SSN-64..SSN-1) */
	/* calculate distance of ssn from V(S) */
	dist = m_window.mod_sns(m_window.v_s() - ssn);
	/* check if distance is less than distance V(A)..V(S) */
	if (dist >= m_window.distance()) {
		/* this might happpen, if the downlink assignment
		 * was not received by ms and the ack refers
		 * to previous TBF
		 * FIXME: we should implement polling for
		 * control ack!*/
		LOGP(DRLCMACDL, LOGL_NOTICE, "- ack range is out of "
			"V(A)..V(S) range %s Free TBF!\n", tbf_name(this));
		return 1; /* indicate to free TBF */
	}

	error_rate = analyse_errors(show_rbb, ssn, &ana_res);

	if (bts_data()->cs_adj_enabled && ms())
		ms()->update_error_rate(this, error_rate);

	m_window.update(bts, show_rbb, ssn,
			&lost, &received);

	/* report lost and received packets */
	gprs_rlcmac_received_lost(this, received, lost);

	/* Used to measure the leak rate */
	gprs_bssgp_update_bytes_received(ana_res.received_bytes,
		ana_res.received_packets + ana_res.lost_packets);

	/* raise V(A), if possible */
	m_window.raise(m_window.move_window());

	/* show receive state array in debug (V(A)..V(S)-1) */
	m_window.show_state(show_v_b);
	LOGP(DRLCMACDL, LOGL_DEBUG, "- V(B): (V(A)=%d)\"%s\""
		"(V(S)-1=%d)  A=Acked N=Nacked U=Unacked "
		"X=Resend-Unacked I=Invalid\n",
		m_window.v_a(), show_v_b,
		m_window.v_s_mod(-1));

	if (state_is(GPRS_RLCMAC_FINISHED) && m_window.window_empty()) {
		LOGP(DRLCMACDL, LOGL_NOTICE, "Received acknowledge of "
			"all blocks, but without final ack "
			"inidcation (don't worry)\n");
	}
	return 0;
}


int gprs_rlcmac_dl_tbf::maybe_start_new_window()
{
	release();

	/* check for LLC PDU in the LLC Queue */
	if (llc_queue()->size() > 0)
		/* we have more data so we will re-use this tbf */
		establish_dl_tbf_on_pacch();

	return 0;
}

int gprs_rlcmac_dl_tbf::release()
{
	uint16_t received;

	/* range V(A)..V(S)-1 */
	received = m_window.count_unacked();

	/* report all outstanding packets as received */
	gprs_rlcmac_received_lost(this, received, 0);

	set_state(GPRS_RLCMAC_WAIT_RELEASE);

	/* start T3193 */
	tbf_timer_start(this, 3193,
		bts_data()->t3193_msec / 1000,
		(bts_data()->t3193_msec % 1000) * 1000);

	/* reset rlc states */
	m_tx_counter = 0;
	m_wait_confirm = 0;
	m_window.reset();

	/* keep to flags */
	state_flags &= GPRS_RLCMAC_FLAG_TO_MASK;
	state_flags &= ~(1 << GPRS_RLCMAC_FLAG_CCCH);

	return 0;
}

int gprs_rlcmac_dl_tbf::abort()
{
	uint16_t lost;

	if (state_is(GPRS_RLCMAC_FLOW)) {
		/* range V(A)..V(S)-1 */
		lost = m_window.count_unacked();

		/* report all outstanding packets as lost */
		gprs_rlcmac_received_lost(this, 0, lost);
		gprs_rlcmac_lost_rep(this);

		/* TODO: Reschedule all LLC frames starting with the one that is
		 * (partly) encoded in chunk 1 of block V(A). (optional) */
	}

	set_state(GPRS_RLCMAC_RELEASING);

	/* reset rlc states */
	m_window.reset();

	/* keep to flags */
	state_flags &= GPRS_RLCMAC_FLAG_TO_MASK;
	state_flags &= ~(1 << GPRS_RLCMAC_FLAG_CCCH);

	return 0;
}

int gprs_rlcmac_dl_tbf::rcvd_dl_ack(uint8_t final_ack, unsigned first_bsn,
	struct bitvec *rbb)
{
	int rc;
	LOGP(DRLCMACDL, LOGL_DEBUG, "%s downlink acknowledge\n", tbf_name(this));

	rc = update_window(first_bsn, rbb);

	if (final_ack) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Final ACK received.\n");
		rc = maybe_start_new_window();
	} else if (state_is(GPRS_RLCMAC_FINISHED) && m_window.window_empty()) {
		LOGP(DRLCMACDL, LOGL_NOTICE, "Received acknowledge of "
			"all blocks, but without final ack "
			"indication (don't worry)\n");
	}

	return rc;
}

int gprs_rlcmac_dl_tbf::rcvd_dl_ack(uint8_t final_ack, uint8_t ssn, uint8_t *rbb)
{
	LOGP(DRLCMACDL, LOGL_DEBUG, "%s downlink acknowledge\n", tbf_name(this));

	if (!final_ack)
		return update_window(ssn, rbb);

	LOGP(DRLCMACDL, LOGL_DEBUG, "- Final ACK received.\n");
	return maybe_start_new_window();
}

bool gprs_rlcmac_dl_tbf::dl_window_stalled() const
{
	return m_window.window_stalled();
}

void gprs_rlcmac_dl_tbf::request_dl_ack()
{
	m_dl_ack_requested = true;
}

bool gprs_rlcmac_dl_tbf::need_control_ts() const
{
	if (poll_state != GPRS_RLCMAC_POLL_NONE)
		return false;

	return state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK) ||
		m_tx_counter >= POLL_ACK_AFTER_FRAMES ||
		m_dl_ack_requested;
}

bool gprs_rlcmac_dl_tbf::have_data() const
{
	return m_llc.chunk_size() > 0 ||
		(llc_queue() && llc_queue()->size() > 0);
}

int gprs_rlcmac_dl_tbf::frames_since_last_poll(unsigned fn) const
{
	unsigned wrapped;
	if (m_last_dl_poll_fn < 0)
		return -1;

	wrapped = (fn + 2715648 - m_last_dl_poll_fn) % 2715648;
	if (wrapped < 2715648/2)
		return wrapped;
	else
		return wrapped - 2715648;
}

int gprs_rlcmac_dl_tbf::frames_since_last_drain(unsigned fn) const
{
	unsigned wrapped;
	if (m_last_dl_drained_fn < 0)
		return -1;

	wrapped = (fn + 2715648 - m_last_dl_drained_fn) % 2715648;
	if (wrapped < 2715648/2)
		return wrapped;
	else
		return wrapped - 2715648;
}

bool gprs_rlcmac_dl_tbf::keep_open(unsigned fn) const
{
	int keep_time_frames;

	if (bts_data()->dl_tbf_idle_msec <= 0)
		return false;

	keep_time_frames = msecs_to_frames(bts_data()->dl_tbf_idle_msec);
	return frames_since_last_drain(fn) <= keep_time_frames;
}
