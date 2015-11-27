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


static const struct gprs_rlcmac_cs gprs_rlcmac_cs[] = {
/*	frame length	data block	max payload */
	{ 0,		0,		0  },
	{ 23,		23,		20 }, /* CS-1 */
	{ 34,		33,		30 }, /* CS-2 */
	{ 40,		39,		36 }, /* CS-3 */
	{ 54,		53,		50 }, /* CS-4 */
};

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
		const uint8_t ms_class, const uint8_t egprs_ms_class,
		const uint16_t delay_csec,
		const uint8_t *data, const uint16_t len)
{
	struct gprs_rlcmac_dl_tbf *dl_tbf = NULL;
	int rc;
	GprsMs *ms, *ms_old;

	/* check for existing TBF */
	ms = bts->bts->ms_store().get_ms(tlli, tlli_old, imsi);
	if (ms)
		dl_tbf = ms->dl_tbf();

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

/*
 * Create DL data block
 * The messages are fragmented and forwarded as data blocks.
 */
struct msgb *gprs_rlcmac_dl_tbf::create_dl_acked_block(uint32_t fn, uint8_t ts)
{
	LOGP(DRLCMACDL, LOGL_DEBUG, "%s downlink (V(A)==%d .. "
		"V(S)==%d)\n", tbf_name(this),
		m_window.v_a(), m_window.v_s());

do_resend:
	/* check if there is a block with negative acknowledgement */
	int resend_bsn = m_window.resend_needed();
	if (resend_bsn >= 0) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Resending BSN %d\n", resend_bsn);
		/* re-send block with negative aknowlegement */
		m_window.m_v_b.mark_unacked(resend_bsn);
		bts->rlc_resent();
		return create_dl_acked_block(fn, ts, resend_bsn);
	}

	/* if the window has stalled, or transfer is complete,
	 * send an unacknowledged block */
	if (state_is(GPRS_RLCMAC_FINISHED)) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
			"because all blocks have been transmitted.\n",
			m_window.v_a());
		bts->rlc_restarted();
	} else if (dl_window_stalled()) {
		LOGP(DRLCMACDL, LOGL_NOTICE, "- Restarting at BSN %d, "
			"because all window is stalled.\n",
			m_window.v_a());
		bts->rlc_stalled();
	} else if (have_data()) {
		/* New blocks may be send */
		return create_new_bsn(fn, ts);
	} else if (!m_window.window_empty()) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- Restarting at BSN %d, "
			"because all blocks have been transmitted (FLOW).\n",
			m_window.v_a());
		bts->rlc_restarted();
	} else {
		/* Nothing left to send, create dummy LLC commands */
		return create_new_bsn(fn, ts);
	}

	/* If V(S) == V(A) and finished state, we would have received
	 * acknowledgement of all transmitted block. In this case we
	 * would have transmitted the final block, and received ack
	 * from MS. But in this case we did not receive the final ack
	 * indication from MS. This should never happen if MS works
	 * correctly. */
	if (m_window.window_empty()) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "- MS acked all blocks, "
			"so we re-transmit final block!\n");
		/* we just send final block again */
		int16_t index = m_window.v_s_mod(-1);
		bts->rlc_resent();
		return create_dl_acked_block(fn, ts, index);
	}

	/* cycle through all unacked blocks */
	int resend = m_window.mark_for_resend();

	/* At this point there should be at least one unacked block
	 * to be resent. If not, this is an software error. */
	if (resend == 0) {
		LOGP(DRLCMACDL, LOGL_ERROR, "Software error: "
			"There are no unacknowledged blocks, but V(A) "
			" != V(S). PLEASE FIX!\n");
		/* we just send final block again */
		int16_t index = m_window.v_s_mod(-1);
		return create_dl_acked_block(fn, ts, index);
	}
	goto do_resend;
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

struct msgb *gprs_rlcmac_dl_tbf::create_new_bsn(const uint32_t fn, const uint8_t ts)
{
	struct rlc_dl_header *rh;
	struct rlc_li_field *li;
	uint8_t *delimiter, *data, *e_pointer;
	uint16_t space, chunk;
	gprs_rlc_data *rlc_data;
	const uint16_t bsn = m_window.v_s();
	uint8_t cs = 1;

	if (m_llc.frame_length() == 0)
		schedule_next_frame();

	cs = current_cs();

	LOGP(DRLCMACDL, LOGL_DEBUG, "- Sending new block at BSN %d, CS=%d\n",
		m_window.v_s(), cs);

	OSMO_ASSERT(cs >= 1);
	OSMO_ASSERT(cs <= 4);

	/* total length of block, including spare bits */
	const uint8_t block_length = gprs_rlcmac_cs[cs].block_length;
	/* length of usable data of block, w/o spare bits, inc. MAC */
	const uint8_t block_data_len = gprs_rlcmac_cs[cs].block_data;

	/* now we still have untransmitted LLC data, so we fill mac block */
	rlc_data = m_rlc.block(bsn);
	data = rlc_data->prepare(block_data_len);
	rlc_data->cs = cs;

	rh = (struct rlc_dl_header *)data;
	rh->pt = 0; /* Data Block */
	rh->rrbp = rh->s_p = 0; /* Polling, set later, if required */
	rh->usf = 7; /* will be set at scheduler */
	rh->pr = 0; /* FIXME: power reduction */
	rh->tfi = m_tfi; /* TFI */
	rh->fbi = 0; /* Final Block Indicator, set late, if true */
	rh->bsn = bsn; /* Block Sequence Number */
	rh->e = 0; /* Extension bit, maybe set later */
	e_pointer = data + 2; /* points to E of current chunk */
	data += sizeof(*rh);
	delimiter = data; /* where next length header would be stored */
	space = block_data_len - sizeof(*rh);
	while (1) {
		if (m_llc.frame_length() == 0) {
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

		chunk = m_llc.chunk_size();

		/* if chunk will exceed block limit */
		if (chunk > space) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
				"larger than space (%d) left in block: copy "
				"only remaining space, and we are done\n",
				chunk, space);
			/* block is filled, so there is no extension */
			*e_pointer |= 0x01;
			/* fill only space */
			m_llc.consume(data, space);
			/* return data block as message */
			break;
		}
		/* if FINAL chunk would fit precisely in space left */
		if (chunk == space && llc_queue()->size() == 0 && !keep_open(fn))
		{
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
				"would exactly fit into space (%d): because "
				"this is a final block, we don't add length "
				"header, and we are done\n", chunk, space);
			LOGP(DRLCMACDL, LOGL_INFO, "Complete DL frame for "
				"%s that fits precisely in last block: "
				"len=%d\n", tbf_name(this), m_llc.frame_length());
			gprs_rlcmac_dl_bw(this, m_llc.frame_length());
			/* block is filled, so there is no extension */
			*e_pointer |= 0x01;
			/* fill space */
			m_llc.consume(data, space);
			m_llc.reset();
			/* final block */
			rh->fbi = 1; /* we indicate final block */
			request_dl_ack();
			set_state(GPRS_RLCMAC_FINISHED);
			/* return data block as message */
			break;
		}
		/* if chunk would fit exactly in space left */
		if (chunk == space) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
				"would exactly fit into space (%d): add length "
				"header with LI=0, to make frame extend to "
				"next block, and we are done\n", chunk, space);
			/* make space for delimiter */
			if (delimiter != data)
				memmove(delimiter + 1, delimiter,
					data - delimiter);
			data++;
			space--;
			/* add LI with 0 length */
			li = (struct rlc_li_field *)delimiter;
			li->e = 1; /* not more extension */
			li->m = 0; /* shall be set to 0, in case of li = 0 */
			li->li = 0; /* chunk fills the complete space */
			// no need to set e_pointer nor increase delimiter
			/* fill only space, which is 1 octet less than chunk */
			m_llc.consume(data, space);
			/* return data block as message */
			break;
		}

		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d is less "
			"than remaining space (%d): add length header to "
			"to delimit LLC frame\n", chunk, space);
		/* the LLC frame chunk ends in this block */
		/* make space for delimiter */
		if (delimiter != data)
			memmove(delimiter + 1, delimiter, data - delimiter);
		data++;
		space--;
		/* add LI to delimit frame */
		li = (struct rlc_li_field *)delimiter;
		li->e = 0; /* Extension bit, maybe set later */
		li->m = 0; /* will be set later, if there is more LLC data */
		li->li = chunk; /* length of chunk */
		e_pointer = delimiter; /* points to E of current delimiter */
		delimiter++;
		/* copy (rest of) LLC frame to space and reset later */
		m_llc.consume(data, chunk);
		data += chunk;
		space -= chunk;
		LOGP(DRLCMACDL, LOGL_INFO, "Complete DL frame for %s"
			"len=%d\n", tbf_name(this), m_llc.frame_length());
		gprs_rlcmac_dl_bw(this, m_llc.frame_length());
		m_llc.reset();
		/* dequeue next LLC frame, if any */
		schedule_next_frame();
		/* if we have more data and we have space left */
		if (space > 0 && (m_llc.frame_length() || keep_open(fn))) {
			li->m = 1; /* we indicate more frames to follow */
			continue;
		}
		/* if we don't have more LLC frames */
		if (!m_llc.frame_length() && !keep_open(fn)) {
			LOGP(DRLCMACDL, LOGL_DEBUG, "-- Final block, so we "
				"done.\n");
			li->e = 1; /* we cannot extend */

			rh->fbi = 1; /* we indicate final block */
			request_dl_ack();
			set_state(GPRS_RLCMAC_FINISHED);
			break;
		}
		/* we have no space left */
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- No space left, so we are "
			"done.\n");
		li->e = 1; /* we cannot extend */
		break;
	}
	LOGP(DRLCMACDL, LOGL_DEBUG, "data block: %s\n",
		osmo_hexdump(rlc_data->block, block_length));
#warning "move this up?"
	rlc_data->len = block_length;
	/* raise send state and set ack state array */
	m_window.m_v_b.mark_unacked(bsn);
	m_window.increment_send();

	return create_dl_acked_block(fn, ts, bsn);
}

struct msgb *gprs_rlcmac_dl_tbf::create_dl_acked_block(
				const uint32_t fn, const uint8_t ts,
				const int index)
{
	uint8_t *data;
	struct rlc_dl_header *rh;
	struct msgb *dl_msg;
	uint8_t len;
	bool need_poll;

	/* get data and header from current block */
	data = m_rlc.block(index)->block;
	len = m_rlc.block(index)->len;
	rh = (struct rlc_dl_header *)data;

	/* If the TBF has just started, relate frames_since_last_poll to the
	 * current fn */
	if (m_last_dl_poll_fn < 0)
		m_last_dl_poll_fn = fn;

	need_poll = state_flags & (1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);
	/* Clear Polling, if still set in history buffer */
	rh->s_p = 0;
		
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
		/* scheduling not possible, because: */
		if (poll_state != GPRS_RLCMAC_POLL_NONE)
			LOGP(DRLCMACDL, LOGL_DEBUG, "Polling is already "
				"sheduled for %s, so we must wait for "
				"requesting downlink ack\n", tbf_name(this));
		else if (control_ts != ts)
			LOGP(DRLCMACDL, LOGL_DEBUG, "Polling cannot be "
				"sheduled in this TS %d, waiting for "
				"TS %d\n", ts, control_ts);
		else if (bts->sba()->find(trx->trx_no, ts, (fn + 13) % 2715648))
			LOGP(DRLCMACDL, LOGL_DEBUG, "Polling cannot be "
				"sheduled, because single block alllocation "
				"already exists\n");
		else  {
			LOGP(DRLCMACDL, LOGL_DEBUG, "Polling sheduled in this "
				"TS %d\n", ts);
			m_tx_counter = 0;
			/* start timer whenever we send the final block */
			if (rh->fbi == 1)
				tbf_timer_start(this, 3191, bts_data()->t3191, 0);

			/* schedule polling */
			poll_state = GPRS_RLCMAC_POLL_SCHED;
			poll_fn = (fn + 13) % 2715648;

			/* Clear poll timeout flag */
			state_flags &= ~(1 << GPRS_RLCMAC_FLAG_TO_DL_ACK);

			/* Clear request flag */
			m_dl_ack_requested = false;

			/* set polling in header */
			rh->rrbp = 0; /* N+13 */
			rh->s_p = 1; /* Polling */

			m_last_dl_poll_fn = poll_fn;

			LOGP(DRLCMACDL, LOGL_INFO,
				"%s Scheduled Ack/Nack polling on FN=%d, TS=%d\n",
				name(), poll_fn, ts);
		}
	}

	/* return data block as message */
	dl_msg = msgb_alloc(len, "rlcmac_dl_data");
	if (!dl_msg)
		return NULL;

	/* Increment TX-counter */
	m_tx_counter++;

	memcpy(msgb_put(dl_msg, len), data, len);
	bts->rlc_sent();

	return dl_msg;
}

static uint16_t bitnum_to_bsn(int bitnum, uint16_t ssn, uint16_t mod_sns)
{
	return (ssn - 1 - bitnum) & mod_sns;
}

int gprs_rlcmac_dl_tbf::analyse_errors(char *show_rbb, uint8_t ssn,
	ana_result *res)
{
	gprs_rlc_data *rlc_data;
	uint16_t lost = 0, received = 0, skipped = 0;
	char info[65];
	memset(info, '.', sizeof(info));
	info[64] = 0;
	uint16_t bsn = 0;
	unsigned received_bytes = 0, lost_bytes = 0;
	unsigned received_packets = 0, lost_packets = 0;

	/* SSN - 1 is in range V(A)..V(S)-1 */
	for (int bitpos = 0; bitpos < m_window.ws(); bitpos++) {
		bool is_received = show_rbb[m_window.ws() - 1 - bitpos] == 'R';

		bsn = bitnum_to_bsn(bitpos, ssn, m_window.mod_sns());

		if (bsn == ((m_window.v_a() - 1) & m_window.mod_sns())) {
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


int gprs_rlcmac_dl_tbf::update_window(const uint8_t ssn, const uint8_t *rbb)
{
	int16_t dist; /* must be signed */
	uint16_t lost = 0, received = 0;
	char show_rbb[65];
	char show_v_b[RLC_MAX_SNS + 1];
	const uint16_t mod_sns = m_window.mod_sns();
	int error_rate;
	struct ana_result ana_res;

	Decoding::extract_rbb(rbb, show_rbb);
	/* show received array in debug (bit 64..1) */
	LOGP(DRLCMACDL, LOGL_DEBUG, "- ack:  (BSN=%d)\"%s\""
		"(BSN=%d)  R=ACK I=NACK\n", (ssn - 64) & mod_sns,
		show_rbb, (ssn - 1) & mod_sns);

	/* apply received array to receive state (SSN-64..SSN-1) */
	/* calculate distance of ssn from V(S) */
	dist = (m_window.v_s() - ssn) & mod_sns;
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
