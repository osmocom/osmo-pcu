/* PDCH scheduler
 *
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
 
#include <gprs_bssgp_pcu.h>
#include <gprs_rlcmac.h>
#include <pcu_l1_if.h>
#include <bts.h>
#include <tbf.h>

#include "pcu_utils.h"

static uint32_t sched_poll(BTS *bts,
		    uint8_t trx, uint8_t ts, uint32_t fn, uint8_t block_nr,
		    struct gprs_rlcmac_tbf **poll_tbf,
		    struct gprs_rlcmac_tbf **ul_ass_tbf,
		    struct gprs_rlcmac_tbf **dl_ass_tbf,
		    struct gprs_rlcmac_ul_tbf **ul_ack_tbf)
{
	struct gprs_rlcmac_ul_tbf *ul_tbf;
	struct gprs_rlcmac_dl_tbf *dl_tbf;
	LListHead<gprs_rlcmac_tbf> *pos;
	uint32_t poll_fn;

	/* check special TBF for events */
	poll_fn = fn + 4;
	if ((block_nr % 3) == 2)
		poll_fn ++;
	poll_fn = poll_fn % GSM_MAX_FN;
	llist_for_each(pos, &bts->ul_tbfs()) {
		ul_tbf = as_ul_tbf(pos->entry());
		OSMO_ASSERT(ul_tbf);
		/* this trx, this ts */
		if (ul_tbf->trx->trx_no != trx || !ul_tbf->is_control_ts(ts))
			continue;
		/* polling for next uplink block */
		if (ul_tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && ul_tbf->poll_fn == poll_fn)
			*poll_tbf = ul_tbf;
		if (ul_tbf->ul_ack_state == GPRS_RLCMAC_UL_ACK_SEND_ACK)
			*ul_ack_tbf = ul_tbf;
		if (ul_tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_SEND_ASS)
			*dl_ass_tbf = ul_tbf;
		if (ul_tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_SEND_ASS
			|| ul_tbf->ul_ass_state ==
				GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ)
			*ul_ass_tbf = ul_tbf;
/* FIXME: Is this supposed to be fair? The last TBF for each wins? Maybe use llist_add_tail and skip once we have all
states? */
	}
	llist_for_each(pos, &bts->dl_tbfs()) {
		dl_tbf = as_dl_tbf(pos->entry());
		OSMO_ASSERT(dl_tbf);
		/* this trx, this ts */
		if (dl_tbf->trx->trx_no != trx || !dl_tbf->is_control_ts(ts))
			continue;
		/* polling for next uplink block */
		if (dl_tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && dl_tbf->poll_fn == poll_fn)
			*poll_tbf = dl_tbf;
		if (dl_tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_SEND_ASS)
			*dl_ass_tbf = dl_tbf;
		if (dl_tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_SEND_ASS
		 || dl_tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ)
			*ul_ass_tbf = dl_tbf;
	}

	return poll_fn;
}

static uint8_t sched_select_uplink(uint8_t trx, uint8_t ts, uint32_t fn,
	uint8_t block_nr, struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_ul_tbf *tbf;
	uint8_t usf = 0x07;
	uint8_t i, tfi;

	/* select uplink resource */
	for (i = 0, tfi = pdch->next_ul_tfi; i < 32;
	     i++, tfi = (tfi + 1) & 31) {
		tbf = pdch->ul_tbf_by_tfi(tfi);
		/* no TBF for this tfi, go next */
		if (!tbf)
			continue;
		/* no UL resources needed, go next */
		/* we don't need to give resources in FINISHED state,
		 * because we have received all blocks and only poll
		 * for packet control ack. */
		if (tbf->state_is_not(GPRS_RLCMAC_FLOW))
			continue;

		/* use this USF */
		usf = tbf->m_usf[ts];
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling USF=%d for "
			"required uplink resource of UL TFI=%d\n", trx, ts, fn,
			block_nr, usf, tfi);
		/* next TBF to handle resource is the next one */
		pdch->next_ul_tfi = (tfi + 1) & 31;
		break;
	}

	return usf;
}

static struct msgb *sched_select_ctrl_msg(
		    uint8_t trx, uint8_t ts, uint32_t fn,
		    uint8_t block_nr, struct gprs_rlcmac_pdch *pdch,
		    struct gprs_rlcmac_tbf *ul_ass_tbf,
		    struct gprs_rlcmac_tbf *dl_ass_tbf,
		    struct gprs_rlcmac_ul_tbf *ul_ack_tbf)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_tbf *tbf = NULL;
	struct gprs_rlcmac_tbf *next_list[3] = { ul_ass_tbf, dl_ass_tbf, ul_ack_tbf };

	for (size_t i = 0; i < ARRAY_SIZE(next_list); ++i) {
		tbf = next_list[(pdch->next_ctrl_prio + i) % 3];
		if (!tbf)
			continue;

		/*
		 * Assignments for the same direction have lower precedence,
		 * because they may kill the TBF when the CONTROL ACK is
		 * received, thus preventing the others from being processed.
		 */
		if (tbf == ul_ass_tbf && tbf->ul_ass_state ==
				GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ)
			msg = ul_ass_tbf->create_packet_access_reject();
		else if (tbf == ul_ass_tbf && tbf->direction ==
				GPRS_RLCMAC_DL_TBF)
			if (tbf->ul_ass_state ==
					GPRS_RLCMAC_UL_ASS_SEND_ASS_REJ)
				msg = ul_ass_tbf->create_packet_access_reject();
			else
				msg = ul_ass_tbf->create_ul_ass(fn, ts);
		else if (tbf == dl_ass_tbf && tbf->direction == GPRS_RLCMAC_UL_TBF)
			msg = dl_ass_tbf->create_dl_ass(fn, ts);
		else if (tbf == ul_ack_tbf)
			msg = ul_ack_tbf->create_ul_ack(fn, ts);

		if (!msg) {
			tbf = NULL;
			continue;
		}

		pdch->next_ctrl_prio += 1;
		pdch->next_ctrl_prio %= 3;
		break;
	}

	if (!msg) {
		/*
		 * If one of these is left, the response (CONTROL ACK) from the
		 * MS will kill the current TBF, only one of them can be
		 * non-NULL
		 */
		if (dl_ass_tbf) {
			tbf = dl_ass_tbf;
			msg = dl_ass_tbf->create_dl_ass(fn, ts);
		} else if (ul_ass_tbf) {
			tbf = ul_ass_tbf;
			msg = ul_ass_tbf->create_ul_ass(fn, ts);
		}
	}

	/* any message */
	if (msg) {
		if (!tbf) {
			LOGP(DRLCMACSCHED, LOGL_ERROR,
			     "Control message to be scheduled, but no TBF (TRX=%d, TS=%d)\n", trx, ts);
			msgb_free(msg);
			return NULL;
		}
		tbf->rotate_in_list();
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling control "
			"message at RTS for %s (TRX=%d, TS=%d)\n",
			tbf_name(tbf), trx, ts);
		/* Updates the dl ctrl msg counter for ms */
		tbf->ms()->update_dl_ctrl_msg();
		return msg;
	}

	/* schedule PACKET PAGING REQUEST, if any are pending */
	msg = pdch->packet_paging_request();
	if (msg) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling paging request "
			"message at RTS for (TRX=%d, TS=%d)\n", trx, ts);
		return msg;
	}

	return NULL;
}

static inline enum tbf_dl_prio tbf_compute_priority(const struct gprs_rlcmac_bts *bts, struct gprs_rlcmac_dl_tbf *tbf,
						    uint8_t ts, uint32_t fn, int age)
{
	const gprs_rlc_dl_window *w = tbf->window();
	int age_thresh1 = msecs_to_frames(200),
		age_thresh2 = msecs_to_frames(OSMO_MIN(BTS::TIMER_T3190_MSEC/2, bts->dl_tbf_idle_msec));

	if (tbf->is_control_ts(ts) && tbf->need_control_ts())
		return DL_PRIO_CONTROL;

	if (tbf->is_control_ts(ts) && age > age_thresh2 && age_thresh2 > 0)
		return DL_PRIO_HIGH_AGE;

	if ((tbf->state_is(GPRS_RLCMAC_FLOW) && tbf->have_data()) || w->resend_needed() >= 0)
		return DL_PRIO_NEW_DATA;

	if (tbf->is_control_ts(ts) && age > age_thresh1 && tbf->keep_open(fn))
		return DL_PRIO_LOW_AGE;

	if (!w->window_empty())
		return DL_PRIO_SENT_DATA;

	return DL_PRIO_NONE;
}

static struct msgb *sched_select_downlink(struct gprs_rlcmac_bts *bts,
		    uint8_t trx, uint8_t ts, uint32_t fn,
		    uint8_t block_nr, struct gprs_rlcmac_pdch *pdch)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_dl_tbf *tbf, *prio_tbf = NULL;
	enum tbf_dl_prio prio, max_prio = DL_PRIO_NONE;

	uint8_t i, tfi, prio_tfi;
	int age;

	/* select downlink resource */
	for (i = 0, tfi = pdch->next_dl_tfi; i < 32;
	     i++, tfi = (tfi + 1) & 31) {
		tbf = pdch->dl_tbf_by_tfi(tfi);
		/* no TBF for this tfi, go next */
		if (!tbf)
			continue;
		/* no DL TBF, go next */
		if (tbf->direction != GPRS_RLCMAC_DL_TBF)
			continue;
		/* no DL resources needed, go next */
		if (tbf->state_is_not(GPRS_RLCMAC_FLOW)
		 && tbf->state_is_not(GPRS_RLCMAC_FINISHED))
			continue;

		/* waiting for CCCH IMM.ASS confirm */
		if (tbf->m_wait_confirm)
			continue;

		age = tbf->frames_since_last_poll(fn);

		/* compute priority */
		prio = tbf_compute_priority(bts, tbf, ts, fn, age);
		if (prio == DL_PRIO_NONE)
			continue;

		/* get the TBF with the highest priority */
		if (prio > max_prio) {
			prio_tfi = tfi;
			prio_tbf = tbf;
			max_prio = prio;
		}
	}

	if (prio_tbf) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling data message at "
			"RTS for DL TFI=%d (TRX=%d, TS=%d) prio=%d\n",
			prio_tfi, trx, ts, max_prio);
		/* next TBF to handle resource is the next one */
		pdch->next_dl_tfi = (prio_tfi + 1) & 31;
		/* generate DL data block */
		msg = prio_tbf->create_dl_acked_block(fn, ts);
	}

	return msg;
}

static const uint8_t rlcmac_dl_idle[23] = {
	0x47, /* control without optional header octets, no polling, USF=111 */
	0x94, /* dummy downlink control message, paging mode 00 */
	0x2b, /* no persistance level, 7 bits spare pattern */
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
};

static struct msgb *sched_dummy(void)
{
	struct msgb *msg;

	msg = msgb_alloc(23, "rlcmac_dl_idle");
	if (!msg)
		return NULL;
	memcpy(msgb_put(msg, 23), rlcmac_dl_idle, 23);

	return msg;
}

static inline void tap_n_acc(const struct msgb *msg, const struct gprs_rlcmac_bts *bts, uint8_t trx, uint8_t ts,
			     uint32_t fn, enum pcu_gsmtap_category cat)
{
	if (!msg)
		return;

	switch(cat) {
	case PCU_GSMTAP_C_DL_CTRL:
		bts->bts->rlc_sent_control();
		bts->bts->send_gsmtap(PCU_GSMTAP_C_DL_CTRL, false, trx, ts, GSMTAP_CHANNEL_PACCH, fn, msg->data,
				      msg->len);
		break;
	case PCU_GSMTAP_C_DL_DATA_GPRS:
		bts->bts->rlc_sent();
		/* FIXME: distinguish between GPRS and EGPRS */
		bts->bts->send_gsmtap(PCU_GSMTAP_C_DL_DATA_GPRS, false, trx, ts, GSMTAP_CHANNEL_PDTCH, fn, msg->data,
				      msg->len);
		break;
	case PCU_GSMTAP_C_DL_DUMMY:
		bts->bts->rlc_sent_dummy();
		bts->bts->send_gsmtap(PCU_GSMTAP_C_DL_DUMMY, false, trx, ts, GSMTAP_CHANNEL_PACCH, fn, msg->data,
				      msg->len);
		break;
	default:
		break;
	}
}

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts,
        uint32_t fn, uint8_t block_nr)
{
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf *poll_tbf = NULL, *dl_ass_tbf = NULL,
		*ul_ass_tbf = NULL;
	struct gprs_rlcmac_ul_tbf *ul_ack_tbf = NULL;
	uint8_t usf = 0x7;
	struct msgb *msg = NULL;
	uint32_t poll_fn, sba_fn;

	if (trx >= 8 || ts >= 8)
		return -EINVAL;
	pdch = &bts->trx[trx].pdch[ts];

	if (!pdch->is_enabled()) {
		LOGP(DRLCMACSCHED, LOGL_ERROR, "Received RTS on disabled PDCH: "
			"TRX=%d TS=%d\n", trx, ts);
		return -EIO;
	}

	/* store last frame number of RTS */
	pdch->last_rts_fn = fn;

	poll_fn = sched_poll(bts->bts, trx, ts, fn, block_nr, &poll_tbf, &ul_ass_tbf,
		&dl_ass_tbf, &ul_ack_tbf);
	/* check uplink resource for polling */
	if (poll_tbf)
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling free USF for "
			"polling at FN=%d of %s\n", trx, ts, fn,
			block_nr, poll_fn,
			tbf_name(poll_tbf));
		/* use free USF */
	/* else. check for sba */
	else if ((sba_fn = bts->bts->sba()->sched(trx, ts, fn, block_nr) != 0xffffffff))
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling free USF for "
			"single block allocation at FN=%d\n", trx, ts, fn,
			block_nr, sba_fn);
		/* use free USF */
	/* else, we search for uplink resource */
	else
		usf = sched_select_uplink(trx, ts, fn, block_nr, pdch);

	/* Prio 1: select control message */
	msg = sched_select_ctrl_msg(trx, ts, fn, block_nr, pdch, ul_ass_tbf,
		dl_ass_tbf, ul_ack_tbf);
	tap_n_acc(msg, bts, trx, ts, fn, PCU_GSMTAP_C_DL_CTRL);

	/* Prio 2: select data message for downlink */
	if (!msg) {
		msg = sched_select_downlink(bts, trx, ts, fn, block_nr, pdch);
		tap_n_acc(msg, bts, trx, ts, fn, PCU_GSMTAP_C_DL_DATA_GPRS);
	}

	/* Prio 3: send dummy contol message */
	if (!msg) {
		/* increase counter */
		msg = sched_dummy();
		tap_n_acc(msg, bts, trx, ts, fn, PCU_GSMTAP_C_DL_DUMMY);
	}

	if (!msg)
		return -ENOMEM;
	/* msg is now available */
	bts->bts->rlc_dl_bytes(msg->data_len);

	/* set USF */
	OSMO_ASSERT(msgb_length(msg) > 0);
	msg->data[0] = (msg->data[0] & 0xf8) | usf;

	/* Used to measure the leak rate, count all blocks */
	gprs_bssgp_update_frames_sent();

	/* send PDTCH/PACCH to L1 */
	pcu_l1if_tx_pdtch(msg, trx, ts, bts->trx[trx].arfcn, fn, block_nr);

	return 0;
}
