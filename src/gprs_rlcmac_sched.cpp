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

static uint32_t sched_poll(struct gprs_rlcmac_bts *bts,
		    uint8_t trx, uint8_t ts, uint32_t fn, uint8_t block_nr,
		    struct gprs_rlcmac_tbf **poll_tbf,
		    struct gprs_rlcmac_tbf **ul_ass_tbf,
		    struct gprs_rlcmac_tbf **dl_ass_tbf,
		    struct gprs_rlcmac_tbf **ul_ack_tbf)
{
	struct gprs_rlcmac_tbf *tbf;
	uint32_t poll_fn;

	/* check special TBF for events */
	poll_fn = fn + 4;
	if ((block_nr % 3) == 2)
		poll_fn ++;
	poll_fn = poll_fn % 2715648;
	llist_for_each_entry(tbf, &bts->ul_tbfs, list) {
		/* this trx, this ts */
		if (tbf->trx_no != trx || tbf->control_ts != ts)
			continue;
		/* polling for next uplink block */
		if (tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == poll_fn)
			*poll_tbf = tbf;
		if (tbf->ul_ack_state == GPRS_RLCMAC_UL_ACK_SEND_ACK)
			*ul_ack_tbf = tbf;
		if (tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_SEND_ASS)
			*dl_ass_tbf = tbf;
		if (tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_SEND_ASS)
			*ul_ass_tbf = tbf;
#warning "Is this supposed to be fair? The last TBF for each wins? Maybe use llist_add_tail and skip once we have all states?"
	}
	llist_for_each_entry(tbf, &bts->dl_tbfs, list) {
		/* this trx, this ts */
		if (tbf->trx_no != trx || tbf->control_ts != ts)
			continue;
		/* polling for next uplink block */
		if (tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == poll_fn)
			*poll_tbf = tbf;
		if (tbf->dl_ass_state == GPRS_RLCMAC_DL_ASS_SEND_ASS)
			*dl_ass_tbf = tbf;
		if (tbf->ul_ass_state == GPRS_RLCMAC_UL_ASS_SEND_ASS)
			*ul_ass_tbf = tbf;
	}

	return poll_fn;
}

uint8_t sched_select_uplink(uint8_t trx, uint8_t ts, uint32_t fn,
	uint8_t block_nr, struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_tbf *tbf;
	uint8_t usf = 0x07;
	uint8_t i, tfi;

	/* select uplink ressource */
	for (i = 0, tfi = pdch->next_ul_tfi; i < 32;
	     i++, tfi = (tfi + 1) & 31) {
		tbf = pdch->ul_tbf[tfi];
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
		usf = tbf->dir.ul.usf[ts];
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling USF=%d for "
			"required uplink ressource of UL TBF=%d\n", trx, ts, fn,
			block_nr, usf, tfi);
		/* next TBF to handle ressource is the next one */
		pdch->next_ul_tfi = (tfi + 1) & 31;
		break;
	}

	return usf;
}

static struct msgb *sched_select_ctrl_msg(struct gprs_rlcmac_bts *bts,
		    uint8_t trx, uint8_t ts, uint32_t fn,
		    uint8_t block_nr, struct gprs_rlcmac_pdch *pdch,
		    struct gprs_rlcmac_tbf *ul_ass_tbf,
		    struct gprs_rlcmac_tbf *dl_ass_tbf,
		    struct gprs_rlcmac_tbf *ul_ack_tbf)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_tbf *tbf = NULL;

	/* schedule PACKET UPLINK ASSIGNMENT (1st priority) */
	if (ul_ass_tbf) {
		tbf = ul_ass_tbf;
		msg = gprs_rlcmac_send_packet_uplink_assignment(tbf, fn);
	}
	/* schedule PACKET DOWNLINK ASSIGNMENT (2nd priotiry) */
	if (!msg && dl_ass_tbf) {
		tbf = dl_ass_tbf;
		msg = tbf->create_dl_ass(fn);
	}
	/* schedule PACKET UPLINK ACK (3rd priority) */
	if (!msg && ul_ack_tbf) {
		tbf = ul_ack_tbf;
		msg = tbf->create_ul_ack(fn);
	}
	/* any message */
	if (msg) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling control "
			"message at RTS for %s TBF=%d (TRX=%d, TS=%d)\n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF)
					? "UL" : "DL", tbf->tfi, trx, ts);
		return msg;
	}
	/* schedule PACKET PAGING REQUEST */
	msg = pdch->packet_paging_request();
	if (msg) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling paging request "
			"message at RTS for (TRX=%d, TS=%d)\n", trx, ts);
		return msg;
	}

	return NULL;
}

static struct msgb *sched_select_downlink(struct gprs_rlcmac_bts *bts,
		    uint8_t trx, uint8_t ts, uint32_t fn,
		    uint8_t block_nr, struct gprs_rlcmac_pdch *pdch)
{
	struct msgb *msg = NULL;
	struct gprs_rlcmac_tbf *tbf = NULL;
	uint8_t i, tfi;

	/* select downlink ressource */
	for (i = 0, tfi = pdch->next_dl_tfi; i < 32;
	     i++, tfi = (tfi + 1) & 31) {
		tbf = pdch->dl_tbf[tfi];
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
		if (tbf->dir.dl.wait_confirm)
			continue;

		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling data message at "
			"RTS for DL TBF=%d (TRX=%d, TS=%d)\n", tfi, trx, ts);
		/* next TBF to handle ressource is the next one */
		pdch->next_dl_tfi = (tfi + 1) & 31;
		/* generate DL data block */
		msg = gprs_rlcmac_send_data_block_acknowledged(tbf, fn, ts);
		break;
	}

	return msg;
}
static uint8_t rlcmac_dl_idle[23] = {
	0x47, /* control without optional header octets, no polling, USF=111 */
	0x94, /* dummy downlink control message, paging mode 00 */
	0x2b, /* no persistance level, 7 bits spare pattern */
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
};

struct msgb *sched_dummy(void)
{
	struct msgb *msg;

	msg = msgb_alloc(23, "rlcmac_dl_idle");
	if (!msg)
		return NULL;
	memcpy(msgb_put(msg, 23), rlcmac_dl_idle, 23);

	return msg;
}

int gprs_rlcmac_rcv_rts_block(struct gprs_rlcmac_bts *bts,
	uint8_t trx, uint8_t ts, uint16_t arfcn,
        uint32_t fn, uint8_t block_nr)
{
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf *poll_tbf = NULL, *dl_ass_tbf = NULL,
		*ul_ass_tbf = NULL, *ul_ack_tbf = NULL;
	uint8_t usf = 0x7;
	struct msgb *msg = NULL;
	uint32_t poll_fn, sba_fn;

#warning "ARFCN... it is already in the TRX..... is it consistent with it?"

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

	poll_fn = sched_poll(bts, trx, ts, fn, block_nr, &poll_tbf, &ul_ass_tbf,
		&dl_ass_tbf, &ul_ack_tbf);
	/* check uplink ressource for polling */
	if (poll_tbf)
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling free USF for "
			"polling at FN=%d of %s TFI=%d\n", trx, ts, fn,
			block_nr, poll_fn,
			(poll_tbf->direction == GPRS_RLCMAC_UL_TBF)
				? "UL" : "DL", poll_tbf->tfi);
		/* use free USF */
	/* else. check for sba */
	else if ((sba_fn = bts->bts->sba()->sched(trx, ts, fn, block_nr) != 0xffffffff))
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling free USF for "
			"single block allocation at FN=%d\n", trx, ts, fn,
			block_nr, sba_fn);
		/* use free USF */
	/* else, we search for uplink ressource */
	else
		usf = sched_select_uplink(trx, ts, fn, block_nr, pdch);

	/* Prio 1: select control message */
	msg = sched_select_ctrl_msg(bts, trx, ts, fn, block_nr, pdch, ul_ass_tbf,
		dl_ass_tbf, ul_ack_tbf);

	/* Prio 2: select data message for downlink */
	if (!msg)
		msg = sched_select_downlink(bts, trx, ts, fn, block_nr, pdch);

	/* Prio 3: send dummy contol message */
	if (!msg)
		msg = sched_dummy();

	if (!msg)
		return -ENOMEM;
	/* msg is now available */

	/* set USF */
	msg->data[0] = (msg->data[0] & 0xf8) | usf;

	/* send PDTCH/PACCH to L1 */
	pcu_l1if_tx_pdtch(msg, trx, ts, arfcn, fn, block_nr);

	return 0;
}
