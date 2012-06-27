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

extern struct llist_head block_queue;

static uint8_t rlcmac_dl_idle[23] = {
	0x47, /* control without optional header octets, no polling, USF=111 */
	0x94, /* dummy downlink control message, paging mode 00 */
	0x2b, /* no persistance level, 7 bits spare pattern */
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b,
	0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b, 0x2b
};

int gprs_rlcmac_rcv_rts_block(uint8_t trx, uint8_t ts, uint16_t arfcn,
        uint32_t fn, uint8_t block_nr)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf *tbf;
	uint8_t usf = 0x7;
	struct msgb *msg = NULL;
	uint32_t poll_fn;
	uint8_t i, tfi;

	if (trx >= 8 || ts >= 8)
		return -EINVAL;
	pdch = &bts->trx[trx].pdch[ts];

	if (!pdch->enable) {
		LOGP(DRLCMACSCHED, LOGL_ERROR, "Received RTS on disabled PDCH: "
			"TRX=%d TS=%d\n", trx, ts);
		return -EIO;
	}

	/* check uplink ressource for polling */
	poll_fn = fn + 4;
	if ((block_nr % 3) == 2)
		poll_fn ++;
	poll_fn = poll_fn % 2715648;
	for (tfi = 0; tfi < 32; tfi++) {
		tbf = pdch->tbf[tfi];
		/* no TBF for this tfi, go next */
		if (!tbf)
			continue;
		/* no polling */
		if (tbf->poll_state != GPRS_RLCMAC_POLL_SCHED)
			continue;
		/* polling for next uplink block */
		if (tbf->poll_fn == poll_fn)
			break;
	}
	/* found uplink where a block is polled */
	if (tfi < 32) {
		LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: TRX=%d "
			"TS=%d FN=%d block_nr=%d scheduling free USF for "
			"polling at FN=%d of TFI=%d\n", trx, ts, fn, block_nr,
			poll_fn, tfi);
		/* reset poll state */
		tbf->poll_state = GPRS_RLCMAC_POLL_NONE;
		/* use free USF */
	/* else, we search for uplink ressource */
	} else {
		/* select uplink ressource */
		for (i = 0, tfi = pdch->next_ul_tfi; i < 32;
		     i++, tfi = (tfi + 1) & 31) {
			tbf = pdch->tbf[tfi];
			/* no TBF for this tfi, go next */
			if (!tbf)
				continue;
			/* no UL TBF, go next */
			if (tbf->direction != GPRS_RLCMAC_UL_TBF)
				continue;
			/* no UL ressources needed, go next */
			if (tbf->state != GPRS_RLCMAC_FLOW)
				continue;
			break;
		}
		if (i < 32) {
			/* use this USF */
			usf = tbf->dir.ul.usf;
			LOGP(DRLCMACSCHED, LOGL_DEBUG, "Received RTS for PDCH: "
				"TRX=%d TS=%d FN=%d block_nr=%d scheduling "
				"USF=%d for required uplink ressource of "
				"TFB=%d\n", trx, ts, fn, block_nr, usf, tfi);
			/* next TFB to handle ressource is the next one */
			pdch->next_ul_tfi = (tfi + 1) & 31;
		}
	}

	/* Prio 1: select control message */
	if (!msg) {
		for (tfi = 0; tfi < 32; tfi++) {
			tbf = pdch->tbf[tfi];
			/* no TBF for this tfi, go next */
			if (!tbf)
				continue;
			/* no UL TBF, go next */
			if (tbf->direction != GPRS_RLCMAC_UL_TBF)
				continue;
			if (tbf->dir.ul.substate == GPRS_RLCMAC_UL_SEND_ACK)
				break;
		}
		if (tfi < 32) {
			LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling control "
				"message at RTS for TFB=%d\n", tfi);
			/* generate ack message */
			msg = gprs_rlcmac_send_uplink_ack(tbf, fn);
		}
	}

	/* Prio 2: select data message for downlink */
	if (!msg) {
		/* select downlink ressource */
		for (i = 0, tfi = pdch->next_dl_tfi; i < 32;
		     i++, tfi = (tfi + 1) & 31) {
			tbf = pdch->tbf[tfi];
			/* no TBF for this tfi, go next */
			if (!tbf)
				continue;
			/* no DD TBF, go next */
			if (tbf->direction != GPRS_RLCMAC_DL_TBF)
				continue;
			/* FIXME: */
		}
		if (i < 32) {
			LOGP(DRLCMACSCHED, LOGL_DEBUG, "Scheduling data "
				"message at RTS for TFB=%d\n", tfi);
			/* next TFB to handle ressource is the next one */
			pdch->next_dl_tfi = (tfi + 1) & 31;
			/* generate ack message */
			/* FIXME: */
		}
/* FIXME: remove that when DL TBF is finished */
set_current_fn(fn);
msg = msgb_dequeue(&block_queue);
	}

	/* Prio 3: send dummy contol message */
	if (!msg) {
		msg = msgb_alloc(23, "rlcmac_dl_idle");
		if (!msg)
			return -ENOMEM;
		memcpy(msgb_put(msg, 23), rlcmac_dl_idle, 23);
	}
	/* msg is now available */

	/* set USF */
	msg->data[0] = (msg->data[0] & 0xf8) | usf;

//	printf("len=%d, date=%s\n", msg->len, osmo_hexdump(msg->data, msg->len));

	/* send PDTCH/PACCH to L1 */
	pcu_l1if_tx_pdtch(msg, trx, ts, arfcn, fn, block_nr);

	return 0;
}
