/* Copied from gprs_bssgp_pcu.cpp
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
#include <gprs_rlcmac.h>
#include <gprs_debug.h>

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
}

#include <errno.h>
#include <string.h>

extern void *tall_pcu_ctx;

static inline void tbf_update_ms_class(struct gprs_rlcmac_tbf *tbf,
					const uint8_t ms_class)
{
	if (!tbf->ms_class && ms_class)
		tbf->ms_class = ms_class;
}

static inline void tbf_assign_imsi(struct gprs_rlcmac_tbf *tbf,
					const char *imsi)
{
	strncpy(tbf->meas.imsi, imsi, sizeof(tbf->meas.imsi) - 1);
}

static struct gprs_rlcmac_tbf *tbf_lookup_dl(BTS *bts,
					const uint32_t tlli, const char *imsi)
{
	/* TODO: look up by IMSI first, then tlli, then old_tlli */
	return bts->tbf_by_tlli(tlli, GPRS_RLCMAC_DL_TBF);
}

static int tbf_append_data(struct gprs_rlcmac_tbf *tbf,
				struct gprs_rlcmac_bts *bts,
				const uint8_t ms_class,
				const uint16_t pdu_delay_csec,
				const uint8_t *data, const uint16_t len)
{
	LOGP(DRLCMAC, LOGL_INFO, "TBF: APPEND TFI: %u TLLI: 0x%08x\n", tbf->tfi, tbf->tlli);
	if (tbf->state_is(GPRS_RLCMAC_WAIT_RELEASE)) {
		LOGP(DRLCMAC, LOGL_DEBUG, "TBF in WAIT RELEASE state "
			"(T3193), so reuse TBF\n");
		memcpy(tbf->llc_frame, data, len);
		tbf->llc_length = len;
		/* reset rlc states */
		memset(&tbf->dir.dl, 0, sizeof(tbf->dir.dl));
		/* keep to flags */
		tbf->state_flags &= GPRS_RLCMAC_FLAG_TO_MASK;
		tbf->state_flags &= ~(1 << GPRS_RLCMAC_FLAG_CCCH);
		tbf_update_ms_class(tbf, ms_class);
		tbf_update(tbf);
		gprs_rlcmac_trigger_downlink_assignment(bts, tbf, tbf, NULL);
	} else {
		/* the TBF exists, so we must write it in the queue
		 * we prepend lifetime in front of PDU */
		struct timeval *tv;
		struct msgb *llc_msg = msgb_alloc(len + sizeof(*tv),
			"llc_pdu_queue");
		if (!llc_msg)
			return -ENOMEM;
		tv = (struct timeval *)msgb_put(llc_msg, sizeof(*tv));

		uint16_t delay_csec;
		if (bts->force_llc_lifetime)
			delay_csec = bts->force_llc_lifetime;
		else
			delay_csec = pdu_delay_csec;
		/* keep timestap at 0 for infinite delay */
		if (delay_csec != 0xffff) {
			/* calculate timestamp of timeout */
			gettimeofday(tv, NULL);
			tv->tv_usec += (delay_csec % 100) * 10000;
			tv->tv_sec += delay_csec / 100;
			if (tv->tv_usec > 999999) {
				tv->tv_usec -= 1000000;
				tv->tv_sec++;
			}
		}
		memcpy(msgb_put(llc_msg, len), data, len);
		msgb_enqueue(&tbf->llc_queue, llc_msg);
		tbf_update_ms_class(tbf, ms_class);
	}

	return 0;
}

static int tbf_new_dl_assignment(struct gprs_rlcmac_bts *bts,
				const char *imsi,
				const uint32_t tlli, const uint8_t ms_class,
				const uint8_t *data, const uint16_t len)
{
	uint8_t trx, ta, ss;
	int8_t use_trx;
	struct gprs_rlcmac_tbf *old_tbf, *tbf;
	int8_t tfi; /* must be signed */
	int rc;

	/* check for uplink data, so we copy our informations */
#warning "Do the same look up for IMSI, TLLI and OLD_TLLI"
#warning "Refactor the below lines... into a new method"
	tbf = bts->bts->tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
	if (tbf && tbf->dir.ul.contention_resolution_done
	 && !tbf->dir.ul.final_ack_sent) {
		use_trx = tbf->trx_no;
		ta = tbf->ta;
		ss = 0;
		old_tbf = tbf;
	} else {
		use_trx = -1;
		/* we already have an uplink TBF, so we use that TA */
		if (tbf)
			ta = tbf->ta;
		else {
			/* recall TA */
			rc = bts->bts->timing_advance()->recall(tlli);
			if (rc < 0) {
				LOGP(DRLCMAC, LOGL_NOTICE, "TA unknown"
					", assuming 0\n");
				ta = 0;
			} else
				ta = rc;
		}
		ss = 1; /* PCH assignment only allows one timeslot */
		old_tbf = NULL;
	}

	// Create new TBF (any TRX)
#warning "Copy and paste with alloc_ul_tbf"
	tfi = tfi_find_free(bts, GPRS_RLCMAC_DL_TBF, &trx, use_trx);
	if (tfi < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH resource\n");
		/* FIXME: send reject */
		return -EBUSY;
	}
	/* set number of downlink slots according to multislot class */
	tbf = tbf_alloc(bts, tbf, GPRS_RLCMAC_DL_TBF, tfi, trx, ms_class, ss);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
		/* FIXME: send reject */
		return -EBUSY;
	}
	tbf->tlli = tlli;
	tbf->tlli_valid = 1;
	tbf->ta = ta;

	LOGP(DRLCMAC, LOGL_DEBUG,
		"TBF: [DOWNLINK] START TFI: %d TLLI: 0x%08x \n",
		tbf->tfi, tbf->tlli);

	/* new TBF, so put first frame */
	memcpy(tbf->llc_frame, data, len);
	tbf->llc_length = len;

	/* trigger downlink assignment and set state to ASSIGN.
	 * we don't use old_downlink, so the possible uplink is used
	 * to trigger downlink assignment. if there is no uplink,
	 * AGCH is used. */
	gprs_rlcmac_trigger_downlink_assignment(bts, tbf, old_tbf, imsi);

	/* store IMSI for debugging purpose. TODO: it is more than debugging */
	tbf_assign_imsi(tbf, imsi);
	return 0;
}

/**
 * TODO: split into unit test-able parts...
 */
int tbf_handle(struct gprs_rlcmac_bts *bts,
		const uint32_t tlli, const char *imsi,
		const uint8_t ms_class, const uint16_t delay_csec,
		const uint8_t *data, const uint16_t len)
{
	struct gprs_rlcmac_tbf *tbf;

	/* check for existing TBF */
	tbf = tbf_lookup_dl(bts->bts, tlli, imsi);
	if (tbf) {
		int rc = tbf_append_data(tbf, bts, ms_class,
						delay_csec, data, len);
		if (rc >= 0)
			tbf_assign_imsi(tbf, imsi);
		return rc;
	} 

	return tbf_new_dl_assignment(bts, imsi, tlli, ms_class, data, len);
}

struct gprs_rlcmac_tbf *tbf_alloc_ul(struct gprs_rlcmac_bts *bts,
	int8_t use_trx, uint8_t ms_class,
	uint32_t tlli, uint8_t ta, struct gprs_rlcmac_tbf *dl_tbf)
{
	uint8_t trx;
	struct gprs_rlcmac_tbf *tbf;
	uint8_t tfi;

#warning "Copy and paste with tbf_new_dl_assignment"
	/* create new TBF, use sme TRX as DL TBF */
	tfi = tfi_find_free(bts, GPRS_RLCMAC_UL_TBF, &trx, use_trx);
	if (tfi < 0) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
		/* FIXME: send reject */
		return NULL;
	}
	/* use multislot class of downlink TBF */
	tbf = tbf_alloc(bts, dl_tbf, GPRS_RLCMAC_UL_TBF, tfi, trx, ms_class, 0);
	if (!tbf) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH ressource\n");
		/* FIXME: send reject */
		return NULL;
	}
	tbf->tlli = tlli;
	tbf->tlli_valid = 1; /* no contention resolution */
	tbf->dir.ul.contention_resolution_done = 1;
	tbf->ta = ta; /* use current TA */
	tbf_new_state(tbf, GPRS_RLCMAC_ASSIGN);
	tbf->state_flags |= (1 << GPRS_RLCMAC_FLAG_PACCH);
	tbf_timer_start(tbf, 3169, bts->t3169, 0);

	return tbf;
}

static void tbf_unlink_pdch(struct gprs_rlcmac_tbf *tbf)
{
	struct gprs_rlcmac_pdch *pdch;
	int ts;

	if (tbf->direction == GPRS_RLCMAC_UL_TBF) {
		tbf->trx->ul_tbf[tbf->tfi] = NULL;
		for (ts = 0; ts < 8; ts++) {
			pdch = tbf->pdch[ts];
			if (pdch)
				pdch->ul_tbf[tbf->tfi] = NULL;
			tbf->pdch[ts] = NULL;
		}
	} else {
		tbf->trx->dl_tbf[tbf->tfi] = NULL;
		for (ts = 0; ts < 8; ts++) {
			pdch = tbf->pdch[ts];
			if (pdch)
				pdch->dl_tbf[tbf->tfi] = NULL;
			tbf->pdch[ts] = NULL;
		}
	}
}

void tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	struct msgb *msg;

	/* Give final measurement report */
	gprs_rlcmac_rssi_rep(tbf);
	gprs_rlcmac_lost_rep(tbf);

	debug_diagram(tbf->bts, tbf->diag, "+---------------+");
	debug_diagram(tbf->bts, tbf->diag, "|    THE END    |");
	debug_diagram(tbf->bts, tbf->diag, "+---------------+");
	LOGP(DRLCMAC, LOGL_INFO, "Free %s TBF=%d with TLLI=0x%08x.\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi,
		tbf->tlli);
	if (tbf->ul_ass_state != GPRS_RLCMAC_UL_ASS_NONE)
		LOGP(DRLCMAC, LOGL_ERROR, "Software error: Pending uplink "
			"assignment. This may not happen, because the "
			"assignment message never gets transmitted. Please "
			"be shure not to free in this state. PLEASE FIX!\n");
	if (tbf->dl_ass_state != GPRS_RLCMAC_DL_ASS_NONE)
		LOGP(DRLCMAC, LOGL_ERROR, "Software error: Pending downlink "
			"assignment. This may not happen, because the "
			"assignment message never gets transmitted. Please "
			"be shure not to free in this state. PLEASE FIX!\n");
	tbf_timer_stop(tbf);
	while ((msg = msgb_dequeue(&tbf->llc_queue)))
		msgb_free(msg);
	tbf_unlink_pdch(tbf);
	llist_del(&tbf->list);
	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF ends here **********\n");
	talloc_free(tbf);
}

int tbf_update(struct gprs_rlcmac_tbf *tbf)
{
	struct gprs_rlcmac_tbf *ul_tbf = NULL;
	gprs_rlcmac_bts *bts = tbf->bts->bts_data();
	int rc;

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF update **********\n");

	if (tbf->direction != GPRS_RLCMAC_DL_TBF)
		return -EINVAL;

	if (!tbf->ms_class) {
		LOGP(DRLCMAC, LOGL_DEBUG, "- Cannot update, no class\n");
		return -EINVAL;
	}

	ul_tbf = bts->bts->tbf_by_tlli(tbf->tlli, GPRS_RLCMAC_UL_TBF);

	tbf_unlink_pdch(tbf);
	rc = bts->alloc_algorithm(bts, ul_tbf, tbf, bts->alloc_algorithm_curst, 0);
	/* if no ressource */
	if (rc < 0) {
		LOGP(DRLCMAC, LOGL_ERROR, "No ressource after update???\n");
		return -rc;
	}

	return 0;
}

int tbf_assign_control_ts(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->control_ts == 0xff)
		LOGP(DRLCMAC, LOGL_INFO, "- Setting Control TS %d\n",
			tbf->first_common_ts);
	else if (tbf->control_ts != tbf->first_common_ts)
		LOGP(DRLCMAC, LOGL_INFO, "- Changing Control TS %d\n",
			tbf->first_common_ts);
	tbf->control_ts = tbf->first_common_ts;

	return 0;
}

static const char *tbf_state_name[] = {
	"NULL",
	"ASSIGN",
	"FLOW",
	"FINISHED",
	"WAIT RELEASE",
	"RELEASING",
};

void tbf_new_state(struct gprs_rlcmac_tbf *tbf,
	enum gprs_rlcmac_tbf_state state)
{
	debug_diagram(tbf->bts, tbf->diag, "->%s", tbf_state_name[state]);
	LOGP(DRLCMAC, LOGL_DEBUG, "%s TBF=%d changes state from %s to %s\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi,
		tbf_state_name[tbf->state], tbf_state_name[state]);
	tbf->set_state(state);
}

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
			unsigned int seconds, unsigned int microseconds)
{
	if (!osmo_timer_pending(&tbf->timer))
		LOGP(DRLCMAC, LOGL_DEBUG, "Starting %s TBF=%d timer %u.\n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			tbf->tfi, T);
	else
		LOGP(DRLCMAC, LOGL_DEBUG, "Restarting %s TBF=%d timer %u "
			"while old timer %u pending \n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			tbf->tfi, T, tbf->T);

	tbf->T = T;
	tbf->num_T_exp = 0;

	/* Tunning timers can be safely re-scheduled. */
	tbf->timer.data = tbf;
	tbf->timer.cb = &tbf_timer_cb;

	osmo_timer_schedule(&tbf->timer, seconds, microseconds);
}

void tbf_timer_stop(struct gprs_rlcmac_tbf *tbf)
{
	if (osmo_timer_pending(&tbf->timer)) {
		LOGP(DRLCMAC, LOGL_DEBUG, "Stopping %s TBF=%d timer %u.\n",
			(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
			tbf->tfi, tbf->T);
		osmo_timer_del(&tbf->timer);
	}
}

/* lookup TBF Entity (by TFI) */
struct gprs_rlcmac_tbf *tbf_by_tfi(struct gprs_rlcmac_bts *bts,
	uint8_t tfi, uint8_t trx, enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;

	if (tfi >= 32 || trx >= 8)
		return NULL;

	if (dir == GPRS_RLCMAC_UL_TBF)
		tbf = bts->trx[trx].ul_tbf[tfi];
	else
		tbf = bts->trx[trx].dl_tbf[tfi];
	if (!tbf)
		return NULL;

	if (tbf->state_is_not(GPRS_RLCMAC_RELEASING))
		return tbf;

	return NULL;
}

struct gprs_rlcmac_tbf *tbf_alloc(struct gprs_rlcmac_bts *bts,
	struct gprs_rlcmac_tbf *old_tbf, enum gprs_rlcmac_tbf_direction dir,
	uint8_t tfi, uint8_t trx,
	uint8_t ms_class, uint8_t single_slot)
{
	struct gprs_rlcmac_tbf *tbf;
	int rc;

#ifdef DEBUG_DIAGRAM
	/* hunt for first free number in diagram */
	int diagram_num;
	for (diagram_num = 0; ; diagram_num++) {
		llist_for_each_entry(tbf, &bts->ul_tbfs, list) {
			if (tbf->diag == diagram_num)
				goto next_diagram;
		}
		llist_for_each_entry(tbf, &bts->dl_tbfs, list) {
			if (tbf->diag == diagram_num)
				goto next_diagram;
		}
		break;
next_diagram:
		continue;
	}
#endif

	LOGP(DRLCMAC, LOGL_DEBUG, "********** TBF starts here **********\n");
	LOGP(DRLCMAC, LOGL_INFO, "Allocating %s TBF: TFI=%d TRX=%d "
		"MS_CLASS=%d\n", (dir == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL",
		tfi, trx, ms_class);

	if (trx >= 8 || tfi >= 32)
		return NULL;

	tbf = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_tbf);
	if (!tbf)
		return NULL;

	tbf->bts = bts->bts;
#ifdef DEBUG_DIAGRAM
	tbf->diag = diagram_num;
#endif
	tbf->direction = dir;
	tbf->tfi = tfi;
	tbf->trx_no = trx;
	tbf->trx = &bts->trx[trx];
	tbf->arfcn = bts->trx[trx].arfcn;
	tbf->ms_class = ms_class;
	tbf->ws = 64;
	tbf->sns = 128;
	/* select algorithm */
	rc = bts->alloc_algorithm(bts, old_tbf, tbf, bts->alloc_algorithm_curst,
		single_slot);
	/* if no ressource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}
	/* assign control ts */
	tbf->control_ts = 0xff;
	rc = tbf_assign_control_ts(tbf);
	/* if no ressource */
	if (rc < 0) {
		talloc_free(tbf);
		return NULL;
	}

	/* set timestamp */
	gettimeofday(&tbf->meas.dl_bw_tv, NULL);
	gettimeofday(&tbf->meas.rssi_tv, NULL);
	gettimeofday(&tbf->meas.dl_loss_tv, NULL);

	INIT_LLIST_HEAD(&tbf->llc_queue);
	if (dir == GPRS_RLCMAC_UL_TBF)
		llist_add(&tbf->list, &bts->ul_tbfs);
	else
		llist_add(&tbf->list, &bts->dl_tbfs);

	debug_diagram(bts->bts, tbf->diag, "+-----------------+");
	debug_diagram(bts->bts, tbf->diag, "|NEW %s TBF TFI=%2d|",
		(dir == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tfi);
	debug_diagram(bts->bts, tbf->diag, "+-----------------+");

	return tbf;
}

void tbf_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	LOGP(DRLCMAC, LOGL_DEBUG, "%s TBF=%d timer %u expired.\n",
		(tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi,
		tbf->T);

	tbf->num_T_exp++;

	switch (tbf->T) {
#ifdef DEBUG_DL_ASS_IDLE
	case 1234:
		gprs_rlcmac_trigger_downlink_assignment(tbf, NULL, debug_imsi);
		break;
#endif
	case 0: /* assignment */
		if ((tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH))) {
			if (tbf->state_is(GPRS_RLCMAC_ASSIGN)) {
				LOGP(DRLCMAC, LOGL_NOTICE, "Releasing due to "
					"PACCH assignment timeout.\n");
				tbf_free(tbf);
			} else
				LOGP(DRLCMAC, LOGL_ERROR, "Error: TBF is not "
					"in assign state\n");
		}
		if ((tbf->state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH))) {
			/* change state to FLOW, so scheduler will start transmission */
			tbf->dir.dl.wait_confirm = 0;
			if (tbf->state_is(GPRS_RLCMAC_ASSIGN)) {
				tbf_new_state(tbf, GPRS_RLCMAC_FLOW);
				tbf_assign_control_ts(tbf);
			} else
				LOGP(DRLCMAC, LOGL_NOTICE, "Continue flow after "
					"IMM.ASS confirm\n");
		}
		break;
	case 3169:
	case 3191:
	case 3195:
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF T%d timeout during "
			"transsmission\n", tbf->T);
		tbf->rlcmac_diag();
		/* fall through */
	case 3193:
		if (tbf->T == 3193)
		        debug_diagram(tbf->bts, tbf->diag, "T3193 timeout");
		LOGP(DRLCMAC, LOGL_DEBUG, "TBF will be freed due to timeout\n");
		/* free TBF */
		tbf_free(tbf);
		break;
	default:
		LOGP(DRLCMAC, LOGL_ERROR, "Timer expired in unknown mode: %u\n",
			tbf->T);
	}
}

int gprs_rlcmac_tbf::rlcmac_diag()
{
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_CCCH)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Assignment was on CCCH\n");
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_PACCH)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Assignment was on PACCH\n");
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_UL_DATA)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Uplink data was received\n");
	else if (direction == GPRS_RLCMAC_UL_TBF)
		LOGP(DRLCMAC, LOGL_NOTICE, "- No uplink data received yet\n");
	if ((state_flags & (1 << GPRS_RLCMAC_FLAG_DL_ACK)))
		LOGP(DRLCMAC, LOGL_NOTICE, "- Downlink ACK was received\n");
	else if (direction == GPRS_RLCMAC_DL_TBF)
		LOGP(DRLCMAC, LOGL_NOTICE, "- No downlink ACK received yet\n");

	return 0;
}

void gprs_rlcmac_tbf::free_all(struct gprs_rlcmac_trx *trx)
{
	for (uint8_t tfi = 0; tfi < 32; tfi++) {
		struct gprs_rlcmac_tbf *tbf;

		tbf = trx->ul_tbf[tfi];
		if (tbf)
			tbf_free(tbf);
		tbf = trx->dl_tbf[tfi];
		if (tbf)
			tbf_free(tbf);
	}
}

void gprs_rlcmac_tbf::free_all(struct gprs_rlcmac_pdch *pdch)
{
	for (uint8_t tfi = 0; tfi < 32; tfi++) {
		struct gprs_rlcmac_tbf *tbf;

		tbf = pdch->ul_tbf[tfi];
		if (tbf)
			tbf_free(tbf);
		tbf = pdch->dl_tbf[tfi];
		if (tbf)
			tbf_free(tbf);
	}
}
