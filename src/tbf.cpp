/* Copied from gprs_bssgp_pcu.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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

#include <tbf.h>
#include <gprs_rlcmac.h>
#include <gprs_debug.h>

extern "C" {
#include <osmocom/core/msgb.h>
}

#include <errno.h>
#include <string.h>

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

static struct gprs_rlcmac_tbf *tbf_lookup_dl(const uint32_t tlli, const char *imsi)
{
	/* TODO: look up by IMSI first, then tlli, then old_tlli */
	return tbf_by_tlli(tlli, GPRS_RLCMAC_DL_TBF);
}

static int tbf_append_data(struct gprs_rlcmac_tbf *tbf,
				struct gprs_rlcmac_bts *bts,
				const uint8_t ms_class,
				const uint16_t pdu_delay_csec,
				const uint8_t *data, const uint16_t len)
{
	LOGP(DRLCMAC, LOGL_INFO, "TBF: APPEND TFI: %u TLLI: 0x%08x\n", tbf->tfi, tbf->tlli);
	if (tbf->state == GPRS_RLCMAC_WAIT_RELEASE) {
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
		gprs_rlcmac_trigger_downlink_assignment(tbf, tbf, NULL);
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
	tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
	if (tbf && tbf->dir.ul.contention_resolution_done
	 && !tbf->dir.ul.final_ack_sent) {
		use_trx = tbf->trx;
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
			rc = recall_timing_advance(tlli);
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
	gprs_rlcmac_trigger_downlink_assignment(tbf, old_tbf, imsi);

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
	tbf = tbf_lookup_dl(tlli, imsi);
	if (tbf) {
		int rc = tbf_append_data(tbf, bts, ms_class,
						delay_csec, data, len);
		if (rc >= 0)
			tbf_assign_imsi(tbf, imsi);
		return rc;
	} 

	return tbf_new_dl_assignment(bts, imsi, tlli, ms_class, data, len);
}
