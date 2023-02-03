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

#include <er_ccu_descr.h>
#include <er_ccu_if.h>

#include <string.h>
#include <errno.h>

#include <osmocom/pcu/pcuif_proto.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/trau/trau_sync.h>
#include <osmocom/trau/trau_pcu_ericsson.h>
#include <osmocom/gsm/gsm0502.h>
#include <osmocom/core/talloc.h>

#include <bts.h>
#include <pcu_l1_if.h>
#include <pcu_l1_if_phy.h>

extern void *tall_pcu_ctx;

const uint8_t fn_inc_table[4] = { 4, 4, 5, 0 };
const uint8_t blk_nr_table[4] = { 4, 4, 5, 0 };

#define SYNC_CHECK_INTERVAL GSM_TDMA_SUPERFRAME * 8

/* Subtrahend to convert Ericsson adjusted (block ending) fn to regular fn (uplink only) */
#define AFN_SUBTRAHEND 3

#define LOGPL1IF(ccu_descr, level, tag, fmt, args...)	       \
	LOGP(DL1IF, level, "%s: PDCH(trx=%u,ts=%u) E1-line(line=%u,ts=%u,ss=%u) " fmt, \
	     tag, ccu_descr->pcu.trx_no, ccu_descr->pcu.ts, \
	     ccu_descr->e1_conn_pars->e1_nr, ccu_descr->e1_conn_pars->e1_ts, \
	     ccu_descr->e1_conn_pars->e1_ts_ss == E1_SUBSLOT_FULL ? 0 : ccu_descr->e1_conn_pars->e1_ts_ss, \
	     ## args)

/* Calculate GPRS block number from frame number */
static uint8_t fn_to_block_nr(uint32_t fn)
{
	/* Note: See also 3GPP TS 03.64 6.5.7.2.1,
	 * Mapping on the multiframe structure */

	uint8_t rel_fn;
	uint8_t super_block;
	uint8_t local_block;

	rel_fn = fn % 52;

	/* Warn in case of frames that do not belong to a block */
	if (rel_fn == 12 || rel_fn == 25 || rel_fn == 38 || rel_fn == 51)
		LOGP(DL1IF, LOGL_ERROR, "Frame number is referencing invalid block!\n");

	super_block = (rel_fn / 13);
	local_block = rel_fn % 13 / 4;
	return super_block * 3 + local_block;
}

static uint32_t fn_dl_advance(uint32_t fn, uint32_t n_blocks)
{
	uint32_t i;

	uint8_t inc_fn;

	for (i = 0; i < n_blocks; i++) {
		inc_fn = fn_inc_table[(fn % 13) / 4];
		fn = GSM_TDMA_FN_SUM(fn, inc_fn);
	}

	return fn;
}

static bool mac_block_is_noise(struct er_gprs_trau_frame *trau_frame)
{
	switch (trau_frame->u.ccu_data_ind.cs_hdr) {
	case CS_OR_HDR_CS1:
	case CS_OR_HDR_CS2:
	case CS_OR_HDR_CS3:
	case CS_OR_HDR_CS4:
		if (!trau_frame->u.ccu_data_ind.u.gprs.parity_ok)
			return true;
		break;
	case CS_OR_HDR_HDR1:
	case CS_OR_HDR_HDR2:
	case CS_OR_HDR_HDR3:
		if (!trau_frame->u.ccu_data_ind.u.egprs.hdr_good)
			return true;
		if (!trau_frame->u.ccu_data_ind.u.egprs.data_good[0]
		    && !trau_frame->u.ccu_data_ind.u.egprs.data_good[1])
			return true;
		break;
	case CS_OR_HDR_AB:
		/* We are not interested in receiving access bursts. */
		return true;
	}

	/* No noise, this block is interesting for us. */
	return false;
}

static void log_data_ind(struct er_ccu_descr *ccu_descr, struct er_gprs_trau_frame *trau_frame, uint32_t afn_ul_comp,
			 uint32_t afn_dl_comp)
{
	switch (trau_frame->u.ccu_data_ind.cs_hdr) {
	case CS_OR_HDR_CS1:
	case CS_OR_HDR_CS2:
	case CS_OR_HDR_CS3:
	case CS_OR_HDR_CS4:
		LOGPL1IF(ccu_descr, LOGL_DEBUG, "CCU-DATA-IND",
			 "tav=%u, dbe=%u, cs_hdr=%u, rx_lev=%u, est_acc_del_dev=%u,"
			 "block_qual=%u, parity_ok=%u, data=%s<==, afn_ul_comp=%u/%u\n", trau_frame->u.ccu_data_ind.tav,
			 trau_frame->u.ccu_data_ind.dbe, trau_frame->u.ccu_data_ind.cs_hdr,
			 trau_frame->u.ccu_data_ind.rx_lev, trau_frame->u.ccu_data_ind.est_acc_del_dev,
			 trau_frame->u.ccu_data_ind.u.gprs.block_qual, trau_frame->u.ccu_data_ind.u.gprs.parity_ok,
			 osmo_hexdump_nospc(trau_frame->u.ccu_data_ind.data, trau_frame->u.ccu_data_ind.data_len),
			 afn_ul_comp, afn_ul_comp % 52);
		break;
	case CS_OR_HDR_HDR1:
	case CS_OR_HDR_HDR2:
	case CS_OR_HDR_HDR3:
	case CS_OR_HDR_AB:
		LOGPL1IF(ccu_descr, LOGL_DEBUG, "CCU-DATA-IND",
			 "tav=%u, dbe=%u, cs_hdr=%u, rx_lev=%u, est_acc_del_dev=%u,"
			 "mean_bep=%u, cv_bep=%u, hdr_good=%u, data_good[0]=%u, data_good[1]=%u, data=%s<==, afn_ul_comp=%u/%u\n",
			 trau_frame->u.ccu_data_ind.tav, trau_frame->u.ccu_data_ind.dbe,
			 trau_frame->u.ccu_data_ind.cs_hdr, trau_frame->u.ccu_data_ind.rx_lev,
			 trau_frame->u.ccu_data_ind.est_acc_del_dev, trau_frame->u.ccu_data_ind.u.egprs.mean_bep,
			 trau_frame->u.ccu_data_ind.u.egprs.cv_bep, trau_frame->u.ccu_data_ind.u.egprs.hdr_good,
			 trau_frame->u.ccu_data_ind.u.egprs.data_good[0],
			 trau_frame->u.ccu_data_ind.u.egprs.data_good[1],
			 osmo_hexdump_nospc(trau_frame->u.ccu_data_ind.data, trau_frame->u.ccu_data_ind.data_len),
			 afn_ul_comp, afn_ul_comp % 52);
	}
}

/* Receive block from CCU */
static void er_ccu_rx_cb(struct er_ccu_descr *ccu_descr, const ubit_t *bits, unsigned int num_bits)
{
	int rc;
	struct er_gprs_trau_frame trau_frame;
	uint8_t inc_ul;
	uint8_t inc_dl;
	uint32_t afn_ul;
	uint32_t afn_dl;
	uint32_t afn_ul_comp;
	uint32_t afn_dl_comp;
	struct pcu_l1_meas meas = { 0 };
	struct gprs_rlcmac_bts *bts;
	struct gprs_rlcmac_pdch *pdch;

	/* Compute the current frame numbers from the last frame number */
	inc_ul = fn_inc_table[(ccu_descr->sync.last_afn_ul % 13) / 4];
	inc_dl = fn_inc_table[(ccu_descr->sync.last_afn_dl % 13) / 4];
	afn_ul = GSM_TDMA_FN_SUM(ccu_descr->sync.last_afn_ul, inc_ul);
	afn_dl = GSM_TDMA_FN_SUM(ccu_descr->sync.last_afn_dl, inc_dl);

	/* Compute compensated frame numbers. This will be the framenumbers we
	 * will use to exchange blocks with the PCU code. The following applies:
	 *
	 * 1. The uplink related frame numbers sent by the ericsson CCU refer to the end of a block. This is
	 *    compensated by subtracting three frames.
	 * 2. The CCU downlink frame number runs one block past the uplink frame number. This needs to be
	 *    compesated as well (+1).
	 * 3. The difference between the local (PCU) and the returned (CCU) pseq counter value is the number of blocks
	 *    that the PCU must
	 *    shift its downlink alignment in order to compensate the link latency between PCU and CCU. */
	afn_ul_comp = GSM_TDMA_FN_SUB(afn_ul, AFN_SUBTRAHEND);
	afn_dl_comp = afn_dl;
	afn_dl_comp = fn_dl_advance(afn_dl_comp, GSM_TDMA_FN_DIFF(ccu_descr->sync.pseq_pcu, ccu_descr->sync.pseq_ccu) + 1);

	LOGPL1IF(ccu_descr, LOGL_DEBUG, "CCU-SYNC",
		 "afn_ul=%u/%u, afn_dl=%u/%u, afn_diff=%u => afn_ul_comp=%u/%u, afn_dl_comp=%u/%u, afn_diff_comp=%u\n",
		 afn_ul, afn_ul % 52, afn_dl, afn_dl % 52, GSM_TDMA_FN_DIFF(afn_ul, afn_dl), afn_ul_comp,
		 afn_ul_comp % 52, afn_dl_comp, afn_dl_comp % 52, GSM_TDMA_FN_DIFF(afn_ul_comp, afn_dl_comp));

	LOGPL1IF(ccu_descr, LOGL_DEBUG, "CCU-SYNC", "pseq_pcu=%u, pseq_ccu=%u, pseq_diff=%u\n",
		 ccu_descr->sync.pseq_pcu, ccu_descr->sync.pseq_ccu, GSM_TDMA_FN_DIFF(ccu_descr->sync.pseq_pcu, ccu_descr->sync.pseq_ccu));

	/* Decode indication from CCU */
	if (ccu_descr->e1_conn_pars->e1_ts_ss == E1_SUBSLOT_FULL)
		rc = er_gprs_trau_frame_decode_64k(&trau_frame, bits);
	else
		rc = er_gprs_trau_frame_decode_16k(&trau_frame, bits);
	if (rc < 0) {
		LOGPL1IF(ccu_descr, LOGL_ERROR, "CCU-XXXX-IND",
			 "unable to decode uplink TRAU frame, afn_ul_comp=%u/%u\n", afn_ul_comp, afn_ul_comp % 52);

		/* Report to the CCU that there is an issue with uplink TRAU frames, the CCU will then send
		 * a CCU-SYNC-IND within the next TRAU frame, so we can check if we are still in sync and trigger
		 * synchronization procedure if necessary. */
		ccu_descr->sync.ul_frame_err = true;
		goto skip;
	}

	switch (trau_frame.type) {
	case ER_GPRS_TRAU_FT_SYNC:
		if (trau_frame.u.ccu_sync_ind.pseq != 0x3FFFFF) {
			LOGPL1IF(ccu_descr, LOGL_DEBUG, "CCU-SYNC-IND",
				 "tav=%u, dbe=%u, dfe=%u, pseq=%u, afn_ul=%u, afn_dl=%u\n",
				 trau_frame.u.ccu_sync_ind.tav, trau_frame.u.ccu_sync_ind.dbe,
				 trau_frame.u.ccu_sync_ind.dfe, trau_frame.u.ccu_sync_ind.pseq,
				 trau_frame.u.ccu_sync_ind.afn_ul, trau_frame.u.ccu_sync_ind.afn_dl);

			/* Synchronize the current CCU PSEQ state */
			ccu_descr->sync.pseq_ccu = trau_frame.u.ccu_sync_ind.pseq;
		} else {
			LOGPL1IF(ccu_descr, LOGL_DEBUG, "CCU-SYNC-IND",
				 "tav=%u, dbe=%u, dfe=%u, pseq=(none), afn_ul=%u, afn_dl=%u\n",
				 trau_frame.u.ccu_sync_ind.tav, trau_frame.u.ccu_sync_ind.dbe,
				 trau_frame.u.ccu_sync_ind.dfe, trau_frame.u.ccu_sync_ind.afn_ul,
				 trau_frame.u.ccu_sync_ind.afn_dl);
		}

		ccu_descr->sync.tav = trau_frame.u.ccu_sync_ind.tav;

		/* Check if we are in sync with the CCU, if not trigger synchronization procedure */
		if (afn_ul != trau_frame.u.ccu_sync_ind.afn_ul || afn_dl != trau_frame.u.ccu_sync_ind.afn_dl) {
			if (afn_ul != trau_frame.u.ccu_sync_ind.afn_ul)
				LOGPL1IF(ccu_descr, LOGL_NOTICE, "CCU-SYNC-IND",
					 "afn_ul=%u (computed) != afn_ul=%u (sync-ind) => delta=%u\n", afn_ul,
					 trau_frame.u.ccu_sync_ind.afn_ul,
					 GSM_TDMA_FN_DIFF(afn_ul, trau_frame.u.ccu_sync_ind.afn_ul));
			if (afn_dl != trau_frame.u.ccu_sync_ind.afn_dl)
				LOGPL1IF(ccu_descr, LOGL_NOTICE, "CCU-SYNC-IND",
					 "afn_dl=%u (computed) != afn_dl=%u (sync-ind) => delta=%u\n", afn_dl,
					 trau_frame.u.ccu_sync_ind.afn_dl,
					 GSM_TDMA_FN_DIFF(afn_dl, trau_frame.u.ccu_sync_ind.afn_dl));
			LOGPL1IF(ccu_descr, LOGL_NOTICE, "CCU-SYNC-IND",
				 "FN jump detected, lost sync with CCU -- (re)synchronizing...\n");
			ccu_descr->sync.ccu_synced = false;
		} else {
			LOGPL1IF(ccu_descr, LOGL_NOTICE, "CCU-SYNC-IND", "in sync with CCU\n");
			ccu_descr->sync.ccu_synced = true;
		}

		/* Overwrite calculated afn_ul and afn_dl with the actual values from the SYNC indication */
		afn_ul = trau_frame.u.ccu_sync_ind.afn_ul;
		afn_dl = trau_frame.u.ccu_sync_ind.afn_dl;

		break;
	case ER_GPRS_TRAU_FT_DATA:

		ccu_descr->sync.tav = trau_frame.u.ccu_data_ind.tav;

		/* Ignore all data indications that contain only noise */
		if (mac_block_is_noise(&trau_frame))
			break;

		log_data_ind(ccu_descr, &trau_frame, afn_ul_comp, afn_dl_comp);

		/* Hand received MAC block into PCU */
		bts = gprs_pcu_get_bts_by_nr(the_pcu, ccu_descr->pcu.bts_nr);
		if (!bts)
			break;
		meas.have_rssi = 1;
		meas.rssi = rxlev2dbm(trau_frame.u.ccu_data_ind.rx_lev);
		meas.have_link_qual = 1;
		meas.link_qual = trau_frame.u.ccu_data_ind.u.gprs.block_qual;
		pdch = &bts->trx[ccu_descr->pcu.trx_no].pdch[ccu_descr->pcu.ts];
		rc = pcu_rx_data_ind_pdtch(bts, pdch, trau_frame.u.ccu_data_ind.data,
					   trau_frame.u.ccu_data_ind.data_len, afn_ul_comp, &meas);
		break;
	default:
		LOGPL1IF(ccu_descr, LOGL_ERROR, "CCU-XXXX-IND", "unhandled CCU indication!\n");
	}

skip:
	if (ccu_descr->sync.ccu_synced) {
		bts = gprs_pcu_get_bts_by_nr(the_pcu, ccu_descr->pcu.bts_nr);
		if (bts) {
			/* The PCU timing is locked to the uplink fame number. The downlink frame number is advanced
			 * into the future so that the line latency is compensated and the frame arrives at the right
			 * point in time. */
			pdch = &bts->trx[ccu_descr->pcu.trx_no].pdch[ccu_descr->pcu.ts];
			pcu_rx_block_time(bts, pdch->trx->arfcn, afn_ul_comp, ccu_descr->pcu.ts);
			rc = pcu_rx_rts_req_pdtch(bts, ccu_descr->pcu.trx_no, ccu_descr->pcu.ts, afn_dl_comp,
						  fn_to_block_nr(afn_dl_comp));
		}
	}

	/* We do not receive sync indications in every cycle. When traffic is transferred we won't get frame numbers
	 * from the CCU. In this case we must update the last_afn_ul/dl values from the computed frame numbers
	 * (see above) */
	ccu_descr->sync.last_afn_ul = afn_ul;
	ccu_descr->sync.last_afn_dl = afn_dl;
	ccu_descr->sync.pseq_pcu++;
	ccu_descr->sync.pseq_ccu++;
}

static void er_ccu_empty_cb(struct er_ccu_descr *ccu_descr)
{
	struct er_gprs_trau_frame trau_frame;
	ubit_t trau_frame_encoded[ER_GPRS_TRAU_FRAME_LEN_64K];
	int rc;

	memset(&trau_frame, 0, sizeof(trau_frame));
	trau_frame.u.pcu_sync_ind.pseq = ccu_descr->sync.pseq_pcu;
	trau_frame.u.pcu_sync_ind.tav = ccu_descr->sync.tav;
	trau_frame.u.pcu_sync_ind.fn_ul = 0x3FFFFF;
	trau_frame.u.pcu_sync_ind.fn_dl = 0x3FFFFF;
	trau_frame.u.pcu_sync_ind.fn_ss = 0x3FFFFF;
	trau_frame.u.pcu_sync_ind.ls = 0x3FFFFF;
	trau_frame.u.pcu_sync_ind.ss = 0x3FFFFF;
	trau_frame.type = ER_GPRS_TRAU_FT_SYNC;

	if (ccu_descr->e1_conn_pars->e1_ts_ss == E1_SUBSLOT_FULL)
		rc = er_gprs_trau_frame_encode_64k(trau_frame_encoded, &trau_frame);
	else
		rc = er_gprs_trau_frame_encode_16k(trau_frame_encoded, &trau_frame);
	if (rc < 0) {
		LOGPL1IF(ccu_descr, LOGL_ERROR, "PCU-SYNC-IND", "unable to encode TRAU frame\n");
		return;
	}
	LOGPL1IF(ccu_descr, LOGL_DEBUG, "PCU-SYNC-IND", "pseq=%u, tav=%u\n",
		 trau_frame.u.pcu_sync_ind.pseq, trau_frame.u.pcu_sync_ind.tav);
	er_ccu_if_tx(ccu_descr, trau_frame_encoded, rc);

	/* Make sure timing adjustment value is reset after use */
	ccu_descr->sync.tav = TIME_ADJ_NONE;
}

/* use the length of the block to determine the coding scheme */
static int cs_hdr_from_len(uint8_t len)
{
	switch (len) {
	case 23:
		return CS_OR_HDR_CS1;
	case 34:
		return CS_OR_HDR_CS2;
	case 40:
		return CS_OR_HDR_CS3;
	case 54:
		return CS_OR_HDR_CS4;
	case 27:
	case 33:
	case 42:
	case 49:
		return CS_OR_HDR_HDR3;
	case 60:
	case 78:
		return CS_OR_HDR_HDR2;
	case 118:
	case 142:
	case 154:
		return CS_OR_HDR_HDR1;
	default:
		return -EINVAL;
	}
}

/* send packet data request to L1 */
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn,
		  uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len)
{
	struct er_ccu_descr *ccu_descr = obj;
	struct er_gprs_trau_frame trau_frame;
	ubit_t trau_frame_encoded[ER_GPRS_TRAU_FRAME_LEN_64K];
	struct gprs_rlcmac_bts *bts;
	int rc;

	/* Make sure that the CCU is synchronized and connected. */
	if (!ccu_descr) {
		LOGP(DL1IF, LOGL_ERROR, "PCU-DATA-IND: PDCH(ts=%u, arfcn=%u) no CCU context, tossing MAC block...\n",
		     ts, arfcn);
		return -EINVAL;
	}
	if (!ccu_descr->link.ccu_connected) {
		LOGPL1IF(ccu_descr, LOGL_NOTICE, "PCU-DATA-IND", "CCU not connected, tossing MAC block...\n");
		return -EINVAL;
	}
	if (!ccu_descr->sync.ccu_synced) {
		LOGPL1IF(ccu_descr, LOGL_NOTICE, "PCU-DATA-IND", "CCU not synchronized, tossing MAC block...\n");
		return -EINVAL;
	}

	/* Hand received MAC block into PCU */
	bts = gprs_pcu_get_bts_by_nr(the_pcu, ccu_descr->pcu.bts_nr);
	if (!bts) {
		LOGPL1IF(ccu_descr, LOGL_NOTICE, "PCU-DATA-IND", "no BTS, tossing MAC block...\n");
		return -EINVAL;
	}

	memset(&trau_frame, 0, sizeof(trau_frame));
	trau_frame.type = ER_GPRS_TRAU_FT_DATA;

	rc = cs_hdr_from_len(len);
	if (rc < 0) {
		LOGPL1IF(ccu_descr, LOGL_ERROR, "PCU-DATA-IND",
			 "unable to encode TRAU frame, invalid CS or MCS value set\n");
		return -EINVAL;
	}
	trau_frame.u.pcu_data_ind.cs_hdr = (enum er_cs_or_hdr)rc;
	trau_frame.u.pcu_data_ind.tav = ccu_descr->sync.tav;
	trau_frame.u.pcu_data_ind.ul_frame_err = ccu_descr->sync.ul_frame_err;
	if (bts->mcs_mask)
		trau_frame.u.pcu_data_ind.ul_chan_mode = ER_UL_CHMOD_NB_UNKN;
	else
		trau_frame.u.pcu_data_ind.ul_chan_mode = ER_UL_CHMOD_NB_GMSK;
	OSMO_ASSERT(len < sizeof(trau_frame.u.pcu_data_ind.data));
	memcpy(trau_frame.u.pcu_data_ind.data, data, len);

	/* Regulary ignore one MAC block in uplink. The CCU will then send one CCU-SYNC-IND instead. We use this
	 * indication to check whether we are still in sync with the CCU. */
	if (fn % SYNC_CHECK_INTERVAL == 0)
		trau_frame.u.pcu_data_ind.ul_chan_mode = ER_UL_CHMOD_VOID;

	if (ccu_descr->e1_conn_pars->e1_ts_ss == E1_SUBSLOT_FULL)
		rc = er_gprs_trau_frame_encode_64k(trau_frame_encoded, &trau_frame);
	else
		rc = er_gprs_trau_frame_encode_16k(trau_frame_encoded, &trau_frame);
	if (rc < 0) {
		LOGPL1IF(ccu_descr, LOGL_ERROR, "PCU-DATA-IND", "unable to encode TRAU frame\n");
		return -EINVAL;
	}
	LOGPL1IF(ccu_descr, LOGL_DEBUG, "PCU-DATA-IND",
		 "tav=%u, ul_frame_err=%u, cs_hdr=%u, ul_chan_mode=%u, atten_db=%u, timing_offset=%u,"
		 " data=%s==>, fn=%u/%u (comp)\n", trau_frame.u.pcu_data_ind.tav,
		 trau_frame.u.pcu_data_ind.ul_frame_err, trau_frame.u.pcu_data_ind.cs_hdr,
		 trau_frame.u.pcu_data_ind.ul_chan_mode, trau_frame.u.pcu_data_ind.atten_db,
		 trau_frame.u.pcu_data_ind.timing_offset, osmo_hexdump_nospc(trau_frame.u.pcu_data_ind.data, len), fn,
		 fn % 52);
	er_ccu_if_tx(ccu_descr, trau_frame_encoded, rc);

	/* Make sure timing adjustment value is reset after use */
	ccu_descr->sync.tav = TIME_ADJ_NONE;
	ccu_descr->sync.ul_frame_err = false;

	return 0;
}

void *l1if_open_pdch(uint8_t bts_nr, uint8_t trx_no, uint32_t hlayer1, struct gsmtap_inst *gsmtap)
{
	struct er_ccu_descr *ccu_descr;

	/* Note: We do not have enough information to really open anything at
	 * this point. We will just create the CCU context. */

	ccu_descr = talloc_zero(tall_pcu_ctx, struct er_ccu_descr);
	OSMO_ASSERT(ccu_descr);
	ccu_descr->er_ccu_rx_cb = er_ccu_rx_cb;
	ccu_descr->er_ccu_empty_cb = er_ccu_empty_cb;
	ccu_descr->pcu.trx_no = trx_no;
	ccu_descr->pcu.bts_nr = bts_nr;

	return ccu_descr;
}

int l1if_close_pdch(void *obj)
{
	struct er_ccu_descr *ccu_descr = obj;

	if (!ccu_descr) {
		LOGP(DL1IF, LOGL_ERROR, "PCU-DATA-IND: no CCU context, cannot close unknown PDCH...\n");
		return -EINVAL;
	}

	er_ccu_if_close(ccu_descr);
	talloc_free(ccu_descr);
	return 0;
}

int l1if_connect_pdch(void *obj, uint8_t ts)
{
	struct er_ccu_descr *ccu_descr = obj;
	int rc;

	if (!ccu_descr) {
		LOGP(DL1IF, LOGL_ERROR, "SETUP: PDCH(ts=%u) no CCU context, PDCH never opened before?\n", ts);
		return -EINVAL;
	}

	ccu_descr->pcu.ts = ts;

	rc = pcu_l1if_get_e1_ccu_conn_pars(&ccu_descr->e1_conn_pars, ccu_descr->pcu.bts_nr, ccu_descr->pcu.trx_no,
					   ccu_descr->pcu.ts);
	if (rc < 0) {
		LOGPL1IF(ccu_descr, LOGL_ERROR, "SETUP", "cannot find E1 connection parameters for CCU\n");
		return -EINVAL;
	}

	rc = er_ccu_if_open(ccu_descr);
	if (rc < 0)
		return -EINVAL;

	return 0;
}

int l1if_disconnect_pdch(void *obj, uint8_t ts)
{
	struct er_ccu_descr *ccu_descr = obj;

	if (!ccu_descr) {
		LOGP(DL1IF, LOGL_ERROR, "SETUP: PDCH(ts=%u) no CCU context, PDCH never opened before?\n", ts);
		return -EINVAL;
	}

	er_ccu_if_close(ccu_descr);

	return 0;
}

int l1if_init(void)
{
	er_ccu_if_init(tall_pcu_ctx);
	return 0;
}
