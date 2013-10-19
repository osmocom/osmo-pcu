/*
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <bts.h>
#include <poll_controller.h>
#include <tbf.h>
#include <encoding.h>

#include <gprs_rlcmac.h>
#include <gprs_debug.h>

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/msgb.h>
}

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>

extern void *tall_pcu_ctx;

static BTS s_bts;

BTS* BTS::main_bts()
{
	return &s_bts;
}

struct gprs_rlcmac_bts *BTS::bts_data()
{
	return &m_bts;
}

struct gprs_rlcmac_bts *bts_main_data()
{
	return BTS::main_bts()->bts_data();
}

BTS::BTS()
	: m_cur_fn(0)
	, m_pollController(*this)
	, m_sba(*this)
{
	memset(&m_bts, 0, sizeof(m_bts));
	INIT_LLIST_HEAD(&m_bts.ul_tbfs);
	INIT_LLIST_HEAD(&m_bts.dl_tbfs);
	m_bts.bts = this;
}

void BTS::set_current_frame_number(int fn)
{
	m_cur_fn = fn;
	m_pollController.expireTimedout(m_cur_fn);
}

int BTS::add_paging(uint8_t chan_needed, uint8_t *identity_lv)
{
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_paging *pag;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	llist_head *tbfs_lists[] = {
		&m_bts.ul_tbfs,
		&m_bts.dl_tbfs,
		NULL
	};


	LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n",
		chan_needed, osmo_hexdump(identity_lv + 1, identity_lv[0]));

	/* collect slots to page
	 * Mark slots for every TBF, but only mark one of it.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));
	for (l = 0; tbfs_lists[l]; l++) {
		llist_for_each_entry(tbf, tbfs_lists[l], list) {
			first_ts = -1;
			for (ts = 0; ts < 8; ts++) {
				if (tbf->pdch[ts]) {
					/* remember the first slot found */
					if (first_ts < 0)
						first_ts = ts;
					/* break, if we already marked a slot */
					if ((slot_mask[tbf->trx_no] & (1 << ts)))
						break;
				}
			}
			/* mark first slot found, if none is marked already */
			if (ts == 8 && first_ts >= 0) {
				LOGP(DRLCMAC, LOGL_DEBUG, "- %s TBF=%d uses "
					"TRX=%d TS=%d, so we mark\n",
					(tbf->direction == GPRS_RLCMAC_UL_TBF)
						? "UL" : "DL",
					tbf->tfi, tbf->trx_no, first_ts);
				slot_mask[tbf->trx_no] |= (1 << first_ts);
			} else
				LOGP(DRLCMAC, LOGL_DEBUG, "- %s TBF=%d uses "
					"already marked TRX=%d TS=%d\n",
					(tbf->direction == GPRS_RLCMAC_UL_TBF)
						? "UL" : "DL",
					tbf->tfi, tbf->trx_no, ts);
		}
	}

	/* Now we have a list of marked slots. Every TBF uses at least one
	 * of these slots. */

	/* schedule paging to all marked slots */
	for (trx = 0; trx < 8; trx++) {
		if (slot_mask[trx] == 0)
			continue;
		for (ts = 0; ts < 8; ts++) {
			if ((slot_mask[trx] & (1 << ts))) {
				/* schedule */
				pag = talloc_zero(tall_pcu_ctx,
					struct gprs_rlcmac_paging);
				if (!pag)
					return -ENOMEM;
				pag->chan_needed = chan_needed;
				memcpy(pag->identity_lv, identity_lv,
					identity_lv[0] + 1);
				m_bts.trx[trx].pdch[ts].add_paging(pag);
				LOGP(DRLCMAC, LOGL_INFO, "Paging on PACCH of "
					"TRX=%d TS=%d\n", trx, ts);
				any_tbf = 1;
			}
		}
	}

	if (!any_tbf)
		LOGP(DRLCMAC, LOGL_INFO, "No paging, because no TBF\n");

	return 0;
}

/* search for active downlink or uplink tbf */
gprs_rlcmac_tbf *BTS::tbf_by_tlli(uint32_t tlli, enum gprs_rlcmac_tbf_direction dir)
{
	struct gprs_rlcmac_tbf *tbf;
	if (dir == GPRS_RLCMAC_UL_TBF) {
		llist_for_each_entry(tbf, &m_bts.ul_tbfs, list) {
			if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
			 && tbf->tlli == tlli && tbf->tlli_valid)
				return tbf;
		}
	} else {
		llist_for_each_entry(tbf, &m_bts.dl_tbfs, list) {
			if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
			 && tbf->tlli == tlli)
				return tbf;
		}
	}
	return NULL;
}

gprs_rlcmac_tbf *BTS::tbf_by_poll_fn(uint32_t fn, uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_tbf *tbf;

	/* only one TBF can poll on specific TS/FN, because scheduler can only
	 * schedule one downlink control block (with polling) at a FN per TS */
	llist_for_each_entry(tbf, &m_bts.ul_tbfs, list) {
		if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn && tbf->trx_no == trx
		 && tbf->control_ts == ts)
			return tbf;
	}
	llist_for_each_entry(tbf, &m_bts.dl_tbfs, list) {
		if (tbf->state_is_not(GPRS_RLCMAC_RELEASING)
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn && tbf->trx_no == trx
		 && tbf->control_ts == ts)
			return tbf;
	}
	return NULL;
}

void gprs_rlcmac_pdch::enable()
{
	/* TODO: Check if there are still allocated resources.. */
	INIT_LLIST_HEAD(&paging_list);
	m_is_enabled = 1;
}

void gprs_rlcmac_pdch::disable()
{
	/* TODO.. kick free_resources once we know the TRX/TS we are on */
	m_is_enabled = 0;
}

/* TODO: kill the parameter and make a pdch belong to a trx.. to a bts.. */
void gprs_rlcmac_pdch::free_resources(BTS *bts, uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_paging *pag;

	/* we are not enabled. there should be no resources */
	if (!is_enabled())
		return;

	/* kick all TBF on slot */
	gprs_rlcmac_tbf::free_all(this);

	/* flush all pending paging messages */
	while ((pag = dequeue_paging()))
		talloc_free(pag);

	bts->sba()->free_resources(trx, ts);
}

struct gprs_rlcmac_paging *gprs_rlcmac_pdch::dequeue_paging()
{
	struct gprs_rlcmac_paging *pag;

	if (llist_empty(&paging_list))
		return NULL;
	pag = llist_entry(paging_list.next, struct gprs_rlcmac_paging, list);
	llist_del(&pag->list);

	return pag;
}

struct msgb *gprs_rlcmac_pdch::packet_paging_request()
{
	struct gprs_rlcmac_paging *pag;
	struct msgb *msg;
	unsigned wp = 0, len;

	/* no paging, no message */
	pag = dequeue_paging();
	if (!pag)
		return NULL;

	LOGP(DRLCMAC, LOGL_DEBUG, "Scheduling paging\n");

	/* alloc message */
	msg = msgb_alloc(23, "pag ctrl block");
	if (!msg) {
		talloc_free(pag);
		return NULL;
	}
	bitvec *pag_vec = bitvec_alloc(23);
	if (!pag_vec) {
		msgb_free(msg);
		talloc_free(pag);
		return NULL;
	}
	wp = Encoding::write_packet_paging_request(pag_vec);

	/* loop until message is full */
	while (pag) {
		/* try to add paging */
		if ((pag->identity_lv[1] & 0x07) == 4) {
			/* TMSI */
			LOGP(DRLCMAC, LOGL_DEBUG, "- TMSI=0x%08x\n",
				ntohl(*((uint32_t *)(pag->identity_lv + 1))));
			len = 1 + 1 + 1 + 32 + 2 + 1;
			if (pag->identity_lv[0] != 5) {
				LOGP(DRLCMAC, LOGL_ERROR, "TMSI paging with "
					"MI != 5 octets!\n");
				goto continue_next;
			}
		} else {
			/* MI */
			LOGP(DRLCMAC, LOGL_DEBUG, "- MI=%s\n",
				osmo_hexdump(pag->identity_lv + 1,
					pag->identity_lv[0]));
			len = 1 + 1 + 1 + 4 + (pag->identity_lv[0]<<3) + 2 + 1;
			if (pag->identity_lv[0] > 8) {
				LOGP(DRLCMAC, LOGL_ERROR, "Paging with "
					"MI > 8 octets!\n");
				goto continue_next;
			}
		}
		if (wp + len > 184) {
			LOGP(DRLCMAC, LOGL_DEBUG, "- Does not fit, so schedule "
				"next time\n");
			/* put back paging record, because does not fit */
			llist_add_tail(&pag->list, &paging_list);
			break;
		}
		Encoding::write_repeated_page_info(pag_vec, wp, pag->identity_lv[0],
			pag->identity_lv + 1, pag->chan_needed);

continue_next:
		talloc_free(pag);
		pag = dequeue_paging();
	}

	bitvec_pack(pag_vec, msgb_put(msg, 23));
	RlcMacDownlink_t * mac_control_block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Paging Request +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(pag_vec, mac_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Paging Request -------------------------\n");
	bitvec_free(pag_vec);
	talloc_free(mac_control_block);

	return msg;
}

void gprs_rlcmac_pdch::add_paging(struct gprs_rlcmac_paging *pag)
{
	llist_add(&pag->list, &paging_list);
}
