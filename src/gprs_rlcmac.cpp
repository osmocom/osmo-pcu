/* gprs_rlcmac.cpp
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
 
#include <gprs_bssgp_pcu.h>
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <tbf.h>


struct gprs_rlcmac_cs gprs_rlcmac_cs[] = {
/*	frame length	data block	max payload */
	{ 0,		0,		0  },
	{ 23,		23,		20 }, /* CS-1 */
	{ 34,		33,		30 }, /* CS-2 */
	{ 40,		39,		36 }, /* CS-3 */
	{ 54,		53,		50 }, /* CS-4 */
};

LLIST_HEAD(gprs_rlcmac_ul_tbfs);
LLIST_HEAD(gprs_rlcmac_dl_tbfs);
llist_head *gprs_rlcmac_tbfs_lists[] = {
	&gprs_rlcmac_ul_tbfs,
	&gprs_rlcmac_dl_tbfs,
	NULL
};
extern void *tall_pcu_ctx;

#ifdef DEBUG_DIAGRAM
struct timeval diagram_time = {0,0};
struct timeval diagram_last_tv = {0,0};

void debug_diagram(int diag, const char *format, ...)
{
	va_list ap;
	char debug[128];
	char line[1024];
	struct gprs_rlcmac_tbf *tbf, *tbf_a[16];
	int max_diag = -1, i;
	uint64_t diff = 0;

	va_start(ap, format);
	vsnprintf(debug, sizeof(debug) - 1, format, ap);
	debug[19] = ' ';
	debug[20] = '\0';
	va_end(ap);

	memset(tbf_a, 0, sizeof(tbf_a));
	llist_for_each_entry(tbf, &gprs_rlcmac_ul_tbfs, list) {
		if (tbf->diag < 16) {
			if (tbf->diag > max_diag)
				max_diag = tbf->diag;
			tbf_a[tbf->diag] = tbf;
		}
	}
	llist_for_each_entry(tbf, &gprs_rlcmac_dl_tbfs, list) {
		if (tbf->diag < 16) {
			if (tbf->diag > max_diag)
				max_diag = tbf->diag;
			tbf_a[tbf->diag] = tbf;
		}
	}

	if (diagram_last_tv.tv_sec) {
		diff = (uint64_t)(diagram_time.tv_sec -
					diagram_last_tv.tv_sec) * 1000;
		diff += diagram_time.tv_usec / 1000;
		diff -= diagram_last_tv.tv_usec / 1000;
	}
	memcpy(&diagram_last_tv, &diagram_time, sizeof(struct timeval));

	if (diff > 0) {
		if (diff > 99999)
			strcpy(line, "  ...  : ");
		else
			sprintf(line, "%3d.%03d: ", (int)(diff / 1000),
				(int)(diff % 1000));
		for (i = 0; i <= max_diag; i++) {
			if (tbf_a[i] == NULL) {
				strcat(line, "                    ");
				continue;
			}
			if (tbf_a[i]->diag_new) {
				strcat(line, "         |          ");
				continue;
			}
			strcat(line, "                    ");
		}
		puts(line);
	}
	strcpy(line, "       : ");
	for (i = 0; i <= max_diag; i++) {
		if (tbf_a[i] == NULL) {
			strcat(line, "                    ");
			continue;
		}
		if (tbf_a[i]->diag != diag) {
			strcat(line, "         |          ");
			continue;
		}
		if (strlen(debug) < 19) {
			strcat(line, "                    ");
			memcpy(line + strlen(line) - 11 - strlen(debug) / 2,
				debug, strlen(debug));
		} else
			strcat(line, debug);
		tbf_a[i]->diag_new = 1;
	}
	puts(line);
}
#endif

/* FIXME: spread resources over multiple TRX. Also add option to use same
 * TRX in case of existing TBF for TLLI in the other direction. */
/* search for free TFI and return TFI, TRX */
int tfi_find_free(struct gprs_rlcmac_bts *bts, enum gprs_rlcmac_tbf_direction dir,
		uint8_t *_trx, int8_t use_trx)
{
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf **tbfp;
	uint8_t trx_from, trx_to, trx, ts, tfi;

	if (use_trx >= 0 && use_trx < 8)
		trx_from = trx_to = use_trx;
	else {
		trx_from = 0;
		trx_to = 7;
	}

	/* on TRX find first enabled TS */
	for (trx = trx_from; trx <= trx_to; trx++) {
		for (ts = 0; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->enable)
				continue;
			break;
		}
		if (ts < 8)
			break;
	}
	if (trx > trx_to) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		return -EINVAL;
	}


	LOGP(DRLCMAC, LOGL_DEBUG, "Searching for first unallocated TFI: "
		"TRX=%d first TS=%d\n", trx, ts);
	if (dir == GPRS_RLCMAC_UL_TBF)
		tbfp = bts->trx[trx].ul_tbf;
	else
		tbfp = bts->trx[trx].dl_tbf;
	for (tfi = 0; tfi < 32; tfi++) {
		if (!tbfp[tfi])
			break;
	}
	
	if (tfi < 32) {
		LOGP(DRLCMAC, LOGL_DEBUG, " Found TFI=%d.\n", tfi);
		*_trx = trx;
		return tfi;
	}
	LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available.\n");

	return -1;
}

/* starting time for assigning single slot
 * This offset must be a multiple of 13. */
#define AGCH_START_OFFSET 52

LLIST_HEAD(gprs_rlcmac_sbas);

int sba_alloc(uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta)
{

	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_sba *sba;
	uint8_t trx, ts;
	uint32_t fn;

	sba = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_sba);
	if (!sba)
		return -ENOMEM;

	for (trx = 0; trx < 8; trx++) {
		for (ts = 0; ts < 8; ts++) {
			pdch = &bts->trx[trx].pdch[ts];
			if (!pdch->enable)
				continue;
			break;
		}
		if (ts < 8)
			break;
	}
	if (trx == 8) {
		LOGP(DRLCMAC, LOGL_NOTICE, "No PDCH available.\n");
		talloc_free(sba);
		return -EINVAL;
	}

	fn = (pdch->last_rts_fn + AGCH_START_OFFSET) % 2715648;

	sba->trx = trx;
	sba->ts = ts;
	sba->fn = fn;
	sba->ta = ta;

	llist_add(&sba->list, &gprs_rlcmac_sbas);

	*_trx = trx;
	*_ts = ts;
	*_fn = fn;
	return 0;
}

struct gprs_rlcmac_sba *sba_find(uint8_t trx, uint8_t ts, uint32_t fn)
{
	struct gprs_rlcmac_sba *sba;

	llist_for_each_entry(sba, &gprs_rlcmac_sbas, list) {
		if (sba->trx == trx && sba->ts == ts && sba->fn == fn)
			return sba;
	}

	return NULL;
}

/* received RLC/MAC block from L1 */
int gprs_rlcmac_rcv_block(uint8_t trx, uint8_t ts, uint8_t *data, uint8_t len,
	uint32_t fn, int8_t rssi)
{
	unsigned payload = data[0] >> 6;
	bitvec *block;
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = gprs_rlcmac_rcv_data_block_acknowledged(trx, ts, data,
			len, rssi);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		block = bitvec_alloc(len);
		if (!block)
			return -ENOMEM;
		bitvec_unpack(block, data);
		rc = gprs_rlcmac_rcv_control_block(block, trx, ts, fn);
		bitvec_free(block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload(%u).\n", payload);
		rc = -EINVAL;
	}

	return rc;
}

/* add paging to paging queue(s) */
int gprs_rlcmac_add_paging(uint8_t chan_needed, uint8_t *identity_lv)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	uint8_t l, trx, ts, any_tbf = 0;
	struct gprs_rlcmac_tbf *tbf;
	struct gprs_rlcmac_paging *pag;
	uint8_t slot_mask[8];
	int8_t first_ts; /* must be signed */

	LOGP(DRLCMAC, LOGL_INFO, "Add RR paging: chan-needed=%d MI=%s\n",
		chan_needed, osmo_hexdump(identity_lv + 1, identity_lv[0]));

	/* collect slots to page
	 * Mark slots for every TBF, but only mark one of it.
	 * Mark only the first slot found.
	 * Don't mark, if TBF uses a different slot that is already marked. */
	memset(slot_mask, 0, sizeof(slot_mask));
	for (l = 0; gprs_rlcmac_tbfs_lists[l]; l++) {
		llist_for_each_entry(tbf, gprs_rlcmac_tbfs_lists[l], list) {
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
		any_tbf = 1;
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
				llist_add(&pag->list,
					&bts->trx[trx].pdch[ts].paging_list);
				LOGP(DRLCMAC, LOGL_INFO, "Paging on PACCH of "
					"TRX=%d TS=%d\n", trx, ts);
			}
		}
	}

	if (!any_tbf)
		LOGP(DRLCMAC, LOGL_INFO, "No paging, because no TBF\n");

	return 0;
}

struct gprs_rlcmac_paging *gprs_rlcmac_dequeue_paging(
	struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_paging *pag;

	if (llist_empty(&pdch->paging_list))
		return NULL;
	pag = llist_entry(pdch->paging_list.next,
		struct gprs_rlcmac_paging, list);
        llist_del(&pag->list);

	return pag;
}

struct msgb *gprs_rlcmac_send_packet_paging_request(
	struct gprs_rlcmac_pdch *pdch)
{
	struct gprs_rlcmac_paging *pag;
	struct msgb *msg;
	unsigned wp = 0, len;

	/* no paging, no message */
	pag = gprs_rlcmac_dequeue_paging(pdch);
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
	wp = write_packet_paging_request(pag_vec);

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
			llist_add_tail(&pag->list, &pdch->paging_list);
			break;
		}
		write_repeated_page_info(pag_vec, wp, pag->identity_lv[0],
			pag->identity_lv + 1, pag->chan_needed);

continue_next:
		talloc_free(pag);
		pag = gprs_rlcmac_dequeue_paging(pdch);
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

// GSM 04.08 9.1.18 Immediate assignment
int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra,
	uint32_t ref_fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc,
	uint8_t tfi, uint8_t usf, uint32_t tlli,
	uint8_t polling, uint32_t fn, uint8_t single_block, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx)
{
	unsigned wp = 0;
	uint8_t plen;

	bitvec_write_field(dest, wp,0x0,4);  // Skip Indicator
	bitvec_write_field(dest, wp,0x6,4);  // Protocol Discriminator
	bitvec_write_field(dest, wp,0x3F,8); // Immediate Assignment Message Type

	// 10.5.2.25b Dedicated mode or TBF
	bitvec_write_field(dest, wp,0x0,1);      // spare
	bitvec_write_field(dest, wp,0x0,1);      // TMA : Two-message assignment: No meaning
	bitvec_write_field(dest, wp,downlink,1); // Downlink : Downlink assignment to mobile in packet idle mode
	bitvec_write_field(dest, wp,0x1,1);      // T/D : TBF or dedicated mode: this message assigns a Temporary Block Flow (TBF).

	bitvec_write_field(dest, wp,0x0,4); // Page Mode

	// GSM 04.08 10.5.2.25a Packet Channel Description
	bitvec_write_field(dest, wp,0x1,5);                               // Channel type
	bitvec_write_field(dest, wp,ts,3);     // TN
	bitvec_write_field(dest, wp,tsc,3);    // TSC
	bitvec_write_field(dest, wp,0x0,3);                               // non-hopping RF channel configuraion
	bitvec_write_field(dest, wp,arfcn,10); // ARFCN

	//10.5.2.30 Request Reference
	bitvec_write_field(dest, wp,ra,8);                    // RA
	bitvec_write_field(dest, wp,(ref_fn / (26 * 51)) % 32,5); // T1'
	bitvec_write_field(dest, wp,ref_fn % 51,6);               // T3
	bitvec_write_field(dest, wp,ref_fn % 26,5);               // T2

	// 10.5.2.40 Timing Advance
	bitvec_write_field(dest, wp,0x0,2); // spare
	bitvec_write_field(dest, wp,ta,6);  // Timing Advance value

	// No mobile allocation in non-hopping systems.
	// A zero-length LV.  Just write L=0.
	bitvec_write_field(dest, wp,0,8);

	if ((wp % 8)) {
		LOGP(DRLCMACUL, LOGL_ERROR, "Length of IMM.ASS without rest "
			"octets is not multiple of 8 bits, PLEASE FIX!\n");
		exit (0);
	}
	plen = wp / 8;

	if (downlink)
	{
		// GSM 04.08 10.5.2.16 IA Rest Octets
		bitvec_write_field(dest, wp, 3, 2);   // "HH"
		bitvec_write_field(dest, wp, 1, 2);   // "01" Packet Downlink Assignment
		bitvec_write_field(dest, wp,tlli,32); // TLLI
		bitvec_write_field(dest, wp,0x1,1);   // switch TFI   : on
		bitvec_write_field(dest, wp,tfi,5);   // TFI
		bitvec_write_field(dest, wp,0x0,1);   // RLC acknowledged mode
		if (alpha) {
			bitvec_write_field(dest, wp,0x1,1);   // ALPHA = present
			bitvec_write_field(dest, wp,alpha,4);   // ALPHA
		} else {
			bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
		}
		bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
		bitvec_write_field(dest, wp,polling,1);   // Polling Bit
		bitvec_write_field(dest, wp,!polling,1);   // TA_VALID ???
		if (ta_idx < 0) {
			bitvec_write_field(dest, wp,0x0,1);   // switch TIMING_ADVANCE_INDEX = off
		} else {
			bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
			bitvec_write_field(dest, wp,ta_idx,4);   // TIMING_ADVANCE_INDEX
		}
		if (polling) {
			bitvec_write_field(dest, wp,0x1,1);   // TBF Starting TIME present
			bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
			bitvec_write_field(dest, wp,fn % 51,6);               // T3
			bitvec_write_field(dest, wp,fn % 26,5);               // T2
		} else {
			bitvec_write_field(dest, wp,0x0,1);   // TBF Starting TIME present
		}
		bitvec_write_field(dest, wp,0x0,1);   // P0 not present
//		bitvec_write_field(dest, wp,0x1,1);   // P0 not present
//		bitvec_write_field(dest, wp,0xb,4);
	}
	else
	{
		struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
		// GMS 04.08 10.5.2.37b 10.5.2.16
		bitvec_write_field(dest, wp, 3, 2);    // "HH"
		bitvec_write_field(dest, wp, 0, 2);    // "0" Packet Uplink Assignment
		if (single_block) {
			bitvec_write_field(dest, wp, 0, 1);    // Block Allocation : Single Block Allocation
			if (alpha) {
				bitvec_write_field(dest, wp,0x1,1);   // ALPHA = present
				bitvec_write_field(dest, wp,alpha,4);   // ALPHA = present
			} else
				bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
			bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
			if (ta_idx < 0) {
				bitvec_write_field(dest, wp,0x0,1);   // switch TIMING_ADVANCE_INDEX = off
			} else {
				bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
				bitvec_write_field(dest, wp,ta_idx,4);   // TIMING_ADVANCE_INDEX
			}
			bitvec_write_field(dest, wp, 1, 1);    // TBF_STARTING_TIME_FLAG
			bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
			bitvec_write_field(dest, wp,fn % 51,6);               // T3
			bitvec_write_field(dest, wp,fn % 26,5);               // T2
		} else {
			bitvec_write_field(dest, wp, 1, 1);    // Block Allocation : Not Single Block Allocation
			bitvec_write_field(dest, wp, tfi, 5);  // TFI_ASSIGNMENT Temporary Flow Identity
			bitvec_write_field(dest, wp, 0, 1);    // POLLING
			bitvec_write_field(dest, wp, 0, 1);    // ALLOCATION_TYPE: dynamic
			bitvec_write_field(dest, wp, usf, 3);    // USF
			bitvec_write_field(dest, wp, 0, 1);    // USF_GRANULARITY
			bitvec_write_field(dest, wp, 0, 1);   // "0" power control: Not Present
			bitvec_write_field(dest, wp, bts->initial_cs_ul-1, 2);    // CHANNEL_CODING_COMMAND 
			bitvec_write_field(dest, wp, 1, 1);    // TLLI_BLOCK_CHANNEL_CODING
			if (alpha) {
				bitvec_write_field(dest, wp,0x1,1);   // ALPHA = present
				bitvec_write_field(dest, wp,alpha,4);   // ALPHA
			} else
				bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
			bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
			/* note: there is no choise for TAI and no starting time */
			bitvec_write_field(dest, wp, 0, 1);   // switch TIMING_ADVANCE_INDEX = off
			bitvec_write_field(dest, wp, 0, 1);    // TBF_STARTING_TIME_FLAG
		}
	}

	return plen;
}

/* generate uplink assignment */
void write_packet_uplink_assignment(bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
	struct gprs_rlcmac_tbf *tbf, uint8_t poll, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	unsigned wp = 0;
	uint8_t ts;

	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber (N+13)
	bitvec_write_field(dest, wp,poll,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	bitvec_write_field(dest, wp,0xa,6);  // MESSAGE TYPE

	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1); // switch PERSIST_LEVEL: off
	if (use_tlli) {
		bitvec_write_field(dest, wp,0x2,2); // switch TLLI   : on
		bitvec_write_field(dest, wp,tlli,32); // TLLI
	} else {
		bitvec_write_field(dest, wp,0x0,1); // switch TFI : on
		bitvec_write_field(dest, wp,old_downlink,1); // 0=UPLINK TFI, 1=DL TFI
		bitvec_write_field(dest, wp,old_tfi,5); // TFI
	}

	bitvec_write_field(dest, wp,0x0,1); // Message escape
	bitvec_write_field(dest, wp,bts->initial_cs_ul-1, 2); // CHANNEL_CODING_COMMAND 
	bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 
	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(dest, wp,tbf->ta,6); // TIMING_ADVANCE_VALUE
	if (ta_idx < 0) {
		bitvec_write_field(dest, wp,0x0,1);   // switch TIMING_ADVANCE_INDEX = off
	} else {
		bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
		bitvec_write_field(dest, wp,ta_idx,4);   // TIMING_ADVANCE_INDEX
	}

#if 1
	bitvec_write_field(dest, wp,0x1,1); // Frequency Parameters information elements = present
	bitvec_write_field(dest, wp,tbf->tsc,3); // Training Sequence Code (TSC)
	bitvec_write_field(dest, wp,0x0,2); // ARFCN = present
	bitvec_write_field(dest, wp,tbf->arfcn,10); // ARFCN
#else
	bitvec_write_field(dest, wp,0x0,1); // Frequency Parameters = off
#endif

	bitvec_write_field(dest, wp,0x1,2); // Dynamic Allocation
	
	bitvec_write_field(dest, wp,0x0,1); // Extended Dynamic Allocation = off
	bitvec_write_field(dest, wp,0x0,1); // P0 = off
	
	bitvec_write_field(dest, wp,0x0,1); // USF_GRANULARITY
	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,tbf->tfi,5);// TFI

	bitvec_write_field(dest, wp,0x0,1); //
	bitvec_write_field(dest, wp,0x0,1); // TBF Starting Time = off
	if (alpha || gamma) {
		bitvec_write_field(dest, wp,0x1,1); // Timeslot Allocation with Power Control
		bitvec_write_field(dest, wp,alpha,4);   // ALPHA
	} else
		bitvec_write_field(dest, wp,0x0,1); // Timeslot Allocation
	
	for (ts = 0; ts < 8; ts++) {
		if (tbf->pdch[ts]) {
			bitvec_write_field(dest, wp,0x1,1); // USF_TN(i): on
			bitvec_write_field(dest, wp,tbf->dir.ul.usf[ts],3); // USF_TN(i)
			if (alpha || gamma)
				bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
		} else
			bitvec_write_field(dest, wp,0x0,1); // USF_TN(i): off
	}
//	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
}


/* generate downlink assignment */
void write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t old_tfi,
	uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx, uint8_t ta_ts)
{
	// Packet downlink assignment TS 44.060 11.2.7

	uint8_t tn;

	block->PAYLOAD_TYPE = 0x1;  // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0;  // N+13
	block->SP           = poll; // RRBP field is valid
	block->USF          = 0x0;  // Uplink state flag

	block->u.Packet_Downlink_Assignment.MESSAGE_TYPE = 0x2;  // Packet Downlink Assignment
	block->u.Packet_Downlink_Assignment.PAGE_MODE    = 0x0;  // Normal Paging

	block->u.Packet_Downlink_Assignment.Exist_PERSISTENCE_LEVEL      = 0x0;          // PERSISTENCE_LEVEL: off

	block->u.Packet_Downlink_Assignment.ID.UnionType                 = 0x0;          // TFI = on
	block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.UnionType    = old_downlink; // 0=UPLINK TFI, 1=DL TFI
	block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.u.UPLINK_TFI = old_tfi;      // TFI

	block->u.Packet_Downlink_Assignment.MAC_MODE            = 0x0;          // Dynamic Allocation
	block->u.Packet_Downlink_Assignment.RLC_MODE            = 0x0;          // RLC acknowledged mode
	block->u.Packet_Downlink_Assignment.CONTROL_ACK         = old_downlink; // NW establishes no new DL TBF for the MS with running timer T3192
	block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION = 0;   // timeslot(s)
	for (tn = 0; tn < 8; tn++) {
		if (tbf->pdch[tn])
			block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION |= 0x80 >> tn;   // timeslot(s)
	}

	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_TIMING_ADVANCE_VALUE = 0x1; // TIMING_ADVANCE_VALUE = on
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_VALUE       = tbf->ta;  // TIMING_ADVANCE_VALUE
	if (ta_idx < 0) {
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x0; // TIMING_ADVANCE_INDEX = off
	} else {
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x1; // TIMING_ADVANCE_INDEX = on
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_INDEX       = ta_idx; // TIMING_ADVANCE_INDEX
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_TIMESLOT_NUMBER = ta_ts; // TIMING_ADVANCE_TS
	}

	block->u.Packet_Downlink_Assignment.Exist_P0_and_BTS_PWR_CTRL_MODE = 0x0;   // POWER CONTROL = off

	block->u.Packet_Downlink_Assignment.Exist_Frequency_Parameters     = 0x1;   // Frequency Parameters = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.TSC       = tbf->tsc;   // Training Sequence Code (TSC)
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.UnionType = 0x0;   // ARFCN = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.u.ARFCN   = tbf->arfcn; // ARFCN

	block->u.Packet_Downlink_Assignment.Exist_DOWNLINK_TFI_ASSIGNMENT  = 0x1;     // DOWNLINK TFI ASSIGNMENT = on
	block->u.Packet_Downlink_Assignment.DOWNLINK_TFI_ASSIGNMENT        = tbf->tfi; // TFI

	block->u.Packet_Downlink_Assignment.Exist_Power_Control_Parameters = 0x1;   // Power Control Parameters = on
	block->u.Packet_Downlink_Assignment.Power_Control_Parameters.ALPHA = alpha;   // ALPHA

	for (tn = 0; tn < 8; tn++)
	{
		if (tbf->pdch[tn])
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].Exist    = 0x1; // Slot[i] = on
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].GAMMA_TN = gamma; // GAMMA_TN
		}
		else
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].Exist    = 0x0; // Slot[i] = off
		}
	}

	block->u.Packet_Downlink_Assignment.Exist_TBF_Starting_Time   = 0x0; // TBF Starting TIME = off
	block->u.Packet_Downlink_Assignment.Exist_Measurement_Mapping = 0x0; // Measurement_Mapping = off
	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x0; // AdditionsR99 = off
}

/* generate paging request */
int write_paging_request(bitvec * dest, uint8_t *ptmsi, uint16_t ptmsi_len)
{
	unsigned wp = 0;
	int plen;

	bitvec_write_field(dest, wp,0x0,4);  // Skip Indicator
	bitvec_write_field(dest, wp,0x6,4);  // Protocol Discriminator
	bitvec_write_field(dest, wp,0x21,8); // Paging Request Message Type

	bitvec_write_field(dest, wp,0x0,4);  // Page Mode
	bitvec_write_field(dest, wp,0x0,4);  // Channel Needed

	// Mobile Identity
	bitvec_write_field(dest, wp,ptmsi_len+1,8);  // Mobile Identity length
	bitvec_write_field(dest, wp,0xf,4);          // unused
	bitvec_write_field(dest, wp,0x4,4);          // PTMSI type
	for (int i = 0; i < ptmsi_len; i++)
	{
		bitvec_write_field(dest, wp,ptmsi[i],8); // PTMSI
	}
	if ((wp % 8)) {
		LOGP(DRLCMACUL, LOGL_ERROR, "Length of PAG.REQ without rest "
			"octets is not multiple of 8 bits, PLEASE FIX!\n");
		exit (0);
	}
	plen = wp / 8;
	bitvec_write_field(dest, wp,0x0,1); // "L" NLN(PCH) = off
	bitvec_write_field(dest, wp,0x0,1); // "L" Priority1 = off
	bitvec_write_field(dest, wp,0x1,1); // "L" Priority2 = off
	bitvec_write_field(dest, wp,0x0,1); // "L" Group Call information = off
	bitvec_write_field(dest, wp,0x0,1); // "H" Packet Page Indication 1 = packet paging procedure
	bitvec_write_field(dest, wp,0x1,1); // "H" Packet Page Indication 2 = packet paging procedure

	return plen;
}

/* generate uplink ack */
void write_packet_uplink_ack(RlcMacDownlink_t * block, struct gprs_rlcmac_tbf *tbf,
	uint8_t final)
{
	// Packet Uplink Ack/Nack  TS 44.060 11.2.28

	char show_v_n[65];

	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	uint8_t rbb = 0;
	uint16_t i, bbn;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	char bit;

	LOGP(DRLCMACUL, LOGL_DEBUG, "Sending Ack/Nack for TBF=%d "
		"(final=%d)\n", tbf->tfi, final);

	block->PAYLOAD_TYPE = 0x1;   // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0;   // N+13
	block->SP           = final; // RRBP field is valid, if it is final ack
	block->USF          = 0x0;   // Uplink state flag

	block->u.Packet_Uplink_Ack_Nack.MESSAGE_TYPE = 0x9;      // Packet Downlink Assignment
	block->u.Packet_Uplink_Ack_Nack.PAGE_MODE    = 0x0;      // Normal Paging
	block->u.Packet_Uplink_Ack_Nack.UPLINK_TFI   = tbf->tfi; // Uplink TFI

	block->u.Packet_Uplink_Ack_Nack.UnionType    = 0x0;      // PU_AckNack_GPRS = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.CHANNEL_CODING_COMMAND                        = bts->initial_cs_ul - 1;             // CS1
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.FINAL_ACK_INDICATION     = final;           // FINAL ACK INDICATION
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER = tbf->dir.ul.v_r; // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	for (i = 0, bbn = (tbf->dir.ul.v_r - 64) & mod_sns_half; i < 64;
	     i++, bbn = (bbn + 1) & mod_sns_half) {
	     	bit = tbf->dir.ul.v_n[bbn];
		if (bit == 0)
			bit = ' ';
		show_v_n[i] = bit;
		if (bit == 'R')
			rbb = (rbb << 1)|1;
		else
			rbb = (rbb << 1);
		if((i%8) == 7)
		{
			block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP[i/8] = rbb;
			rbb = 0;
		}
	}
	show_v_n[64] = '\0';
	LOGP(DRLCMACUL, LOGL_DEBUG, "- V(N): \"%s\" R=Received "
		"N=Not-Received\n", show_v_n);

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.UnionType              = 0x0; // Fixed Allocation Dummy = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.u.FixedAllocationDummy = 0x0; // Fixed Allocation Dummy
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Exist_AdditionsR99     = 0x0; // AdditionsR99 = off

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI = 0x1;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI       = tbf->tlli;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance      = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits             = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters   = 0x0;
}

unsigned write_packet_paging_request(bitvec * dest)
{
	unsigned wp = 0;

	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,3);  // No polling
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	bitvec_write_field(dest, wp,0x22,6);  // MESSAGE TYPE

	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1);  // No PERSISTENCE_LEVEL
	bitvec_write_field(dest, wp,0x0,1);  // No NLN

	return wp;
}

unsigned write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
	uint8_t *identity, uint8_t chan_needed)
{
	bitvec_write_field(dest, wp,0x1,1);  // Repeated Page info exists

	bitvec_write_field(dest, wp,0x1,1);  // RR connection paging

	if ((identity[0] & 0x07) == 4) {
		bitvec_write_field(dest, wp,0x0,1);  // TMSI
		identity++;
		len--;
	} else {
		bitvec_write_field(dest, wp,0x0,1);  // MI
		bitvec_write_field(dest, wp,len,4);  // MI len
	}
	while (len) {
		bitvec_write_field(dest, wp,*identity++,8);  // MI data
		len--;
	}
	bitvec_write_field(dest, wp,chan_needed,2);  // CHANNEL_NEEDED
	bitvec_write_field(dest, wp,0x0,1);  // No eMLPP_PRIORITY

	return wp;
}

/* Send Uplink unit-data to SGSN. */
int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf)
{
	uint8_t qos_profile[3];
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + tbf->llc_index;
	struct bssgp_bvc_ctx *bctx = gprs_bssgp_pcu_current_bctx();

	LOGP(DBSSGP, LOGL_INFO, "LLC [PCU -> SGSN] TFI: %u TLLI: 0x%08x len=%d\n", tbf->tfi, tbf->tlli, tbf->llc_index);
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	
	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	uint8_t *buf = msgb_push(llc_pdu, TL16V_GROSS_LEN(sizeof(uint8_t)*tbf->llc_index));
	tl16v_put(buf, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*tbf->llc_index, tbf->llc_frame);
	qos_profile[0] = QOS_PROFILE >> 16;
	qos_profile[1] = QOS_PROFILE >> 8;
	qos_profile[2] = QOS_PROFILE;
	bssgp_tx_ul_ud(bctx, tbf->tlli, qos_profile, llc_pdu);

	return 0;
}

int gprs_rlcmac_paging_request(uint8_t *ptmsi, uint16_t ptmsi_len,
	const char *imsi)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] Paging Request (CCCH)\n");
	bitvec *paging_request = bitvec_alloc(23);
	bitvec_unhex(paging_request, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	int plen = write_paging_request(paging_request, ptmsi, ptmsi_len);
	pcu_l1if_tx_pch(paging_request, plen, (char *)imsi);
	bitvec_free(paging_request);

	return 0;
}


/*
 * timing advance memory
 */

/* enable to debug timing advance memory */
//#define DEBUG_TA

static LLIST_HEAD(gprs_rlcmac_ta_list);
static int gprs_rlcmac_ta_num = 0;

struct gprs_rlcmac_ta {
	struct llist_head	list;
	uint32_t		tlli;
	uint8_t			ta;
};

/* remember timing advance of a given TLLI */
int remember_timing_advance(uint32_t tlli, uint8_t ta)
{
	struct gprs_rlcmac_ta *ta_entry;

	/* check for existing entry */
	llist_for_each_entry(ta_entry, &gprs_rlcmac_ta_list, list) {
		if (ta_entry->tlli == tlli) {
#ifdef DEBUG_TA
			fprintf(stderr, "update %08x %d\n", tlli, ta);
#endif
			ta_entry->ta = ta;
			/* relink to end of list */
			llist_del(&ta_entry->list);
			llist_add_tail(&ta_entry->list, &gprs_rlcmac_ta_list);
			return 0;
		}
	}

#ifdef DEBUG_TA
	fprintf(stderr, "remember %08x %d\n", tlli, ta);
#endif
	/* if list is full, remove oldest entry */
	if (gprs_rlcmac_ta_num == 30) {
		ta_entry = llist_entry(gprs_rlcmac_ta_list.next,
			struct gprs_rlcmac_ta, list);
	        llist_del(&ta_entry->list);
		talloc_free(ta_entry);
		gprs_rlcmac_ta_num--;
	}

	/* create new TA entry */
	ta_entry = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_ta);
	if (!ta_entry)
		return -ENOMEM;

	ta_entry->tlli = tlli;
	ta_entry->ta = ta;
	llist_add_tail(&ta_entry->list, &gprs_rlcmac_ta_list);
	gprs_rlcmac_ta_num++;

	return 0;
}

int recall_timing_advance(uint32_t tlli)
{
	struct gprs_rlcmac_ta *ta_entry;
	uint8_t ta;

	llist_for_each_entry(ta_entry, &gprs_rlcmac_ta_list, list) {
		if (ta_entry->tlli == tlli) {
			ta = ta_entry->ta;
#ifdef DEBUG_TA
			fprintf(stderr, "recall %08x %d\n", tlli, ta);
#endif
			return ta;
		}
	}
#ifdef DEBUG_TA
	fprintf(stderr, "no entry for %08x\n", tlli);
#endif

	return -EINVAL;
}

int flush_timing_advance(void)
{
	struct gprs_rlcmac_ta *ta_entry;
	int count = 0;

	while (!llist_empty(&gprs_rlcmac_ta_list)) {
		ta_entry = llist_entry(gprs_rlcmac_ta_list.next,
			struct gprs_rlcmac_ta, list);
#ifdef DEBUG_TA
		fprintf(stderr, "flush entry %08x %d\n", ta_entry->tlli,
			ta_entry->ta);
#endif
	        llist_del(&ta_entry->list);
		talloc_free(ta_entry);
		count++;
	}
	gprs_rlcmac_ta_num = 0;

	return count;
}

