/* gprs_rlcmac.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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
#include <pcu_l1_if.h>
#include <gprs_rlcmac.h>
#include <gsmL1prim.h>

LLIST_HEAD(gprs_rlcmac_tbfs);
void *rlcmac_tall_ctx;

/* FIXME: spread ressources on multiple TRX */
int tfi_alloc(uint8_t *_trx, uint8_t *_ts)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	uint8_t trx, ts, tfi;

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
		return -EINVAL;
	}


	LOGP(DRLCMAC, LOGL_DEBUG, "Searching for first unallocated TFI: "
		"TRX=%d TS=%d\n", trx, ts);
	for (tfi = 0; tfi < 32; tfi++) {
		if (!pdch->tbf[tfi])
			break;
	}
	
	if (tfi < 32) {
		LOGP(DRLCMAC, LOGL_DEBUG, " Found TFI=%d.\n", tfi);
		*_trx = trx;
		*_ts = ts;
		return tfi;
	}
	LOGP(DRLCMAC, LOGL_NOTICE, "No TFI available.\n");

	return -1;
}

int find_free_usf(uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf *tbf;
	uint8_t usf_map = 0;
	uint8_t tfi, usf;

	if (trx >= 8 || ts >= 8)
		return -EINVAL;
	pdch = &bts->trx[trx].pdch[ts];

	/* make map of used USF */
	for (tfi = 0; tfi < 32; tfi++) {
		tbf = pdch->tbf[tfi];
		if (!tbf)
			continue;
		if (tbf->direction != GPRS_RLCMAC_UL_TBF)
			continue;
		usf_map |= (1 << tbf->dir.ul.usf);
	}

	/* look for USF, don't use USF=7 */
	for (usf = 0; usf < 7; usf++) {
		if (!(usf_map & (1 << usf))) {
			LOGP(DRLCMAC, LOGL_DEBUG, " Found USF=%d.\n", usf);
			return usf;
		}
	}
	LOGP(DRLCMAC, LOGL_NOTICE, "No USF available.\n");

	return -1;
}

/* lookup TBF Entity (by TFI) */
#warning FIXME: use pdch instance by trx and ts, because tfi is local
struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi, int direction)
{
	struct gprs_rlcmac_tbf *tbf;

	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if (tbf->state != GPRS_RLCMAC_RELEASING
		 && tbf->tfi == tfi
		 && tbf->direction == direction)
			return tbf;
	}
	return NULL;
}

/* search for active downlink or uplink tbf */
struct gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli, int direction)
{
	struct gprs_rlcmac_tbf *tbf;
	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if (tbf->state != GPRS_RLCMAC_RELEASING
		 && tbf->tlli == tlli
		 && tbf->direction == direction)
			return tbf;
	}
	return NULL;
}

#warning FIXME: use pdch instance by trx and ts, because polling is local
struct gprs_rlcmac_tbf *tbf_by_poll_fn(uint32_t fn)
{
	struct gprs_rlcmac_tbf *tbf;
	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if (tbf->state != GPRS_RLCMAC_RELEASING
		 && tbf->poll_state == GPRS_RLCMAC_POLL_SCHED
		 && tbf->poll_fn == fn)
			return tbf;
	}
	return NULL;
}

struct gprs_rlcmac_tbf *tbf_alloc(uint8_t tfi, uint8_t trx, uint8_t ts)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct gprs_rlcmac_tbf *tbf;

	LOGP(DRLCMAC, LOGL_INFO, "********** TBF starts here **********\n");
	LOGP(DRLCMAC, LOGL_INFO, "Allocating TBF with TFI=%d.\n", tfi);

	if (trx >= 8 || ts >= 8 || tfi >= 32)
		return NULL;
	pdch = &bts->trx[trx].pdch[ts];

	tbf = talloc_zero(rlcmac_tall_ctx, struct gprs_rlcmac_tbf);
	if (!tbf)
		return NULL;

	tbf->tfi = tfi;
	tbf->trx = trx;
	tbf->ts = ts;
	tbf->arfcn = bts->trx[trx].arfcn;
	tbf->tsc = bts->trx[trx].pdch[ts].tsc;
	tbf->pdch = pdch;
	tbf->ws = 64;
	tbf->sns = 128;
	INIT_LLIST_HEAD(&tbf->llc_queue);
	llist_add(&tbf->list, &gprs_rlcmac_tbfs);
	pdch->tbf[tfi] = tbf;

	return tbf;
}

void tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	struct gprs_rlcmac_pdch *pdch;
	struct msgb *msg;

	LOGP(DRLCMAC, LOGL_INFO, "Free TBF=%d with TLLI=0x%08x.\n", tbf->tfi,
		tbf->tlli);
	tbf_timer_stop(tbf);
	while ((msg = msgb_dequeue(&tbf->llc_queue)))
		msgb_free(msg);
	pdch = &bts->trx[tbf->trx].pdch[tbf->ts];
	pdch->tbf[tbf->tfi] = NULL;
	llist_del(&tbf->list);
	LOGP(DRLCMAC, LOGL_INFO, "********** TBF ends here **********\n");
	talloc_free(tbf);
}

const char *tbf_state_name[] = {
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
	LOGP(DRLCMAC, LOGL_INFO, "TBF=%d changes state from %s to %s\n",
		tbf->tfi, tbf_state_name[tbf->state], tbf_state_name[state]);
	tbf->state = state;
}

void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
			unsigned int seconds, unsigned int microseconds)
{
	if (!osmo_timer_pending(&tbf->timer))
		LOGP(DRLCMAC, LOGL_DEBUG, "Starting TBF=%d timer %u.\n",
			tbf->tfi, T);
	else
		LOGP(DRLCMAC, LOGL_DEBUG, "Restarting TBF=%d timer %u while "
			"old timer %u pending \n", tbf->tfi, T, tbf->T);

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
		LOGP(DRLCMAC, LOGL_DEBUG, "Stopping TBF=%d timer %u.\n",
			tbf->tfi, tbf->T);
		osmo_timer_del(&tbf->timer);
	}
}

#if 0
static void tbf_gsm_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	tbf->num_fT_exp++;

	switch (tbf->fT) {
	case 0:
hier alles überdenken
		// This is timer for delay RLC/MAC data sending after Downlink Immediate Assignment on CCCH.
		gprs_rlcmac_segment_llc_pdu(tbf);
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] END TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
		tbf_free(tbf);
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Timer expired in unknown mode: %u \n", tbf->fT);
	}
}

static void tbf_gsm_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int fT,
				int frames)
{
	if (osmo_gsm_timer_pending(&tbf->gsm_timer))
		LOGP(DRLCMAC, LOGL_NOTICE, "Starting TBF timer %u while old timer %u pending \n", fT, tbf->fT);
	tbf->fT = fT;
	tbf->num_fT_exp = 0;

	/* FIXME: we should do this only once ? */
	tbf->gsm_timer.data = tbf;
	tbf->gsm_timer.cb = &tbf_gsm_timer_cb;

	osmo_gsm_timer_schedule(&tbf->gsm_timer, frames);
}

eine stop-funktion, auch im tbf_free aufrufen

#endif

#if 0
void gprs_rlcmac_enqueue_block(bitvec *block, int len)
{
	struct msgb *msg = msgb_alloc(len, "rlcmac_dl");
	bitvec_pack(block, msgb_put(msg, len));
	msgb_enqueue(&block_queue, msg);
}
#endif

/* received RLC/MAC block from L1 */
int gprs_rlcmac_rcv_block(uint8_t *data, uint8_t len, uint32_t fn)
{
	unsigned payload = data[0] >> 6;
	bitvec *block;
	int rc = 0;

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		rc = gprs_rlcmac_rcv_data_block_acknowledged(data, len);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		block = bitvec_alloc(len);
		if (!block)
			return -ENOMEM;
		bitvec_unpack(block, data);
		rc = gprs_rlcmac_rcv_control_block(block, fn);
		bitvec_free(block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		LOGP(DRLCMAC, LOGL_NOTICE, "GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "Unknown RLCMAC block payload.\n");
		rc = -EINVAL;
	}

	return rc;
}

// GSM 04.08 9.1.18 Immediate assignment
int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra,
	uint32_t fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc,
	uint8_t tfi, uint8_t usf, uint32_t tlli,
	uint8_t polling, uint32_t poll_fn)
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
	bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
	bitvec_write_field(dest, wp,fn % 51,6);               // T3
	bitvec_write_field(dest, wp,fn % 26,5);               // T2

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
		bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
		bitvec_write_field(dest, wp,0x0,5);   // GAMMA power control parameter
		bitvec_write_field(dest, wp,polling,1);   // Polling Bit
		bitvec_write_field(dest, wp,!polling,1);   // TA_VALID ???
		bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
		bitvec_write_field(dest, wp,0x0,4);   // TIMING_ADVANCE_INDEX
		if (polling) {
			bitvec_write_field(dest, wp,0x1,1);   // TBF Starting TIME present
			bitvec_write_field(dest, wp,(poll_fn / (26 * 51)) % 32,5); // T1'
			bitvec_write_field(dest, wp,poll_fn % 51,6);               // T3
			bitvec_write_field(dest, wp,poll_fn % 26,5);               // T2
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
		bitvec_write_field(dest, wp, 1, 1);    // Block Allocation : Not Single Block Allocation
		bitvec_write_field(dest, wp, tfi, 5);  // TFI_ASSIGNMENT Temporary Flow Identity
		bitvec_write_field(dest, wp, 0, 1);    // POLLING
		bitvec_write_field(dest, wp, 0, 1);    // ALLOCATION_TYPE: dynamic
		bitvec_write_field(dest, wp, usf, 3);    // USF
		bitvec_write_field(dest, wp, 0, 1);    // USF_GRANULARITY
		bitvec_write_field(dest, wp, 0 , 1);   // "0" power control: Not Present
		bitvec_write_field(dest, wp, bts->initial_cs-1, 2);    // CHANNEL_CODING_COMMAND 
		bitvec_write_field(dest, wp, 1, 1);    // TLLI_BLOCK_CHANNEL_CODING
		bitvec_write_field(dest, wp, 1 , 1);   // "1" Alpha : Present
		bitvec_write_field(dest, wp, 0, 4);    // Alpha
		bitvec_write_field(dest, wp, 0, 5);    // Gamma
		bitvec_write_field(dest, wp, 0, 1);    // TIMING_ADVANCE_INDEX_FLAG
		bitvec_write_field(dest, wp, 0, 1);    // TBF_STARTING_TIME_FLAG
	}

	return plen;
}

/* generate uplink assignment */
void write_packet_uplink_assignment(bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli, uint8_t new_tfi,
	uint8_t usf, uint16_t arfcn, uint8_t tn, uint8_t ta, uint8_t tsc,
	uint8_t poll)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	unsigned wp = 0;
	int i;

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
	bitvec_write_field(dest, wp, bts->initial_cs-1, 2); // CHANNEL_CODING_COMMAND 
	bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 

	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(dest, wp,ta,6); // TIMING_ADVANCE_VALUE
	bitvec_write_field(dest, wp,0x0,1); // switch TIMING_ADVANCE_INDEX = off

#if 1
	bitvec_write_field(dest, wp,0x1,1); // Frequency Parameters information elements = present
	bitvec_write_field(dest, wp,tsc,3); // Training Sequence Code (TSC)
	bitvec_write_field(dest, wp,0x0,2); // ARFCN = present
	bitvec_write_field(dest, wp,arfcn,10); // ARFCN
#else
	bitvec_write_field(dest, wp,0x0,1); // Frequency Parameters = off
#endif

	bitvec_write_field(dest, wp,0x1,2); // Dynamic Allocation
	
	bitvec_write_field(dest, wp,0x0,1); // Extended Dynamic Allocation = off
	bitvec_write_field(dest, wp,0x0,1); // P0 = off
	
	bitvec_write_field(dest, wp,0x0,1); // USF_GRANULARITY
	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,new_tfi,5);// TFI

	bitvec_write_field(dest, wp,0x0,1); //
	bitvec_write_field(dest, wp,0x0,1); // TBF Starting Time = off
	bitvec_write_field(dest, wp,0x0,1); // Timeslot Allocation
	
	for (i = 0; i < 8; i++) {
		if (tn == i) {
			bitvec_write_field(dest, wp,0x1,1); // USF_TN(i): on
			bitvec_write_field(dest, wp,usf,3); // USF_TN(i)
		} else
			bitvec_write_field(dest, wp,0x0,1); // USF_TN(i): off
	}
//	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
}

/* generate downlink assignment */
void write_packet_downlink_assignment(bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint8_t new_tfi, uint16_t arfcn,
	uint8_t tn, uint8_t ta, uint8_t tsc, uint8_t poll)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	int i;
	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber (FN+13)
	bitvec_write_field(dest, wp,poll,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	bitvec_write_field(dest, wp,0x2,6);  // MESSAGE TYPE
	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1); // switch PERSIST_LEVEL: off
	bitvec_write_field(dest, wp,0x0,1); // switch TFI : on
	bitvec_write_field(dest, wp,old_downlink,1); // 0=UPLINK TFI, 1=DL TFI
	bitvec_write_field(dest, wp,old_tfi,5); // TFI

	bitvec_write_field(dest, wp,0x0,1); // Message escape
	bitvec_write_field(dest, wp,0x0,2); // Medium Access Method: Dynamic Allocation
	bitvec_write_field(dest, wp,0x0,1); // RLC acknowledged mode

	bitvec_write_field(dest, wp,old_downlink,1); // the network establishes no new downlink TBF for the mobile station
	bitvec_write_field(dest, wp,0x80 >> tn,8); // timeslot(s)

	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(dest, wp,ta,6); // TIMING_ADVANCE_VALUE
	bitvec_write_field(dest, wp,0x0,1); // switch TIMING_ADVANCE_INDEX = off

	bitvec_write_field(dest, wp,0x0,1); // switch POWER CONTROL = off
	bitvec_write_field(dest, wp,0x1,1); // Frequency Parameters information elements = present

	bitvec_write_field(dest, wp,tsc,3); // Training Sequence Code (TSC) = 2
	bitvec_write_field(dest, wp,0x0,2); // ARFCN = present
	bitvec_write_field(dest, wp,arfcn,10); // ARFCN

	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,new_tfi,5);// TFI

	bitvec_write_field(dest, wp,0x1,1); // Power Control Parameters IE = present
	bitvec_write_field(dest, wp,0x0,4); // ALPHA power control parameter
	for (i = 0; i < 8; i++)
		bitvec_write_field(dest, wp,(tn == i),1); // switch GAMMA_TN[i] = on or off
	bitvec_write_field(dest, wp,0x0,5); // GAMMA_TN[tn]

	bitvec_write_field(dest, wp,0x0,1); // TBF Starting TIME IE not present
	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
	bitvec_write_field(dest, wp,0x0,1);
}

/* generate uplink ack */
void write_packet_uplink_ack(bitvec * dest, struct gprs_rlcmac_tbf *tbf,
	uint8_t final)
{
	char show_v_n[65];

	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	uint16_t i, bbn;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	char bit;

	LOGP(DRLCMACUL, LOGL_DEBUG, "Sending Ack/Nack for TBF=%d "
		"(final=%d)\n", tbf->tfi, final);

	bitvec_write_field(dest, wp,0x1,2);  // payload
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber (N+13)
	bitvec_write_field(dest, wp,final,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x0,3);  // Uplink state flag
	
	//bitvec_write_field(dest, wp,0x0,1);  // Reduced block sequence number
	//bitvec_write_field(dest, wp,BSN+6,5);  // Radio transaction identifier
	//bitvec_write_field(dest, wp,0x1,1);  // Final segment
	//bitvec_write_field(dest, wp,0x1,1);  // Address control

	//bitvec_write_field(dest, wp,0x0,2);  // Power reduction: 0
	//bitvec_write_field(dest, wp,TFI,5);  // Temporary flow identifier
	//bitvec_write_field(dest, wp,0x1,1);  // Direction

	bitvec_write_field(dest, wp,0x09,6); // MESSAGE TYPE
	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,2);
	bitvec_write_field(dest, wp,tbf->tfi,5); // Uplink TFI
	bitvec_write_field(dest, wp,0x0,1);
	
	bitvec_write_field(dest, wp,0x0,2);  // CS1
	bitvec_write_field(dest, wp,final,1);  // FINAL_ACK_INDICATION
	bitvec_write_field(dest, wp,tbf->dir.ul.v_r,7); // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	for (i = 0, bbn = (tbf->dir.ul.v_r - 64) & mod_sns_half; i < 64;
	     i++, bbn = (bbn + 1) & mod_sns_half) {
	     	bit = tbf->dir.ul.v_n[bbn];
		if (bit == 0)
			bit = ' ';
		show_v_n[i] = bit;
		bitvec_write_field(dest, wp,(bit == 'R'),1);
	}
	show_v_n[64] = '\0';
	LOGP(DRLCMACUL, LOGL_DEBUG, "- V(N): \"%s\" R=Received "
		"N=Not-Received\n", show_v_n);
	bitvec_write_field(dest, wp,0x1,1);  // CONTENTION_RESOLUTION_TLLI = present
	bitvec_write_field(dest, wp,tbf->tlli,8*4);
	bitvec_write_field(dest, wp,0x00,4); //spare
	bitvec_write_field(dest, wp,0x5,4); //0101
}

/* Send Uplink unit-data to SGSN. */
int gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf)
{
	const uint8_t qos_profile = QOS_PROFILE;
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + tbf->llc_index;

	LOGP(DBSSGP, LOGL_NOTICE, "TX: [PCU -> SGSN ] TFI: %u TLLI: 0x%08x DataLen: %u\n", tbf->tfi, tbf->tlli, tbf->llc_index);
	if (!bctx) {
		LOGP(DBSSGP, LOGL_ERROR, "No bctx\n");
		return -EIO;
	}
	//LOGP(DBSSGP, LOGL_NOTICE, " Data = ");
	//for (unsigned i = 0; i < tbf->llc_index; i++)
	//	LOGPC(DBSSGP, LOGL_NOTICE, "%02x ", tbf->llc_frame[i]);
	
	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	msgb_tvlv_push(llc_pdu, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*tbf->llc_index, tbf->llc_frame);
	bssgp_tx_ul_ud(bctx, tbf->tlli, &qos_profile, llc_pdu);

	return 0;
}

