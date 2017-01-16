/* encoding.cpp
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

#include <encoding.h>
#include <gprs_rlcmac.h>
#include <bts.h>
#include <tbf.h>
#include <gprs_debug.h>
#include <egprs_rlc_compression.h>

extern "C" {
#include <osmocom/gprs/protocol/gsm_04_60.h>
}

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <stdbool.h>
#include <errno.h>
#include <string.h>

/* { 0 | 1 < TIMING_ADVANCE_INDEX : bit (4) > } */
static inline bool write_tai(bitvec *dest, unsigned& wp, int8_t tai)
{
	if (tai < 0) { /* No TIMING_ADVANCE_INDEX: */
		bitvec_write_field(dest, wp, 0, 1);
		return false;
	}
	/* TIMING_ADVANCE_INDEX: */
	bitvec_write_field(dest, wp, 1, 1);
	bitvec_write_field(dest, wp, tai, 4);
	return true;
}

/* { 0 | 1 < TIMING_ADVANCE_VALUE : bit (6) > } */
static inline void write_ta(bitvec *dest, unsigned& wp, int8_t ta)
{
	if (ta < 0) /* No TIMING_ADVANCE_VALUE: */
		bitvec_write_field(dest, wp, 0, 1);
	else { /* TIMING_ADVANCE_VALUE: */
		bitvec_write_field(dest, wp, 1, 1);
		bitvec_write_field(dest, wp, ta, 6);
	}
}

/* 3GPP TS 44.060 § 12.12:
   { 0 | 1 < TIMING_ADVANCE_VALUE : bit (6) > }
   { 0 | 1 < TIMING_ADVANCE_INDEX : bit (4) >
           < TIMING_ADVANCE_TIMESLOT_NUMBER : bit (3) > }
 */
static inline void write_ta_ie(bitvec *dest, unsigned& wp,
			       int8_t ta, int8_t tai, uint8_t ts)
{
	write_ta(dest, wp, ta);
	if (write_tai(dest, wp, tai)) /* TIMING_ADVANCE_TIMESLOT_NUMBER: */
		bitvec_write_field(dest, wp, ts, 3);
}

static int write_ia_rest_downlink(
	gprs_rlcmac_dl_tbf *tbf,
	bitvec * dest, unsigned& wp,
	uint8_t polling, bool ta_valid, uint32_t fn,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx)
{
	if (!tbf) {
		LOGP(DRLCMACDL, LOGL_ERROR,
			"Cannot encode DL IMMEDIATE ASSIGNMENT without TBF\n");
		return -EINVAL;
	}
	// GSM 04.08 10.5.2.16 IA Rest Octets
	bitvec_write_field_lh(dest, wp, 3, 2);   // "HH"
	bitvec_write_field(dest, wp, 1, 2);   // "01" Packet Downlink Assignment
	bitvec_write_field(dest, wp,tbf->tlli(),32); // TLLI
	bitvec_write_field(dest, wp,0x1,1);   // switch TFI   : on
	bitvec_write_field(dest, wp,tbf->tfi(),5);   // TFI
	bitvec_write_field(dest, wp,0x0,1);   // RLC acknowledged mode
	if (alpha) {
		bitvec_write_field(dest, wp,0x1,1);   // ALPHA = present
		bitvec_write_field(dest, wp,alpha,4);   // ALPHA
	} else {
		bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
	}
	bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
	bitvec_write_field(dest, wp,polling,1);   // Polling Bit
	bitvec_write_field(dest, wp, ta_valid, 1); // N. B: NOT related to TAI!
	write_tai(dest, wp, ta_idx);
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
	if (tbf->is_egprs_enabled()) {
		/* see GMS 44.018, 10.5.2.16 */
		unsigned int ws_enc = (tbf->m_window.ws() - 64) / 32;
		bitvec_write_field_lh(dest, wp, 1, 1);  // "H"
		bitvec_write_field(dest, wp, ws_enc,5); // EGPRS Window Size
		bitvec_write_field(dest, wp, 0x0,2);    // LINK_QUALITY_MEASUREMENT_MODE
		bitvec_write_field(dest, wp, 0,1);      // BEP_PERIOD2 not present
	}

	return 0;
}

static int write_ia_rest_uplink(
	gprs_rlcmac_ul_tbf *tbf,
	bitvec * dest, unsigned& wp,
	uint8_t usf, uint32_t fn,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx)
{
	OSMO_ASSERT(!tbf || !tbf->is_egprs_enabled());

	// GMS 04.08 10.5.2.37b 10.5.2.16
	bitvec_write_field_lh(dest, wp, 3, 2);    // "HH"
	bitvec_write_field(dest, wp, 0, 2);    // "0" Packet Uplink Assignment
	if (tbf == NULL) {
		bitvec_write_field(dest, wp, 0, 1);    // Block Allocation : Single Block Allocation
		if (alpha) {
			bitvec_write_field(dest, wp,0x1,1);   // ALPHA = present
			bitvec_write_field(dest, wp,alpha,4);   // ALPHA = present
		} else
			bitvec_write_field(dest, wp,0x0,1);   // ALPHA = not present
		bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
		write_tai(dest, wp, ta_idx);
		bitvec_write_field(dest, wp, 1, 1);    // TBF_STARTING_TIME_FLAG
		bitvec_write_field(dest, wp,(fn / (26 * 51)) % 32,5); // T1'
		bitvec_write_field(dest, wp,fn % 51,6);               // T3
		bitvec_write_field(dest, wp,fn % 26,5);               // T2
	} else {
		bitvec_write_field(dest, wp, 1, 1);    // Block Allocation : Not Single Block Allocation
		bitvec_write_field(dest, wp, tbf->tfi(), 5);  // TFI_ASSIGNMENT Temporary Flow Identity
		bitvec_write_field(dest, wp, 0, 1);    // POLLING
		bitvec_write_field(dest, wp, 0, 1);    // ALLOCATION_TYPE: dynamic
		bitvec_write_field(dest, wp, usf, 3);    // USF
		bitvec_write_field(dest, wp, 0, 1);    // USF_GRANULARITY
		bitvec_write_field(dest, wp, 0, 1);   // "0" power control: Not Present
		bitvec_write_field(dest, wp, tbf->current_cs().to_num()-1, 2);    // CHANNEL_CODING_COMMAND 
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
	return 0;
}

static int write_ia_rest_egprs_uplink(
	gprs_rlcmac_ul_tbf *tbf,
	bitvec * dest, unsigned& wp,
	uint8_t usf, uint32_t fn,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx,
	enum ph_burst_type burst_type, uint16_t ra)
{
	unsigned int ws_enc = 0;
	uint8_t extended_ra = 0;

	extended_ra = (ra & 0x1F);

	bitvec_write_field(dest, wp, 1, 2);    /* LH */
	bitvec_write_field(dest, wp, 0, 2);    /* 0 EGPRS Uplink Assignment */
	bitvec_write_field(dest, wp, extended_ra, 5);    /* Extended RA */
	bitvec_write_field(dest, wp, 0, 1);    /* Access technology Request */

	if (tbf == NULL) {

		bitvec_write_field(dest, wp, 0, 1); /* multiblock allocation */

		if (alpha) {
			bitvec_write_field(dest, wp, 0x1, 1); /* ALPHA =yes */
			bitvec_write_field(dest, wp, alpha, 4); /* ALPHA */
		} else {
			bitvec_write_field(dest, wp, 0x0, 1); /* ALPHA = no */
		}

		bitvec_write_field(dest, wp, gamma, 5); /* GAMMA power contrl */
		bitvec_write_field(dest, wp, (fn / (26 * 51)) % 32, 5);/* T1' */
		bitvec_write_field(dest, wp, fn % 51, 6);              /* T3 */
		bitvec_write_field(dest, wp, fn % 26, 5);              /* T2 */
		bitvec_write_field(dest, wp, 0, 2); /* Radio block allocation */

		bitvec_write_field(dest, wp, 0, 1);

	} else {

		ws_enc = (tbf->m_window.ws() - 64) / 32;

		bitvec_write_field(dest, wp, 1, 1);     /* single block alloc */
		bitvec_write_field(dest, wp, tbf->tfi(), 5);/* TFI assignment */
		bitvec_write_field(dest, wp, 0, 1);     /* polling bit */
		bitvec_write_field(dest, wp, 0, 1);     /* constant */
		bitvec_write_field(dest, wp, usf, 3);   /* USF bit */
		bitvec_write_field(dest, wp, 0, 1);     /* USF granularity */
		bitvec_write_field(dest, wp, 0, 1);     /* P0 */
		/* MCS */
		bitvec_write_field(dest, wp, tbf->current_cs().to_num()-1, 4);
		/* tlli channel block */
		bitvec_write_field(dest, wp, tbf->tlli(), 1);
		bitvec_write_field(dest, wp, 0, 1);   /* BEP period present */
		bitvec_write_field(dest, wp, 0, 1);   /* resegmentation */
		bitvec_write_field(dest, wp, ws_enc, 5);/* egprs window_size */

		if (alpha) {
			bitvec_write_field(dest, wp, 0x1, 1);   /* ALPHA =yes */
			bitvec_write_field(dest, wp, alpha, 4); /* ALPHA */
		} else {
			bitvec_write_field(dest, wp, 0x0, 1);   /* ALPHA = no */
		}

		bitvec_write_field(dest, wp, gamma, 5); /* GAMMA power contrl */
		bitvec_write_field(dest, wp, 0, 1); /* TIMING_ADVANCE_INDEX */
		bitvec_write_field(dest, wp, 0, 1); /* TBF_STARTING_TIME_FLAG */
		bitvec_write_field(dest, wp, 0, 1); /* NULL */
	}

	return 0;
}

/*
 * Immediate assignment reject, sent on the CCCH/AGCH
 * see GSM 44.018, 9.1.20 + 10.5.2.30
 */
int Encoding::write_immediate_assignment_reject(
	bitvec *dest, uint16_t ra,
	uint32_t ref_fn,
	enum ph_burst_type burst_type)
{
	unsigned wp = 0;
	int plen;
	int i;

	bitvec_write_field(dest, wp, 0x0, 4);  // Skip Indicator
	bitvec_write_field(dest, wp, 0x6, 4);  // Protocol Discriminator
	bitvec_write_field(dest, wp, 0x3A, 8); // Immediate Assign Message Type

	// feature indicator
	bitvec_write_field(dest, wp, 0x0, 1);      // spare
	bitvec_write_field(dest, wp, 0x0, 1);      // spare
	bitvec_write_field(dest, wp, 0x0, 1);      // no cs
	bitvec_write_field(dest, wp, 0x1, 1);      // implicit detach for PS

	bitvec_write_field(dest, wp, 0x0, 4); // Page Mode
	/*
	 * 9.1.20.2 of 44.018 version 11.7.0 Release 11
	 * Filling of the message
	 * If necessary the request reference information element and the
	 * wait indication information element should be duplicated to
	 * fill the message.
	 * TODO: group rejection for multiple MS
	*/
	for (i = 0; i < 4; i++) {
		//10.5.2.30 Request Reference
		if (((burst_type == GSM_L1_BURST_TYPE_ACCESS_1) ||
			(burst_type == GSM_L1_BURST_TYPE_ACCESS_2))) {
			//9.1.20.2a of 44.018 version 11.7.0 Release 11
			bitvec_write_field(dest, wp, 0x7f, 8);  /* RACH value */
		} else {
			bitvec_write_field(dest, wp, ra, 8);	/* RACH value */
		}

		bitvec_write_field(dest, wp,
					(ref_fn / (26 * 51)) % 32, 5); // T1'
		bitvec_write_field(dest, wp, ref_fn % 51, 6);          // T3
		bitvec_write_field(dest, wp, ref_fn % 26, 5);          // T2

		/* TODO: Make it configurable */
		bitvec_write_field(dest, wp, 20, 8); //Wait Indication 1
	}

	plen = wp / 8;

	if ((wp % 8)) {
		LOGP(DRLCMACUL, LOGL_ERROR, "Length of IMM.ASS.Rej without"
			"rest octets is not multiple of 8 bits, PLEASE FIX!\n");
		return -1;
	}

	// Extended RA
	else if (((burst_type == GSM_L1_BURST_TYPE_ACCESS_1) ||
			(burst_type == GSM_L1_BURST_TYPE_ACCESS_2))) {
		//9.1.20.2a of 44.018 version 11.7.0 Release 11
		uint8_t extended_ra = 0;

		extended_ra = (ra & 0x1F);
		bitvec_write_field(dest, wp, 0x1, 1);
		bitvec_write_field(dest, wp, extended_ra, 5); /* Extended RA */
	} else {
		bitvec_write_field(dest, wp, 0x0, 1);
	}
	bitvec_write_field(dest, wp, 0x0, 1);
	bitvec_write_field(dest, wp, 0x0, 1);
	bitvec_write_field(dest, wp, 0x0, 1);

	return plen;
}

/*
 * Immediate assignment, sent on the CCCH/AGCH
 * see GSM 04.08, 9.1.18 and GSM 44.018, 9.1.18 + 10.5.2.16
 */
int Encoding::write_immediate_assignment(
	struct gprs_rlcmac_tbf *tbf,
	bitvec * dest, uint8_t downlink, uint16_t ra,
	uint32_t ref_fn, uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc,
	uint8_t usf, uint8_t polling, uint32_t fn, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx, enum ph_burst_type burst_type, uint8_t sb)
{
	unsigned wp = 0;
	int plen;
	int rc;

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
	if (((burst_type == GSM_L1_BURST_TYPE_ACCESS_1) ||
		(burst_type == GSM_L1_BURST_TYPE_ACCESS_2))) {
		bitvec_write_field(dest, wp, 0x7f, 8);  /* RACH value */
	} else {
		bitvec_write_field(dest, wp, ra, 8);	/* RACH value */
	}

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
		rc = write_ia_rest_downlink(as_dl_tbf(tbf), dest, wp,
					    polling, gsm48_ta_is_valid(ta), fn,
			alpha, gamma, ta_idx);
	else if (((burst_type == GSM_L1_BURST_TYPE_ACCESS_1) ||
			(burst_type == GSM_L1_BURST_TYPE_ACCESS_2)))
		rc = write_ia_rest_egprs_uplink(as_ul_tbf(tbf), dest, wp,
			usf, fn,
			alpha, gamma, ta_idx, burst_type, ra);
	else
		rc = write_ia_rest_uplink(as_ul_tbf(tbf), dest, wp,
			usf, fn,
			alpha, gamma, ta_idx);

	if (rc < 0) {
		LOGP(DRLCMAC, LOGL_ERROR,
			"Failed to create IMMEDIATE ASSIGMENT (%s) for %s\n",
			downlink ? "downlink" : "uplink",
			tbf ? tbf->name() : "single block allocation");
		return rc;
	}

	return plen;
}

/* generate uplink assignment */
void Encoding::write_packet_uplink_assignment(
	struct gprs_rlcmac_bts *bts,
	bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
	struct gprs_rlcmac_ul_tbf *tbf, uint8_t poll, uint8_t rrbp, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx, int8_t use_egprs)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	uint8_t ts;
	/* timeslot assigned for the Continuous Timing Advance procedure */
	uint8_t ta_ts = 0; /* FIXME: supply it as parameter from caller */

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

	if (!use_egprs) {
		bitvec_write_field(dest, wp,0x0,1); // Message escape
		bitvec_write_field(dest, wp,tbf->current_cs().to_num()-1, 2); // CHANNEL_CODING_COMMAND 
		bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 
		write_ta_ie(dest, wp,tbf->ta(), ta_idx, ta_ts);
	} else { /* EPGRS */
		unsigned int ws_enc = (tbf->m_window.ws() - 64) / 32;
		bitvec_write_field(dest, wp,0x1,1); // Message escape
		bitvec_write_field(dest, wp,0x0,2); // EGPRS message contents
		bitvec_write_field(dest, wp,0x0,1); // No CONTENTION_RESOLUTION_TLLI
		bitvec_write_field(dest, wp,0x0,1); // No COMPACT reduced MA
		bitvec_write_field(dest, wp,tbf->current_cs().to_num()-1, 4); // EGPRS Modulation and Coding IE
		/* 0: no RESEGMENT, 1: Segmentation*/
		bitvec_write_field(dest, wp, 0x1, 1);
		bitvec_write_field(dest, wp,ws_enc,5); // EGPRS Window Size
		bitvec_write_field(dest, wp,0x0,1); // No Access Technologies Request
		bitvec_write_field(dest, wp,0x0,1); // No ARAC RETRANSMISSION REQUEST
		bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 
		bitvec_write_field(dest, wp,0x0,1); // No BEP_PERIOD2
		write_ta_ie(dest, wp,tbf->ta(), ta_idx, ta_ts);
		bitvec_write_field(dest, wp,0x0,1); // No Packet Extended Timing Advance
	}

#if 1
	bitvec_write_field(dest, wp,0x1,1); // Frequency Parameters information elements = present
	bitvec_write_field(dest, wp,tbf->tsc(),3); // Training Sequence Code (TSC)
	bitvec_write_field(dest, wp,0x0,2); // ARFCN = present
	bitvec_write_field(dest, wp,tbf->trx->arfcn,10); // ARFCN
#else
	bitvec_write_field(dest, wp,0x0,1); // Frequency Parameters = off
#endif

	bitvec_write_field(dest, wp,0x1,2); // Dynamic Allocation

	bitvec_write_field(dest, wp,0x0,1); // Extended Dynamic Allocation = off
	bitvec_write_field(dest, wp,0x0,1); // P0 = off

	bitvec_write_field(dest, wp,0x0,1); // USF_GRANULARITY
	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,tbf->tfi(),5);// TFI

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
			bitvec_write_field(dest, wp,tbf->m_usf[ts],3); // USF_TN(i)
			if (alpha || gamma)
				bitvec_write_field(dest, wp,gamma,5);   // GAMMA power control parameter
		} else
			bitvec_write_field(dest, wp,0x0,1); // USF_TN(i): off
	}
	//	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
}


/* generate downlink assignment */
void Encoding::write_packet_downlink_assignment(RlcMacDownlink_t * block,
	bool old_tfi_is_valid, uint8_t old_tfi, uint8_t old_downlink,
	struct gprs_rlcmac_tbf *tbf, uint8_t poll, uint8_t rrbp,
	uint8_t alpha, uint8_t gamma, int8_t ta_idx,
	uint8_t ta_ts, bool use_egprs)
{
	// Packet downlink assignment TS 44.060 11.2.7

	PDA_AdditionsR99_t *pda_r99;

	uint8_t tn;
	unsigned int ws_enc;

	block->PAYLOAD_TYPE = 0x1;  // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = rrbp;  // 0: N+13
	block->SP           = poll; // RRBP field is valid
	block->USF          = 0x0;  // Uplink state flag

	block->u.Packet_Downlink_Assignment.MESSAGE_TYPE = 0x2;  // Packet Downlink Assignment
	block->u.Packet_Downlink_Assignment.PAGE_MODE    = 0x0;  // Normal Paging

	block->u.Packet_Downlink_Assignment.Exist_PERSISTENCE_LEVEL      = 0x0;          // PERSISTENCE_LEVEL: off

	if (old_tfi_is_valid) {
		block->u.Packet_Downlink_Assignment.ID.UnionType                 = 0x0;          // TFI = on
		block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.UnionType    = old_downlink; // 0=UPLINK TFI, 1=DL TFI
		block->u.Packet_Downlink_Assignment.ID.u.Global_TFI.u.UPLINK_TFI = old_tfi;      // TFI
	} else {
		block->u.Packet_Downlink_Assignment.ID.UnionType                 = 0x1;          // TLLI
		block->u.Packet_Downlink_Assignment.ID.u.TLLI                    = tbf->tlli();
	}

	block->u.Packet_Downlink_Assignment.MAC_MODE            = 0x0;          // Dynamic Allocation
	block->u.Packet_Downlink_Assignment.RLC_MODE            = 0x0;          // RLC acknowledged mode
	block->u.Packet_Downlink_Assignment.CONTROL_ACK         = tbf->was_releasing; // NW establishes no new DL TBF for the MS with running timer T3192
	block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION = 0;   // timeslot(s)
	for (tn = 0; tn < 8; tn++) {
		if (tbf->pdch[tn])
			block->u.Packet_Downlink_Assignment.TIMESLOT_ALLOCATION |= 0x80 >> tn;   // timeslot(s)
	}

	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_TIMING_ADVANCE_VALUE = 0x1; // TIMING_ADVANCE_VALUE = on
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_VALUE       = tbf->ta();  // TIMING_ADVANCE_VALUE
	if (ta_idx < 0) {
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x0; // TIMING_ADVANCE_INDEX = off
	} else {
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x1; // TIMING_ADVANCE_INDEX = on
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_INDEX       = ta_idx; // TIMING_ADVANCE_INDEX
		block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.TIMING_ADVANCE_TIMESLOT_NUMBER = ta_ts; // TIMING_ADVANCE_TS
	}

	block->u.Packet_Downlink_Assignment.Exist_P0_and_BTS_PWR_CTRL_MODE = 0x0;   // POWER CONTROL = off

	block->u.Packet_Downlink_Assignment.Exist_Frequency_Parameters     = 0x1;   // Frequency Parameters = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.TSC       = tbf->tsc();   // Training Sequence Code (TSC)
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.UnionType = 0x0;   // ARFCN = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.u.ARFCN   = tbf->trx->arfcn; // ARFCN

	block->u.Packet_Downlink_Assignment.Exist_DOWNLINK_TFI_ASSIGNMENT  = 0x1;     // DOWNLINK TFI ASSIGNMENT = on
	block->u.Packet_Downlink_Assignment.DOWNLINK_TFI_ASSIGNMENT        = tbf->tfi(); // TFI

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
	if (!use_egprs) {
		block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x0; // AdditionsR99 = off
		return;
	}

	ws_enc = (tbf->window()->ws() - 64) / 32;

	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x1; // AdditionsR99 = on
	pda_r99 = &block->u.Packet_Downlink_Assignment.AdditionsR99;
	pda_r99->Exist_EGPRS_Params = 1;
	pda_r99->EGPRS_WindowSize = ws_enc; /* see TS 44.060, table 12.5.2.1 */
	pda_r99->LINK_QUALITY_MEASUREMENT_MODE = 0x0; /* no meas, see TS 44.060, table 11.2.7.2 */
	pda_r99->Exist_BEP_PERIOD2 = 0; /* No extra EGPRS BEP PERIOD */
	pda_r99->Exist_Packet_Extended_Timing_Advance = 0;
	pda_r99->Exist_COMPACT_ReducedMA = 0;
}

/* generate paging request */
int Encoding::write_paging_request(bitvec * dest, uint8_t *ptmsi, uint16_t ptmsi_len)
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

/**
 * The index of the array show_rbb is the bit position inside the rbb
 * (show_rbb[63] relates to BSN ssn-1)
 */
void Encoding::encode_rbb(const char *show_rbb, uint8_t *rbb)
{
	uint8_t rbb_byte = 0;

	// RECEIVE_BLOCK_BITMAP
	for (int i = 0; i < 64; i++) {
		/* Set bit at the appropriate position (see 3GPP TS 04.60 9.1.8.1) */
		if (show_rbb[i] == 'R')
			rbb_byte |= 1<< (7-(i%8));

		if((i%8) == 7) {
			rbb[i/8] = rbb_byte;
			rbb_byte = 0;
		}
	}
}

static void write_packet_ack_nack_desc_gprs(
	struct gprs_rlcmac_bts *bts, bitvec * dest, unsigned& wp,
	gprs_rlc_ul_window *window, bool is_final)
{
	char rbb[65];

	window->update_rbb(rbb);

	rbb[64] = 0;
	LOGP(DRLCMACUL, LOGL_DEBUG, "- V(N): \"%s\" R=Received "
		"I=Invalid\n", rbb);

	bitvec_write_field(dest, wp, is_final, 1); // FINAL_ACK_INDICATION
	bitvec_write_field(dest, wp, window->ssn(), 7); // STARTING_SEQUENCE_NUMBER

	for (int i = 0; i < 64; i++) {
		/* Set bit at the appropriate position (see 3GPP TS 04.60 9.1.8.1) */
		bool is_ack = (rbb[i] == 'R');
		bitvec_write_field(dest, wp, is_ack, 1);
	}
}

static void write_packet_uplink_ack_gprs(
	struct gprs_rlcmac_bts *bts, bitvec * dest, unsigned& wp,
	struct gprs_rlcmac_ul_tbf *tbf, bool is_final)
{

	bitvec_write_field(dest, wp, tbf->current_cs().to_num() - 1, 2); // CHANNEL_CODING_COMMAND
	write_packet_ack_nack_desc_gprs(bts, dest, wp, &tbf->m_window, is_final);

	bitvec_write_field(dest, wp, 1, 1); // 1: have CONTENTION_RESOLUTION_TLLI
	bitvec_write_field(dest, wp, tbf->tlli(), 32); // CONTENTION_RESOLUTION_TLLI

	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Packet Timing Advance
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Power Control Parameters
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Extension Bits
	bitvec_write_field(dest, wp, 0, 1); // fixed 0
	bitvec_write_field(dest, wp, 1, 1); // 1: have Additions R99
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Packet Extended Timing Advance
	bitvec_write_field(dest, wp, 1, 1); // TBF_EST (enabled)
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have REL 5
};

static void write_packet_ack_nack_desc_egprs(
	struct gprs_rlcmac_bts *bts, bitvec * dest, unsigned& wp,
	gprs_rlc_ul_window *window, bool is_final, unsigned& rest_bits)
{
	unsigned int urbb_len = 0;
	uint8_t crbb_len = 0;
	uint8_t len;
	bool bow = true;
	bool eow = true;
	int ssn = window->mod_sns(window->v_q() + 1);
	unsigned int num_blocks = window->mod_sns(window->v_r() - window->v_q());
	int esn_crbb = window->mod_sns(ssn - 1);
	static  uint8_t rbb[RLC_EGPRS_MAX_WS] = {'\0'};
	uint8_t iter = 0;
	int is_compressed = 0;
	bool try_compression = false;
	uint8_t ucmp_bmplen;
	uint8_t crbb_bitmap[23] = {'\0'};
	bitvec ucmp_vec;
	bitvec crbb_vec;
	uint8_t uclen_crbb = 0;
	bool len_coded = true;
	uint8_t crbb_start_clr_code;
	uint8_t i;
#if 0
	/* static size of 16 bits*/
	 ..0. .... = ACKNACK:  (Union)
        Desc

            ...0 .... = FINAL_ACK_INDICATION: False

            .... 1... = BEGINNING_OF_WINDOW: 1

            .... .1.. = END_OF_WINDOW: 1

            .... ..10  0101 0001  1... .... = STARTING_SEQUENCE_NUMBER: 1187

            .0.. .... = CRBB Exist: 0
#endif
	rest_bits -= 16;

	if (num_blocks > 0)
		/* V(Q) is NACK and omitted -> SSN = V(Q) + 1 */
		num_blocks -= 1;

	if (num_blocks > window->ws())
		num_blocks = window->ws();
	/* Try Compression  as number of blocks does not fit */
	if (num_blocks > rest_bits) {
		try_compression = true;
	}
	if (try_compression == true) {
		ucmp_bmplen = window->update_egprs_rbb(rbb);
		ucmp_vec.data = rbb;
		ucmp_vec.cur_bit = ucmp_bmplen;
		ucmp_vec.data_len = 127;
		crbb_vec.data = crbb_bitmap;
		crbb_vec.cur_bit = 0;
		crbb_vec.data_len = 127;
		LOGP(DRLCMACUL, LOGL_DEBUG,
		"rest_bits=%d uncompressed len %d and uncompressed bitmap = %s\n",
		 rest_bits, ucmp_bmplen,
		osmo_hexdump(ucmp_vec.data, (ucmp_bmplen+7)/8));

		is_compressed = egprs_compress::compress_rbb(&ucmp_vec, /* Uncompressed bitmap*/
			&crbb_vec, /*Compressed bitmap vector */
			&uclen_crbb,
			(rest_bits - 16));/* CRBBlength:7 colourcode:1 dissector length:8*/
		LOGP(DRLCMACUL, LOGL_DEBUG,
		"the ucmp len=%d uclen_crbb=%d num_blocks=%d crbb length %d, "
		"and the CRBB bitmap  = %s\n",
		ucmp_bmplen, uclen_crbb, num_blocks, crbb_vec.cur_bit,
		osmo_hexdump(crbb_bitmap, (crbb_vec.cur_bit+7)/8));
		crbb_len = crbb_vec.cur_bit;
	}

	if (is_compressed == 0) {
		/* length field takes 8 bits*/
		if (num_blocks > rest_bits - 8) {
			eow = false;
			urbb_len = rest_bits;
			len_coded = false;
		} else if (num_blocks == rest_bits) {
			urbb_len = rest_bits;
			len_coded = false;
		} else
			urbb_len = num_blocks;

		len = urbb_len + 15;
	} else {
		if (num_blocks > uclen_crbb) {
			eow = false;
			urbb_len = num_blocks - uclen_crbb;
		}
		/* Union bit takes 1 bit */
		/* Other fields in descr of compresed bitmap takes 23 bits
		 * -8 = CRBB_STARTING_COLOR_CODE + CRBB_LENGTH */
		if (urbb_len > (rest_bits - crbb_len - 8)) {
			eow = false;
			len_coded = false;
			urbb_len = rest_bits - crbb_len - 8;
		/* -16 =  ACKNACK Dissector length + CRBB_STARTING_COLOR_CODE + CRBB_LENGTH */
		} else if (urbb_len > (rest_bits - crbb_len - 16)) {
			eow = false;
			len_coded = false;
			urbb_len = rest_bits - crbb_len - 16;
		}
		len = urbb_len + crbb_len + 23;
	}

	/* EGPRS Ack/Nack Description IE */
	if (len_coded == false) {
		bitvec_write_field(dest, wp, 0, 1); // 0: don't have length
	} else {
		bitvec_write_field(dest, wp, 1, 1); // 1: have length
		bitvec_write_field(dest, wp, len, 8); // length
	}

	bitvec_write_field(dest, wp, is_final, 1); // FINAL_ACK_INDICATION
	bitvec_write_field(dest, wp, bow, 1); // BEGINNING_OF_WINDOW
	bitvec_write_field(dest, wp, eow, 1); // END_OF_WINDOW
	bitvec_write_field(dest, wp, ssn, 11); // STARTING_SEQUENCE_NUMBER
	if (is_compressed) {
		bitvec_write_field(dest, wp, 1, 1); // CRBB_Exist
		bitvec_write_field(dest, wp, crbb_len, 7); // CRBB_LENGTH
		crbb_start_clr_code = (0x80 & ucmp_vec.data[0])>>7;
		bitvec_write_field(dest, wp, crbb_start_clr_code, 1); // CRBB_clr_code
		LOGP(DRLCMACUL, LOGL_DEBUG,
			"EGPRS CRBB, crbb_len = %d, crbb_start_clr_code = %d\n",
			crbb_len, crbb_start_clr_code);
		while (crbb_len != 0) {
			if (crbb_len > 8) {
				bitvec_write_field(dest, wp, crbb_bitmap[iter], 8);
				crbb_len = crbb_len - 8;
				iter++;
			} else {
				bitvec_write_field(dest, wp, crbb_bitmap[iter], crbb_len);
				crbb_len = 0;
			}
		}
		esn_crbb = window->mod_sns(esn_crbb + uclen_crbb);
	} else {
		bitvec_write_field(dest, wp, 0, 1); // CRBB_Exist
	}
	LOGP(DRLCMACUL, LOGL_DEBUG,
		"EGPRS URBB, urbb len = %d, SSN = %d, ESN_CRBB = %d, "
		"len present = %s,desc len = %d, "
		"SNS = %d, WS = %d, V(Q) = %d, V(R) = %d%s%s\n",
		urbb_len, ssn, esn_crbb, len_coded ? "yes" : "No" , len,
		window->sns(), window->ws(), window->v_q(), window->v_r(),
		bow ? ", BOW" : "", eow ? ", EOW" : "");

	for (i = urbb_len; i > 0; i--) {
		/* Set bit at the appropriate position (see 3GPP TS 04.60 12.3.1) */
		bool is_ack = window->m_v_n.is_received(esn_crbb + i);
		bitvec_write_field(dest, wp, is_ack, 1);
	}
}

static void write_packet_uplink_ack_egprs(
	struct gprs_rlcmac_bts *bts, bitvec * dest, unsigned& wp,
	struct gprs_rlcmac_ul_tbf *tbf, bool is_final)
{
	bitvec_write_field(dest, wp, 0, 2); // fixed 00
	/* CHANNEL_CODING_COMMAND */
	bitvec_write_field(dest, wp,
		tbf->current_cs().to_num() - 1, 4);
	/* 0: no RESEGMENT, 1: Segmentation*/
	bitvec_write_field(dest, wp, 1, 1);
	bitvec_write_field(dest, wp, 1, 1); // PRE_EMPTIVE_TRANSMISSION, TODO: This resembles GPRS, change it?
	bitvec_write_field(dest, wp, 0, 1); // 0: no PRR_RETRANSMISSION_REQUEST, TODO: clarify
	bitvec_write_field(dest, wp, 0, 1); // 0: no ARAC_RETRANSMISSION_REQUEST, TODO: clarify
	bitvec_write_field(dest, wp, 1, 1); // 1: have CONTENTION_RESOLUTION_TLLI
	bitvec_write_field(dest, wp, tbf->tlli(), 32); // CONTENTION_RESOLUTION_TLLI
	bitvec_write_field(dest, wp, 1, 1); // TBF_EST (enabled)
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Packet Timing Advance
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Packet Extended Timing Advance
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Power Control Parameters
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have Extension Bits

	/* -2 for last bit 0 mandatory and REL5 not supported */
	unsigned bits_ack_nack = dest->data_len * 8 - wp - 2;
	write_packet_ack_nack_desc_egprs(bts, dest, wp, &tbf->m_window, is_final, bits_ack_nack);

	bitvec_write_field(dest, wp, 0, 1); // fixed 0
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have REL 5
};

void Encoding::write_packet_uplink_ack(
	struct gprs_rlcmac_bts *bts, bitvec * dest,
	struct gprs_rlcmac_ul_tbf *tbf, bool is_final,
	uint8_t rrbp)
{
	unsigned wp = 0;

	LOGP(DRLCMACUL, LOGL_DEBUG, "Encoding Ack/Nack for %s "
		"(final=%d)\n", tbf_name(tbf), is_final);

	bitvec_write_field(dest, wp, 0x1, 2);  // Payload Type
	bitvec_write_field(dest, wp, rrbp, 2);  // Uplink block with TDMA framenumber
	bitvec_write_field(dest, wp, is_final, 1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp, 0x0, 3);  // Uplink state flag
	bitvec_write_field(dest, wp, 0x9, 6);  // MESSAGE TYPE Uplink Ack/Nack
	bitvec_write_field(dest, wp, 0x0, 2);  // Page Mode

	bitvec_write_field(dest, wp, 0x0, 2);  // fixed 00
	bitvec_write_field(dest, wp, tbf->tfi(), 5);  // Uplink TFI

	if (tbf->is_egprs_enabled()) {
		/* PU_AckNack_EGPRS = on */
		bitvec_write_field(dest, wp, 1, 1);  // 1: EGPRS
		write_packet_uplink_ack_egprs(bts, dest, wp, tbf, is_final);
	} else {
		/* PU_AckNack_GPRS = on */
		bitvec_write_field(dest, wp, 0, 1);  // 0: GPRS
		write_packet_uplink_ack_gprs(bts, dest, wp, tbf, is_final);
	}

	LOGP(DRLCMACUL, LOGL_DEBUG,
		"Uplink Ack/Nack bit count %d, max %d, message = %s\n",
		wp, dest->data_len * 8,
		osmo_hexdump(dest->data, dest->data_len));
}

unsigned Encoding::write_packet_paging_request(bitvec * dest)
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

unsigned Encoding::write_repeated_page_info(bitvec * dest, unsigned& wp, uint8_t len,
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

int Encoding::rlc_write_dl_data_header(const struct gprs_rlc_data_info *rlc,
	uint8_t *data)
{
	struct gprs_rlc_dl_header_egprs_1 *egprs1;
	struct gprs_rlc_dl_header_egprs_2 *egprs2;
	struct gprs_rlc_dl_header_egprs_3 *egprs3;
	struct rlc_dl_header *gprs;
	unsigned int e_fbi_header;
	GprsCodingScheme cs = rlc->cs;
	unsigned int offs;
	unsigned int bsn_delta;

	switch(cs.headerTypeData()) {
	case GprsCodingScheme::HEADER_GPRS_DATA:
		gprs = static_cast<struct rlc_dl_header *>
			((void *)data);

		gprs->usf   = rlc->usf;
		gprs->s_p   = rlc->es_p != 0 ? 1 : 0;
		gprs->rrbp  = rlc->rrbp;
		gprs->pt    = 0;
		gprs->tfi   = rlc->tfi;
		gprs->pr    = rlc->pr;

		gprs->fbi   = rlc->block_info[0].cv == 0;
		gprs->e     = rlc->block_info[0].e;
		gprs->bsn   = rlc->block_info[0].bsn;
		break;

	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1:
		egprs1 = static_cast<struct gprs_rlc_dl_header_egprs_1 *>
			((void *)data);

		egprs1->usf    = rlc->usf;
		egprs1->es_p   = rlc->es_p;
		egprs1->rrbp   = rlc->rrbp;
		egprs1->tfi_hi = rlc->tfi >> 0; /* 1 bit LSB */
		egprs1->tfi_lo = rlc->tfi >> 1; /* 4 bits */
		egprs1->pr     = rlc->pr;
		egprs1->cps    = rlc->cps;

		egprs1->bsn1_hi  = rlc->block_info[0].bsn >> 0; /* 2 bits LSB */
		egprs1->bsn1_mid = rlc->block_info[0].bsn >> 2; /* 8 bits */
		egprs1->bsn1_lo  = rlc->block_info[0].bsn >> 10; /* 1 bit */

		bsn_delta = (rlc->block_info[1].bsn - rlc->block_info[0].bsn) &
			(RLC_EGPRS_SNS - 1);

		egprs1->bsn2_hi = bsn_delta >> 0; /* 7 bits LSB */
		egprs1->bsn2_lo = bsn_delta >> 7; /* 3 bits */

		/* first FBI/E header */
		e_fbi_header   = rlc->block_info[0].e       ? 0x01 : 0;
		e_fbi_header  |= rlc->block_info[0].cv == 0 ? 0x02 : 0; /* FBI */
		offs = rlc->data_offs_bits[0] / 8;
		OSMO_ASSERT(rlc->data_offs_bits[0] % 8 == 2);
		e_fbi_header <<= 0;
		data[offs] = (data[offs] & 0b11111100) | e_fbi_header;

		/* second FBI/E header */
		e_fbi_header   = rlc->block_info[1].e       ? 0x01 : 0;
		e_fbi_header  |= rlc->block_info[1].cv == 0 ? 0x02 : 0; /* FBI */
		offs = rlc->data_offs_bits[1] / 8;
		OSMO_ASSERT(rlc->data_offs_bits[1] % 8 == 4);
		e_fbi_header <<= 2;
		data[offs] = (data[offs] & 0b11110011) | e_fbi_header;
		break;

	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2:
		egprs2 = static_cast<struct gprs_rlc_dl_header_egprs_2 *>
			((void *)data);

		egprs2->usf    = rlc->usf;
		egprs2->es_p   = rlc->es_p;
		egprs2->rrbp   = rlc->rrbp;
		egprs2->tfi_hi = rlc->tfi >> 0; /* 1 bit LSB */
		egprs2->tfi_lo = rlc->tfi >> 1; /* 4 bits */
		egprs2->pr     = rlc->pr;
		egprs2->cps    = rlc->cps;

		egprs2->bsn1_hi  = rlc->block_info[0].bsn >> 0; /* 2 bits LSB */
		egprs2->bsn1_mid = rlc->block_info[0].bsn >> 2; /* 8 bits */
		egprs2->bsn1_lo  = rlc->block_info[0].bsn >> 10; /* 1 bit */

		e_fbi_header   = rlc->block_info[0].e       ? 0x01 : 0;
		e_fbi_header  |= rlc->block_info[0].cv == 0 ? 0x02 : 0; /* FBI */
		offs = rlc->data_offs_bits[0] / 8;
		OSMO_ASSERT(rlc->data_offs_bits[0] % 8 == 6);
		e_fbi_header <<= 4;
		data[offs] = (data[offs] & 0b11001111) | e_fbi_header;
		break;

	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3:
		egprs3 = static_cast<struct gprs_rlc_dl_header_egprs_3 *>
			((void *)data);

		egprs3->usf    = rlc->usf;
		egprs3->es_p   = rlc->es_p;
		egprs3->rrbp   = rlc->rrbp;
		egprs3->tfi_hi = rlc->tfi >> 0; /* 1 bit LSB */
		egprs3->tfi_lo = rlc->tfi >> 1; /* 4 bits */
		egprs3->pr     = rlc->pr;
		egprs3->cps    = rlc->cps;

		egprs3->bsn1_hi  = rlc->block_info[0].bsn >> 0; /* 2 bits LSB */
		egprs3->bsn1_mid = rlc->block_info[0].bsn >> 2; /* 8 bits */
		egprs3->bsn1_lo  = rlc->block_info[0].bsn >> 10; /* 1 bit */

		egprs3->spb    = rlc->block_info[0].spb;

		e_fbi_header   = rlc->block_info[0].e       ? 0x01 : 0;
		e_fbi_header  |= rlc->block_info[0].cv == 0 ? 0x02 : 0; /* FBI */
		offs = rlc->data_offs_bits[0] / 8;
		OSMO_ASSERT(rlc->data_offs_bits[0] % 8 == 1);
		e_fbi_header <<= 7;
		data[offs-1] = (data[offs-1] & 0b01111111) | (e_fbi_header >> 0);
		data[offs]   = (data[offs]   & 0b11111110) | (e_fbi_header >> 8);
		break;

	default:
		LOGP(DRLCMACDL, LOGL_ERROR,
			"Encoding of uplink %s data blocks not yet supported.\n",
			cs.name());
		return -ENOTSUP;
	};

	return 0;
}

/**
 * \brief Copy LSB bitstream RLC data block from byte aligned buffer.
 *
 * Note that the bitstream is encoded in LSB first order, so the two octets
 * 654321xx xxxxxx87 contain the octet 87654321 starting at bit position 3
 * (LSB has bit position 1). This is a different order than the one used by
 * CSN.1.
 *
 * \param data_block_idx  The block index, 0..1 for header type 1, 0 otherwise
 * \param src     A pointer to the start of the RLC block (incl. the header)
 * \param buffer  A data area of a least the size of the RLC block
 * \returns  the number of bytes copied
 */
unsigned int Encoding::rlc_copy_from_aligned_buffer(
	const struct gprs_rlc_data_info *rlc,
	unsigned int data_block_idx,
	uint8_t *dst, const uint8_t *buffer)
{
	unsigned int hdr_bytes;
	unsigned int extra_bits;
	unsigned int i;

	uint8_t c, last_c;
	const uint8_t *src;
	const struct gprs_rlc_data_block_info *rdbi;

	OSMO_ASSERT(data_block_idx < rlc->num_data_blocks);
	rdbi = &rlc->block_info[data_block_idx];

	hdr_bytes = rlc->data_offs_bits[data_block_idx] / 8;
	extra_bits = (rlc->data_offs_bits[data_block_idx] % 8);

	if (extra_bits == 0) {
		/* It is aligned already */
		memmove(dst + hdr_bytes, buffer, rdbi->data_len);
		return rdbi->data_len;
	}

	src = buffer;
	dst = dst + hdr_bytes;
	last_c = *dst << (8 - extra_bits);

	for (i = 0; i < rdbi->data_len; i++) {
		c = src[i];
		*(dst++) = (last_c >> (8 - extra_bits)) | (c << extra_bits);
		last_c = c;
	}

	/* overwrite the lower extra_bits */
	*dst = (*dst & (0xff << extra_bits)) | (last_c >> (8 - extra_bits));

	return rdbi->data_len;
}

/*!
 * \brief (GPRS) put llc pdu into an rlc/mac block. fragment the llc pdu if needed
 * \param rdbi rlc/mac block info
 * \param llc llc pdu
 * \param offset given offset within the rlc/mac block
 * \param num_chunks count the chunks (llc pdu data) within rlc/mac
 * \param data_block buffer holds rlc/mac data
 * \param is_final if this is the last rlc/mac within a TBF
 * \param count_payload if not NULL save the written size of payload in bytes into it
 * \return the state of the rlc/mac like if there is more space for another chunk
 */
static Encoding::AppendResult rlc_data_to_dl_append_gprs(
	struct gprs_rlc_data_block_info *rdbi,
	gprs_llc *llc, int *offset, int *num_chunks,
	uint8_t *data_block, bool is_final, int *count_payload)
{
	int chunk;
	int space;
	struct rlc_li_field *li;
	uint8_t *delimiter, *data, *e_pointer;

	data = data_block + *offset;
	delimiter = data_block + *num_chunks;
	e_pointer = (*num_chunks ? delimiter - 1 : NULL);

	chunk = llc->chunk_size();
	space = rdbi->data_len - *offset;

	/* if chunk will exceed block limit */
	if (chunk > space) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
			"larger than space (%d) left in block: copy "
			"only remaining space, and we are done\n",
			chunk, space);
		/* block is filled, so there is no extension */
		if (e_pointer)
			*e_pointer |= 0x01;
		/* fill only space */
		llc->consume(data, space);
		if (count_payload)
			*count_payload = space;
		/* return data block as message */
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return Encoding::AR_NEED_MORE_BLOCKS;
	}
	/* if FINAL chunk would fit precisely in space left */
	if (chunk == space && is_final)
	{
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
			"would exactly fit into space (%d): because "
			"this is a final block, we don't add length "
			"header, and we are done\n", chunk, space);
		/* block is filled, so there is no extension */
		if (e_pointer)
			*e_pointer |= 0x01;
		/* fill space */
		llc->consume(data, space);
		if (count_payload)
			*count_payload = space;
		*offset = rdbi->data_len;
		(*num_chunks)++;
		rdbi->cv = 0;
		return Encoding::AR_COMPLETED_BLOCK_FILLED;
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
		(*offset)++;
		space--;
		/* add LI with 0 length */
		li = (struct rlc_li_field *)delimiter;
		li->e = 1; /* not more extension */
		li->m = 0; /* shall be set to 0, in case of li = 0 */
		li->li = 0; /* chunk fills the complete space */
		rdbi->e = 0; /* 0: extensions present */
		// no need to set e_pointer nor increase delimiter
		/* fill only space, which is 1 octet less than chunk */
		llc->consume(data, space);
		if (count_payload)
			*count_payload = space;
		/* return data block as message */
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return Encoding::AR_NEED_MORE_BLOCKS;
	}

	LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d is less "
		"than remaining space (%d): add length header to "
		"to delimit LLC frame\n", chunk, space);
	/* the LLC frame chunk ends in this block */
	/* make space for delimiter */
	if (delimiter != data)
		memmove(delimiter + 1, delimiter, data - delimiter);
	data++;
	(*offset)++;
	space--;
	/* add LI to delimit frame */
	li = (struct rlc_li_field *)delimiter;
	li->e = 0; /* Extension bit, maybe set later */
	li->m = 0; /* will be set later, if there is more LLC data */
	li->li = chunk; /* length of chunk */
	rdbi->e = 0; /* 0: extensions present */
	(*num_chunks)++;
	/* copy (rest of) LLC frame to space and reset later */
	llc->consume(data, chunk);
	if (count_payload)
		*count_payload = chunk;
	data += chunk;
	space -= chunk;
	(*offset) += chunk;
	/* if we have more data and we have space left */
	if (space > 0 && !is_final) {
		li->m = 1; /* we indicate more frames to follow */
		return Encoding::AR_COMPLETED_SPACE_LEFT;
	}
	/* if we don't have more LLC frames */
	if (is_final) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Final block, so we "
			"done.\n");
		li->e = 1; /* we cannot extend */
		rdbi->cv = 0;
		return Encoding::AR_COMPLETED_BLOCK_FILLED;
	}
	/* we have no space left */
	LOGP(DRLCMACDL, LOGL_DEBUG, "-- No space left, so we are "
		"done.\n");
	li->e = 1; /* we cannot extend */
	return Encoding::AR_COMPLETED_BLOCK_FILLED;
}

/*!
 * \brief (EGPRS) put llc pdu into an rlc/mac block. fragment the llc pdu if needed
 * \param rdbi rlc/mac block info
 * \param llc llc pdu
 * \param offset given offset within the rlc/mac block
 * \param num_chunks count the chunks (llc pdu data) within rlc/mac
 * \param data_block buffer holds rlc/mac data
 * \param is_final if this is the last rlc/mac within a TBF
 * \param count_payload if not NULL save the written size of payload in bytes into it
 * \return the state of the rlc/mac like if there is more space for another chunk
 */
static Encoding::AppendResult rlc_data_to_dl_append_egprs(
	struct gprs_rlc_data_block_info *rdbi,
	gprs_llc *llc, int *offset, int *num_chunks,
	uint8_t *data_block,
	bool is_final, int *count_payload)
{
	int chunk;
	int space;
	struct rlc_li_field_egprs *li;
	struct rlc_li_field_egprs *prev_li;
	uint8_t *delimiter, *data;

	data = data_block + *offset;
	delimiter = data_block + *num_chunks;
	prev_li = (struct rlc_li_field_egprs *)
		(*num_chunks ? delimiter - 1 : NULL);

	chunk = llc->chunk_size();
	space = rdbi->data_len - *offset;

	/* if chunk will exceed block limit */
	if (chunk > space) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
			"larger than space (%d) left in block: copy "
			"only remaining space, and we are done\n",
			chunk, space);
		/* fill only space */
		llc->consume(data, space);
		if (count_payload)
			*count_payload = space;
		/* return data block as message */
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return Encoding::AR_NEED_MORE_BLOCKS;
	}
	/* if FINAL chunk would fit precisely in space left */
	if (chunk == space && is_final)
	{
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
			"would exactly fit into space (%d): because "
			"this is a final block, we don't add length "
			"header, and we are done\n", chunk, space);
		/* fill space */
		llc->consume(data, space);
		if (count_payload)
			*count_payload = space;
		*offset = rdbi->data_len;
		(*num_chunks)++;
		rdbi->cv = 0;
		return Encoding::AR_COMPLETED_BLOCK_FILLED;
	}
	/* if chunk would fit exactly in space left */
	if (chunk == space) {
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d "
			"would exactly fit into space (%d): just copy "
			"it, and we are done. The next block will have "
			"to start with an empty chunk\n",
			chunk, space);
		/* fill space */
		llc->consume(data, space);
		if (count_payload)
			*count_payload = space;
		*offset = rdbi->data_len;
		(*num_chunks)++;
		return Encoding::AR_NEED_MORE_BLOCKS;
	}

	LOGP(DRLCMACDL, LOGL_DEBUG, "-- Chunk with length %d is less "
		"than remaining space (%d): add length header to "
		"to delimit LLC frame\n", chunk, space);
	/* the LLC frame chunk ends in this block */
	/* make space for delimiter */

	if (delimiter != data)
		memmove(delimiter + 1, delimiter, data - delimiter);

	data      += 1;
	(*offset) += 1;
	space     -= 1;
	/* add LI to delimit frame */
	li = (struct rlc_li_field_egprs *)delimiter;
	li->e = 1; /* Extension bit, maybe set later */
	li->li = chunk; /* length of chunk */
	/* tell previous extension header about the new one */
	if (prev_li)
		prev_li->e = 0;
	rdbi->e = 0; /* 0: extensions present */
	delimiter++;
	prev_li = li;
	(*num_chunks)++;
	/* copy (rest of) LLC frame to space and reset later */
	llc->consume(data, chunk);
	if (count_payload)
		*count_payload = chunk;
	data += chunk;
	space -= chunk;
	(*offset) += chunk;
	/* if we have more data and we have space left */
	if (space > 0) {
		if (!is_final)
			return Encoding::AR_COMPLETED_SPACE_LEFT;

		/* we don't have more LLC frames */
		/* We will have to add another chunk with filling octets */
		LOGP(DRLCMACDL, LOGL_DEBUG,
			"-- There is remaining space (%d): add filling byte chunk\n",
			space);

		if (delimiter != data)
			memmove(delimiter + 1, delimiter, data - delimiter);

		data      += 1;
		(*offset) += 1;
		space     -= 1;

		/* set filling bytes extension */
		li = (struct rlc_li_field_egprs *)delimiter;
		li->e = 1;
		li->li = 127;

		/* tell previous extension header about the new one */
		if (prev_li)
			prev_li->e = 0;

		delimiter++;
		(*num_chunks)++;

		rdbi->cv = 0;

		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Final block, so we "
			"are done.\n");

		*offset = rdbi->data_len;
		return Encoding::AR_COMPLETED_BLOCK_FILLED;
	}

	if (is_final) {
		/* we don't have more LLC frames */
		LOGP(DRLCMACDL, LOGL_DEBUG, "-- Final block, so we "
			"are done.\n");
		rdbi->cv = 0;
		return Encoding::AR_COMPLETED_BLOCK_FILLED;
	}

	/* we have no space left */
	LOGP(DRLCMACDL, LOGL_DEBUG, "-- No space left, so we are "
		"done.\n");
	return Encoding::AR_COMPLETED_BLOCK_FILLED;
}

/*!
 * \brief Encoding::rlc_data_to_dl_append
 * \param rdbi rlc/mac block info
 * \param cs the coding scheme to use
 * \param llc llc pdu
 * \param offset given offset within the rlc/mac block
 * \param num_chunks count the chunks (llc pdu data) within rlc/mac
 * \param data_block buffer holds rlc/mac data
 * \param is_final if this is the last rlc/mac within a TBF
 * \param count_payload if not NULL save the written size of payload in bytes into it
 * \return the state of the rlc/mac like if there is more space for another chunk
 */
Encoding::AppendResult Encoding::rlc_data_to_dl_append(
	struct gprs_rlc_data_block_info *rdbi, GprsCodingScheme cs,
	gprs_llc *llc, int *offset, int *num_chunks,
	uint8_t *data_block, bool is_final, int *count_payload)
{
	if (cs.isGprs())
		return rlc_data_to_dl_append_gprs(rdbi,
			llc, offset, num_chunks, data_block, is_final,
			count_payload);

	if (cs.isEgprs())
		return rlc_data_to_dl_append_egprs(rdbi,
			llc, offset, num_chunks, data_block, is_final,
			count_payload);

	LOGP(DRLCMACDL, LOGL_ERROR, "%s data block encoding not implemented\n",
		cs.name());

	return AR_NEED_MORE_BLOCKS;
}

/*
 * Refer 44.060 version 7.27.0 Release 7
 * section 7.1.3.2.1 On receipt of a PACKET RESOURCE REQUEST message
 * 8.1.2.5 Establishment of uplink TBF
 */
void Encoding::write_packet_access_reject(
	bitvec * dest, uint32_t tlli)
{
	unsigned wp = 0;

	bitvec_write_field(dest, wp, 0x1, 2);  // Payload Type
	bitvec_write_field(dest, wp, 0x0, 2);  // Uplink block with TDMA FN
	bitvec_write_field(dest, wp, 0, 1);  // No Polling Bit
	bitvec_write_field(dest, wp, 0x0, 3);  // Uplink state flag
	bitvec_write_field(dest, wp,
				MT_PACKET_ACCESS_REJECT, 6);  // MESSAGE TYPE
	bitvec_write_field(dest, wp, 0, 2); // fixed 00
	bitvec_write_field(dest, wp, 0x0, 1);  //  TLLI / G-RNTI : bit (32)
	bitvec_write_field(dest, wp, tlli, 32); // CONTENTION_RESOLUTION_TLLI
	bitvec_write_field(dest, wp, 1, 1);  //  WAIT_INDICATION size in seconds
	/* TODO: make it configurable */
	bitvec_write_field(dest, wp, 5, 8);  //  WAIT_INDICATION value
	bitvec_write_field(dest, wp, 0, 1);  //  WAIT_INDICATION size in seconds
}
