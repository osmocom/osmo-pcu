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

#include <errno.h>
#include <string.h>

// GSM 04.08 9.1.18 Immediate assignment
int Encoding::write_immediate_assignment(
	struct gprs_rlcmac_bts *bts,
	bitvec * dest, uint8_t downlink, uint8_t ra,
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
void Encoding::write_packet_uplink_assignment(
	struct gprs_rlcmac_bts *bts,
	bitvec * dest, uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
	struct gprs_rlcmac_ul_tbf *tbf, uint8_t poll, uint8_t alpha,
	uint8_t gamma, int8_t ta_idx, int8_t use_egprs)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
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

	if (!use_egprs) {
		bitvec_write_field(dest, wp,0x0,1); // Message escape
		bitvec_write_field(dest, wp,tbf->current_cs().to_num()-1, 2); // CHANNEL_CODING_COMMAND 
		bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 
		bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
		bitvec_write_field(dest, wp,tbf->ta(),6); // TIMING_ADVANCE_VALUE
		if (ta_idx < 0) {
			bitvec_write_field(dest, wp,0x0,1);   // switch TIMING_ADVANCE_INDEX = off
		} else {
			bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
			bitvec_write_field(dest, wp,ta_idx,4);   // TIMING_ADVANCE_INDEX
		}

	} else { /* EPGRS */
		bitvec_write_field(dest, wp,0x1,1); // Message escape
		bitvec_write_field(dest, wp,0x0,2); // EGPRS message contents
		bitvec_write_field(dest, wp,0x0,1); // No CONTENTION_RESOLUTION_TLLI
		bitvec_write_field(dest, wp,0x0,1); // No COMPACT reduced MA
		bitvec_write_field(dest, wp,tbf->current_cs().to_num()-1, 4); // EGPRS Modulation and Coding IE
		bitvec_write_field(dest, wp,0x0,1); // No RESEGMENT
		bitvec_write_field(dest, wp,0x0,5); // EGPRS Window Size = 64
		bitvec_write_field(dest, wp,0x0,1); // No Access Technologies Request
		bitvec_write_field(dest, wp,0x0,1); // No ARAC RETRANSMISSION REQUEST
		bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 
		bitvec_write_field(dest, wp,0x0,1); // No BEP_PERIOD2

		bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
		bitvec_write_field(dest, wp,tbf->ta(),6); // TIMING_ADVANCE_VALUE
		if (ta_idx < 0) {
			bitvec_write_field(dest, wp,0x0,1);   // switch TIMING_ADVANCE_INDEX = off
		} else {
			bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
			bitvec_write_field(dest, wp,ta_idx,4);   // TIMING_ADVANCE_INDEX
		}

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
	uint8_t old_tfi, uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf,
	uint8_t poll, uint8_t alpha, uint8_t gamma, int8_t ta_idx, uint8_t ta_ts,
	bool use_egprs)
{
	// Packet downlink assignment TS 44.060 11.2.7

	PDA_AdditionsR99_t *pda_r99;

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
	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x1; // AdditionsR99 = on
	pda_r99 = &block->u.Packet_Downlink_Assignment.AdditionsR99;
	pda_r99->Exist_EGPRS_Params = 1;
	pda_r99->EGPRS_WindowSize = 0; /* 64, see TS 44.060, table 12.5.2.1 */
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
	gprs_rlc_ul_window *window, bool is_final)
{
	int urbb_len = 0;
	int crbb_len = 0;
	int len;
	bool bow = true;
	bool eow = true;
	int ssn = window->mod_sns(window->v_q() + 1);
	int num_blocks = window->mod_sns(window->v_r() - window->v_q());
	int esn_crbb = window->mod_sns(ssn - 1);
	int rest_bits = dest->data_len * 8 - wp;

	if (num_blocks > 0)
		/* V(Q) is NACK and omitted -> SSN = V(Q) + 1 */
		num_blocks -= 1;

	if (num_blocks > window->ws())
		num_blocks = window->ws();

	if (num_blocks > rest_bits) {
		eow = false;
		urbb_len = rest_bits;
		/* TODO: use compression, start encoding bits and stop when the
		 * space is exhausted. Use the first combination that encodes
		 * all bits. If there is none, use the combination that encodes
		 * the largest number of bits (e.g. by setting num_blocks to the
		 * max and repeating the construction).
		 */
	} else if (num_blocks > rest_bits - 9) {
		/* union bit and length field take 9 bits */
		eow = false;
		urbb_len = rest_bits - 9;
		/* TODO: use compression (see above) */
	}

	if (urbb_len + crbb_len == rest_bits)
		len = -1;
	else if (crbb_len == 0)
		len = urbb_len + 15;
	else
		len = urbb_len + crbb_len + 23;

	/* EGPRS Ack/Nack Description IE */
	if (len < 0) {
		bitvec_write_field(dest, wp, 0, 1); // 0: don't have length
	} else {
		bitvec_write_field(dest, wp, 1, 1); // 1: have length
		bitvec_write_field(dest, wp, len, 8); // length
	}

	bitvec_write_field(dest, wp, is_final, 1); // FINAL_ACK_INDICATION
	bitvec_write_field(dest, wp, bow, 1); // BEGINNING_OF_WINDOW
	bitvec_write_field(dest, wp, eow, 1); // END_OF_WINDOW
	bitvec_write_field(dest, wp, ssn, 11); // STARTING_SEQUENCE_NUMBER
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have CRBB

	/* TODO: Add CRBB support */

	LOGP(DRLCMACUL, LOGL_DEBUG,
		" - EGPRS URBB, len = %d, SSN = %d, ESN_CRBB = %d, "
		"SNS = %d, WS = %d, V(Q) = %d, V(R) = %d%s%s\n",
		urbb_len, ssn, esn_crbb,
		window->sns(), window->ws(), window->v_q(), window->v_r(),
		bow ? ", BOW" : "", eow ? ", EOW" : "");
	for (int i = urbb_len; i > 0; i--) {
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
	bitvec_write_field(dest, wp, 2, 4); // CHANNEL_CODING_COMMAND: MCS-3
	// bitvec_write_field(dest, wp, tbf->current_cs() - 1, 4); // CHANNEL_CODING_COMMAND
	bitvec_write_field(dest, wp, 0, 1); // 0: no RESEGMENT (nyi)
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

	write_packet_ack_nack_desc_egprs(bts, dest, wp, &tbf->m_window, is_final);

	bitvec_write_field(dest, wp, 0, 1); // fixed 0
	bitvec_write_field(dest, wp, 0, 1); // 0: don't have REL 5
};

void Encoding::write_packet_uplink_ack(
	struct gprs_rlcmac_bts *bts, bitvec * dest,
	struct gprs_rlcmac_ul_tbf *tbf, bool is_final)
{
	unsigned wp = 0;

	LOGP(DRLCMACUL, LOGL_DEBUG, "Encoding Ack/Nack for %s "
		"(final=%d)\n", tbf_name(tbf), is_final);

	bitvec_write_field(dest, wp, 0x1, 2);  // Payload Type
	bitvec_write_field(dest, wp, 0x0, 2);  // Uplink block with TDMA framenumber (N+13)
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
	struct gprs_rlc_dl_header_egprs_3 *egprs3;
	struct rlc_dl_header *gprs;
	unsigned int e_fbi_header;
	GprsCodingScheme cs = rlc->cs;

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

	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3:
		egprs3 = static_cast<struct gprs_rlc_dl_header_egprs_3 *>
			((void *)data);

		egprs3->usf    = rlc->usf;
		egprs3->es_p   = rlc->es_p;
		egprs3->rrbp   = rlc->rrbp;
		egprs3->tfi_a  = rlc->tfi >> 0; /* 1 bit LSB */
		egprs3->tfi_b  = rlc->tfi >> 1; /* 4 bits */
		egprs3->pr     = rlc->pr;
		egprs3->cps    = rlc->cps;

		egprs3->bsn1_a = rlc->block_info[0].bsn >> 0; /* 2 bits LSB */
		egprs3->bsn1_b = rlc->block_info[0].bsn >> 2; /* 8 bits */
		egprs3->bsn1_c = rlc->block_info[0].bsn >> 10; /* 1 bit */

		egprs3->spb    = rlc->block_info[0].spb;

		e_fbi_header   = rlc->block_info[0].e       ? 0x01 : 0;
		e_fbi_header  |= rlc->block_info[0].cv == 0 ? 0x02 : 0; /* FBI */
		e_fbi_header <<= 7;
		data[3] = (data[3] & 0b01111111) | (e_fbi_header >> 0);
		data[4] = (data[4] & 0b11111110) | (e_fbi_header >> 8);
		break;

	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1:
	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2:
		/* TODO: Support both header types */
		/* fall through */
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
