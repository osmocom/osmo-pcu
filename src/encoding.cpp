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
	uint8_t gamma, int8_t ta_idx)
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

	bitvec_write_field(dest, wp,0x0,1); // Message escape
	bitvec_write_field(dest, wp,bts->initial_cs_ul-1, 2); // CHANNEL_CODING_COMMAND 
	bitvec_write_field(dest, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 
	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(dest, wp,tbf->ta(),6); // TIMING_ADVANCE_VALUE
	if (ta_idx < 0) {
		bitvec_write_field(dest, wp,0x0,1);   // switch TIMING_ADVANCE_INDEX = off
	} else {
		bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
		bitvec_write_field(dest, wp,ta_idx,4);   // TIMING_ADVANCE_INDEX
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
void Encoding::write_packet_downlink_assignment(RlcMacDownlink_t * block, uint8_t old_tfi,
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
	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x0; // AdditionsR99 = off
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

/* generate uplink ack */
void Encoding::write_packet_uplink_ack(struct gprs_rlcmac_bts *bts,
	RlcMacDownlink_t * block, struct gprs_rlcmac_ul_tbf *tbf,
	uint8_t final)
{
	// Packet Uplink Ack/Nack  TS 44.060 11.2.28

	char rbb[65];

	tbf->m_window.update_rbb(rbb);

	LOGP(DRLCMACUL, LOGL_DEBUG, "Encoding Ack/Nack for %s "
		"(final=%d)\n", tbf_name(tbf), final);

	block->PAYLOAD_TYPE = 0x1;   // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0;   // N+13
	block->SP           = final; // RRBP field is valid, if it is final ack
	block->USF          = 0x0;   // Uplink state flag

	block->u.Packet_Uplink_Ack_Nack.MESSAGE_TYPE = 0x9;      // Packet Downlink Assignment
	block->u.Packet_Uplink_Ack_Nack.PAGE_MODE    = 0x0;      // Normal Paging
	block->u.Packet_Uplink_Ack_Nack.UPLINK_TFI   = tbf->tfi(); // Uplink TFI

	block->u.Packet_Uplink_Ack_Nack.UnionType    = 0x0;      // PU_AckNack_GPRS = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.CHANNEL_CODING_COMMAND                        = bts->initial_cs_ul - 1;             // CS1
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.FINAL_ACK_INDICATION     = final;           // FINAL ACK INDICATION
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER = tbf->m_window.ssn(); // STARTING_SEQUENCE_NUMBER

	encode_rbb(rbb, block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP);

	/* rbb is not NULL terminated */
	rbb[64] = 0;
	LOGP(DRLCMACUL, LOGL_DEBUG, "- V(N): \"%s\" R=Received "
		"I=Invalid\n", rbb);

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.UnionType              = 0x0; // Fixed Allocation Dummy = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.u.FixedAllocationDummy = 0x0; // Fixed Allocation Dummy
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Exist_AdditionsR99     = 0x0; // AdditionsR99 = off

	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_CONTENTION_RESOLUTION_TLLI = 0x1;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.CONTENTION_RESOLUTION_TLLI       = tbf->tlli();
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Packet_Timing_Advance      = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Extension_Bits             = 0x0;
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.Common_Uplink_Ack_Nack_Data.Exist_Power_Control_Parameters   = 0x0;
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

