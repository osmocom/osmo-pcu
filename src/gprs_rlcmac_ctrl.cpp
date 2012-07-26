/* gprs_rlcmac_ctrl.cpp
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

#include <errno.h>
#include <arpa/inet.h>
#include "bitvector.h"
#include "gsm_rlcmac.h"
extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include "gprs_debug.h"
#include "gprs_rlcmac.h"
}
#include "gprs_rlcmac_ctrl.h"

extern void *tall_pcu_ctx;

// GSM 04.08 9.1.18 Immediate assignment
static uint8_t write_immediate_assignment(bitvec * dest, uint8_t downlink,
	uint8_t ra, uint32_t fn, uint8_t ta, uint16_t arfcn, uint8_t ts,
	uint8_t tsc, uint8_t tfi, uint8_t usf, uint32_t tlli, uint8_t polling,
	uint32_t poll_fn)
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

extern "C"
int write_immediate_assignment_uplink(uint8_t *data, uint8_t ra, uint32_t fn,
	uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, uint8_t tfi,
	uint8_t usf, uint8_t polling, uint32_t poll_fn)
{
	bitvec *ass_vec;
	uint8_t plen;

	ass_vec = bitvec_alloc(22); /* without plen */
	if (!ass_vec)
		return -ENOMEM;
	bitvec_unhex(ass_vec, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	plen = write_immediate_assignment(ass_vec, 0, ra, fn, ta, arfcn,
		ts, tsc, tfi, usf, 0, polling, poll_fn);
	bitvec_pack(ass_vec, data + 1);
	data[0] = (plen << 2) | 0x01;
	bitvec_free(ass_vec);

	return 0;
}

extern "C"
int write_immediate_assignment_downlink(uint8_t *data, uint8_t ra, uint32_t fn,
	uint8_t ta, uint16_t arfcn, uint8_t ts, uint8_t tsc, uint8_t tfi,
	uint32_t tlli, uint8_t polling, uint32_t poll_fn)
{
	bitvec *ass_vec;
	uint8_t plen;

	ass_vec = bitvec_alloc(22); /* without plen */
	if (!ass_vec)
		return -ENOMEM;
	bitvec_unhex(ass_vec, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");

	plen = write_immediate_assignment(ass_vec, 1, ra, fn, ta, arfcn,
		ts, tsc, tfi, 0, tlli, polling, poll_fn);
	bitvec_pack(ass_vec, data + 1);
	data[0] = (plen << 2) | 0x01;
	bitvec_free(ass_vec);

	return 0;
}

/* generate uplink assignment */
extern "C"
struct msgb *write_packet_uplink_assignment(uint8_t old_tfi,
	uint8_t old_downlink, uint32_t tlli, uint8_t use_tlli,
	struct gprs_rlcmac_tbf *tbf, uint8_t poll)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	unsigned wp = 0;
	uint8_t ts;
	struct msgb *msg;
	bitvec *ass_vec;
	RlcMacDownlink_t *block;

	msg = msgb_alloc(23, "rlcmac_ul_ass");
	if (!msg)
		return NULL;
	ass_vec = bitvec_alloc(23);
	if (!ass_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ass_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	if (!block) {
		bitvec_free(ass_vec);
		msgb_free(msg);
		return NULL;
	}

	bitvec_write_field(ass_vec, wp,0x1,2);  // Payload Type
	bitvec_write_field(ass_vec, wp,0x0,2);  // Uplink block with TDMA framenumber (N+13)
	bitvec_write_field(ass_vec, wp,poll,1);  // Suppl/Polling Bit
	bitvec_write_field(ass_vec, wp,0x0,3);  // Uplink state flag
	bitvec_write_field(ass_vec, wp,0xa,6);  // MESSAGE TYPE

	bitvec_write_field(ass_vec, wp,0x0,2);  // Page Mode

	bitvec_write_field(ass_vec, wp,0x0,1); // switch PERSIST_LEVEL: off
	if (use_tlli) {
		bitvec_write_field(ass_vec, wp,0x2,2); // switch TLLI   : on
		bitvec_write_field(ass_vec, wp,tlli,32); // TLLI
	} else {
		bitvec_write_field(ass_vec, wp,0x0,1); // switch TFI : on
		bitvec_write_field(ass_vec, wp,old_downlink,1); // 0=UPLINK TFI, 1=DL TFI
		bitvec_write_field(ass_vec, wp,old_tfi,5); // TFI
	}

	bitvec_write_field(ass_vec, wp,0x0,1); // Message escape
	bitvec_write_field(ass_vec, wp,bts->initial_cs-1, 2); // CHANNEL_CODING_COMMAND 
	bitvec_write_field(ass_vec, wp,0x1,1); // TLLI_BLOCK_CHANNEL_CODING 

	bitvec_write_field(ass_vec, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(ass_vec, wp,tbf->ta,6); // TIMING_ADVANCE_VALUE
	bitvec_write_field(ass_vec, wp,0x0,1); // switch TIMING_ADVANCE_INDEX = off

#if 1
	bitvec_write_field(ass_vec, wp,0x1,1); // Frequency Parameters information elements = present
	bitvec_write_field(ass_vec, wp,tbf->tsc,3); // Training Sequence Code (TSC)
	bitvec_write_field(ass_vec, wp,0x0,2); // ARFCN = present
	bitvec_write_field(ass_vec, wp,tbf->arfcn,10); // ARFCN
#else
	bitvec_write_field(ass_vec, wp,0x0,1); // Frequency Parameters = off
#endif

	bitvec_write_field(ass_vec, wp,0x1,2); // Dynamic Allocation
	
	bitvec_write_field(ass_vec, wp,0x0,1); // Extended Dynamic Allocation = off
	bitvec_write_field(ass_vec, wp,0x0,1); // P0 = off
	
	bitvec_write_field(ass_vec, wp,0x0,1); // USF_GRANULARITY
	bitvec_write_field(ass_vec, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(ass_vec, wp,tbf->tfi,5);// TFI

	bitvec_write_field(ass_vec, wp,0x0,1); //
	bitvec_write_field(ass_vec, wp,0x0,1); // TBF Starting Time = off
	bitvec_write_field(ass_vec, wp,0x0,1); // Timeslot Allocation
	
	for (ts = 0; ts < 8; ts++) {
		if (tbf->pdch[ts]) {
			bitvec_write_field(ass_vec, wp,0x1,1); // USF_TN(i): on
			bitvec_write_field(ass_vec, wp,tbf->dir.ul.usf[ts],3); // USF_TN(i)
		} else
			bitvec_write_field(ass_vec, wp,0x0,1); // USF_TN(i): off
	}
//	bitvec_write_field(ass_vec, wp,0x0,1); // Measurement Mapping struct not present

	bitvec_pack(ass_vec, msgb_put(msg, 23));
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Assignment +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(ass_vec, block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Uplink Assignment -------------------------\n");
	bitvec_free(ass_vec);
	talloc_free(block);

	return msg;
}


/* generate downlink assignment */
extern "C"
struct msgb *write_packet_downlink_assignment(uint8_t old_tfi,
	uint8_t old_downlink, struct gprs_rlcmac_tbf *tbf, uint8_t poll)
{
	// Packet downlink assignment TS 44.060 11.2.7

	uint8_t tn;
	struct msgb *msg;
	bitvec *ass_vec;
	RlcMacDownlink_t *block;

	msg = msgb_alloc(23, "rlcmac_dl_ass");
	if (!msg)
		return NULL;
	ass_vec = bitvec_alloc(23);
	if (!ass_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ass_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	if (!block) {
		bitvec_free(ass_vec);
		msgb_free(msg);
		return NULL;
	}

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
	block->u.Packet_Downlink_Assignment.Packet_Timing_Advance.Exist_IndexAndtimeSlot     = 0x0; // TIMING_ADVANCE_INDEX = off

	block->u.Packet_Downlink_Assignment.Exist_P0_and_BTS_PWR_CTRL_MODE = 0x0;   // POWER CONTROL = off

	block->u.Packet_Downlink_Assignment.Exist_Frequency_Parameters     = 0x1;   // Frequency Parameters = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.TSC       = tbf->tsc;   // Training Sequence Code (TSC)
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.UnionType = 0x0;   // ARFCN = on
	block->u.Packet_Downlink_Assignment.Frequency_Parameters.u.ARFCN   = tbf->arfcn; // ARFCN

	block->u.Packet_Downlink_Assignment.Exist_DOWNLINK_TFI_ASSIGNMENT  = 0x1;     // DOWNLINK TFI ASSIGNMENT = on
	block->u.Packet_Downlink_Assignment.DOWNLINK_TFI_ASSIGNMENT        = tbf->tfi; // TFI

	block->u.Packet_Downlink_Assignment.Exist_Power_Control_Parameters = 0x1;   // Power Control Parameters = on
	block->u.Packet_Downlink_Assignment.Power_Control_Parameters.ALPHA = 0x0;   // ALPHA

	for (tn = 0; tn < 8; tn++)
	{
		if (tbf->pdch[tn])
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].Exist    = 0x1; // Slot[i] = on
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].GAMMA_TN = 0x0; // GAMMA_TN
		}
		else
		{
			block->u.Packet_Downlink_Assignment.Power_Control_Parameters.Slot[tn].Exist    = 0x0; // Slot[i] = off
		}
	}

	block->u.Packet_Downlink_Assignment.Exist_TBF_Starting_Time   = 0x0; // TBF Starting TIME = off
	block->u.Packet_Downlink_Assignment.Exist_Measurement_Mapping = 0x0; // Measurement_Mapping = off
	block->u.Packet_Downlink_Assignment.Exist_AdditionsR99        = 0x0; // AdditionsR99 = off

	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Downlink Assignment +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink(ass_vec, block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- TX : Packet Downlink Assignment -------------------------\n");
	bitvec_pack(ass_vec, msgb_put(msg, 23));
	bitvec_free(ass_vec);
	talloc_free(block);

	return msg;
}

/* generate uplink ack */
extern "C"
struct msgb *write_packet_uplink_ack(struct gprs_rlcmac_tbf *tbf, uint8_t final)
{
	// Packet Uplink Ack/Nack  TS 44.060 11.2.28

	char show_v_n[65];

	struct gprs_rlcmac_bts *bts = gprs_rlcmac_bts;
	uint8_t rbb = 0;
	uint16_t i, bbn;
	uint16_t mod_sns_half = (tbf->sns >> 1) - 1;
	char bit;
	struct msgb *msg;
	bitvec *ack_vec;
	RlcMacDownlink_t *block;

	LOGP(DRLCMACUL, LOGL_DEBUG, "Sending Ack/Nack for TBF=%d "
		"(final=%d)\n", tbf->tfi, final);

	msg = msgb_alloc(23, "rlcmac_ul_ack");
	if (!msg)
		return NULL;
	ack_vec = bitvec_alloc(23);
	if (!ack_vec) {
		msgb_free(msg);
		return NULL;
	}
	bitvec_unhex(ack_vec,
		"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	block = (RlcMacDownlink_t *)talloc_zero(tall_pcu_ctx, RlcMacDownlink_t);
	if (!block) {
		bitvec_free(ack_vec);
		msgb_free(msg);
		return NULL;
	}

	block->PAYLOAD_TYPE = 0x1;   // RLC/MAC control block that does not include the optional octets of the RLC/MAC control header
	block->RRBP         = 0x0;   // N+13
	block->SP           = final; // RRBP field is valid, if it is final ack
	block->USF          = 0x0;   // Uplink state flag

	block->u.Packet_Uplink_Ack_Nack.MESSAGE_TYPE = 0x9;      // Packet Downlink Assignment
	block->u.Packet_Uplink_Ack_Nack.PAGE_MODE    = 0x0;      // Normal Paging
	block->u.Packet_Uplink_Ack_Nack.UPLINK_TFI   = tbf->tfi; // Uplink TFI

	block->u.Packet_Uplink_Ack_Nack.UnionType    = 0x0;      // PU_AckNack_GPRS = on
	block->u.Packet_Uplink_Ack_Nack.u.PU_AckNack_GPRS_Struct.CHANNEL_CODING_COMMAND                        = bts->initial_cs - 1;             // CS1
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

	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Ack/Nack +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink(ack_vec, block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ TX : Packet Uplink Ack/Nack +++++++++++++++++++++++++\n");
	bitvec_pack(ack_vec, msgb_put(msg, 23));
	bitvec_free(ack_vec);
	talloc_free(block);

	return msg;
}

static unsigned write_packet_paging_request(bitvec * dest)
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

static unsigned write_repeated_page_info(bitvec * dest, unsigned& wp,
	uint8_t len, uint8_t *identity, uint8_t chan_needed)
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

extern "C"
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
	if (!msg)
		return NULL;
	bitvec *pag_vec = bitvec_alloc(23);
	if (!pag_vec) {
		msgb_free(msg);
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
				break;
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
				break;
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

/* Received Uplink RLC control block. */
extern "C"
int gprs_rlcmac_rcv_control_block(uint8_t trx, uint8_t ts, uint32_t fn,
	uint8_t *data, uint8_t len)
{
	uint32_t tlli = 0;
	int8_t tfi = 0; /* must be signed */
	struct gprs_rlcmac_tbf *tbf;
	bitvec *block;
	RlcMacUplink_t * ul_control_block;

	block = bitvec_alloc(len);
	if (!block)
		return -ENOMEM;
	bitvec_unpack(block, data);

	ul_control_block = (RlcMacUplink_t *)talloc_zero(tall_pcu_ctx, RlcMacUplink_t);
	if (!ul_control_block) {
		bitvec_free(block);
		return -ENOMEM;
	}

	LOGP(DRLCMAC, LOGL_DEBUG, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink(block, ul_control_block);
	LOGPC(DCSN1, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_DEBUG, "------------------------- RX : Uplink Control Block -------------------------\n");
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		tlli = ul_control_block->u.Packet_Control_Acknowledgement.TLLI;
		gprs_rlcmac_rcv_control_ack(trx, ts, fn, tlli);
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		tfi = ul_control_block->u.Packet_Downlink_Ack_Nack.DOWNLINK_TFI;
		gprs_rlcmac_rcv_downlink_ack(trx, ts, fn, tfi,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.FINAL_ACK_INDICATION,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.STARTING_SEQUENCE_NUMBER,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Ack_Nack_Description.RECEIVED_BLOCK_BITMAP,
			ul_control_block->u.Packet_Downlink_Ack_Nack.Exist_Channel_Request_Description);
		break;
	case MT_PACKET_RESOURCE_REQUEST:
		if (ul_control_block->u.Packet_Resource_Request.ID.UnionType) {
			tlli = ul_control_block->u.Packet_Resource_Request.ID.u.TLLI;
			tbf = tbf_by_tlli(tlli, GPRS_RLCMAC_UL_TBF);
			if (!tbf) {
				LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown uplink TLLI=0x%08x\n", tlli);
				break;
			}
			tfi = tbf->tfi;
		} else {
			if (ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.UnionType) {
				tfi = ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.u.DOWNLINK_TFI;
				tbf = tbf_by_tfi(tfi, trx, ts, GPRS_RLCMAC_DL_TBF);
				if (!tbf) {
					LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown downlink TBF=%d\n", tlli);
					break;
				}
			} else {
				tfi = ul_control_block->u.Packet_Resource_Request.ID.u.Global_TFI.u.UPLINK_TFI;
				tbf = tbf_by_tfi(tfi, trx, ts, GPRS_RLCMAC_UL_TBF);
				if (!tbf) {
					LOGP(DRLCMAC, LOGL_NOTICE, "PACKET RESSOURCE REQ unknown uplink TBF=%d\n", tlli);
					break;
				}
			}
			tlli = tbf->tlli;
		}
		LOGP(DRLCMAC, LOGL_ERROR, "RX: [PCU <- BTS] %s TFI: %u TLLI: 0x%08x FIXME: Packet ressource request\n", (tbf->direction == GPRS_RLCMAC_UL_TBF) ? "UL" : "DL", tbf->tfi, tbf->tlli);
		break;
	default:
		LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] unknown control block received\n");
	}
	talloc_free(ul_control_block);
	bitvec_free(block);
	return 1;
}

