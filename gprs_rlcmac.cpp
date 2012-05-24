/* gprs_rlcmac.cpp
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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
#include <Threads.h>
#include <gprs_rlcmac.h>
#include <gsmL1prim.h>

LLIST_HEAD(gprs_rlcmac_tbfs);
void *rlcmac_tall_ctx;

int tfi_alloc()
{
	struct gprs_rlcmac_tbf *tbf;
	uint32_t tfi_map = 0;
	uint32_t tfi_ind = 0;
	uint32_t mask = 1;
	uint8_t i;

	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		tfi_ind = 1 << tbf->tfi;
		tfi_map = tfi_map|tfi_ind;
	}
	
	for (i = 0; i < 32; i++) {
		if(((tfi_map >> i) & mask) == 0) {
			return i;
		}
	}
	return -1;
}

/* lookup TBF Entity (by TFI) */
static struct gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi)
{
	struct gprs_rlcmac_tbf *tbf;

	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if (tbf->tfi == tfi)
			return tbf;
	}
	return NULL;
}

static struct gprs_rlcmac_tbf *tbf_by_tlli(uint32_t tlli)
{
	struct gprs_rlcmac_tbf *tbf;
	llist_for_each_entry(tbf, &gprs_rlcmac_tbfs, list) {
		if ((tbf->tlli == tlli)&&(tbf->direction == GPRS_RLCMAC_UL_TBF))
			return tbf;
	}
	return NULL;
}

struct gprs_rlcmac_tbf *tbf_alloc(uint8_t tfi)
{
	struct gprs_rlcmac_tbf *tbf;

	tbf = talloc_zero(rlcmac_tall_ctx, struct gprs_rlcmac_tbf);
	if (!tbf)
		return NULL;

	tbf->tfi = tfi;
	llist_add(&tbf->list, &gprs_rlcmac_tbfs);

	return tbf;
}

static void tbf_free(struct gprs_rlcmac_tbf *tbf)
{
	llist_del(&tbf->list);
	talloc_free(tbf);
}


static void tbf_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	tbf->num_T_exp++;

	switch (tbf->T) {
	case 1111:
		// TODO: We should add timers for TBF.
		break;
	default:
		COUT("Timer expired in unknown mode" << tbf->T);
	}
}

static void tbf_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int T,
				unsigned int seconds)
{
	if (osmo_timer_pending(&tbf->timer))
		COUT("Starting TBF timer %u while old timer %u pending" << T << tbf->T);
	tbf->T = T;
	tbf->num_T_exp = 0;

	/* FIXME: we should do this only once ? */
	tbf->timer.data = tbf;
	tbf->timer.cb = &tbf_timer_cb;

	osmo_timer_schedule(&tbf->timer, seconds, 0);
}


static void tbf_gsm_timer_cb(void *_tbf)
{
	struct gprs_rlcmac_tbf *tbf = (struct gprs_rlcmac_tbf *)_tbf;

	tbf->num_fT_exp++;

	switch (tbf->fT) {
	case 0:
		// This is timer for delay RLC/MAC data sending after Downlink Immediate Assignment on CCCH.
		gprs_rlcmac_segment_llc_pdu(tbf);
		LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [DOWNLINK] END TFI: %u TLLI: 0x%08x \n", tbf->tfi, tbf->tlli);
		break;
	default:
		COUT("Timer expired in unknown mode" << tbf->fT);
	}
}

static void tbf_gsm_timer_start(struct gprs_rlcmac_tbf *tbf, unsigned int fT,
				int frames)
{
	if (osmo_gsm_timer_pending(&tbf->gsm_timer))
		COUT("Starting TBF timer %u while old timer %u pending" << fT << tbf->fT);
	tbf->fT = fT;
	tbf->num_fT_exp = 0;

	/* FIXME: we should do this only once ? */
	tbf->gsm_timer.data = tbf;
	tbf->gsm_timer.cb = &tbf_gsm_timer_cb;

	osmo_gsm_timer_schedule(&tbf->gsm_timer, frames);
}

void  write_packet_downlink_assignment(bitvec * dest, uint8_t tfi, uint32_t tlli)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber
	bitvec_write_field(dest, wp,0x1,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x1,3);  // Uplink state flag
	bitvec_write_field(dest, wp,0x2,6);  // MESSAGE TYPE
	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1); // switch PERSIST_LEVEL: off
	bitvec_write_field(dest, wp,0x2,2); // switch TLLI   : on
	bitvec_write_field(dest, wp,tlli,32); // TLLI

	bitvec_write_field(dest, wp,0x0,1); // Message escape
	bitvec_write_field(dest, wp,0x0,2); // Medium Access Method: Dynamic Allocation
	bitvec_write_field(dest, wp,0x0,1); // RLC acknowledged mode

	bitvec_write_field(dest, wp,0x0,1); // the network establishes no new downlink TBF for the mobile station
	bitvec_write_field(dest, wp,0x1,8); // timeslot 7
	bitvec_write_field(dest, wp,0x1,8); // TIMING_ADVANCE_INDEX

	bitvec_write_field(dest, wp,0x0,1); // switch TIMING_ADVANCE_VALUE = off
	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_INDEX = on
	bitvec_write_field(dest, wp,0xC,4); // TIMING_ADVANCE_INDEX
	bitvec_write_field(dest, wp,0x7,3); // TIMING_ADVANCE_TIMESLOT_NUMBER

	bitvec_write_field(dest, wp,0x0,1); // switch POWER CONTROL = off
	bitvec_write_field(dest, wp,0x1,1); // Frequency Parameters information elements = present

	bitvec_write_field(dest, wp,0x2,3); // Training Sequence Code (TSC) = 2
	bitvec_write_field(dest, wp,0x1,2); // Indirect encoding struct = present
	bitvec_write_field(dest, wp,0x0,6); // MAIO
	bitvec_write_field(dest, wp,0xE,4); // MA_Number
	bitvec_write_field(dest, wp,0x8,4); // CHANGE_MARK_1 CHANGE_MARK_2

	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,tfi,5);// TFI

	bitvec_write_field(dest, wp,0x1,1); // Power Control Parameters IE = present
	bitvec_write_field(dest, wp,0x0,4); // ALPHA power control parameter
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN0 = off
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN1 = off
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN2 = off
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN3 = off
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN4 = off
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN5 = off
	bitvec_write_field(dest, wp,0x0,1); // switch GAMMA_TN6 = off
	bitvec_write_field(dest, wp,0x1,1); // switch GAMMA_TN7 = on
	bitvec_write_field(dest, wp,0x0,5); // GAMMA_TN7

	bitvec_write_field(dest, wp,0x0,1); // TBF Starting TIME IE not present
	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
}

void  write_packet_uplink_assignment(bitvec * dest, uint8_t tfi, uint32_t tlli)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	bitvec_write_field(dest, wp,0x1,2);  // Payload Type
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber
	bitvec_write_field(dest, wp,0x1,1);  // Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x1,3);  // Uplink state flag


	bitvec_write_field(dest, wp,0xa,6);  // MESSAGE TYPE

	bitvec_write_field(dest, wp,0x0,2);  // Page Mode

	bitvec_write_field(dest, wp,0x0,1); // switch PERSIST_LEVEL: off
	bitvec_write_field(dest, wp,0x2,2); // switch TLLI   : on
	bitvec_write_field(dest, wp,tlli,32); // TLLI

	bitvec_write_field(dest, wp,0x0,1); // Message escape
	bitvec_write_field(dest, wp,0x0,2); // CHANNEL_CODING_COMMAND
	bitvec_write_field(dest, wp,0x0,1); // TLLI_BLOCK_CHANNEL_CODING 

	bitvec_write_field(dest, wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	bitvec_write_field(dest, wp,0x0,6); // TIMING_ADVANCE_VALUE
	bitvec_write_field(dest, wp,0x0,1); // switch TIMING_ADVANCE_INDEX = off
	
	bitvec_write_field(dest, wp,0x0,1); // Frequency Parameters = off

	bitvec_write_field(dest, wp,0x1,2); // Dynamic Allocation = off
	
	bitvec_write_field(dest, wp,0x0,1); // Dynamic Allocation
	bitvec_write_field(dest, wp,0x0,1); // P0 = off
	
	bitvec_write_field(dest, wp,0x1,1); // USF_GRANULARITY
	bitvec_write_field(dest, wp,0x1,1); // switch TFI   : on
	bitvec_write_field(dest, wp,tfi,5);// TFI

	bitvec_write_field(dest, wp,0x0,1); //
	bitvec_write_field(dest, wp,0x0,1); // TBF Starting Time = off
	bitvec_write_field(dest, wp,0x0,1); // Timeslot Allocation
	
	bitvec_write_field(dest, wp,0x0,5); // USF_TN 0 - 4
	bitvec_write_field(dest, wp,0x1,1); // USF_TN 5
	bitvec_write_field(dest, wp,0x1,3); // USF_TN 5
	bitvec_write_field(dest, wp,0x0,2); // USF_TN 6 - 7
//	bitvec_write_field(dest, wp,0x0,1); // Measurement Mapping struct not present
}


// GSM 04.08 9.1.18 Immediate assignment
int write_immediate_assignment(bitvec * dest, uint8_t downlink, uint8_t ra, uint32_t fn,
								uint8_t ta, uint8_t tfi = 0, uint32_t tlli = 0)
{
	unsigned wp = 0;

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
	bitvec_write_field(dest, wp,(l1fh->fl1h)->channel_info.tn,3);     // TN
	bitvec_write_field(dest, wp,(l1fh->fl1h)->channel_info.tsc,3);    // TSC
	bitvec_write_field(dest, wp,0x0,3);                               // non-hopping RF channel configuraion
	bitvec_write_field(dest, wp,(l1fh->fl1h)->channel_info.arfcn,10); // ARFCN

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

	if (downlink)
	{
		// GSM 04.08 10.5.2.16 IA Rest Octets
		bitvec_write_field(dest, wp, 3, 2);   // "HH"
		bitvec_write_field(dest, wp, 1, 2);   // "01" Packet Downlink Assignment
		bitvec_write_field(dest, wp,tlli,32); // TLLI
		bitvec_write_field(dest, wp,0x1,1);   // switch TFI   : on
		bitvec_write_field(dest, wp,tfi,5);   // TFI
		bitvec_write_field(dest, wp,0x0,1);   // RLC acknowledged mode
		bitvec_write_field(dest, wp,0x0,1);   // ALPHA = present
		bitvec_write_field(dest, wp,0x0,5);   // GAMMA power control parameter
		bitvec_write_field(dest, wp,0x0,1);   // Polling Bit
		bitvec_write_field(dest, wp,0x1,1);   // TA_VALID ???
		bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
		bitvec_write_field(dest, wp,0x0,4);   // TIMING_ADVANCE_INDEX
		bitvec_write_field(dest, wp,0x0,1);   // TBF Starting TIME present
		bitvec_write_field(dest, wp,0x0,1);   // P0 not present
		bitvec_write_field(dest, wp,0x1,1);   // P0 not present
		bitvec_write_field(dest, wp,0xb,4);
	}
	else
	{
		// GMS 04.08 10.5.2.37b 10.5.2.16
		bitvec_write_field(dest, wp, 3, 2);    // "HH"
		bitvec_write_field(dest, wp, 0, 2);    // "0" Packet Uplink Assignment
		bitvec_write_field(dest, wp, 1, 1);    // Block Allocation : Not Single Block Allocation
		bitvec_write_field(dest, wp, tfi, 5);  // TFI_ASSIGNMENT Temporary Flow Identity
		bitvec_write_field(dest, wp, 0, 1);    // POLLING
		bitvec_write_field(dest, wp, 0, 1);    // ALLOCATION_TYPE: dynamic
		bitvec_write_field(dest, wp, 1, 3);    // USF
		bitvec_write_field(dest, wp, 1, 1);    // USF_GRANULARITY
		bitvec_write_field(dest, wp, 0 , 1);   // "0" power control: Not Present
		bitvec_write_field(dest, wp, 0, 2);    // CHANNEL_CODING_COMMAND 
		bitvec_write_field(dest, wp, 1, 1);    // TLLI_BLOCK_CHANNEL_CODING
		bitvec_write_field(dest, wp, 1 , 1);   // "1" Alpha : Present
		bitvec_write_field(dest, wp, 0, 4);    // Alpha
		bitvec_write_field(dest, wp, 0, 5);    // Gamma
		bitvec_write_field(dest, wp, 0, 1);    // TIMING_ADVANCE_INDEX_FLAG
		bitvec_write_field(dest, wp, 0, 1);    // TBF_STARTING_TIME_FLAG
	}

	if (wp%8)
		return wp/8+1;
	else
		return wp/8;
}


void write_ia_rest_octets_downlink_assignment(bitvec * dest, uint8_t tfi, uint32_t tlli)
{
	// GSM 04.08 10.5.2.16
	unsigned wp = 0;
	bitvec_write_field(dest, wp, 3, 2);    // "HH"
	bitvec_write_field(dest, wp, 1, 2);    // "01" Packet Downlink Assignment
	bitvec_write_field(dest, wp,tlli,32); // TLLI
	bitvec_write_field(dest, wp,0x1,1);   // switch TFI   : on
	bitvec_write_field(dest, wp,tfi,5);   // TFI
	bitvec_write_field(dest, wp,0x0,1);   // RLC acknowledged mode
	bitvec_write_field(dest, wp,0x0,1);   // ALPHA = present
	bitvec_write_field(dest, wp,0x0,5);   // GAMMA power control parameter
	bitvec_write_field(dest, wp,0x0,1);   // Polling Bit
	bitvec_write_field(dest, wp,0x1,1);   // TA_VALID ???
	bitvec_write_field(dest, wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
	bitvec_write_field(dest, wp,0x0,4);   // TIMING_ADVANCE_INDEX
	bitvec_write_field(dest, wp,0x0,1);   // TBF Starting TIME present
	bitvec_write_field(dest, wp,0x0,1);   // P0 not present
	bitvec_write_field(dest, wp,0x1,1);   // P0 not present
	bitvec_write_field(dest, wp,0xb,4);
}

void write_packet_uplink_ack(bitvec * dest, uint8_t tfi, uint32_t tlli, unsigned cv, unsigned bsn)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	bitvec_write_field(dest, wp,0x1,2);  // payload
	bitvec_write_field(dest, wp,0x0,2);  // Uplink block with TDMA framenumber
	if (cv == 0) bitvec_write_field(dest, wp,0x1,1);  // Suppl/Polling Bit
	else bitvec_write_field(dest, wp,0x0,1);  //Suppl/Polling Bit
	bitvec_write_field(dest, wp,0x1,3);  // Uplink state flag
	
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
	bitvec_write_field(dest, wp,tfi,5); // Uplink TFI
	bitvec_write_field(dest, wp,0x0,1);
	
	bitvec_write_field(dest, wp,0x0,2);  // CS1
	if (cv == 0) bitvec_write_field(dest, wp,0x1,1);  // FINAL_ACK_INDICATION
	else bitvec_write_field(dest, wp,0x0,1);  // FINAL_ACK_INDICATION
	bitvec_write_field(dest, wp,bsn + 1,7); // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	for (unsigned i=0; i<8; i++) {
		bitvec_write_field(dest, wp,0xff,8);
	}
	bitvec_write_field(dest, wp,0x1,1);  // CONTENTION_RESOLUTION_TLLI = present
	bitvec_write_field(dest, wp,tlli,8*4);
	bitvec_write_field(dest, wp,0x00,4); //spare
}

void gprs_rlcmac_tx_ul_ack(uint8_t tfi, uint32_t tlli, RlcMacUplinkDataBlock_t * ul_data_block)
{
	bitvec *packet_uplink_ack_vec = bitvec_alloc(23);
	bitvec_unhex(packet_uplink_ack_vec, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	write_packet_uplink_ack(packet_uplink_ack_vec, tfi, tlli, ul_data_block->CV, ul_data_block->BSN);
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u TLLI: 0x%08x Packet Uplink Ack\n", tfi, tlli);
	RlcMacDownlink_t * packet_uplink_ack = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ TX : Packet Uplink Ack +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_downlink(packet_uplink_ack_vec, packet_uplink_ack);
	LOGPC(DRLCMAC, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- TX : Packet Uplink Ack -------------------------\n");
	free(packet_uplink_ack);
	pcu_l1if_tx(packet_uplink_ack_vec, GsmL1_Sapi_Pacch);
	bitvec_free(packet_uplink_ack_vec);
}

void gprs_rlcmac_data_block_parse(gprs_rlcmac_tbf* tbf, RlcMacUplinkDataBlock_t * ul_data_block)
{
	unsigned block_data_len = 0;
	unsigned data_octet_num = 0;
	
	if (ul_data_block->E_1 == 0) // Extension octet follows immediately
	{
		// TODO We should implement case with several LLC PDU in one data block.
		block_data_len = ul_data_block->LENGTH_INDICATOR[0];
	}
	else
	{
		block_data_len = 20; // RLC data length without 3 header octets.
		if(ul_data_block->TI == 1) // TLLI field is present
		{
			tbf->tlli = ul_data_block->TLLI;
			block_data_len -= 4; // TLLI length
			if (ul_data_block->PI == 1) // PFI is present if TI field indicates presence of TLLI
			{
				block_data_len -= 1; // PFI length
			}
		}
	}

	for (unsigned i = tbf->data_index;  i < tbf->data_index + block_data_len; i++)
	{
		tbf->rlc_data[i] = ul_data_block->RLC_DATA[data_octet_num];
		data_octet_num++;
	}
	tbf->data_index += block_data_len;
}

/* Received Uplink RLC data block. */
int gprs_rlcmac_rcv_data_block(bitvec *rlc_block)
{
	struct gprs_rlcmac_tbf *tbf;

	LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] Uplink Data Block\n");
	RlcMacUplinkDataBlock_t * ul_data_block = (RlcMacUplinkDataBlock_t *)malloc(sizeof(RlcMacUplinkDataBlock_t));
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ RX : Uplink Data Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink_data(rlc_block, ul_data_block);
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- RX : Uplink Data Block -------------------------\n");
	tbf = tbf_by_tfi(ul_data_block->TFI);
	if (!tbf) {
		return 0;
	}

	switch (tbf->state) {
	case GPRS_RLCMAC_WAIT_DATA_SEQ_START: 
		if (ul_data_block->BSN == 0) {
			tbf->data_index = 0;
			gprs_rlcmac_data_block_parse(tbf, ul_data_block);
			gprs_rlcmac_tx_ul_ack(tbf->tfi, tbf->tlli, ul_data_block);
			tbf->state = GPRS_RLCMAC_WAIT_NEXT_DATA_BLOCK;
			tbf->bsn = ul_data_block->BSN;
		}
		break;
	case GPRS_RLCMAC_WAIT_NEXT_DATA_BLOCK:
		if (tbf->bsn == (ul_data_block->BSN - 1)) {
			gprs_rlcmac_data_block_parse(tbf, ul_data_block);
			gprs_rlcmac_tx_ul_ack(tbf->tfi, tbf->tlli, ul_data_block);
			if (ul_data_block->CV == 0) {
				// Recieved last Data Block in this sequence.
				gsmtap_send_llc(tbf->rlc_data, tbf->data_index);
				tbf->state = GPRS_RLCMAC_WAIT_NEXT_DATA_SEQ;
			} else {
				tbf->bsn = ul_data_block->BSN;
				tbf->state = GPRS_RLCMAC_WAIT_NEXT_DATA_BLOCK;
			}
		} else {
			// Recieved Data Block with unexpected BSN.
			// We should try to find nesessary Data Block. 
			tbf->state = GPRS_RLCMAC_WAIT_NEXT_DATA_BLOCK;
		}
		break;
	case GPRS_RLCMAC_WAIT_NEXT_DATA_SEQ:
		// Now we just ignore all Data Blocks and wait next Uplink TBF
		break;
	}

	free(ul_data_block);
	return 1;
}

/* Received Uplink RLC control block. */
int gprs_rlcmac_rcv_control_block(bitvec *rlc_block)
{
	//static unsigned shutUp = 0;
	uint8_t tfi = 0;
	uint32_t tlli = 0;
	struct gprs_rlcmac_tbf *tbf;

	RlcMacUplink_t * ul_control_block = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ RX : Uplink Control Block +++++++++++++++++++++++++\n");
	decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	LOGPC(DRLCMAC, LOGL_NOTICE, "\n");
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- RX : Uplink Control Block -------------------------\n");
	switch (ul_control_block->u.MESSAGE_TYPE) {
	case MT_PACKET_CONTROL_ACK:
		tlli = ul_control_block->u.Packet_Control_Acknowledgement.TLLI;
		tbf = tbf_by_tlli(tlli);
		if (!tbf) {
			return 0;
		}
		gprs_rlcmac_tx_ul_ud(tbf);
		tbf_free(tbf);
		break;
	case MT_PACKET_DOWNLINK_ACK_NACK:
		tfi = ul_control_block->u.Packet_Downlink_Ack_Nack.DOWNLINK_TFI;
		tbf = tbf_by_tfi(tfi);
		if (!tbf) {
			return 0;
		}
		LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u TLLI: 0x%08x Packet Uplink Assignment\n", tbf->tfi, tbf->tlli);
		bitvec *packet_uplink_assignment = bitvec_alloc(23);
		bitvec_unhex(packet_uplink_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
		write_packet_uplink_assignment(packet_uplink_assignment, tbf->tfi, tbf->tlli);
		pcu_l1if_tx(packet_uplink_assignment, GsmL1_Sapi_Pacch);
		bitvec_free(packet_uplink_assignment);
		break;
	}
	free(ul_control_block);
	return 1;
}

void gprs_rlcmac_rcv_block(bitvec *rlc_block)
{
	unsigned readIndex = 0;
	unsigned payload = bitvec_read_field(rlc_block, readIndex, 2);

	switch (payload) {
	case GPRS_RLCMAC_DATA_BLOCK:
		gprs_rlcmac_rcv_data_block(rlc_block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK:
		gprs_rlcmac_rcv_control_block(rlc_block);
		break;
	case GPRS_RLCMAC_CONTROL_BLOCK_OPT:
		COUT("GPRS_RLCMAC_CONTROL_BLOCK_OPT block payload is not supported.\n");
	default:
		COUT("Unknown RLCMAC block payload.\n");
	}
}

int gprs_rlcmac_rcv_rach(uint8_t ra, uint32_t Fn, uint16_t ta)
{
	struct gprs_rlcmac_tbf *tbf;

	// Create new TBF
	int tfi = tfi_alloc();
	if (tfi < 0) {
		return tfi;
	}
	tbf = tbf_alloc(tfi);
	tbf->direction = GPRS_RLCMAC_UL_TBF;
	tbf->state = GPRS_RLCMAC_WAIT_DATA_SEQ_START;
	LOGP(DRLCMAC, LOGL_NOTICE, "TBF: [UPLINK] START TFI: %u\n", tbf->tfi);
	LOGP(DRLCMAC, LOGL_NOTICE, "RX: [PCU <- BTS] TFI: %u RACH\n", tbf->tfi);
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u Packet Immidiate Assignment\n", tbf->tfi);
	bitvec *immediate_assignment = bitvec_alloc(23);
	bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	int len = write_immediate_assignment(immediate_assignment, 0, ra, Fn, ta, tbf->tfi);
	pcu_l1if_tx(immediate_assignment, GsmL1_Sapi_Agch, len);
	bitvec_free(immediate_assignment);
}

// Send RLC data to OpenBTS.
void gprs_rlcmac_tx_dl_data_block(uint32_t tlli, uint8_t tfi, uint8_t *pdu, int start_index, int end_index, uint8_t bsn, uint8_t fbi)
{
	int spare_len = 0;
	bitvec *data_block_vector = bitvec_alloc(BLOCK_LEN);
	bitvec_unhex(data_block_vector, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlinkDataBlock_t * data_block = (RlcMacDownlinkDataBlock_t *)malloc(sizeof(RlcMacDownlinkDataBlock_t));
	data_block->PAYLOAD_TYPE = 0;
	data_block->RRBP = 0;
	data_block->SP = 1;
	data_block->USF = 1;
	data_block->PR = 0;
	data_block->TFI = tfi;
	data_block->FBI = fbi;
	data_block->BSN = bsn;
	if ((end_index - start_index) < 19) {
		data_block->E_1 = 0;
		data_block->LENGTH_INDICATOR[0] = end_index-start_index;
		data_block->M[0] = 0;
		data_block->E[0] = 1;
		spare_len = 19 - data_block->LENGTH_INDICATOR[0];
	} else {
		data_block->E_1 = 1; 
	}
	int j = 0;
	int i = 0;
	for(i = start_index; i < end_index; i++) {
		data_block->RLC_DATA[j] = pdu[i];
		j++;
	}
	
	for(i = j; i < j + spare_len; i++) {
		data_block->RLC_DATA[i] = 0x2b;
	}
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] Downlink Data Block\n");
	LOGP(DRLCMAC, LOGL_NOTICE, "+++++++++++++++++++++++++ TX : Downlink Data Block +++++++++++++++++++++++++\n");
	encode_gsm_rlcmac_downlink_data(data_block_vector, data_block);
	LOGP(DRLCMAC, LOGL_NOTICE, "------------------------- TX : Downlink Data Block -------------------------\n");
	free(data_block);
	pcu_l1if_tx(data_block_vector, GsmL1_Sapi_Pdtch);
	bitvec_free(data_block_vector);
}

int gprs_rlcmac_segment_llc_pdu(struct gprs_rlcmac_tbf *tbf)
{
	int fbi = 0;
	int num_blocks = 0;
	int i;

	if (tbf->data_index > BLOCK_DATA_LEN + 1)
	{
		int block_data_len = BLOCK_DATA_LEN;
		num_blocks = tbf->data_index/BLOCK_DATA_LEN;
		int rest_len = tbf->data_index%BLOCK_DATA_LEN;
		int start_index = 0;
		int end_index = 0;
		if (tbf->data_index%BLOCK_DATA_LEN > 0)
		{
			num_blocks++;
		}
		for (i = 0; i < num_blocks; i++)
		{
			if (i == num_blocks-1)
			{
				if (rest_len > 0)
				{
					block_data_len = rest_len;
				}
				fbi = 1;
			}
			end_index = start_index + block_data_len;
			gprs_rlcmac_tx_dl_data_block(tbf->tlli, tbf->tfi, tbf->rlc_data, start_index, end_index, i, fbi);
			start_index += block_data_len;
		}
	}
	else
	{
		gprs_rlcmac_tx_dl_data_block(tbf->tlli, tbf->tfi, tbf->rlc_data, 0, tbf->data_index, 0, 1);
	}
}

/* Send Uplink unit-data to SGSN. */
void gprs_rlcmac_tx_ul_ud(gprs_rlcmac_tbf *tbf)
{
	const uint8_t qos_profile = QOS_PROFILE;
	struct msgb *llc_pdu;
	unsigned msg_len = NS_HDR_LEN + BSSGP_HDR_LEN + tbf->data_index;

	LOGP(DBSSGP, LOGL_DEBUG, "TX: [PCU -> SGSN ] TFI: %u TLLI: 0x%08x DataLen: %u", tbf->tfi, tbf->tlli, tbf->data_index);
	//for (unsigned i = 0; i < dataLen; i++)
	//	LOGP(DBSSGP, LOGL_DEBUG, " Data[%u] = %u", i, rlc_data[i]);
	
	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = MNC;
	bctx->ra_id.mcc = MCC;
	bctx->ra_id.lac = PCU_LAC;
	bctx->ra_id.rac = PCU_RAC;
	bctx->bvci = BVCI;

	llc_pdu = msgb_alloc_headroom(msg_len, msg_len,"llc_pdu");
	msgb_tvlv_push(llc_pdu, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*tbf->data_index, tbf->rlc_data);
	bssgp_tx_ul_ud(bctx, tbf->tlli, &qos_profile, llc_pdu);
}

void gprs_rlcmac_downlink_assignment(gprs_rlcmac_tbf *tbf)
{
	LOGP(DRLCMAC, LOGL_NOTICE, "TX: [PCU -> BTS] TFI: %u TLLI: 0x%08x Immidiate Assignment (CCCH)\n", tbf->tfi, tbf->tlli);
	bitvec *immediate_assignment = bitvec_alloc(23);
	bitvec_unhex(immediate_assignment, "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	int len = write_immediate_assignment(immediate_assignment, 1, 125, get_current_fn(), (l1fh->fl1h)->channel_info.ta, tbf->tfi, tbf->tlli);
	pcu_l1if_tx(immediate_assignment, GsmL1_Sapi_Agch, len);
	bitvec_free(immediate_assignment);
	tbf_gsm_timer_start(tbf, 0, 120);
}
