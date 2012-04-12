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

void  write_packet_downlink_assignment(BitVector * dest, uint8_t tfi, uint32_t tlli)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	dest->writeField(wp,0x1,2);  // Payload Type
	dest->writeField(wp,0x0,2);  // Uplink block with TDMA framenumber
	dest->writeField(wp,0x1,1);  // Suppl/Polling Bit
	dest->writeField(wp,0x1,3);  // Uplink state flag
	dest->writeField(wp,0x2,6);  // MESSAGE TYPE
	dest->writeField(wp,0x0,2);  // Page Mode

	dest->writeField(wp,0x0,1); // switch PERSIST_LEVEL: off
	dest->writeField(wp,0x2,2); // switch TLLI   : on
	dest->writeField(wp,tlli,32); // TLLI

	dest->writeField(wp,0x0,1); // Message escape
	dest->writeField(wp,0x0,2); // Medium Access Method: Dynamic Allocation
	dest->writeField(wp,0x0,1); // RLC acknowledged mode

	dest->writeField(wp,0x0,1); // the network establishes no new downlink TBF for the mobile station
	dest->writeField(wp,0x1,8); // timeslot 7
	dest->writeField(wp,0x1,8); // TIMING_ADVANCE_INDEX

	dest->writeField(wp,0x0,1); // switch TIMING_ADVANCE_VALUE = off
	dest->writeField(wp,0x1,1); // switch TIMING_ADVANCE_INDEX = on
	dest->writeField(wp,0xC,4); // TIMING_ADVANCE_INDEX
	dest->writeField(wp,0x7,3); // TIMING_ADVANCE_TIMESLOT_NUMBER

	dest->writeField(wp,0x0,1); // switch POWER CONTROL = off
	dest->writeField(wp,0x1,1); // Frequency Parameters information elements = present

	dest->writeField(wp,0x2,3); // Training Sequence Code (TSC) = 2
	dest->writeField(wp,0x1,2); // Indirect encoding struct = present
	dest->writeField(wp,0x0,6); // MAIO
	dest->writeField(wp,0xE,4); // MA_Number
	dest->writeField(wp,0x8,4); // CHANGE_MARK_1 CHANGE_MARK_2

	dest->writeField(wp,0x1,1); // switch TFI   : on
	dest->writeField(wp,tfi,5);// TFI

	dest->writeField(wp,0x1,1); // Power Control Parameters IE = present
	dest->writeField(wp,0x0,4); // ALPHA power control parameter
	dest->writeField(wp,0x0,1); // switch GAMMA_TN0 = off
	dest->writeField(wp,0x0,1); // switch GAMMA_TN1 = off
	dest->writeField(wp,0x0,1); // switch GAMMA_TN2 = off
	dest->writeField(wp,0x0,1); // switch GAMMA_TN3 = off
	dest->writeField(wp,0x0,1); // switch GAMMA_TN4 = off
	dest->writeField(wp,0x0,1); // switch GAMMA_TN5 = off
	dest->writeField(wp,0x0,1); // switch GAMMA_TN6 = off
	dest->writeField(wp,0x1,1); // switch GAMMA_TN7 = on
	dest->writeField(wp,0x0,5); // GAMMA_TN7

	dest->writeField(wp,0x0,1); // TBF Starting TIME IE not present
	dest->writeField(wp,0x0,1); // Measurement Mapping struct not present
}

void  write_packet_uplink_assignment(BitVector * dest, uint8_t tfi, uint32_t tlli)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	dest->writeField(wp,0x1,2);  // Payload Type
	dest->writeField(wp,0x0,2);  // Uplink block with TDMA framenumber
	dest->writeField(wp,0x1,1);  // Suppl/Polling Bit
	dest->writeField(wp,0x1,3);  // Uplink state flag


	dest->writeField(wp,0xa,6);  // MESSAGE TYPE

	dest->writeField(wp,0x0,2);  // Page Mode

	dest->writeField(wp,0x0,1); // switch PERSIST_LEVEL: off
	dest->writeField(wp,0x2,2); // switch TLLI   : on
	dest->writeField(wp,tlli,32); // TLLI

	dest->writeField(wp,0x0,1); // Message escape
	dest->writeField(wp,0x0,2); // CHANNEL_CODING_COMMAND
	dest->writeField(wp,0x0,1); // TLLI_BLOCK_CHANNEL_CODING 

	dest->writeField(wp,0x1,1); // switch TIMING_ADVANCE_VALUE = on
	dest->writeField(wp,0x0,6); // TIMING_ADVANCE_VALUE
	dest->writeField(wp,0x0,1); // switch TIMING_ADVANCE_INDEX = off
	
	dest->writeField(wp,0x0,1); // Frequency Parameters = off

	dest->writeField(wp,0x1,2); // Dynamic Allocation = off
	
	dest->writeField(wp,0x0,1); // Dynamic Allocation
	dest->writeField(wp,0x0,1); // P0 = off
	
	dest->writeField(wp,0x1,1); // USF_GRANULARITY
	dest->writeField(wp,0x1,1); // switch TFI   : on
	dest->writeField(wp,tfi,5);// TFI

	dest->writeField(wp,0x0,1); //
	dest->writeField(wp,0x0,1); // TBF Starting Time = off
	dest->writeField(wp,0x0,1); // Timeslot Allocation
	
	dest->writeField(wp,0x0,5); // USF_TN 0 - 4
	dest->writeField(wp,0x1,1); // USF_TN 5
	dest->writeField(wp,0x1,3); // USF_TN 5
	dest->writeField(wp,0x0,2); // USF_TN 6 - 7
//	dest->writeField(wp,0x0,1); // Measurement Mapping struct not present
}

void write_ia_rest_octets_downlink_assignment(BitVector * dest, uint8_t tfi, uint32_t tlli)
{
	// GMS 04.08 10.5.2.16
	unsigned wp = 0;
	dest->writeField(wp, 3, 2);    // "HH"
	dest->writeField(wp, 1, 2);    // "01" Packet Downlink Assignment
	dest->writeField(wp,tlli,32); // TLLI
	dest->writeField(wp,0x1,1);   // switch TFI   : on
	dest->writeField(wp,tfi,5);   // TFI
	dest->writeField(wp,0x0,1);   // RLC acknowledged mode
	dest->writeField(wp,0x0,1);   // ALPHA = present
	dest->writeField(wp,0x0,5);   // GAMMA power control parameter
	dest->writeField(wp,0x0,1);   // Polling Bit
	dest->writeField(wp,0x1,1);   // TA_VALID ???
	dest->writeField(wp,0x1,1);   // switch TIMING_ADVANCE_INDEX = on
	dest->writeField(wp,0x0,4);   // TIMING_ADVANCE_INDEX
	dest->writeField(wp,0x0,1);   // TBF Starting TIME present
	dest->writeField(wp,0x0,1);   // P0 not present
	dest->writeField(wp,0x1,1);   // P0 not present
	dest->writeField(wp,0xb,4);
}

void write_packet_uplink_ack(BitVector * dest, uint8_t tfi, uint32_t tlli, unsigned cv, unsigned bsn)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	dest->writeField(wp,0x1,2);  // payload
	dest->writeField(wp,0x0,2);  // Uplink block with TDMA framenumber
	if (cv == 0) dest->writeField(wp,0x1,1);  // Suppl/Polling Bit
	else dest->writeField(wp,0x0,1);  //Suppl/Polling Bit
	dest->writeField(wp,0x1,3);  // Uplink state flag
	
	//dest->writeField(wp,0x0,1);  // Reduced block sequence number
	//dest->writeField(wp,BSN+6,5);  // Radio transaction identifier
	//dest->writeField(wp,0x1,1);  // Final segment
	//dest->writeField(wp,0x1,1);  // Address control

	//dest->writeField(wp,0x0,2);  // Power reduction: 0
	//dest->writeField(wp,TFI,5);  // Temporary flow identifier
	//dest->writeField(wp,0x1,1);  // Direction

	dest->writeField(wp,0x09,6); // MESSAGE TYPE
	dest->writeField(wp,0x0,2);  // Page Mode

	dest->writeField(wp,0x0,2);
	dest->writeField(wp,tfi,5); // Uplink TFI
	dest->writeField(wp,0x0,1);
	
	dest->writeField(wp,0x0,2);  // CS1
	if (cv == 0) dest->writeField(wp,0x1,1);  // FINAL_ACK_INDICATION
	else dest->writeField(wp,0x0,1);  // FINAL_ACK_INDICATION
	dest->writeField(wp,bsn + 1,7); // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	for (unsigned i=0; i<8; i++) {
		dest->writeField(wp,0xff,8);
	}
	dest->writeField(wp,0x1,1);  // CONTENTION_RESOLUTION_TLLI = present
	dest->writeField(wp,tlli,8*4);
	dest->writeField(wp,0x00,4); //spare
}

void gprs_rlcmac_tx_ul_ack(uint8_t tfi, uint32_t tlli, RlcMacUplinkDataBlock_t * ul_data_block)
{
	BitVector packet_uplink_ack_vec(23*8);
	packet_uplink_ack_vec.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	write_packet_uplink_ack(&packet_uplink_ack_vec, tfi, tlli, ul_data_block->CV, ul_data_block->BSN);
	COUT("RLCMAC_CONTROL_BLOCK>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
	RlcMacDownlink_t * packet_uplink_ack = (RlcMacDownlink_t *)malloc(sizeof(RlcMacDownlink_t));
	decode_gsm_rlcmac_downlink(&packet_uplink_ack_vec, packet_uplink_ack);
	free(packet_uplink_ack);
	COUT("RLCMAC_CONTROL_BLOCK_END------------------------------");
	pcu_l1if_tx(&packet_uplink_ack_vec);
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
int gprs_rlcmac_rcv_data_block(BitVector *rlc_block)
{
	struct gprs_rlcmac_tbf *tbf;

	COUT("RLCMAC_DATA_BLOCK<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	RlcMacUplinkDataBlock_t * ul_data_block = (RlcMacUplinkDataBlock_t *)malloc(sizeof(RlcMacUplinkDataBlock_t));
	decode_gsm_rlcmac_uplink_data(rlc_block, ul_data_block);
	COUT("RLCMAC_DATA_BLOCK_END------------------------------");

	tbf = tbf_by_tfi(ul_data_block->TFI);
	if (!tbf) {
		tbf = tbf_alloc(ul_data_block->TFI);
		if (tbf) {
			tbf->tlli = ul_data_block->TLLI;
			tbf->direction = GPRS_RLCMAC_UL_TBF;
			tbf->state = GPRS_RLCMAC_WAIT_DATA_SEQ_START;
		} else {
			return 0;
		}
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
int gprs_rlcmac_rcv_control_block(BitVector *rlc_block)
{
	//static unsigned shutUp = 0;
	uint8_t tfi = 0;
	uint32_t tlli = 0;
	struct gprs_rlcmac_tbf *tbf;

	COUT("RLCMAC_CONTROL_BLOCK<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
	RlcMacUplink_t * ul_control_block = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
	decode_gsm_rlcmac_uplink(rlc_block, ul_control_block);
	COUT("RLCMAC_CONTROL_BLOCK_END------------------------------");

	//gprs_rlcmac_control_block_get_tfi_tlli(ul_control_block, &tfi, &tlli);
	//tbf = tbf_by_tfi(tfi);
	//if (!tbf) {
	//		return 0;
	//}

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
		COUT("SEND PacketUplinkAssignment>>>>>>>>>>>>>>>>>>");
		BitVector packet_uplink_assignment(23*8);
		packet_uplink_assignment.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
		write_packet_uplink_assignment(&packet_uplink_assignment, tbf->tfi, tbf->tlli);
		pcu_l1if_tx(&packet_uplink_assignment);
		break;
	}
	free(ul_control_block);
	return 1;
}

void gprs_rlcmac_rcv_block(BitVector *rlc_block)
{
	unsigned readIndex = 0;
	unsigned payload = rlc_block->readField(readIndex, 2);

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

// Send RLC data to OpenBTS.
void gprs_rlcmac_tx_dl_data_block(uint32_t tlli, uint8_t tfi, uint8_t *pdu, int start_index, int end_index, uint8_t bsn, uint8_t fbi)
{
	int spare_len = 0;
	BitVector data_block_vector(BLOCK_LEN*8);
	data_block_vector.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlinkDataBlock_t * data_block = (RlcMacDownlinkDataBlock_t *)malloc(sizeof(RlcMacDownlinkDataBlock_t));
	data_block->PAYLOAD_TYPE = 0;
	data_block->RRBP = 0;
	data_block->SP = 1;
	data_block->USF = 1;
	data_block->PR = 0;
	data_block->TFI = tfi;
	data_block->FBI = fbi;
	data_block->BSN = bsn;
	if ((end_index - start_index) < 20) {
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
	encode_gsm_rlcmac_downlink_data(&data_block_vector, data_block);
	free(data_block);
	pcu_l1if_tx(&data_block_vector);
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

	LOGP(DBSSGP, LOGL_DEBUG, "Data len %u TLLI 0x%08x , TFI 0x%02x", tbf->data_index, tbf->tlli, tbf->tfi);
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
	COUT("SEND IA Rest Octets Downlink Assignment>>>>>>>>>>>>>>>>>>");
	BitVector ia_rest_octets_downlink_assignment(23*8);
	ia_rest_octets_downlink_assignment.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	write_ia_rest_octets_downlink_assignment(&ia_rest_octets_downlink_assignment, tbf->tfi, tbf->tlli);
	pcu_l1if_tx(&ia_rest_octets_downlink_assignment);
	tbf_gsm_timer_start(tbf, 0, 120);
}
