/*GPRSSocket.cpp
 *
 * Copyright (C) 2011 Ivan Klyuchnikov
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
 
#include <Sockets.h>
#include <Threads.h>
#include <BitVector.h>
#include "GPRSSocket.h"
#include "gsm_rlcmac.h"
#include "bssgp.h"

#define MAX_UDP_LENGTH 1500

#define RLCMAC_DATA_BLOCK 0
#define RLCMAC_CONTROL_BLOCK 1

// TODO: We should take ports and IP from config.
UDPSocket GPRSRLCMACSocket(5070, "127.0.0.1", 5934);

void sendToOpenBTS(BitVector * vector)
{
	char buffer[MAX_UDP_LENGTH];
	int ofs = 0;
	vector->pack((unsigned char*)&buffer[ofs]);
	ofs += vector->size() >> 3;
	COUT("Send to OpenBTS: " << *vector);
	GPRSRLCMACSocket.write(buffer, ofs);
}

void  writePDassignment(BitVector * dest, uint8_t TFI, uint32_t TLLI)
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
	dest->writeField(wp,TLLI,32); // TLLI

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
	dest->writeField(wp,0x14,5);// TFI

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

void writePUack(BitVector * dest, uint8_t TFI, uint32_t TLLI, unsigned CV, unsigned BSN)
{
	// TODO We should use our implementation of encode RLC/MAC Control messages.
	unsigned wp = 0;
	dest->writeField(wp,0x1,2);  // payload
	dest->writeField(wp,0x0,2);  // Uplink block with TDMA framenumber
	if (CV == 0) dest->writeField(wp,0x1,1);  // Suppl/Polling Bit
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
	dest->writeField(wp,TFI,5); // Uplink TFI
	dest->writeField(wp,0x0,1);
	
	dest->writeField(wp,0x0,2);  // CS1
	if (CV == 0) dest->writeField(wp,0x1,1);  // FINAL_ACK_INDICATION
	else dest->writeField(wp,0x0,1);  // FINAL_ACK_INDICATION
	dest->writeField(wp,BSN+1,7); // STARTING_SEQUENCE_NUMBER
	// RECEIVE_BLOCK_BITMAP
	for (unsigned i=0; i<8; i++) {
		dest->writeField(wp,0xff,8);
	}
	dest->writeField(wp,0x1,1);  // CONTENTION_RESOLUTION_TLLI = present
	dest->writeField(wp,TLLI,8*4);
	dest->writeField(wp,0x00,4); //spare
}

void RLCMACDispatchMessage(BitVector *vector)
{
	static uint8_t rlc_data[60];
	static uint8_t tfi = 0;
	static uint32_t tlli = 0;
	static unsigned dataIndex = 0;
	static unsigned startDispatch = 0;
	unsigned blockDataLen = 0;
	unsigned readIndex = 0;
	unsigned payload = vector->readField(readIndex, 2);

	switch (payload) {
	case RLCMAC_DATA_BLOCK: 
		{
			COUT("RLCMAC_DATA_BLOCK<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
			RlcMacUplinkDataBlock_t * dataBlock = (RlcMacUplinkDataBlock_t *)malloc(sizeof(RlcMacUplinkDataBlock_t));
			decode_gsm_rlcmac_uplink_data(vector, dataBlock);
			COUT("RLCMAC_DATA_BLOCK_END------------------------------");
			//TODO Implement other cases.
			if (dataBlock->BSN == 0)
			{
				startDispatch = 1;
			}
			if (startDispatch)
			{
				tfi = dataBlock->TFI;
				if (dataBlock->E_1 == 0) // Extension octet follows immediately
				{
					blockDataLen = dataBlock->LENGTH_INDICATOR[0];
				}
				else
				{
					blockDataLen = 20;
					if(dataBlock->TI == 1) // TLLI field is present
					{
						tlli = dataBlock->TLLI;
						blockDataLen -= 4;
						if (dataBlock->PI == 1) // PFI is present if TI field indicates presence of TLLI
						{
							blockDataLen -= 1;
						}
					}
				}
				unsigned dataOctetNum = 0;
				for (unsigned i = dataIndex;  i < dataIndex + blockDataLen; i++)
				{
					rlc_data[i] = dataBlock->RLC_DATA[dataOctetNum];
					dataOctetNum++;
				}
				dataIndex += blockDataLen;
				BitVector packetUplinkAck(23*8);
				packetUplinkAck.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
				writePUack(&packetUplinkAck, tfi, tlli, dataBlock->CV, dataBlock->BSN);
				COUT("RLCMAC_CONTROL_BLOCK>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
				RlcMacDownlink_t * pUA = (RlcMacDownlink_t *)malloc(sizeof(RlcMacUplink_t));
				decode_gsm_rlcmac_downlink(&packetUplinkAck, pUA);
				free(pUA);
				COUT("RLCMAC_CONTROL_BLOCK_END------------------------------");
				sendToOpenBTS(&packetUplinkAck);
			}
			if (dataBlock->CV == 0)
			{
				sendToSGSN(tfi, tlli, rlc_data, dataIndex);
				dataIndex = 0;
				startDispatch = 0;
			}
			free(dataBlock);
		}
		break;
	case RLCMAC_CONTROL_BLOCK:
		{
			COUT("RLCMAC_CONTROL_BLOCK<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<");
			RlcMacUplink_t * controlBlock = (RlcMacUplink_t *)malloc(sizeof(RlcMacUplink_t));
			decode_gsm_rlcmac_uplink(vector, controlBlock);
			free(controlBlock);
			COUT("RLCMAC_CONTROL_BLOCK_END------------------------------");
		}
		break;
	default:
		COUT("Unknown RLCMAC block payload\n");
	}
}

void *RLCMACSocket(void *)
{
	BitVector *vector = new BitVector(23*8);
	GPRSRLCMACSocket.nonblocking();
	while (1) {
		char buf[MAX_UDP_LENGTH];
		int count = GPRSRLCMACSocket.read(buf, 3000);
		if (count>0) {
			vector->unpack((const unsigned char*)buf);
			COUT("Recieve from OpenBTS (MS): " << *vector);
			RLCMACDispatchMessage(vector);
		}
	}
}
