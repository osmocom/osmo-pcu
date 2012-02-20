/*GPRSSocket.h
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

#ifndef GPRSSOCKET_H
#define GPRSSOCKET_H

#include <BitVector.h>
#include "gsm_rlcmac.h"


enum DataBlockDispatcherState {
	WaitSequenceStart,
	WaitNextBlock,
	WaitNextSequence
};

void sendToGSMTAP(uint8_t * data, unsigned len);

void sendToOpenBTS(BitVector * vector);

void writePUack(BitVector * dest, uint8_t TFI, uint32_t TLLI, unsigned CV, unsigned BSN);

void RLCMACExtractData(uint8_t* tfi, uint32_t* tlli, RlcMacUplinkDataBlock_t * dataBlock, uint8_t* rlc_data, unsigned* dataIndex);

void sendUplinkAck(uint8_t tfi, uint32_t tlli, RlcMacUplinkDataBlock_t * dataBlock);

void RLCMACDispatchDataBlock(BitVector *vector, uint8_t* tfi, uint32_t* tlli, uint8_t* rlc_data, unsigned* dataIndex);

void RLCMACDispatchBlock(BitVector *vector);

void *RLCMACSocket(void *);

#endif // GPRSSOCKET_H
