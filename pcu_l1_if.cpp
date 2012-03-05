/* pcu_l1_if.cpp
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

#include <Sockets.h>
#include <gsmtap.h>
#include <gprs_rlcmac.h>
#include <Threads.h>
#include <pcu_l1_if.h>

#define MAX_UDP_LENGTH 1500

// TODO: We should take ports and IP from config.
UDPSocket pcu_l1if_socket(5070, "127.0.0.1", 5934);
UDPSocket pcu_gsmtap_socket(5077, "127.0.0.1", 4729);

// Send RLC/MAC block to OpenBTS.
void pcu_l1if_tx(BitVector * block)
{
	char buffer[MAX_UDP_LENGTH];
	int ofs = 0;
	block->pack((unsigned char*)&buffer[ofs]);
	ofs += block->size() >> 3;
	COUT("Send to OpenBTS: " << *block);
	pcu_l1if_socket.write(buffer, ofs);
}

// Recieve RLC/MAC block from OpenBTS.
void *pcu_l1if_rx(void *)
{
	BitVector *block = new BitVector(23*8);
	pcu_l1if_socket.nonblocking();
	while (1) {
		char buf[MAX_UDP_LENGTH];
		int count = pcu_l1if_socket.read(buf, 3000);
		if (count>0) {
			block->unpack((const unsigned char*)buf);
			COUT("Recieve from OpenBTS (MS): " << *block);
			gprs_rlcmac_rcv_block(block);
		}
	}
}

void gsmtap_send_llc(uint8_t * data, unsigned len)
{
	char buffer[MAX_UDP_LENGTH];
	int ofs = 0;

	// Build header
	struct gsmtap_hdr *header = (struct gsmtap_hdr *)buffer;
	header->version			= 2;
	header->hdr_len			= sizeof(struct gsmtap_hdr) >> 2;
	header->type			= 0x08;
	header->timeslot		= 5;
	header->arfcn			= 0;
	header->signal_dbm		= 0;
	header->snr_db			= 0;
	header->frame_number	= 0;
	header->sub_type		= 0;
	header->antenna_nr		= 0;
	header->sub_slot		= 0;
	header->res				= 0;

	ofs += sizeof(*header);

	// Add frame data
	unsigned j = 0;
	for (unsigned i = ofs; i < len+ofs; i++)
	{
		buffer[i] = (char)data[j];
		j++;
	}
	ofs += len;
	// Write the GSMTAP packet
	pcu_gsmtap_socket.write(buffer, ofs);
}
