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
UDPSocket pcu_gsmtap_socket(5077, "127.0.0.1", 4729);

// Variable for storage current FN.
int frame_number;

int get_current_fn()
{
	return frame_number;
}

void set_current_fn(int fn)
{
	frame_number = fn;
}

struct msgb *l1p_msgb_alloc(void)
{
	struct msgb *msg = msgb_alloc(sizeof(GsmL1_Prim_t), "l1_prim");

	if (msg)
		msg->l1h = msgb_put(msg, sizeof(GsmL1_Prim_t));

	return msg;
}

struct msgb *gen_dummy_msg(void)
{
	int ofs = 0;
	struct msgb *msg = l1p_msgb_alloc();
	GsmL1_Prim_t *prim = msgb_l1prim(msg);
	// RLC/MAC filler with USF=1
	BitVector filler("0100000110010100001010110010101100101011001010110010101100101011001010110010101100101011001010110010101100101011001010110010101100101011001010110010101100101011001010110010101100101011");
	prim->id = GsmL1_PrimId_PhDataReq;
	prim->u.phDataReq.sapi = GsmL1_Sapi_Pacch;
	filler.pack((unsigned char*)&(prim->u.phDataReq.msgUnitParam.u8Buffer[ofs]));
	ofs += filler.size() >> 3;
	prim->u.phDataReq.msgUnitParam.u8Size = ofs;
	return msg;
}

// Send RLC/MAC block to OpenBTS.
void pcu_l1if_tx(BitVector * block, GsmL1_Sapi_t sapi, int len)
{
	int ofs = 0;
	struct msgb *msg = l1p_msgb_alloc();
	struct osmo_wqueue * queue;
	queue = &((l1fh->fl1h)->write_q);
	GsmL1_Prim_t *prim = msgb_l1prim(msg);
	
	prim->id = GsmL1_PrimId_PhDataReq;
	prim->u.phDataReq.sapi = sapi;
	block->pack((unsigned char*)&(prim->u.phDataReq.msgUnitParam.u8Buffer[ofs]));
	ofs += block->size() >> 3;
	prim->u.phDataReq.msgUnitParam.u8Size = len;
	
	COUT("Add Block to WRITE QUEUE: " << *block);
	osmo_wqueue_enqueue(queue, msg);
}

int pcu_l1if_rx_pdch(GsmL1_PhDataInd_t *data_ind)
{
	BitVector *block = new BitVector(23*8);
	block->unpack((const unsigned char*)data_ind->msgUnitParam.u8Buffer);
	COUT("RX: " << *block);
	
	gprs_rlcmac_rcv_block(block);
}

static int handle_ph_connect_ind(struct femtol1_hdl *fl1, GsmL1_PhConnectInd_t *connect_ind)
{
	(l1fh->fl1h)->channel_info.arfcn = connect_ind->u16Arfcn;
	(l1fh->fl1h)->channel_info.tn = connect_ind->u8Tn;
	(l1fh->fl1h)->channel_info.tsc = connect_ind->u8Tsc;
	COUT("RX: [ PCU <- BTS ] PhConnectInd: ARFCN: " << connect_ind->u16Arfcn 
		<<" TN: " << (unsigned)connect_ind->u8Tn << " TSC: " << (unsigned)connect_ind->u8Tsc);
}

static int handle_ph_readytosend_ind(struct femtol1_hdl *fl1, GsmL1_PhReadyToSendInd_t *readytosend_ind)
{
	struct msgb *resp_msg;
	struct osmo_wqueue * queue;
	queue = &((l1fh->fl1h)->write_q);
	
	set_current_fn(readytosend_ind->u32Fn);
	resp_msg = msgb_dequeue(&queue->msg_queue);
	if (!resp_msg) {
		resp_msg = gen_dummy_msg();
		if (!resp_msg)
			return 0;
	}
	osmo_wqueue_enqueue(&l1fh->udp_wq, resp_msg);
	return 1;
}

static int handle_ph_data_ind(struct femtol1_hdl *fl1, GsmL1_PhDataInd_t *data_ind)
{
	int rc = 0;
	switch (data_ind->sapi) {
	case GsmL1_Sapi_Rach:
		break;
	case GsmL1_Sapi_Pdtch:
	case GsmL1_Sapi_Pacch:
		pcu_l1if_rx_pdch(data_ind);
		break;
	case GsmL1_Sapi_Pbcch:
	case GsmL1_Sapi_Pagch:
	case GsmL1_Sapi_Ppch:
	case GsmL1_Sapi_Pnch:
	case GsmL1_Sapi_Ptcch:
	case GsmL1_Sapi_Prach:
		break;
	default:
		//LOGP(DGPRS, LOGL_NOTICE, "Rx PH-DATA.ind for unknown L1 SAPI %u \n", data_ind->sapi);
		break;
	}

	return rc;
}

static int handle_ph_ra_ind(struct femtol1_hdl *fl1, GsmL1_PhRaInd_t *ra_ind)
{
	int rc = 0;
	(l1fh->fl1h)->channel_info.ta = ra_ind->measParam.i16BurstTiming;
	rc = gprs_rlcmac_rcv_rach(ra_ind->msgUnitParam.u8Buffer[0], ra_ind->u32Fn, ra_ind->measParam.i16BurstTiming);
	return rc;
}

/* handle any random indication from the L1 */
int pcu_l1if_handle_l1prim(struct femtol1_hdl *fl1, struct msgb *msg)
{
	GsmL1_Prim_t *l1p = msgb_l1prim(msg);
	int rc = 0;

	switch (l1p->id) {
	case GsmL1_PrimId_PhConnectInd:
		rc = handle_ph_connect_ind(fl1, &l1p->u.phConnectInd);
		break;
	case GsmL1_PrimId_PhReadyToSendInd:
		rc = handle_ph_readytosend_ind(fl1, &l1p->u.phReadyToSendInd);
		break;
	case GsmL1_PrimId_PhDataInd:
		rc = handle_ph_data_ind(fl1, &l1p->u.phDataInd);
		break;
	case GsmL1_PrimId_PhRaInd:
		rc = handle_ph_ra_ind(fl1, &l1p->u.phRaInd);
		break;
	default:
		break;
	}

	/* Special return value '1' means: do not free */
	if (rc != 1)
		msgb_free(msg);

	return rc;
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
