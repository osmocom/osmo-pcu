/* bssgp.cpp
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

#include <arpa/inet.h>
#include <Threads.h>
#include "GPRSSocket.h"
#include "gsm_rlcmac.h"
#include "bssgp.h"

// TODO: We should move this parameters to config file.
#define SGSN_IP "127.0.0.1"
#define SGSN_PORT 23000
#define CELL_ID 3
#define BVCI 7
#define NSEI 3
#define NSVCI 4
#define MNC 1
#define MCC 1
#define LAC 1000
#define RAC 1

#define QOS_PROFILE 0
#define BSSGP_HDR_LEN 20
#define NS_HDR_LEN 4
#define MAX_LEN_PDU 100
#define IE_PDU 14
#define BLOCK_DATA_LEN 19

#define BLOCK_LEN 23

uint16_t bvci = BVCI;
uint16_t nsei = NSEI;
uint8_t TFI;
struct bssgp_bvc_ctx *bctx = btsctx_alloc(bvci, nsei);
struct gprs_nsvc *nsvc;
struct gprs_ns_inst *sgsn_nsi;
struct sgsn_instance *sgsn;
void *tall_bsc_ctx;

// Send RLC data to OpenBTS.
void sendRLC(uint32_t tlli, uint8_t *pdu, unsigned startIndex, unsigned endIndex, unsigned bsn, unsigned fbi)
{
	unsigned spareLen = 0;
	BitVector resultVector(BLOCK_LEN*8);
	resultVector.unhex("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
	RlcMacDownlinkDataBlock_t * dataBlock = (RlcMacDownlinkDataBlock_t *)malloc(sizeof(RlcMacDownlinkDataBlock_t));
	dataBlock->PAYLOAD_TYPE = 0;
	dataBlock->RRBP = 0;
	dataBlock->SP = 1;
	dataBlock->USF = 1;
	dataBlock->PR = 0;
	dataBlock->TFI = 20;
	dataBlock->FBI = fbi;
	dataBlock->BSN = bsn;
	if ((endIndex-startIndex) < 20)
	{
		dataBlock->E_1 = 0;
		dataBlock->LENGTH_INDICATOR[0] = endIndex-startIndex;
		dataBlock->M[0] = 0;
		dataBlock->E[0] = 1;
		spareLen = 19 - dataBlock->LENGTH_INDICATOR[0];
	}
	else
	{
		dataBlock->E_1 = 1; 
	}
	unsigned j = 0;
	for(unsigned i = startIndex; i < endIndex; i++)
	{
		dataBlock->RLC_DATA[j] = pdu[i];
		j++;
	}
	for(unsigned i = j; i < j + spareLen; i++)
	{
		dataBlock->RLC_DATA[i] = 0x2b;
	}
	encode_gsm_rlcmac_downlink_data(&resultVector, dataBlock);
	free(dataBlock);
	sendToOpenBTS(&resultVector);
}

/* Receive a BSSGP PDU from a BSS on a PTP BVCI */
int gprs_bssgp_bss_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;
	uint8_t pdu[MAX_LEN_PDU];
	unsigned rc = 0;
	unsigned dataIndex = 0;
	unsigned numBlocks = 0;
	unsigned i = 0;
	unsigned j = 0;
	unsigned pduIndex = 0;
	unsigned fbi = 0;
	struct bssgp_ud_hdr *budh;

	/* If traffic is received on a BVC that is marked as blocked, the
	* received PDU shall not be accepted and a STATUS PDU (Cause value:
	* BVC Blocked) shall be sent to the peer entity on the signalling BVC */
	if (bctx->state & BVC_S_BLOCKED && pdu_type != BSSGP_PDUT_STATUS)
	{
		uint16_t bvci = msgb_bvci(msg);
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVC_S_BLOCKED\n");
		return bssgp_tx_status(BSSGP_CAUSE_BVCI_BLOCKED, &bvci, msg);
	}

	switch (pdu_type) {
	case BSSGP_PDUT_DL_UNITDATA:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_DL_UNITDATA\n");
		budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP TLLI=0x%08x \n", ntohl(budh->tlli));
		for (i = 4; i < MAX_LEN_PDU; i++)
		{
			//LOGP(DBSSGP, LOGL_NOTICE, "SERCH data = -0x%02x\n", budh ->data[i]);
			if(budh ->data[i] == IE_PDU)
			{
				pduIndex = i+2;
				break;
			}
		}
		for (i = pduIndex; i < pduIndex + (budh->data[pduIndex-1]&0x7f); i++)
		{
			//LOGP(DBSSGP, LOGL_NOTICE, "-0x%02x\n", budh ->data[i]);
			pdu[dataIndex] = budh ->data[i];
			dataIndex++;
		}
		DEBUGP(DBSSGP, "BSSGP Catch from SGSN=%u octets. Send it to OpenBTS.\n", dataIndex);
		sendToGSMTAP(pdu,dataIndex);
		if (dataIndex > BLOCK_DATA_LEN + 1)
		{
			int blockDataLen = BLOCK_DATA_LEN;
			numBlocks = dataIndex/BLOCK_DATA_LEN;
			int ost = dataIndex%BLOCK_DATA_LEN;
			int startIndex = 0;
			int endIndex = 0;
			if (dataIndex%BLOCK_DATA_LEN > 0)
			{
				numBlocks++;
			}
			for (i = 0; i < numBlocks; i++)
			{
				if (i == numBlocks-1)
				{
					if (ost > 0)
					{
						blockDataLen = ost;
					}
					fbi = 1;
				}
				endIndex = startIndex + blockDataLen;
				sendRLC(ntohl(budh->tlli), pdu, startIndex, endIndex, i, fbi);
				startIndex += blockDataLen;
			}
		}
		else
		{
			sendRLC(ntohl(budh->tlli), pdu, 0, dataIndex, 0, 1);
		}
		break;
	case BSSGP_PDUT_PAGING_PS:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_PS\n");
		break;
	case BSSGP_PDUT_PAGING_CS:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_CS\n");
		break;
	case BSSGP_PDUT_RA_CAPA_UPDATE_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_RA_CAPA_UPDATE_ACK\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_FLOW_CONTROL_BVC_ACK\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_MS_ACK:
		LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_FLOW_CONTROL_MS_ACK\n");
		break;
	default:
		DEBUGP(DBSSGP, "BSSGP BVCI=%u PDU type 0x%02x unknown\n", bctx->bvci, pdu_type);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}
	return rc;
}

/* Receive a BSSGP PDU from a SGSN on a SIGNALLING BVCI */
int gprs_bssgp_bss_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	int rc = 0;
	switch (bgph->pdu_type) {
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		DEBUGP(DBSSGP, "BSSGP BVCI=%u Rx BVC STATUS\n", bctx->bvci);
		/* FIXME: send NM_STATUS.ind to NM */
		break;
		case BSSGP_PDUT_SUSPEND_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SUSPEND_ACK\n");
			break;
		case BSSGP_PDUT_SUSPEND_NACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SUSPEND_NACK\n");
			break;
		case BSSGP_PDUT_BVC_RESET_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_BVC_RESET_ACK\n");
			break;
		case BSSGP_PDUT_PAGING_PS:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_PS\n");
			break;
		case BSSGP_PDUT_PAGING_CS:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_PAGING_CS\n");
			break;
		case BSSGP_PDUT_RESUME_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_RESUME_ACK\n");
			break;
		case BSSGP_PDUT_RESUME_NACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_RESUME_NACK\n");
			break;
		case BSSGP_PDUT_FLUSH_LL:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_FLUSH_LL\n");
			break;
		case BSSGP_PDUT_BVC_BLOCK_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SUSPEND_ACK\n");
			break;
		case BSSGP_PDUT_BVC_UNBLOCK_ACK:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_BVC_UNBLOCK_ACK\n");
			break;
		case BSSGP_PDUT_SGSN_INVOKE_TRACE:
			LOGP(DBSSGP, LOGL_NOTICE, "rx BSSGP_PDUT_SGSN_INVOKE_TRACE\n");
			break;
		default:
			DEBUGP(DBSSGP, "BSSGP BVCI=%u Rx PDU type 0x%02x unknown\n", bctx->bvci, bgph->pdu_type);
			rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
			break;
	}
	return rc;
}

int gprs_bssgp_bss_rcvmsg(struct msgb *msg)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	uint16_t ns_bvci = msgb_bvci(msg);
	int data_len;
	int rc = 0;

	/* Identifiers from DOWN: NSEI, BVCI (both in msg->cb) */

	/* UNITDATA BSSGP headers have TLLI in front */
	if (pdu_type != BSSGP_PDUT_UL_UNITDATA && pdu_type != BSSGP_PDUT_DL_UNITDATA)
	{
		data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
		rc = bssgp_tlv_parse(&tp, bgph->data, data_len);
	}
	else
	{
		data_len = msgb_bssgp_len(msg) - sizeof(*budh);
		rc = bssgp_tlv_parse(&tp, budh->data, data_len);
	}

	/* look-up or create the BTS context for this BVC */
	bctx = btsctx_by_bvci_nsei(ns_bvci, msgb_nsei(msg));

	/* Only a RESET PDU can create a new BVC context */
	if (!bctx)
	{
		bctx = btsctx_alloc(ns_bvci, msgb_nsei(msg));
	}

	if (!bctx && pdu_type != BSSGP_PDUT_BVC_RESET_ACK)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "NSEI=%u/BVCI=%u Rejecting PDU "
			"type %u for unknown BVCI\n", msgb_nsei(msg), ns_bvci,
			pdu_type);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
	}

	if (bctx)
	{
		log_set_context(BSC_CTX_BVC, bctx);
		rate_ctr_inc(&bctx->ctrg->ctr[BSSGP_CTR_PKTS_IN]);
		rate_ctr_add(&bctx->ctrg->ctr[BSSGP_CTR_BYTES_IN], msgb_bssgp_len(msg));
	}

	if (ns_bvci == BVCI_SIGNALLING)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVCI_SIGNALLING gprs_bssgp_rx_sign\n");
		rc = gprs_bssgp_bss_rx_sign(msg, &tp, bctx);
	}
	else if (ns_bvci == BVCI_PTM)
	{
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVCI_PTM bssgp_tx_status\n");
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
	}
	else
	{
		LOGP(DBSSGP, LOGL_NOTICE, "rx BVCI_PTP gprs_bssgp_rx_ptp\n");
		rc = gprs_bssgp_bss_rx_ptp(msg, &tp, bctx);
	}
	return rc;
}


int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc, struct msgb *msg, uint16_t bvci)
{
	int rc = 0;
	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = gprs_bssgp_bss_rcvmsg(msg);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "RLCMAC: Unknown event %u from NS\n", event);
		if (msg)
			talloc_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}

// Send RLC data to SGSN.
void sendToSGSN(uint8_t tfi, uint32_t tlli, uint8_t * rlc_data, unsigned dataLen)
{
	const uint8_t qos_profile = QOS_PROFILE;
	struct msgb *llc_pdu;
	unsigned msgLen = NS_HDR_LEN + BSSGP_HDR_LEN + dataLen;
	TFI = tfi;
	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = MNC;
	bctx->ra_id.mcc = MCC;
	bctx->ra_id.lac = LAC;
	bctx->ra_id.rac = RAC;
	bctx->bvci = BVCI;
	LOGP(DBSSGP, LOGL_DEBUG, "Data len %u TLLI 0x%08x , TFI 0x%02x", dataLen, tlli, tfi);
	//for (unsigned i = 0; i < dataLen; i++)
	//	LOGP(DBSSGP, LOGL_DEBUG, " Data[%u] = %u", i, rlc_data[i]);
	llc_pdu = msgb_alloc_headroom(msgLen, msgLen,"llc_pdu");
	msgb_tvlv_push(llc_pdu, BSSGP_IE_LLC_PDU, sizeof(uint8_t)*dataLen, rlc_data);
	bssgp_tx_ul_ud(bctx, tlli, &qos_profile, llc_pdu);
}

void RLCMACServer()
{
	uint16_t nsvci = NSVCI;

	// Socket for reading BitVectors (RLC/MAC Frames) from OpenBTS application.
	Thread RLCMACInterface;
	RLCMACInterface.start(RLCMACSocket,NULL);

	osmo_init_logging(&log_info);
	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb);
	bssgp_nsi = sgsn_nsi;

	if (!bssgp_nsi)
	{
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}

	bctx->cell_id = CELL_ID;
	bctx->nsei = NSEI;
	bctx->ra_id.mnc = MNC;
	bctx->ra_id.mcc = MCC;
	bctx->ra_id.lac = LAC;
	bctx->ra_id.rac = RAC;
	bctx->bvci = BVCI;
	uint8_t cause = 39;
	gprs_ns_nsip_listen(sgsn_nsi);

	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(SGSN_PORT);
	inet_aton(SGSN_IP, &dest.sin_addr);

	nsvc = nsip_connect(sgsn_nsi, &dest, nsei, nsvci);
	unsigned i = 0;
	while (1) 
	{
		osmo_select_main(0);
		if (i == 7)
		{
			bssgp_tx_bvc_reset(bctx, bvci, cause);
		}
		i++;
	}
}
