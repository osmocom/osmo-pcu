/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "openbsc_clone.h"

#include <gprs_debug.h>

#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>

#include <errno.h>

/* Section 6.4 Commands and Responses */
enum gprs_llc_u_cmd {
	GPRS_LLC_U_DM_RESP		= 0x01,
	GPRS_LLC_U_DISC_CMD		= 0x04,
	GPRS_LLC_U_UA_RESP		= 0x06,
	GPRS_LLC_U_SABM_CMD		= 0x07,
	GPRS_LLC_U_FRMR_RESP		= 0x08,
	GPRS_LLC_U_XID			= 0x0b,
	GPRS_LLC_U_NULL_CMD		= 0x00,
};

#define LLC_ALLOC_SIZE 16384
#define UI_HDR_LEN	3
#define N202		4
#define CRC24_LENGTH	3

int gprs_llc_hdr_parse(struct gprs_llc_hdr_parsed *ghp,
			      const uint8_t *llc_hdr, int len)
{
	const uint8_t *ctrl = llc_hdr+1;

	if (len <= CRC24_LENGTH)
		return -EIO;

	ghp->crc_length = len - CRC24_LENGTH;

	ghp->ack_req = 0;

	/* Section 5.5: FCS */
	ghp->fcs = *(llc_hdr + len - 3);
	ghp->fcs |= *(llc_hdr + len - 2) << 8;
	ghp->fcs |= *(llc_hdr + len - 1) << 16;

	/* Section 6.2.1: invalid PD field */
	if (llc_hdr[0] & 0x80)
		return -EIO;

	/* This only works for the MS->SGSN direction */
	if (llc_hdr[0] & 0x40)
		ghp->is_cmd = 0;
	else
		ghp->is_cmd = 1;

	ghp->sapi = llc_hdr[0] & 0xf;

	/* Section 6.2.3: check for reserved SAPI */
	switch (ghp->sapi) {
	case 0:
	case 4:
	case 6:
	case 0xa:
	case 0xc:
	case 0xd:
	case 0xf:
		return -EINVAL;
	}

	if ((ctrl[0] & 0x80) == 0) {
		/* I (Information transfer + Supervisory) format */
		uint8_t k;

		ghp->data = ctrl + 3;

		if (ctrl[0] & 0x40)
			ghp->ack_req = 1;

		ghp->seq_tx  = (ctrl[0] & 0x1f) << 4;
		ghp->seq_tx |= (ctrl[1] >> 4);

		ghp->seq_rx  = (ctrl[1] & 0x7) << 6;
		ghp->seq_rx |= (ctrl[2] >> 2);

		switch (ctrl[2] & 0x03) {
		case 0:
			ghp->cmd = GPRS_LLC_RR;
			break;
		case 1:
			ghp->cmd = GPRS_LLC_ACK;
			break;
		case 2:
			ghp->cmd = GPRS_LLC_RNR;
			break;
		case 3:
			ghp->cmd = GPRS_LLC_SACK;
			k = ctrl[3] & 0x1f;
			ghp->data += 1 + k;
			break;
		}
		ghp->data_len = (llc_hdr + len - 3) - ghp->data;
	} else if ((ctrl[0] & 0xc0) == 0x80) {
		/* S (Supervisory) format */
		ghp->data = NULL;
		ghp->data_len = 0;

		if (ctrl[0] & 0x20)
			ghp->ack_req = 1;
		ghp->seq_rx  = (ctrl[0] & 0x7) << 6;
		ghp->seq_rx |= (ctrl[1] >> 2);

		switch (ctrl[1] & 0x03) {
		case 0:
			ghp->cmd = GPRS_LLC_RR;
			break;
		case 1:
			ghp->cmd = GPRS_LLC_ACK;
			break;
		case 2:
			ghp->cmd = GPRS_LLC_RNR;
			break;
		case 3:
			ghp->cmd = GPRS_LLC_SACK;
			break;
		}
	} else if ((ctrl[0] & 0xe0) == 0xc0) {
		/* UI (Unconfirmed Inforamtion) format */
		ghp->cmd = GPRS_LLC_UI;
		ghp->data = ctrl + 2;
		ghp->data_len = (llc_hdr + len - 3) - ghp->data;

		ghp->seq_tx  = (ctrl[0] & 0x7) << 6;
		ghp->seq_tx |= (ctrl[1] >> 2);
		if (ctrl[1] & 0x02) {
			ghp->is_encrypted = 1;
			/* FIXME: encryption */
		}
		if (ctrl[1] & 0x01) {
			/* FCS over hdr + all inf fields */
		} else {
			/* FCS over hdr + N202 octets (4) */
			if (ghp->crc_length > UI_HDR_LEN + N202)
				ghp->crc_length = UI_HDR_LEN + N202;
		}
	} else {
		/* U (Unnumbered) format: 1 1 1 P/F M4 M3 M2 M1 */
		ghp->data = NULL;
		ghp->data_len = 0;

		switch (ctrl[0] & 0xf) {
		case GPRS_LLC_U_NULL_CMD:
			ghp->cmd = GPRS_LLC_NULL;
			break;
		case GPRS_LLC_U_DM_RESP:
			ghp->cmd = GPRS_LLC_DM;
			break;
		case GPRS_LLC_U_DISC_CMD:
			ghp->cmd = GPRS_LLC_DISC;
			break;
		case GPRS_LLC_U_UA_RESP:
			ghp->cmd = GPRS_LLC_UA;
			break;
		case GPRS_LLC_U_SABM_CMD:
			ghp->cmd = GPRS_LLC_SABM;
			break;
		case GPRS_LLC_U_FRMR_RESP:
			ghp->cmd = GPRS_LLC_FRMR;
			break;
		case GPRS_LLC_U_XID:
			ghp->cmd = GPRS_LLC_XID;
			ghp->data = ctrl + 1;
			ghp->data_len = (llc_hdr + len - 3) - ghp->data;
			break;
		default:
			return -EIO;
		}
	}

	/* FIXME: parse sack frame */
	if (ghp->cmd == GPRS_LLC_SACK) {
		LOGP(DPCU, LOGL_NOTICE, "Unsupported SACK frame\n");
		return -EIO;
	}

	return 0;
}

const struct tlv_definition gsm48_gmm_att_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_FIXED, 1 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
	},
};
