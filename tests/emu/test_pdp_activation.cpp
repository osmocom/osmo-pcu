/* (C) 2013 by Holger Hans Peter Freyther
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

extern "C" {
#include <osmocom/core/msgb.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/gsm/gsm_utils.h>
}

#include "openbsc_clone.h"
#include "gprs_tests.h"

#include <gprs_bssgp_pcu.h>

#include <stdint.h>
#include <string.h>

static const uint8_t attach[] = {
	0x0e, 0x00, 0x26,
	0x01, 0xc0, 0x01, 0x08, 0x01, 0x02, 0xe5, 0x80,
	0x71, 0x0d, 0x01, 0x05, 0xf4, 0x02, 0x30, 0xef,
	0x0e, 0x09, 0xf1, 0x07, 0x00, 0x01, 0x00, 0x0b,
	0x34, 0xc7, 0x03, 0x2a, 0xa0, 0x42, 0x7c, 0xad,
	0xe1, 0x18, 0x0b, 0xf8, 0xef, 0xfc
};

static const uint8_t id_resp_imei[] = {
	0x0e, 0x00, 0x11,
	0x01, 0xc0, 0x05, 0x08, 0x16, 0x08, 0x3a, 0x49,
	0x50, 0x13, 0x28, 0x15, 0x80, 0x01, 0x21, 0x6c,
	0x22
};

static const uint8_t id_resp_imsi[] = {
	0x0e, 0x00, 0x11,
	0x01, 0xc0, 0x09, 0x08, 0x16, 0x08, 0x99, 0x10,
	0x07, 0x00, 0x00, 0x00, 0x03, 0x49, 0xc7, 0x5b,
	0xb6
};

static const uint8_t attach_complete[] = {
	0x0e, 0x00, 0x08,
	0x01, 0xc0, 0x0d, 0x08, 0x03, 0x55, 0x1c, 0xea
};

static const uint8_t pdp_context[] = {
	0x0e, 0x00, 0x5a,
	0x01, 0xc0, 0x11, 0x0a, 0x41, 0x05, 0x03, 0x0c,
	0x00, 0x00, 0x1f, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x21, 0x28,
	0x12, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e,
	0x65, 0x74, 0x05, 0x65, 0x70, 0x6c, 0x75, 0x73,
	0x02, 0x64, 0x65, 0x27, 0x2a, 0x80, 0xc0, 0x23,
	0x13, 0x01, 0x00, 0x00, 0x13, 0x05, 0x65, 0x70,
	0x6c, 0x75, 0x73, 0x08, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x80, 0x21, 0x10, 0x01,
	0x00, 0x00, 0x10, 0x81, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x83, 0x06, 0x00, 0x00, 0x00, 0x00, 0xcf,
	0x90, 0xcc
};

static const uint8_t qos_profile[] = { 0x0, 0x0, 0x04 };
static uint32_t tlli = 0xadf11821;

enum state {
	Test_Start,
	Test_IdRespIMEI,
	Test_IdRespIMSI,
	Test_AttachCompl,
	Test_PDPAct,
	Test_Done,
};

static enum state current_state = Test_Start;

static void extract_tmsi_and_generate_tlli(struct msgb *msg, struct tlv_parsed *tp)
{
	uint32_t tmsi;
	struct gprs_llc_hdr_parsed hp;
	struct tlv_parsed ack_tp;

	gprs_llc_hdr_parse(&hp, TLVP_VAL(tp, BSSGP_IE_LLC_PDU),
				TLVP_LEN(tp, BSSGP_IE_LLC_PDU));
	msgb_gmmh(msg) = (unsigned char *) hp.data;

	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);

	OSMO_ASSERT(gh->msg_type == GSM48_MT_GMM_ATTACH_ACK);
	struct gsm48_attach_ack *ack = (struct gsm48_attach_ack *) gh->data;
	tlv_parse(&ack_tp, &gsm48_gmm_att_tlvdef, ack->data,
			(msg->data + msg->len) - ack->data, 0, 0);


	OSMO_ASSERT(TLVP_PRESENT(&ack_tp, GSM48_IE_GMM_ALLOC_PTMSI));
	memcpy(&tmsi, TLVP_VAL(&ack_tp, GSM48_IE_GMM_ALLOC_PTMSI) + 1, 4);
	tmsi = ntohl(tmsi);
	tlli = gprs_tmsi2tlli(tmsi, TLLI_LOCAL);
	printf("New TLLI(0x%08x) based on tmsi(0x%x)\n", tlli, tmsi);
}

void test_pdp_activation_start(struct gprs_bssgp_pcu *pcu)
{
	struct msgb *msg = create_msg(attach, ARRAY_SIZE(attach));
	bssgp_tx_ul_ud(pcu->bctx, tlli, qos_profile, msg);
	current_state = Test_IdRespIMEI;
}


void test_pdp_activation_data(struct gprs_bssgp_pcu *pcu, struct msgb *msg, struct tlv_parsed *tp)
{
	const uint8_t *data;
	size_t len;

	switch (current_state) {
	case Test_IdRespIMEI:
		data = id_resp_imei;
		len = ARRAY_SIZE(id_resp_imei);
		current_state = Test_IdRespIMSI;
		break;
	case Test_IdRespIMSI:
		data = id_resp_imsi;
		len = ARRAY_SIZE(id_resp_imsi);
		current_state = Test_AttachCompl;
		break;
	case Test_AttachCompl:
		data = attach_complete;
		len = ARRAY_SIZE(attach_complete);
		extract_tmsi_and_generate_tlli(msg, tp);
		current_state = Test_PDPAct;
		break;
	case Test_PDPAct:
		printf("PDP context is active or not...\n");
		return;
		break;
	case Test_Done:
	case Test_Start: /* fall through */
		return;
		break;
	default:
		printf("Unknown state. %d\n", current_state);
		return;
		break;
	};

	struct msgb *out = create_msg(data, len);
	bssgp_tx_ul_ud(pcu->bctx, tlli, qos_profile, out);

	/* send it after the PDP... */
	if (current_state == Test_PDPAct) {
		out = create_msg(pdp_context, ARRAY_SIZE(pdp_context));
		bssgp_tx_ul_ud(pcu->bctx, tlli, qos_profile, out);
	}
}
