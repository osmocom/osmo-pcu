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

/* GPRS attach with a foreign TLLI */
static const uint8_t gprs_attach_llc[] = {
	/* LLC-PDU IE */
	0x0e, 0x00, 0x2e,

	0x01, 0xc0, 0x01, 0x08, 0x01, 0x02, 0xf5, 0x40,
	0x71, 0x08, 0x00, 0x05, 0xf4, 0x2d, 0xf1, 0x18,
	0x20, 0x62, 0xf2, 0x10, 0x09, 0x67, 0x00, 0x13,
	0x16, 0x73, 0x43, 0x2a, 0x80, 0x42, 0x00, 0x42,
	0x88, 0x0b, 0x04, 0x20, 0x04, 0x2e, 0x82, 0x30,
	0x42, 0x00, 0x40, 0xaa, 0xf3, 0x18
};

static uint32_t next_wanted_nu;

void test_replay_gprs_attach(struct gprs_bssgp_pcu *pcu)
{
	uint32_t tlli = 0xadf11820;
	const uint8_t qos_profile[] = { 0x0, 0x0, 0x04 };

	next_wanted_nu = 0;
	struct msgb *msg = create_msg(gprs_attach_llc, ARRAY_SIZE(gprs_attach_llc));
	bssgp_tx_ul_ud(pcu->bctx, tlli, qos_profile, msg);
}

void test_replay_gprs_data(struct gprs_bssgp_pcu *pcu, struct msgb *msg, struct tlv_parsed *tp)
{
	struct bssgp_ud_hdr *budh;
	struct gprs_llc_hdr_parsed ph;
	uint32_t tlli;

	if (!TLVP_PRESENT(tp, BSSGP_IE_LLC_PDU))
		return;


	gprs_llc_hdr_parse(&ph, TLVP_VAL(tp, BSSGP_IE_LLC_PDU),
				TLVP_LEN(tp, BSSGP_IE_LLC_PDU));

	budh = (struct bssgp_ud_hdr *)msgb_bssgph(msg);
	tlli = ntohl(budh->tlli);

	/* all messages we should get, should be for a foreign tlli */
	OSMO_ASSERT(gprs_tlli_type(tlli) == TLLI_FOREIGN);
	printf("TLLI(0x%08x) is foreign!\n", tlli);

	OSMO_ASSERT(ph.cmd == GPRS_LLC_UI);
	OSMO_ASSERT(ph.sapi == 1);
	OSMO_ASSERT(ph.seq_tx == next_wanted_nu);
	next_wanted_nu += 1;

	/* this test just wants to see messages... no further data is sent */
	if (next_wanted_nu == 6) {
		printf("GPRS attach with increasing N(U) done.\n");
		gprs_test_success(pcu);
	}
}
