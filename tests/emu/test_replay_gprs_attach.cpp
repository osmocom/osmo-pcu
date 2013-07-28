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
}

#include <gprs_bssgp_pcu.h>

#include <stdint.h>
#include <string.h>

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

struct msgb *create_msg(const uint8_t *data, size_t len)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "create msg");
	msg->l3h = msgb_put(msg, len);
	memcpy(msg->l3h, data, len);
	return msg;
}

void test_replay_gprs_attach(struct gprs_bssgp_pcu *pcu)
{
	uint32_t tlli = 0xadf11820;
	const uint8_t qos_profile[] = { 0x0, 0x0, 0x04 };

	struct msgb *msg = create_msg(gprs_attach_llc, ARRAY_SIZE(gprs_attach_llc));
	bssgp_tx_ul_ud(pcu->bctx, tlli, qos_profile, msg);
}
