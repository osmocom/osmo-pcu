/* gprs_bssgp_pcu.h
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

#ifndef GPRS_BSSGP_PCU_H
#define GPRS_BSSGP_PCU_H


extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/application.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_bss.h>
#include <osmocom/gprs/gprs_msgb.h>

struct bssgp_bvc_ctx *btsctx_alloc(uint16_t bvci, uint16_t nsei);
}
#include <gprs_debug.h>

#define QOS_PROFILE 4
#define BSSGP_HDR_LEN 53
#define NS_HDR_LEN 4
#define IE_LLC_PDU 14

extern struct bssgp_bvc_ctx *bctx;

int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg, struct tlv_parsed *tp);

int gprs_bssgp_pcu_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx);

int gprs_bssgp_pcu_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx);

int gprs_bssgp_pcu_rcvmsg(struct msgb *msg);

int gprs_bssgp_create(uint16_t local_port, uint32_t sgsn_ip, uint16_t
		sgsn_port, uint16_t nsei, uint16_t nsvci, uint16_t bvci,
		uint16_t mcc, uint16_t mnc, uint16_t lac, uint16_t rac,
		uint16_t cell_id);

void gprs_bssgp_destroy(void);

#endif // GPRS_BSSGP_PCU_H
