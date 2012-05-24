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
#include <openbsc/signal.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>
#include <osmocom/core/application.h>

int bssgp_tx_bvc_reset(struct bssgp_bvc_ctx *bctx, uint16_t bvci, uint8_t cause);

int bssgp_tx_ul_ud(struct bssgp_bvc_ctx *bctx, uint32_t tlli, const uint8_t *qos_profile, struct msgb *llc_pdu);

struct bssgp_bvc_ctx *btsctx_alloc(uint16_t bvci, uint16_t nsei);
}
#include <gprs_debug.h>

#define BVCI 7
#define NSEI 3

#define QOS_PROFILE 0
#define BSSGP_HDR_LEN 20
#define NS_HDR_LEN 4
#define MAX_LEN_PDU 60
#define IE_PDU 14
#define BLOCK_DATA_LEN 19
#define BLOCK_LEN 23

#define CELL_ID 3
#define MNC 55
#define MCC 905
#define PCU_LAC 1000
#define PCU_RAC 1


extern struct bssgp_bvc_ctx *bctx;

int gprs_bssgp_pcu_rx_dl_ud(struct msgb *msg);

int gprs_bssgp_pcu_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx);

int gprs_bssgp_pcu_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx);

int gprs_bssgp_pcu_rcvmsg(struct msgb *msg);

#endif // GPRS_BSSGP_PCU_H
