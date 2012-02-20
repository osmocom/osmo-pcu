/* bssgp.h
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
 
#ifndef BSSGP_H
#define BSSGP_H

extern "C" {
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>
#include <osmocom/core/application.h>

int bssgp_tx_bvc_reset(struct bssgp_bvc_ctx *bctx, uint16_t bvci, uint8_t cause);

int bssgp_tx_ul_ud(struct bssgp_bvc_ctx *bctx, uint32_t tlli, const uint8_t *qos_profile, struct msgb *llc_pdu);

struct bssgp_bvc_ctx *btsctx_alloc(uint16_t bvci, uint16_t nsei);
}

void sendRLC(uint32_t tlli, uint8_t *pdu, unsigned startIndex, unsigned endIndex, unsigned bsn);

int gprs_bssgp_bss_rx_ptp(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx);

int gprs_bssgp_bss_rx_sign(struct msgb *msg, struct tlv_parsed *tp, struct bssgp_bvc_ctx *bctx);

int gprs_bssgp_bss_rcvmsg(struct msgb *msg);

int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc, struct msgb *msg, uint16_t bvci);

void sendToSGSN(uint8_t tfi, uint32_t tlli, uint8_t * rlc_data, unsigned dataLen);

void RLCMACServer();

#endif // BSSGP_H
