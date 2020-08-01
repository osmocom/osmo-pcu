/* gprs_bssgp_pcu.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_bss.h>
#include <osmocom/gprs/gprs_msgb.h>

struct bssgp_bvc_ctx *btsctx_alloc(uint16_t bvci, uint16_t nsei);
}
#include <gprs_debug.h>

#include <time.h>

#define QOS_PROFILE 4
#define BSSGP_HDR_LEN 53
#define NS_HDR_LEN 4
#define IE_LLC_PDU 14

struct gprs_bssgp_pcu {
	struct bssgp_bvc_ctx *bctx;

	struct gprs_rlcmac_bts *bts;

	struct osmo_timer_list bvc_timer;

	int nsvc_unblocked;

	int bvc_sig_reset;
	int bvc_reset;
	int bvc_unblocked;

	/* Flow control */
	struct timespec queue_delay_sum;
	unsigned queue_delay_count;
	uint8_t fc_tag;
	unsigned queue_frames_sent;
	unsigned queue_bytes_recv;
	unsigned queue_frames_recv;

	/** callbacks below */

	/* The BSSGP has been unblocked */
	void (*on_unblock_ack)(struct gprs_bssgp_pcu *pcu);

	/* When BSSGP data arrives. The msgb is not only for reference */
	void (*on_dl_unit_data)(struct gprs_bssgp_pcu *pcu, struct msgb *msg,
				struct tlv_parsed *tp);
};

struct gprs_bssgp_pcu *gprs_bssgp_create_and_connect(struct gprs_rlcmac_bts *bts,
	struct osmo_sockaddr *local, struct osmo_sockaddr *sgsn,
	uint16_t nsei, uint16_t nsvci, uint16_t bvci,
	uint16_t mcc, uint16_t mnc, bool mnc_3_digits,
	uint16_t lac, uint16_t rac, uint16_t cell_id);


int gprs_bssgp_ns_cb(enum gprs_ns2_evt event, struct msgb *msg,
		     uint16_t nsei, uint16_t bvci);

void gprs_bssgp_destroy(struct gprs_rlcmac_bts *bts);

struct bssgp_bvc_ctx *gprs_bssgp_pcu_current_bctx(void);

void gprs_bssgp_update_queue_delay(const struct timespec *tv_recv,
		const struct timespec *tv_now);
void gprs_bssgp_update_frames_sent();
void gprs_bssgp_update_bytes_received(unsigned bytes_recv, unsigned frames_recv);

#endif // GPRS_BSSGP_PCU_H
