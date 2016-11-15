/* l2tp to PCU interface */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Harald Welte, Philipp Maier
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
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <bts.h>
#include "gprs_debug.h"
#include "pgsl.h"
#include "pgsl_l1_if.h"
#include "l2tp_sock.h"

enum pdch_cs_len {
	PDCH_CS_1 = 23,
	PDCH_CS_2 = 34,
	PDCH_CS_3 = 40,
	PDCH_CS_4 = 54,
	PDCH_MCS_1 = 27,
	PDCH_MCS_2 = 33,
	PDCH_MCS_3 = 42,
	PDCH_MCS_4 = 49,
	PDCH_MCS_5 = 60,
	PDCH_MCS_6 = 78,
	PDCH_MCS_7 = 118,
	PDCH_MCS_8 = 142,
	PDCH_MCS_9 = 154
};

#define DEBUG_DISABLE_SEQNO_CHECK 1
#define LAPD_HDR_LEN 2
#define LAPD_SAPI_SHIFT 10
#define LAPD_SAPI_MASK 0xfc00
#define LAPD_TEI_SHIFT 1
#define LAPD_TEI_MASK  0x00fe
#define LAPD_EA2_BIT_MASK 0x0001

/* Note: Ericsson uses a fixed TEI=>Transceiver assignment. (TRX0 = TEI0, ...)
 * This results in a possible maximum of 128 transceivers, however more than
 * 12 transceivers on one BTS wil not make sense in practice */
#define TRX_MAX 128

/* Note: Ericssons PGSL protocol is assigned to SAPI=12, the asignment is
 * fix and can not be changed */
#define LAPD_SAPI_PGSL 12

/* convenience logging macro for per-TN log lines */
#define LOGPTN(tns, logl, fmt, args ...) \
	LOGP(DPGSL, logl, "(%u/%u) " fmt, (tns)->trxs->nr, (tns)->tn, ##args)

/* (tns-variable) */
struct pgsl_tn_state {
	/* back-pointer to TRX */
	struct pgsl_trx_state *trxs;
	/* timeslot number */
	uint8_t tn;
	struct {
		/* next expected rx seqno from CCU */
		uint8_t next_seqno;
	} rx;
	struct {
		/* next tx seqno towards CCU */
		uint8_t next_seqno;
	} tx;
};

/* (ps variable) */
struct pgsl_trx_state {
	/* TRX number */
	uint32_t nr;
	/* next expected rx seqno from CCU */
	uint8_t next_seqno;
	/* per-timeslot state */
	struct pgsl_tn_state tn[8];
};

static struct pgsl_trx_state ps[TRX_MAX];

/* Check that the trx sequence number of incoming frames is consecutive */
static int check_inc_trx_seqno(struct pgsl_trx_state *ps, uint32_t trx_seqno)
{
#if DEBUG_DISABLE_SEQNO_CHECK == 0
	if (ps->next_seqno != trx_seqno) {
		LOGP(DPGSL, LOGL_ERROR,
		     "Gap in TRX seqno detected (trx_seqno=%u, expected=%u)\n",
		     trx_seqno, ps->next_seqno);
		return -1;
	}
#endif
	ps->next_seqno = trx_seqno + 1;
	return 0;
}

/* Check that the rn sequence number of incoming frames is consecutive */
static int check_inc_tn_seqno(struct pgsl_tn_state *tns, uint32_t tn_seqno)
{
#if DEBUG_DISABLE_SEQNO_CHECK == 0
	if (tns->rx.next_seqno != tn_seqno) {
		LOGPTN(tns, LOGL_ERROR,
		       "Gap in TN seqno detected (tn_seqno=%u, expected=%u)\n",
		       tn_seqno, tns->rx.next_seqno);
		return -1;
	}
#endif
	tns->rx.next_seqno = tn_seqno + 1;
	return 0;
}

/* Get the trx state for a specified time slot number */
static struct pgsl_tn_state *resolve_tn_state(struct pgsl_trx_state *ps,
					      uint8_t tn)
{
	OSMO_ASSERT(tn < ARRAY_SIZE(ps->tn));
	return &ps->tn[tn];
}

/* Initalize the pgsl frame structure */
static inline void *pgsl_frm_init(struct er_pgsl_frame *frm,
				  enum er_pgsl_frame_type type)
{
	memset(frm, 0, sizeof(*frm));
	frm->type = type;
	return &frm->u;
}

/* Receive ULDATA.ind (ccu sends uplink data to PCU) */
static int rx_uldata_ind(struct pgsl_tn_state *tns,
			 const struct decoded_uldata_ind *ind)
{
	LOGPTN(tns, LOGL_DEBUG, "Rx ULDATA.ind (fn=%u, cs=%u, data=%s)\n",
	       ind->afn_u, ind->cs_ucm, osmo_hexdump(ind->data, ind->data_len));

	/* Hand over data to PCU logic */
	return pcu_rx_data_ind_pdtch(tns->trxs->nr, tns->tn,
				     (uint8_t *) ind->data, ind->data_len,
				     ind->afn_u, NULL);
}

/* Calculate GPRS block number from frame number */
static uint8_t fn_to_block_nr(uint32_t fn)
{
	/* Note: See also 3GPP TS 03.64 6.5.7.2.1,
	 * Mapping on the multiframe structure */

	uint8_t rel_fn;
	uint8_t super_block;
	uint8_t local_block;

	rel_fn = fn % 52;

	/* Warn in case of frames that do not belong to a block */
	if (rel_fn == 12 || rel_fn == 25 || rel_fn == 38 || rel_fn == 51)
		LOGP(DPGSL, LOGL_ERROR,
		     "Frame number is referencing invalid block!\n");

	super_block = (rel_fn / 13);
	local_block = rel_fn % 13 / 4;
	return super_block * 3 + local_block;
}

/* Receive DLDATA.ind (ccu is ready to receive downlink data from pcu) */
static int rx_dldata_req(struct pgsl_trx_state *ps,
			 const struct decoded_dldata_req *req)
{
	int rc = 0;
	int final_rc = 0;
	int i;

	DEBUGP(DPGSL,
	       "Rx DLDATA.req (tn_bitmap=0x%02x, fn=%u, ta=%u, ack=%u)\n",
	       req->tn_bitmap, req->afn_d, req->ccu_ta, req->ack_req);

	/* iterate over TN bitmap and send one response for each TN */
	for (i = 0; i < 8; i++) {
		if (req->tn_bitmap & (1 << i)) {
			LOGP(DPGSL, LOGL_DEBUG,
			     "Rx DLDATA.req for ts number: %d\n", i);

			/* Forward DLDATA.req to PCU */
			rc = pcu_rx_rts_req_pdtch(ps->nr, i, req->afn_d,
						  fn_to_block_nr(req->afn_d));

			if (rc) {
				final_rc = -1;
				LOGP(DPGSL, LOGL_ERROR,
				     "Rx DLDATA.req for ts number: %d\n", i);
			}
		}
	}

	return final_rc;
}

/* Receive STATUS.ind (ccu transmits status information to PCU) */
static int rx_status_ind(struct pgsl_tn_state *tns,
			 const struct decoded_status_ind *ind)
{
	LOGPTN(tns, LOGL_NOTICE,
	       "Rx STATUS.ind (tn=%u, cause=0x%02x, addl_info=0x%02x)\n",
	       ind->tn, ind->cause, ind->addl_info);
	/* FIXME: pass up to PCU */
	return 0;
}

/* Defer parsed pgsl frame */
static int rx_pgsl_frame(struct pgsl_trx_state *ps,
			 const struct er_pgsl_frame *frame)
{
	int rc = 0;
	struct pgsl_tn_state *tn_state;

	switch (frame->type) {
	case ER_PGSL_DLDATA_REQ:
		LOGP(DPGSL, LOGL_DEBUG,
		     "received pgsl frame is of type: DLDATA.req\n");
		check_inc_trx_seqno(ps, frame->u.dldata_req.trx_seqno);
		rc = rx_dldata_req(ps, &frame->u.dldata_req);
		break;
	case ER_PGSL_ULDATA_IND:
		LOGP(DPGSL, LOGL_DEBUG,
		     "received pgsl frame is of type: ULDATA.req\n");
		tn_state = resolve_tn_state(ps, frame->u.uldata_ind.tn);
		check_inc_tn_seqno(tn_state, frame->u.uldata_ind.tn_seqno);
		rc = rx_uldata_ind(tn_state, &frame->u.uldata_ind);
		break;
	case ER_PGSL_STATUS_IND:
		LOGP(DPGSL, LOGL_DEBUG,
		     "received pgsl frame is of type: STATUS.ind\n");
		tn_state = resolve_tn_state(ps, frame->u.status_ind.tn);
		check_inc_tn_seqno(tn_state, frame->u.status_ind.tn_seqno);
		rc = rx_status_ind(tn_state, &frame->u.status_ind);
		break;
	default:
		LOGP(DPGSL, LOGL_ERROR,
		     "Unknown P-GSL frame type 0x%02x received\n", frame->type);
		return -1;
	}

	return rc;
}

/* Initalize pgsl interface (called by l2tp_sock_init() int l2tp_sock.c)*/
void pgsl_init(void)
{
	unsigned int i;
	unsigned int k;

	/* Initalize states */
	memset(&ps, 0, sizeof(*ps) * TRX_MAX);
	for (k = 0; k < TRX_MAX; k++) {
		/* Backpointer (timeslot->transceiver) */
		for (i = 0; i < 8; i++)
			ps[k].tn[i].trxs = &ps[k];

		/* Transceiver number */
		ps[k].nr = k;
	}

	LOGP(DPGSL, LOGL_DEBUG, "pgsl-interface inizalized.\n");
}

/* Extract the TEI from the lapd header */
int get_tei_from_lapdhdr(struct msgb *msg, uint8_t *tei)
{
	uint16_t lapd_address = osmo_load16be(msgb_data(msg));
	uint8_t sapi = lapd_address >> LAPD_SAPI_SHIFT;

	LOGP(DPGSL, LOGL_DEBUG, "lapd sapi=%i\n", sapi);

	/* Check id SAPI has the expected value */
	if (sapi != LAPD_SAPI_PGSL) {
		LOGP(DPGSL, LOGL_ERROR,
		     "Unexpected SAPI value, should be %d not %d\n",
		     LAPD_SAPI_PGSL, sapi);
		return -1;
	}

	*tei = (lapd_address & LAPD_TEI_MASK) >> LAPD_TEI_SHIFT;
	LOGP(DPGSL, LOGL_DEBUG, "lapd tei=%i\n", *tei);
	return 0;
}

/* receive message from l2tp socket (called by socket_rx() in l2tp_sock.c) */
void pgsl_msg_rx(struct msgb *msg)
{
	char *hexdump;
	int rc;
	uint8_t tei;
	struct er_pgsl_frame frame;

	hexdump = osmo_hexdump_nospc(msg->data, msg->len);
	LOGP(DPGSL, LOGL_DEBUG, "message received: %s\n", hexdump);

	/* Resolve TEI from LAPD-Header */
	rc = get_tei_from_lapdhdr(msg, &tei);
	if (rc < 0) {
		LOGP(DPGSL, LOGL_ERROR, "message tossed!\n");
		return;
	}

	/* Decode incoming pgsl frame */
	rc = er_pgsl_parse(&frame, msg->data + LAPD_HDR_LEN,
			   msg->len - LAPD_HDR_LEN);
	if (rc < 0) {
		LOGP(DPGSL, LOGL_ERROR, "unable to decode pgsl-frame!\n");
		return;
	}

	/* Forward parsed pgsl frame to input logic */
	rc = rx_pgsl_frame(&ps[tei], &frame);
	if (rc < 0) {
		LOGP(DPGSL, LOGL_ERROR, "unable to handle pgsl data!\n");
		return;
	}
}

/* Find out the trx number (=tei) for a given ARFCN */
static int arfcn_to_trx(uint8_t *trx, uint16_t arfcn)
{
	unsigned int i;
	unsigned int len;
	struct gprs_rlcmac_bts *bts;
	bts = bts_main_data();

	len = sizeof(bts->trx) / sizeof(bts->trx[0]);

	for (i = 0; i < len; i++) {
		if (bts->trx[i].arfcn == arfcn) {
			*trx = bts->trx[i].trx_no;
			return 0;
		}
	}

	return -1;
}

/* Generate lapd header */
static void gen_lapd_hdr(struct msgb *msg, uint8_t tei)
{
	uint16_t lapd_address = 0;
	lapd_address |= (LAPD_SAPI_PGSL << LAPD_SAPI_SHIFT) & LAPD_SAPI_MASK;
	lapd_address |= tei << LAPD_TEI_SHIFT & LAPD_TEI_MASK;
	lapd_address |= LAPD_EA2_BIT_MASK;
	osmo_store16be(lapd_address, msgb_data(msg));
	msgb_put(msg, LAPD_HDR_LEN);
}

/* send packet data request to L1 */
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn,
		  uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len)
{
	/* Note: In this implementation we assume is_ptcch=0. We also
	 * intenionally the *obj parameter */

	struct er_pgsl_frame frame;
	struct msgb *msg = msgb_alloc(1500, "tx pgsl");
	int rc;
	/* TODO: Resolve TEI from arfcn! */
	uint8_t tei;
	arfcn_to_trx(&tei, arfcn);

	/* Feature not supported yet */
	OSMO_ASSERT(is_ptcch == 0);

	/* Encode lapd header */
	gen_lapd_hdr(msg, tei);

	/* Encode pgsl frame */
	memset(&frame, 0, sizeof(frame));
	frame.type = ER_PGSL_DLDATA_IND;
	frame.u.dldata_ind.tn = ts;
	frame.u.dldata_ind.tn_seqno = ps[tei].tn[ts].tx.next_seqno;
	frame.u.dldata_ind.afn_d = fn;
	frame.u.dldata_ind.ack_ind = true;
	if (len)
		frame.u.dldata_ind.data_ind = true;
	else
		frame.u.dldata_ind.data_ind = false;

	switch (len) {
	case PDCH_CS_1:
		frame.u.dldata_ind.cs = ER_PGSL_CS_CS1;
		break;
	case PDCH_CS_2:
		frame.u.dldata_ind.cs = ER_PGSL_CS_CS2;
		break;
	case PDCH_CS_3:
		frame.u.dldata_ind.cs = ER_PGSL_CS_CS3;
		break;
	case PDCH_CS_4:
		frame.u.dldata_ind.cs = ER_PGSL_CS_CS4;
		break;
	case PDCH_MCS_1:
		/* fallthrough */
	case PDCH_MCS_2:
		/* fallthrough */
	case PDCH_MCS_3:
		/* fallthrough */
	case PDCH_MCS_4:
		frame.u.dldata_ind.cs = ER_PGSL_MCS_HDR_T1;
		break;

	case PDCH_MCS_5:
		/* fallthrough */
	case PDCH_MCS_6:
		frame.u.dldata_ind.cs = ER_PGSL_MCS_HDR_T2;
		break;
	case PDCH_MCS_7:
		/* fallthrough */
	case PDCH_MCS_8:
		/* fallthrough */
	case PDCH_MCS_9:
		frame.u.dldata_ind.cs = ER_PGSL_MCS_HDR_T3;
		break;
	default:
		LOGP(DPGSL, LOGL_ERROR,
		     "unable to determine CS/MCS frame type!\n");
		return -EINVAL;
	}

	frame.u.dldata_ind.ucm = ER_PGSL_UCM_NB_CS1_OR_MCS;
	frame.u.dldata_ind.timing_offset = 0;
	frame.u.dldata_ind.pwr_ctrl = 0;
	frame.u.dldata_ind.data_len = len;
	memcpy(frame.u.dldata_ind.data, data, len);

	rc = er_pgsl_encode(msg, &frame);
	if (rc < 0) {
		LOGP(DPGSL, LOGL_ERROR, "unable to encode pgsl frame!\n");
		return -EINVAL;
	}

	/* Transmit data */
	LOGP(DPGSL, LOGL_DEBUG,
	     "sending DLDATA.ind for ts=%d with sequence number %d on tei %i...\n",
	     ts, frame.u.dldata_ind.tn_seqno, tei);
	rc = l2tp_socket_tx(msg);
	msgb_free(msg);
	ps[tei].tn[ts].tx.next_seqno++;
	return rc;
}
