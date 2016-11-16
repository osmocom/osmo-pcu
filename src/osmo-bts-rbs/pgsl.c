/* Ericsson P-GSL protocol parser and encoder */
/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 */

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <string.h>

#include "pgsl.h"

static uint32_t get24le(const uint8_t *data)
{
	return (data[2] << 16) | (data[1] << 8) | data[0];
}

static inline void msgb_put_u24le(struct msgb *msg, uint32_t word)
{
	uint8_t *space = msgb_put(msg, 3);

	space[0] = word & 0xff;
	space[1] = (word >> 8) & 0xff;
	space[2] = (word >> 16) & 0xff;
}

const struct value_string er_pgsl_mstype_vals[] = {
	{ ER_PGSL_DLDATA_REQ, "DLDATA.req" },
	{ ER_PGSL_DLDATA_IND, "DLDATA.ind" },
	{ ER_PGSL_ULDATA_IND, "ULDATA.ind" },
	{ ER_PGSL_STATUS_IND, "STATUS.ind" },
	{ 0, NULL }
};

const struct value_string er_pgsl_cs_vals[] = {
	{ ER_PGSL_CS_AB, "Access Burst" },
	{ ER_PGSL_CS_CS1, "CS1" },
	{ ER_PGSL_CS_CS2, "CS2" },
	{ ER_PGSL_CS_CS3, "CS3" },
	{ ER_PGSL_CS_CS4, "CS4" },
	{ ER_PGSL_MCS_HDR_T1, "EGPRS Header Type 1" },
	{ ER_PGSL_MCS_HDR_T2, "EGPRS Header Type 2" },
	{ ER_PGSL_MCS_HDR_T3, "EGPRS Header Type 3" },
	{ 0, NULL }
};

const struct value_string er_pgsl_ucm_vals[] = {
	{ ER_PGSL_UCM_NB_GSMK, "NB-GSMK" },
	{ ER_PGSL_UCM_NB_CS1_OR_MCS, "NB-unkn" },
	{ ER_PGSL_UCM_AB_8BIT_TS0, "AB-GSMK" },
	{ ER_PGSL_UCM_AB_8BIT_OR_11BIT, "AB-unkn" },
	{ 0, NULL }
};

const struct value_string er_pgsl_cause_vals[] = {
	{ 0, "Frame discarded in CCU, too late" },
	{ 1, "Frame discarded in CCU, too late or OOM" },
	{ 2, "Frame(s) missing in sequence detected by CCU" },
	{ 3, "Frame Format Error" },
	{ 0, NULL }
};


/***********************************************************************?
 * P-GSL Decoder
 ***********************************************************************/

static int er_pgsl_parse_dldata_req(struct decoded_dldata_req *dldrq,
				    const uint8_t *data, unsigned int len)
{
	if (len < 8)
		return -1;

	dldrq->tn_bitmap = data[1];
	dldrq->trx_seqno = data[2];
	dldrq->afn_d = get24le(data+3);
	dldrq->ccu_ta = data[6];
	if (data[7] & 0x01)
		dldrq->ack_req = true;
	else
		dldrq->ack_req = false;

	return 0;
}

static int er_pgsl_parse_uldata_ind(struct decoded_uldata_ind *uldi,
				    const uint8_t *data, unsigned int len)
{

	if (len < 11)
		return -1;

	uldi->tn = data[1];
	uldi->tn_seqno = data[2];
	uldi->afn_u = get24le(data+3);
	uldi->delay = data[6] >> 5;
	uldi->cs_ucm = data[6] & 0x1f;
	uldi->rx_lev = data[7] & 0x3f;

	switch (uldi->cs_ucm) {
	case ER_PGSL_CS_CS1:
	case ER_PGSL_CS_CS2:
	case ER_PGSL_CS_CS3:
	case ER_PGSL_CS_CS4:
		uldi->u.gprs.block_qual = data[8] & 0x7;
		uldi->u.gprs.parity_ok = (data[8] >> 3) & 1;
		break;
	case ER_PGSL_MCS_HDR_T1:
	case ER_PGSL_MCS_HDR_T2:
	case ER_PGSL_MCS_HDR_T3:
		uldi->u.egprs.mean_bep = data[8] & 0x7f;
		uldi->u.egprs.cv_bep = data[9] & 0x7;
		if (data[9] & 0x08)
			uldi->u.egprs.hdr_good = false;
		else
			uldi->u.egprs.hdr_good = true;
		if (data[9] & 0x10)
			uldi->u.egprs.data_good[0] = false;
		else
			uldi->u.egprs.data_good[0] = true;
		if (data[9] & 0x20)
			uldi->u.egprs.data_good[1] = false;
		else
			uldi->u.egprs.data_good[1] = true;
		break;
	default:
		return -1;
	}

	uldi->data_len = data[10];
	if (len - 11 < uldi->data_len)
		return -1;

	memcpy(uldi->data, data+11, uldi->data_len);

	return 0;
}

static int er_pgsl_parse_dldata_ind(struct decoded_dldata_ind *dldi,
				    const uint8_t *data, unsigned int len)
{
	if (len < 7)
		return -1;

	dldi->tn = data[1];
	dldi->tn_seqno = data[2];
	dldi->afn_d = get24le(data+3);
	if (data[6] & 0x01)
		dldi->data_ind = true;
	else
		dldi->data_ind = false;
	if (data[6] & 0x02)
		dldi->ack_ind = true;
	else
		dldi->ack_ind = false;

	if (!dldi->data_ind)
		return 0;

	if (len < 11)
		return -1;

	dldi->ucm = data[7] >> 5;
	dldi->cs = data[7] & 0x1f;
	dldi->timing_offset = data[8];
	dldi->pwr_ctrl = data[9] & 0xf;

	dldi->data_len = data[10];
	if (len-11 < dldi->data_len)
		return -1;
	memcpy(dldi->data, data+11, dldi->data_len);

	return 0;
}

static int er_pgsl_parse_status_ind(struct decoded_status_ind *si,
				    const uint8_t *data, unsigned int len)
{
	if (len < 8)
		return -1;

	si->tn = data[1];
	si->tn_seqno = data[2];
	si->afn_u = get24le(data+3);
	si->cause = data[6];
	si->addl_info = data[7];

	return 0;
}

int er_pgsl_parse(struct er_pgsl_frame *frame, const uint8_t *data, unsigned int len)
{
	int rc;

	frame->type = data[0] & 0xf;
	frame->version = data[0] >> 4;

	switch (frame->type) {
	case ER_PGSL_DLDATA_REQ:
		rc = er_pgsl_parse_dldata_req(&frame->u.dldata_req, data, len);
		break;
	case ER_PGSL_ULDATA_IND:
		rc = er_pgsl_parse_uldata_ind(&frame->u.uldata_ind, data, len);
		break;
	case ER_PGSL_STATUS_IND:
		rc = er_pgsl_parse_status_ind(&frame->u.status_ind, data, len);
		break;
	case ER_PGSL_DLDATA_IND:
		rc = er_pgsl_parse_dldata_ind(&frame->u.dldata_ind, data, len);
		break;
	default:
		return -1;
	}

	return rc;
}


/***********************************************************************?
 * P-GSL Encoder
 ***********************************************************************/

static int er_pgsl_encode_dldata_ind(struct msgb *msg,
				     const struct decoded_dldata_ind *dldi)
{
	uint8_t ack_data_ind = 0;
	uint8_t *cur;

	msgb_put_u8(msg, dldi->tn);
	msgb_put_u8(msg, dldi->tn_seqno);
	msgb_put_u24le(msg, dldi->afn_d);

	if (dldi->ack_ind)
		ack_data_ind |= 0x02;
	if (dldi->data_ind)
		ack_data_ind |= 0x01;
	msgb_put_u8(msg, ack_data_ind);

	if (!dldi->data_ind)
		return 0;

	msgb_put_u8(msg, (dldi->ucm << 5) | (dldi->cs & 0x1f));
	msgb_put_u8(msg, dldi->timing_offset);
	msgb_put_u8(msg, dldi->pwr_ctrl);
	msgb_put_u8(msg, dldi->data_len);

	OSMO_ASSERT(dldi->data_len <= sizeof(dldi->data));
	cur = msgb_put(msg, dldi->data_len);
	memcpy(cur, dldi->data, dldi->data_len);

	return 0;
}

static int er_pgsl_encode_dldata_req(struct msgb *msg,
				     const struct decoded_dldata_req *dldr)
{
	msgb_put_u8(msg, dldr->tn_bitmap);
	msgb_put_u8(msg, dldr->trx_seqno);
	msgb_put_u24le(msg, dldr->afn_d);
	msgb_put_u8(msg, dldr->ccu_ta);
	if (dldr->ack_req)
		msgb_put_u8(msg, 0x01);
	else
		msgb_put_u8(msg, 0x00);

	return 0;
}

static int er_pgsl_encode_uldata_ind(struct msgb *msg,
				     const struct decoded_uldata_ind *uldi)
{
	uint8_t *cur;

	msgb_put_u8(msg, uldi->tn);
	msgb_put_u8(msg, uldi->tn_seqno);
	msgb_put_u24le(msg, uldi->afn_u);

	/* Codec Status */
	msgb_put_u8(msg, ((uldi->delay & 0x7) << 5) |
			 (uldi->cs_ucm & 0x1f));
	msgb_put_u8(msg, uldi->rx_lev & 0x3f);
	switch (uldi->cs_ucm) {
	case ER_PGSL_CS_AB:
	case ER_PGSL_CS_CS1:
	case ER_PGSL_CS_CS2:
	case ER_PGSL_CS_CS3:
	case ER_PGSL_CS_CS4:
		msgb_put_u8(msg, ((uldi->u.gprs.parity_ok & 1) << 3) |
				 (uldi->u.gprs.block_qual & 0x7));
		msgb_put_u8(msg, 0x00);
		break;
	case ER_PGSL_MCS_HDR_T1:
	case ER_PGSL_MCS_HDR_T2:
	case ER_PGSL_MCS_HDR_T3:
		msgb_put_u8(msg, uldi->u.egprs.mean_bep & 0x7f);
		msgb_put_u8(msg, ((uldi->u.egprs.hdr_good & 1) << 3) |
				 ((uldi->u.egprs.data_good[1]) << 4) |
				 ((uldi->u.egprs.data_good[2]) << 5) |
				 (uldi->u.egprs.cv_bep & 0x7));
		break;
	default:
		return -1;
	}

	OSMO_ASSERT(uldi->data_len <= sizeof(uldi->data));
	msgb_put_u8(msg, uldi->data_len);
	cur = msgb_put(msg, uldi->data_len);
	memcpy(cur, uldi->data, uldi->data_len);

	return 0;
}

static int er_pgsl_encode_status_ind(struct msgb *msg,
				     const struct decoded_status_ind *sti)
{
	msgb_put(msg, sti->tn);
	msgb_put(msg, sti->tn_seqno);
	msgb_put_u24le(msg, sti->afn_u);
	msgb_put_u8(msg, sti->cause);
	msgb_put_u8(msg, sti->addl_info);

	return 0;
}

int er_pgsl_encode(struct msgb *msg, const struct er_pgsl_frame *frame)
{
	uint8_t msg_disc;
	int rc;

	msg_disc = (frame->version << 4) | (frame->type & 0xf);
	msgb_put_u8(msg, msg_disc);

	switch (frame->type) {
	case ER_PGSL_DLDATA_IND:
		rc = er_pgsl_encode_dldata_ind(msg, &frame->u.dldata_ind);
		break;
	case ER_PGSL_DLDATA_REQ:
		rc = er_pgsl_encode_dldata_req(msg, &frame->u.dldata_req);
		break;
	case ER_PGSL_ULDATA_IND:
		rc = er_pgsl_encode_uldata_ind(msg, &frame->u.uldata_ind);
		break;
	case ER_PGSL_STATUS_IND:
		rc = er_pgsl_encode_status_ind(msg, &frame->u.status_ind);
		break;
	default:
		return -1;
	}

	return rc;
}

void er_pgsl_dump(const struct er_pgsl_frame *frame)
{
	printf("V%u %s(", frame->version, get_value_string(er_pgsl_mstype_vals, frame->type));
	switch (frame->type) {
	case ER_PGSL_DLDATA_REQ:
		printf("tn_bitmap=0x%02x, trx_seqno=%u, afn_d=%u, ccu_ta=%u, ack_req=%u",
			frame->u.dldata_req.tn_bitmap,
			frame->u.dldata_req.trx_seqno,
			frame->u.dldata_req.afn_d,
			frame->u.dldata_req.ccu_ta,
			frame->u.dldata_req.ack_req);
		break;
	case ER_PGSL_DLDATA_IND:
		printf("tn=%u, tn_seqno=%u, afn_d=%u, ack_ind=%u, data_ind=%u",
			frame->u.dldata_ind.tn,
			frame->u.dldata_ind.tn_seqno,
			frame->u.dldata_ind.afn_d,
			frame->u.dldata_ind.ack_ind,
			frame->u.dldata_ind.data_ind);
		if (frame->u.dldata_ind.data_ind) {
			printf(", ucm=%s", get_value_string(er_pgsl_ucm_vals, frame->u.dldata_ind.ucm));
			printf(", cs=%s", get_value_string(er_pgsl_cs_vals, frame->u.dldata_ind.cs));
			printf(", timing=%u, pwr_ctrl=0x%02x, data=%s",
				frame->u.dldata_ind.timing_offset,
				frame->u.dldata_ind.pwr_ctrl,
				osmo_hexdump(frame->u.dldata_ind.data, frame->u.dldata_ind.data_len));
		}
		break;
	case ER_PGSL_STATUS_IND:
		printf("tn=%u, tn_seqno=%u, afn_u=%u, cause=\"%s\", addl_info=%u",
			frame->u.status_ind.tn,
			frame->u.status_ind.tn_seqno,
			frame->u.status_ind.afn_u,
			get_value_string(er_pgsl_cause_vals, frame->u.status_ind.cause),
			frame->u.status_ind.addl_info);
		break;
	case ER_PGSL_ULDATA_IND:
		printf("tn=%u, tn_seqno=%u, afn_u=%u, delay=%u, cs=\"%s\", rx_lev=%u",
			frame->u.uldata_ind.tn,
			frame->u.uldata_ind.tn_seqno,
			frame->u.uldata_ind.afn_u,
			frame->u.uldata_ind.delay,
			get_value_string(er_pgsl_cs_vals, frame->u.uldata_ind.cs_ucm),
			frame->u.uldata_ind.rx_lev);
		switch (frame->u.uldata_ind.cs_ucm) {
		case ER_PGSL_MCS_HDR_T1:
		case ER_PGSL_MCS_HDR_T2:
		case ER_PGSL_MCS_HDR_T3:
			printf(", mean_bep=%u, cv_bep=%u, QH=%u, Q1=%u, Q2=%u",
				frame->u.uldata_ind.u.egprs.mean_bep,
				frame->u.uldata_ind.u.egprs.cv_bep,
				frame->u.uldata_ind.u.egprs.hdr_good,
				frame->u.uldata_ind.u.egprs.data_good[0],
				frame->u.uldata_ind.u.egprs.data_good[1]);
			break;
		default:
			printf(", bqm=%u, parity_ok=%u",
				frame->u.uldata_ind.u.gprs.block_qual,
				frame->u.uldata_ind.u.gprs.parity_ok);
			break;
		}
		printf(", data=%s",
			osmo_hexdump(frame->u.uldata_ind.data,
				     frame->u.uldata_ind.data_len));
		break;
	};
	printf(")\n");
}
