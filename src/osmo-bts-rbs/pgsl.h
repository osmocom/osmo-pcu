#pragma once

/* Ericsson P-GSL protocol parser and encoder */
/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 */

#include <stdbool.h>

struct msgb;

enum er_pgsl_frame_type {
	ER_PGSL_DLDATA_REQ = 1,
	ER_PGSL_DLDATA_IND = 2,
	ER_PGSL_ULDATA_IND = 3,
	ER_PGSL_STATUS_IND = 4,
};

enum er_pgsl_coding_scheme {
	ER_PGSL_CS_AB		= 0,
	ER_PGSL_CS_CS1		= 1,
	ER_PGSL_CS_CS2		= 2,
	ER_PGSL_CS_CS3		= 3,
	ER_PGSL_CS_CS4		= 4,
	ER_PGSL_MCS_HDR_T1	= 5,
	ER_PGSL_MCS_HDR_T2	= 6,
	ER_PGSL_MCS_HDR_T3	= 7,
};

enum er_pgsl_uplink_chan_mode {
	ER_PGSL_UCM_NB_GSMK		= 1,
	ER_PGSL_UCM_NB_CS1_OR_MCS	= 2,
	ER_PGSL_UCM_AB_8BIT_TS0		= 3,
	ER_PGSL_UCM_AB_8BIT_OR_11BIT	= 4,
};

enum er_pgsl_block_qual {
	ER_PGSL_BQM_SFQ_00_09	= 0,
	ER_PGSL_BQM_SFQ_10_19	= 1,
	ER_PGSL_BQM_SFQ_20_29	= 2,
	ER_PGSL_BQM_SFQ_30_39	= 3,
	ER_PGSL_BQM_SFQ_40_49	= 4,
	ER_PGSL_BQM_SFQ_50_59	= 5,
	ER_PGSL_BQM_SFQ_60_69	= 6,
	ER_PGSL_BQM_SFQ_GE_70	= 7,
};

struct decoded_dldata_req {
	uint8_t tn_bitmap;
	uint8_t trx_seqno;
	uint32_t afn_d;
	uint8_t ccu_ta;
	bool ack_req;
};

struct decoded_dldata_ind {
	uint8_t tn;
	uint8_t tn_seqno;
	uint32_t afn_d;
	bool ack_ind;
	bool data_ind;

	enum er_pgsl_uplink_chan_mode ucm;
	enum er_pgsl_coding_scheme cs;
	uint8_t timing_offset;

	uint8_t pwr_ctrl;

	uint8_t data_len;
	uint8_t data[154];
};

struct decoded_uldata_ind {
	uint8_t tn;
	uint8_t tn_seqno;
	uint32_t afn_u;

	uint8_t delay;
	enum er_pgsl_coding_scheme cs_ucm;
	uint8_t rx_lev;

	union {
		struct {
			enum er_pgsl_block_qual block_qual;
			bool parity_ok;
		} gprs;
		struct {
			uint8_t mean_bep;
			uint8_t cv_bep;
			bool hdr_good;
			bool data_good[2];
		} egprs;
	} u;

	uint8_t data_len;
	uint8_t data[155];
};

struct decoded_status_ind {
	uint8_t tn;
	uint8_t tn_seqno;
	uint32_t afn_u;
	uint8_t cause;
	uint8_t addl_info;
};

struct er_pgsl_frame {
	uint8_t version;
	enum er_pgsl_frame_type type;
	union {
		struct decoded_dldata_req dldata_req;
		struct decoded_dldata_ind dldata_ind;
		struct decoded_uldata_ind uldata_ind;
		struct decoded_status_ind status_ind;
	} u;
};

int er_pgsl_parse(struct er_pgsl_frame *frame, const uint8_t *data, unsigned int len);
int er_pgsl_encode(struct msgb *msg, const struct er_pgsl_frame *frame);
void er_pgsl_dump(const struct er_pgsl_frame *frame);
