/* rlc header descriptions
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include "coding_scheme.h"
#include <osmocom/core/endian.h>

#ifdef __cplusplus
}
#endif

#include <stdint.h>
#include <string.h>

#define RLC_GPRS_SNS 128 /* GPRS, must be power of 2 */
#define RLC_EGPRS_SNS 2048 /* EGPRS, must be power of 2 */
#define RLC_MAX_SNS  RLC_EGPRS_SNS
#define RLC_MAX_LEN 74 /* MCS-9 data unit */

/*
 * EGPRS resegment status information for UL
 * When only first split block is received bsn state
 * will be set to EGPRS_RESEG_FIRST_SEG_RXD and when
 * only second segment is received the state will be
 * set to EGPRS_RESEG_SECOND_SEG_RXD. When both Split
 * blocks are received the state will be set to
 * EGPRS_RESEG_DEFAULT
 * The EGPRS resegmentation feature allows MS to retransmit
 * RLC blocks of HeaderType1, HeaderType2 by segmenting
 * them to 2 HeaderType3 blocks(Example MCS5 will be
 * retransmitted as 2 MCS2 blocks). Table 10.4.8b.1 of 44.060
 * explains the possible values of SPB in HeadrType3 for UL
 * direction. When the MCS is changed at the PCU, PCU directs the
 * changed MCS to MS by PUAN or UPLINK ASSIGNMENT message along
 * with RESEGMENT flag, Then MS may decide to retransmit the
 * blocks by resegmenting it based on Table 8.1.1.1 of 44.060.
 * The retransmission MCS is calculated based on current MCS of
 * the Block and demanded MCS by PCU. Section 10.3a.4.3 of 44.060
 * shows the HeadrType3 with SPB field present in it
*/
enum egprs_rlc_ul_reseg_bsn_state {
	EGPRS_RESEG_DEFAULT = 0,
	EGPRS_RESEG_FIRST_SEG_RXD = 0x01,
	EGPRS_RESEG_SECOND_SEG_RXD = 0x02,
	EGPRS_RESEG_INVALID = 0x04
};

/*
 * EGPRS resegment status information for DL
 * When only first segment is sent, bsn state
 * will be set to EGPRS_RESEG_FIRST_SEG_SENT and when
 * second segment is sent the state will be
 * set to EGPRS_RESEG_SECOND_SEG_SENT.
 * EGPRS_RESEG_DL_INVALID is set to 8 considering there is a scope for
 * 3rd segment according to Table 10.4.8b.2 of 44.060
 * The EGPRS resegmentation feature allows PCU to retransmit
 * RLC blocks of HeaderType1, HeaderType2 by segmenting
 * them to 2 HeaderType3 blocks(Example MCS5 will be
 * retransmitted as 2 MCS2 blocks). Table 10.4.8b.2 of 44.060
 * explains the possible values of SPB in HeadrType3 for DL
 * direction.The PCU decides to retransmit the
 * blocks by resegmenting it based on Table 8.1.1.1 of 44.060.
 * The retransmission MCS is calculated based on current MCS of
 * the Block and demanded MCS by PCU. Section 10.3a.3.3 of 44.060
 * shows the HeadrType3 with SPB field present in it
 */
enum egprs_rlc_dl_reseg_bsn_state {
	EGPRS_RESEG_DL_DEFAULT = 0,
	EGPRS_RESEG_FIRST_SEG_SENT = 0x01,
	EGPRS_RESEG_SECOND_SEG_SENT = 0x02,
	EGPRS_RESEG_DL_INVALID = 0x08
};

/* Table 10.4.8b.2 of 44.060 */
enum egprs_rlcmac_dl_spb {
	EGPRS_RLCMAC_DL_NO_RETX = 0,
	EGPRS_RLCMAC_DL_FIRST_SEG = 2,
	EGPRS_RLCMAC_DL_SEC_SEG = 3,
};

/*
 * Valid puncturing scheme values
 * TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1
 */
enum egprs_puncturing_values {
	EGPRS_PS_1,
	EGPRS_PS_2,
	EGPRS_PS_3,
	EGPRS_PS_INVALID,
};

/*
 * EGPRS_MAX_PS_NUM_2 is valid for MCS 1,2,5,6.
 * And EGPRS_MAX_PS_NUM_3 is valid for MCS 3,4,7,8,9
 * TS 44.060 10.4.8a.3.1, 10.4.8a.2.1, 10.4.8a.1.1
 */
enum egprs_puncturing_types {
	EGPRS_MAX_PS_NUM_2 = 2,
	EGPRS_MAX_PS_NUM_3,
	EGPRS_MAX_PS_NUM_INVALID,
};

static inline uint16_t mod_sns_half()
{
	return (RLC_MAX_SNS / 2) - 1;
}

struct gprs_rlc_data_block_info {
	unsigned int data_len; /* EGPRS: N2, GPRS: N2-2, N-2 */
	unsigned int bsn;
	unsigned int ti;
	unsigned int e;
	unsigned int cv; /* FBI == 1 <=> CV == 0 */
	unsigned int pi;
	unsigned int spb;
};

struct gprs_rlc_data_info {
	enum CodingScheme cs;
	unsigned int r;
	unsigned int si;
	unsigned int tfi;
	unsigned int cps;
	unsigned int rsb;
	unsigned int usf;
	unsigned int es_p;
	unsigned int rrbp;
	unsigned int pr;
	uint8_t num_data_blocks; /* this can actually be only 0, 1, 2: enforced in gprs_rlc_data_header_init() */
	unsigned int with_padding;
	unsigned int data_offs_bits[2];
	struct gprs_rlc_data_block_info block_info[2];
};

/* holds the current status of the block w.r.t UL/DL split blocks */
union split_block_status {
	egprs_rlc_ul_reseg_bsn_state block_status_ul;
	egprs_rlc_dl_reseg_bsn_state block_status_dl;
};

struct gprs_rlc_data {
	/* block data including LI headers */
	uint8_t block[RLC_MAX_LEN];
	/* block data len including LI headers*/
	uint8_t len;

	struct gprs_rlc_data_block_info block_info;
	/*
	 * cs_current_trans is variable to hold the cs_last value for
	 * current transmission. cs_current_trans is same as cs_last during
	 * transmission case. during retransmission cs_current_trans is
	 * fetched from egprs_mcs_retx_tbl table based on
	 * cs and demanded cs.reference is 44.060 Table
	 * 8.1.1.1 and Table 8.1.1.2
	 * For UL. cs_last shall be used everywhere.
	 */
	enum CodingScheme cs_current_trans;
	enum CodingScheme cs_last;

	/*
	 * The MCS of initial transmission of a BSN
	 * This variable is used for split block
	 * processing in DL
	 */
	enum CodingScheme cs_init;

	/* puncturing scheme value to be used for next transmission*/
	enum egprs_puncturing_values next_ps;

	/* holds the status of the block w.r.t UL/DL split blocks*/
	union split_block_status spb_status;
};

uint8_t *prepare(struct gprs_rlc_data *rlc, size_t block_data_length);

void gprs_rlc_data_info_init_dl(struct gprs_rlc_data_info *rlc,
	enum CodingScheme cs, bool with_padding, const unsigned int spb);
void gprs_rlc_data_info_init_ul(struct gprs_rlc_data_info *rlc,
	enum CodingScheme cs, bool with_padding);
void gprs_rlc_data_block_info_init(struct gprs_rlc_data_block_info *rdbi,
	enum CodingScheme cs, bool with_padding, const unsigned int spb);
unsigned int gprs_rlc_mcs_cps(enum CodingScheme cs, enum egprs_puncturing_values
	punct, enum egprs_puncturing_values punct2, bool with_padding);
void gprs_rlc_mcs_cps_decode(unsigned int cps, enum CodingScheme cs,
	int *punct, int *punct2, int *with_padding);
enum egprs_puncturing_values gprs_get_punct_scheme(enum egprs_puncturing_values
	punct, const enum CodingScheme &cs,
	const enum CodingScheme &cs_current_trans,
	const enum egprs_rlcmac_dl_spb spb);
void gprs_update_punct_scheme(enum egprs_puncturing_values *punct,
	const enum CodingScheme &cs);
/*
 * I hold the currently transferred blocks and will provide
 * the routines to manipulate these arrays.
 */
struct gprs_rlc {
	void init();
	gprs_rlc_data *block(int bsn);
	gprs_rlc_data m_blocks[RLC_MAX_SNS/2];
};

extern "C" {
/* TS 44.060  10.2.2 */
struct rlc_ul_header {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	r:1,
		 si:1,
		 cv:4,
		 pt:2;
	uint8_t	ti:1,
		 tfi:5,
		 pi:1,
		 spare:1;
	uint8_t	e:1,
		 bsn:7;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	pt:2, cv:4, si:1, r:1;
	uint8_t	spare:1, pi:1, tfi:5, ti:1;
	uint8_t	bsn:7, e:1;
#endif
} __attribute__ ((packed));

struct rlc_dl_header {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	usf:3,
		 s_p:1,
		 rrbp:2,
		 pt:2;
	uint8_t	fbi:1,
		 tfi:5,
		 pr:2;
	uint8_t	e:1,
		 bsn:7;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	pt:2, rrbp:2, s_p:1, usf:3;
	uint8_t	pr:2, tfi:5, fbi:1;
	uint8_t	bsn:7, e:1;
#endif
} __attribute__ ((packed));

struct rlc_li_field {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	e:1,
		 m:1,
		 li:6;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	li:6, m:1, e:1;
#endif
} __attribute__ ((packed));

struct rlc_li_field_egprs {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t	e:1,
		 li:7;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
	uint8_t	li:7, e:1;
#endif
} __attribute__ ((packed));
}

inline void gprs_rlc::init()
{
	memset(m_blocks, 0, sizeof(m_blocks));
}

inline gprs_rlc_data *gprs_rlc::block(int bsn)
{
	return &m_blocks[bsn & mod_sns_half()];
}
