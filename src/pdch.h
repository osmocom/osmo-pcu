/* pdch.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#pragma once

#ifdef __cplusplus
extern "C" {
#include <osmocom/core/linuxlist.h>
#include "gsm_rlcmac.h"
#include "coding_scheme.h"
}

#include <bts.h>
#endif

#include <tbf.h>

#include <stdint.h>

/* PTCCH (Packet Timing Advance Control Channel) */
#define PTCCH_TAI_FREE		0x7f	/*!< Special value for unused TA Indexes */
#define PTCCH_TAI_NUM		16	/*!< Number of PTCCH/U slots and thus TA Indexes */
#define PTCCH_PADDING		0x2b	/*!< PTCCH/D messages need to be padded to 23 octets */

#define USF_UNUSED 0x07
/* 3GPP TS 05.08 version 8.23.0 "10.2.2 BTS output power". 360 ms */
#define MS_RESYNC_NUM_FRAMES 18

/*
 * PDCH instance
 */
struct gprs_rlcmac_pdch {
#ifdef __cplusplus
	struct gprs_rlcmac_paging *dequeue_paging();
	struct msgb *packet_paging_request();

	bool add_paging(uint8_t chan_needed, const struct osmo_mobile_identity *mi);

	void free_resources();

	bool is_enabled() const;

	void enable();
	void disable();

	/* dispatching of messages */
	int rcv_block(uint8_t *data, uint8_t len, uint32_t fn,
		struct pcu_l1_meas *meas);
	int rcv_block_gprs(uint8_t *data, uint8_t data_len, uint32_t fn,
		struct pcu_l1_meas *meas, enum CodingScheme cs);
	int rcv_data_block(uint8_t *data, uint8_t data_len, uint32_t fn,
		struct pcu_l1_meas *meas, enum CodingScheme cs);

	struct gprs_rlcmac_bts *bts() const;
	uint8_t trx_no() const;

	struct gprs_rlcmac_ul_tbf *ul_tbf_by_tfi(uint8_t tfi);
	struct gprs_rlcmac_dl_tbf *dl_tbf_by_tfi(uint8_t tfi);

	void attach_tbf(gprs_rlcmac_tbf *tbf);
	void detach_tbf(gprs_rlcmac_tbf *tbf);

	unsigned num_tbfs(enum gprs_rlcmac_tbf_direction dir) const;

	void reserve(enum gprs_rlcmac_tbf_direction dir);
	void unreserve(enum gprs_rlcmac_tbf_direction dir);
	unsigned num_reserved(enum gprs_rlcmac_tbf_direction dir) const;

	uint8_t assigned_usf() const;
	uint32_t assigned_tfi(enum gprs_rlcmac_tbf_direction dir) const;

	bool has_gprs_only_tbf_attached() const;
#endif

	uint8_t m_is_enabled; /* TS is enabled */
	uint8_t tsc; /* TSC of this slot */
	uint8_t next_ul_tfi; /* next uplink TBF/TFI to schedule (0..31) */
	uint8_t next_dl_tfi; /* next downlink TBF/TFI to schedule (0..31) */
	uint8_t next_ctrl_prio; /* next kind of ctrl message to schedule */
	struct llist_head paging_list; /* list of paging messages */
	uint32_t last_rts_fn; /* store last frame number of RTS */
	/* store number of contiguous frame number where a DL block was transmitted which can be decoded by GPRS-only MS */
	uint32_t fn_without_cs14;

	/* PTCCH (Packet Timing Advance Control Channel) */
	uint8_t ptcch_msg[GSM_MACBLOCK_LEN]; /* 'ready to use' PTCCH/D message */
#ifdef __cplusplus
	/* Initialize the PTCCH/D message */
	void init_ptcch_msg(void);
	/* Obtain an unused TA Index for a TBF */
	uint8_t reserve_tai(uint8_t ta);
	/* Mark a given TA Index as free, so it can be used again */
	void release_tai(uint8_t tai);
	/* Update the actual Timing Advance value for a given TA Index */
	void update_ta(uint8_t tai, uint8_t ta);
#endif

	/* Frequency hopping parameters */
	struct {
		bool enabled;
		/* 3GPP TS 45.002 HSN / MAIO (6 bit each) */
		uint8_t hsn;
		uint8_t maio;
		/* 3GPP TS 44.018, 10.5.2.21 "Mobile Allocation" */
		uint8_t ma_oct_len;
		uint8_t ma_bit_len;
		uint8_t ma[8];
	} fh;

	/* back pointers */
	struct gprs_rlcmac_trx *trx;
	uint8_t ts_no;

#ifdef __cplusplus
private:
	int rcv_control_block(const uint8_t *data, uint8_t data_len, uint32_t fn,
			      struct pcu_l1_meas *meas, enum CodingScheme cs);

	void rcv_control_ack(Packet_Control_Acknowledgement_t *, uint32_t fn);
	void rcv_control_dl_ack_nack(Packet_Downlink_Ack_Nack_t *, uint32_t fn, struct pcu_l1_meas *meas);
	void rcv_control_egprs_dl_ack_nack(EGPRS_PD_AckNack_t *, uint32_t fn, struct pcu_l1_meas *meas);
	void rcv_resource_request(Packet_Resource_Request_t *t, uint32_t fn, struct pcu_l1_meas *meas);
	void rcv_measurement_report(Packet_Measurement_Report_t *t, uint32_t fn);
	gprs_rlcmac_tbf *tbf_from_list_by_tfi(
		LListHead<gprs_rlcmac_tbf> *tbf_list, uint8_t tfi,
		enum gprs_rlcmac_tbf_direction dir);
	gprs_rlcmac_tbf *tbf_by_tfi(uint8_t tfi,
		enum gprs_rlcmac_tbf_direction dir);
#endif

	uint8_t m_num_tbfs[2];
	uint8_t m_num_reserved[2];
	uint8_t m_assigned_usf; /* bit set */
	uint32_t m_assigned_tfi[2]; /* bit set */
	struct gprs_rlcmac_tbf *m_tbfs[2][32];
};

#ifdef __cplusplus

inline unsigned gprs_rlcmac_pdch::num_tbfs(enum gprs_rlcmac_tbf_direction dir) const
{
	return m_num_tbfs[dir];
}

inline unsigned gprs_rlcmac_pdch::num_reserved(
	enum gprs_rlcmac_tbf_direction dir) const
{
	return gprs_rlcmac_pdch::m_num_reserved[dir];
}

inline uint8_t gprs_rlcmac_pdch::assigned_usf() const
{
	return m_assigned_usf;
}

inline uint32_t gprs_rlcmac_pdch::assigned_tfi(
	enum gprs_rlcmac_tbf_direction dir) const
{
	return m_assigned_tfi[dir];
}

inline bool gprs_rlcmac_pdch::is_enabled() const
{
	return m_is_enabled;
}

#endif /* __cplusplus */
