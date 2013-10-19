/* bts.h
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

#pragma once


#ifdef __cplusplus
extern "C" {
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
}

#include "poll_controller.h"
#endif

#include <stdint.h>

struct gprs_rlcmac_tbf;
struct BTS;

/*
 * PDCH instance
 */
struct gprs_rlcmac_pdch {
#ifdef __cplusplus
	/* TODO: the PDCH should know the trx/ts it belongs to */
	void free_resources(uint8_t trx, uint8_t ts);

	bool is_enabled() const;

	void enable();
	void disable();
#endif

	uint8_t m_is_enabled; /* TS is enabled */
	uint8_t tsc; /* TSC of this slot */
	uint8_t next_ul_tfi; /* next uplink TBF/TFI to schedule (0..31) */
	uint8_t next_dl_tfi; /* next downlink TBF/TFI to schedule (0..31) */
	struct gprs_rlcmac_tbf *ul_tbf[32]; /* array of UL TBF, by UL TFI */
	struct gprs_rlcmac_tbf *dl_tbf[32]; /* array of DL TBF, by DL TFI */
	struct llist_head paging_list; /* list of paging messages */
	uint32_t last_rts_fn; /* store last frame number of RTS */
};

struct gprs_rlcmac_trx {
	void *fl1h;
	uint16_t arfcn;
	struct gprs_rlcmac_pdch pdch[8];
	struct gprs_rlcmac_tbf *ul_tbf[32]; /* array of UL TBF, by UL TFI */
	struct gprs_rlcmac_tbf *dl_tbf[32]; /* array of DL TBF, by DL TFI */
};

/**
 * This is the data from C. As soon as our minimal compiler is gcc 4.7
 * we can start to compile pcu_vty.c with c++ and remove the split.
 */
struct gprs_rlcmac_bts {
	uint8_t bsic;
	uint8_t fc_interval;
	uint8_t cs1;
	uint8_t cs2;
	uint8_t cs3;
	uint8_t cs4;
	uint8_t initial_cs_dl, initial_cs_ul;
	uint8_t force_cs;	/* 0=use from BTS 1=use from VTY */
	uint16_t force_llc_lifetime; /* overrides lifetime from SGSN */
	uint8_t t3142;
	uint8_t t3169;
	uint8_t t3191;
	uint16_t t3193_msec;
	uint8_t t3195;
	uint8_t n3101;
	uint8_t n3103;
	uint8_t n3105;
	struct gprs_rlcmac_trx trx[8];
	int (*alloc_algorithm)(struct gprs_rlcmac_bts *bts,
		struct gprs_rlcmac_tbf *old_tbf,
		struct gprs_rlcmac_tbf *tbf, uint32_t cust, uint8_t single);
	uint32_t alloc_algorithm_curst; /* options to customize algorithm */
	uint8_t force_two_phase;
	uint8_t alpha, gamma;

	/**
	 * Point back to the C++ object. This is used during the transition
	 * period.
	 */
	struct BTS *bts;
};

#ifdef __cplusplus
/**
 * I represent a GSM BTS. I have one or more TRX, I know the current
 * GSM time and I have controllers that help with allocating resources
 * on my TRXs.
 */
struct BTS {
public:
	BTS();

	static BTS* main_bts();

	struct gprs_rlcmac_bts *bts_data();

	/** TODO: change the number to unsigned */
	void set_current_frame_number(int frame_number);
	int current_frame_number() const;

private:
	int m_cur_fn;
	struct gprs_rlcmac_bts m_bts;
	PollController m_pollController;

private:
	/* disable copying to avoid slicing */
	BTS(const BTS&);
	BTS& operator=(const BTS&);
};

inline int BTS::current_frame_number() const
{
	return m_cur_fn;
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
	struct gprs_rlcmac_bts *bts_main_data();
#ifdef __cplusplus
}

inline bool gprs_rlcmac_pdch::is_enabled() const
{
	return m_is_enabled;
}
#endif
