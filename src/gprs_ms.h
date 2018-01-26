/* gprs_ms.h
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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

struct gprs_codel;

#include <gprs_coding_scheme.h>
#include "cxx_linuxlist.h"
#include "llc.h"
#include "tbf.h"
#include "pcu_l1_if.h"
#include <gprs_coding_scheme.h>

extern "C" {
	#include <osmocom/core/timer.h>
	#include <osmocom/core/linuxlist.h>
}

#include <stdint.h>
#include <stddef.h>

struct BTS;
struct gprs_rlcmac_trx;

class GprsMs {
public:
	struct Callback {
		virtual void ms_idle(class GprsMs *) = 0;
		virtual void ms_active(class GprsMs *) = 0;
	};

	class Guard {
		public:
		Guard(GprsMs *ms);
		~Guard();

		bool is_idle() const;

		private:
		GprsMs * const m_ms;
	};

	GprsMs(BTS *bts, uint32_t tlli);
	~GprsMs();

	void set_callback(Callback *cb) {m_cb = cb;}

	void merge_old_ms(GprsMs *old_ms);

	gprs_rlcmac_ul_tbf *ul_tbf() const {return m_ul_tbf;}
	gprs_rlcmac_dl_tbf *dl_tbf() const {return m_dl_tbf;}
	gprs_rlcmac_tbf *tbf(enum gprs_rlcmac_tbf_direction dir) const;
	uint32_t tlli() const;
	void set_tlli(uint32_t tlli);
	bool confirm_tlli(uint32_t tlli);
	bool check_tlli(uint32_t tlli);

	void reset();
	GprsCodingScheme::Mode mode() const;
	void set_mode(GprsCodingScheme::Mode mode);

	const char *imsi() const;
	void set_imsi(const char *imsi);

	uint8_t ta() const;
	void set_ta(uint8_t ta);
	uint8_t ms_class() const;
	uint8_t egprs_ms_class() const;
	void set_ms_class(uint8_t ms_class);
	void set_egprs_ms_class(uint8_t ms_class);
	void set_current_cs_dl(GprsCodingScheme::Scheme scheme);

	GprsCodingScheme current_cs_ul() const;
	GprsCodingScheme current_cs_dl() const;
	GprsCodingScheme max_cs_ul() const;
	GprsCodingScheme max_cs_dl() const;

	int first_common_ts() const;
	uint8_t dl_slots() const;
	uint8_t ul_slots() const;
	uint8_t reserved_dl_slots() const;
	uint8_t reserved_ul_slots() const;
	uint8_t current_pacch_slots() const;
	gprs_rlcmac_trx *current_trx() const;
	void set_reserved_slots(gprs_rlcmac_trx *trx,
		uint8_t ul_slots, uint8_t dl_slots);

	gprs_llc_queue *llc_queue();
	const gprs_llc_queue *llc_queue() const;
	gprs_codel *codel_state() const;

	void set_timeout(unsigned secs);

	void attach_tbf(gprs_rlcmac_tbf *tbf);
	void attach_ul_tbf(gprs_rlcmac_ul_tbf *tbf);
	void attach_dl_tbf(gprs_rlcmac_dl_tbf *tbf);

	void detach_tbf(gprs_rlcmac_tbf *tbf);

	void update_error_rate(gprs_rlcmac_tbf *tbf, int percent);

	bool is_idle() const;
	bool need_dl_tbf() const;

	void* operator new(size_t num);
	void operator delete(void* p);

	LListHead<GprsMs>& list() {return this->m_list;}
	const LListHead<GprsMs>& list() const {return this->m_list;}
	const LListHead<gprs_rlcmac_tbf>& old_tbfs() const {return m_old_tbfs;}

	void update_l1_meas(const pcu_l1_meas *meas);
	const pcu_l1_meas* l1_meas() const {return &m_l1_meas;};
	unsigned nack_rate_dl() const;
	unsigned dl_ctrl_msg() const;
	void update_dl_ctrl_msg();

	/* internal use */
	static void timeout(void *priv_);

protected:
	void update_status();
	GprsMs *ref();
	void unref();
	void start_timer();
	void stop_timer();
	void update_cs_ul(const pcu_l1_meas*);

private:
	BTS *m_bts;
	Callback * m_cb;
	gprs_rlcmac_ul_tbf *m_ul_tbf;
	gprs_rlcmac_dl_tbf *m_dl_tbf;
	LListHead<gprs_rlcmac_tbf> m_old_tbfs;

	uint32_t m_tlli;
	uint32_t m_new_ul_tlli;
	uint32_t m_new_dl_tlli;

	/* store IMSI for look-up and PCH retransmission */
	char m_imsi[16];
	uint8_t m_ta;
	uint8_t m_ms_class;
	uint8_t m_egprs_ms_class;
	/* current coding scheme */
	GprsCodingScheme m_current_cs_ul;
	GprsCodingScheme m_current_cs_dl;

	gprs_llc_queue m_llc_queue;

	bool m_is_idle;
	int m_ref;
	LListHead<GprsMs> m_list;
	struct osmo_timer_list m_timer;
	unsigned m_delay;

	int64_t m_last_cs_not_low;

	pcu_l1_meas m_l1_meas;
	unsigned m_nack_rate_dl;
	uint8_t m_reserved_dl_slots;
	uint8_t m_reserved_ul_slots;
	gprs_rlcmac_trx *m_current_trx;

	struct gprs_codel *m_codel_state;
	GprsCodingScheme::Mode m_mode;

	unsigned m_dl_ctrl_msg;
};

inline bool GprsMs::is_idle() const
{
	return !m_ul_tbf && !m_dl_tbf && !m_ref && llist_empty(&m_old_tbfs);
}

inline bool GprsMs::need_dl_tbf() const
{
	if (dl_tbf() != NULL && dl_tbf()->state_is_not(GPRS_RLCMAC_WAIT_RELEASE))
		return false;

	return llc_queue()->size() > 0;
}

inline uint32_t GprsMs::tlli() const
{
	return m_new_ul_tlli ? m_new_ul_tlli :
	       m_tlli        ? m_tlli :
			       m_new_dl_tlli;
}

inline bool GprsMs::check_tlli(uint32_t tlli)
{
	return tlli != 0 &&
		(tlli == m_tlli || tlli == m_new_ul_tlli || tlli == m_new_dl_tlli);
}

inline const char *GprsMs::imsi() const
{
	return m_imsi;
}

inline uint8_t GprsMs::ta() const
{
	return m_ta;
}

inline uint8_t GprsMs::ms_class() const
{
	return m_ms_class;
}

inline uint8_t GprsMs::egprs_ms_class() const
{
	return m_egprs_ms_class;
}

inline GprsCodingScheme GprsMs::current_cs_ul() const
{
	return m_current_cs_ul;
}

inline GprsCodingScheme::Mode GprsMs::mode() const
{
	return m_mode;
}

inline void GprsMs::set_timeout(unsigned secs)
{
	m_delay = secs;
}

inline gprs_llc_queue *GprsMs::llc_queue()
{
	return &m_llc_queue;
}

inline const gprs_llc_queue *GprsMs::llc_queue() const
{
	return &m_llc_queue;
}

inline gprs_codel *GprsMs::codel_state() const
{
	return m_codel_state;
}

inline unsigned GprsMs::nack_rate_dl() const
{
	return m_nack_rate_dl;
}

inline unsigned GprsMs::dl_ctrl_msg() const
{
	return m_dl_ctrl_msg;
}

inline void GprsMs::update_dl_ctrl_msg()
{
	m_dl_ctrl_msg++;
}

inline uint8_t GprsMs::reserved_dl_slots() const
{
	return m_reserved_dl_slots;
}

inline uint8_t GprsMs::reserved_ul_slots() const
{
	return m_reserved_ul_slots;
}

inline gprs_rlcmac_trx *GprsMs::current_trx() const
{
	return m_current_trx;
}
