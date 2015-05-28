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

struct gprs_rlcmac_tbf;
struct gprs_rlcmac_dl_tbf;
struct gprs_rlcmac_ul_tbf;

#include "cxx_linuxlist.h"
#include "llc.h"

extern "C" {
	#include <osmocom/core/timer.h>
}

#include <stdint.h>
#include <stddef.h>

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

		private:
		GprsMs * const m_ms;
	};

	GprsMs(uint32_t tlli);
	~GprsMs();

	void set_callback(Callback *cb) {m_cb = cb;}

	gprs_rlcmac_ul_tbf *ul_tbf() const {return m_ul_tbf;}
	gprs_rlcmac_dl_tbf *dl_tbf() const {return m_dl_tbf;}
	uint32_t tlli() const;
	void set_tlli(uint32_t tlli);
	bool confirm_tlli(uint32_t tlli);
	bool check_tlli(uint32_t tlli);

	const char *imsi() const;
	void set_imsi(const char *imsi);

	uint8_t ta() const;
	void set_ta(uint8_t ta);

	gprs_llc_queue *llc_queue();
	const gprs_llc_queue *llc_queue() const;

	void set_timeout(unsigned secs);

	void attach_tbf(gprs_rlcmac_tbf *tbf);
	void attach_ul_tbf(gprs_rlcmac_ul_tbf *tbf);
	void attach_dl_tbf(gprs_rlcmac_dl_tbf *tbf);

	void detach_tbf(gprs_rlcmac_tbf *tbf);

	bool is_idle() const {return !m_ul_tbf && !m_dl_tbf && !m_ref;}

	void* operator new(size_t num);
	void operator delete(void* p);

	LListHead<GprsMs>& list() {return this->m_list;}
	const LListHead<GprsMs>& list() const {return this->m_list;}

	/* internal use */
	static void timeout(void *priv_);

protected:
	void update_status();
	GprsMs *ref();
	void unref();
	void start_timer();
	void stop_timer();

private:
	Callback * m_cb;
	gprs_rlcmac_ul_tbf *m_ul_tbf;
	gprs_rlcmac_dl_tbf *m_dl_tbf;
	uint32_t m_tlli;
	uint32_t m_new_ul_tlli;
	uint32_t m_new_dl_tlli;

	/* store IMSI for look-up and PCH retransmission */
	char m_imsi[16];
	uint8_t m_ta;
	gprs_llc_queue m_llc_queue;

	bool m_is_idle;
	int m_ref;
	LListHead<GprsMs> m_list;
	struct osmo_timer_list m_timer;
	unsigned m_delay;
};

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

