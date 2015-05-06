/* gprs_ms.cpp
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


#include "gprs_ms.h"

#include "tbf.h"
#include "gprs_debug.h"

extern "C" {
	#include <osmocom/core/talloc.h>
	#include <osmocom/core/utils.h>
}

extern void *tall_pcu_ctx;

struct GprsMsDefaultCallback: public GprsMs::Callback {
	virtual void ms_idle(class GprsMs *ms) {
		delete ms;
	}
	virtual void ms_active(class GprsMs *) {}
};

static GprsMsDefaultCallback gprs_default_cb;


GprsMs::Guard::Guard(GprsMs *ms) : m_ms(ms)
{
	if (m_ms)
		m_ms->ref();
}

GprsMs::Guard::~Guard()
{
	if (m_ms)
		m_ms->unref();
}

GprsMs::GprsMs(uint32_t tlli) :
	m_cb(&gprs_default_cb),
	m_ul_tbf(NULL),
	m_dl_tbf(NULL),
	m_tlli(tlli),
	m_is_idle(true),
	m_ref(0)
{
	LOGP(DRLCMAC, LOGL_INFO, "Creating MS object, TLLI = 0x%08x\n", tlli);
}

GprsMs::~GprsMs()
{
	LOGP(DRLCMAC, LOGL_INFO, "Destroying MS object, TLLI = 0x%08x\n", tlli());
}

void* GprsMs::operator new(size_t size)
{
	static void *tall_ms_ctx = NULL;
	if (!tall_ms_ctx)
		tall_ms_ctx = talloc_named_const(tall_pcu_ctx, 0, __PRETTY_FUNCTION__);

	return talloc_size(tall_ms_ctx, size);
}

void GprsMs::operator delete(void* p)
{
	talloc_free(p);
}

void GprsMs::ref()
{
	m_ref += 1;
}

void GprsMs::unref()
{
	OSMO_ASSERT(m_ref >= 0);
	m_ref -= 1;
	if (m_ref == 0)
		update_status();
}

void GprsMs::attach_tbf(struct gprs_rlcmac_tbf *tbf)
{
	if (tbf->direction == GPRS_RLCMAC_DL_TBF)
		attach_dl_tbf(static_cast<gprs_rlcmac_dl_tbf *>(tbf));
	else
		attach_ul_tbf(static_cast<gprs_rlcmac_ul_tbf *>(tbf));
}

void GprsMs::attach_ul_tbf(struct gprs_rlcmac_ul_tbf *tbf)
{
	if (m_ul_tbf == tbf)
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Attaching TBF to MS object, TLLI = 0x%08x, TBF = %s\n",
		tlli(), tbf->name());

	Guard guard(this);

	if (m_ul_tbf)
		detach_tbf(m_ul_tbf);

	m_ul_tbf = tbf;
}

void GprsMs::attach_dl_tbf(struct gprs_rlcmac_dl_tbf *tbf)
{
	if (m_dl_tbf == tbf)
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Attaching TBF to MS object, TLLI = 0x%08x, TBF = %s\n",
		tlli(), tbf->name());

	Guard guard(this);

	if (m_dl_tbf)
		detach_tbf(m_dl_tbf);

	m_dl_tbf = tbf;
}

void GprsMs::detach_tbf(gprs_rlcmac_tbf *tbf)
{
	if (m_ul_tbf && tbf == static_cast<gprs_rlcmac_tbf *>(m_ul_tbf))
		m_ul_tbf = NULL;
	else if (m_dl_tbf && tbf == static_cast<gprs_rlcmac_tbf *>(m_dl_tbf))
		m_dl_tbf = NULL;
	else
		return;

	LOGP(DRLCMAC, LOGL_INFO, "Detaching TBF from MS object, TLLI = 0x%08x, TBF = %s\n",
		tlli(), tbf->name());

	update_status();
}

void GprsMs::update_status()
{
	if (m_ref > 0)
		return;

	if (is_idle() && !m_is_idle) {
		m_is_idle = true;
		m_cb->ms_idle(this);
		/* this can be deleted by now, do not access it */
		return;
	}

	if (!is_idle() && m_is_idle) {
		m_is_idle = false;
		m_cb->ms_active(this);
	}
}

void GprsMs::set_tlli(uint32_t tlli)
{
	if (tlli == m_tlli)
		return;

	LOGP(DRLCMAC, LOGL_INFO,
		"Modifying MS object, TLLI: 0x%08x -> 0x%08x\n",
		m_tlli, tlli);

	m_tlli = tlli;
}
