/* gprs_ms_storage.h
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

#include "gprs_ms.h"
#include "cxx_linuxlist.h"
#include "tbf.h"
#include <stdint.h>
#include <stddef.h>

struct BTS;

class GprsMsStorage : public GprsMs::Callback {
public:
	GprsMsStorage(BTS *bts);
	~GprsMsStorage();

	void cleanup();

	virtual void ms_idle(class GprsMs *);
	virtual void ms_active(class GprsMs *);

	GprsMs *get_ms(uint32_t tlli, uint32_t old_tlli = GSM_RESERVED_TMSI, const char *imsi = NULL) const;
	GprsMs *create_ms();

	const LListHead<GprsMs>& ms_list() const {return m_list;}
private:
	BTS *m_bts;
	LListHead<GprsMs> m_list;
};
