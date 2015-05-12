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
#include <stdint.h>
#include <stddef.h>

class GprsMsStorage : public GprsMs::Callback {
public:
	GprsMsStorage();
	~GprsMsStorage();

	virtual void ms_idle(class GprsMs *);
	virtual void ms_active(class GprsMs *);

	GprsMs *get_ms(uint32_t tlli, uint32_t old_tlli = 0, const char *imsi = 0) const;
	GprsMs *get_or_create_ms(uint32_t tlli, uint32_t old_tlli = 0, const char *imsi = 0);

private:
	LListHead<GprsMs> m_list;
};
