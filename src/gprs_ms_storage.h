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
 */

#pragma once

#include "gprs_ms.h"
#include "tbf.h"
#include <stdint.h>
#include <stddef.h>

struct gprs_rlcmac_bts;

struct GprsMsStorage {
public:
	GprsMsStorage(struct gprs_rlcmac_bts *bts);
	~GprsMsStorage();

	void cleanup();

	GprsMs *get_ms(uint32_t tlli, uint32_t old_tlli = GSM_RESERVED_TMSI, const char *imsi = NULL) const;
	GprsMs *create_ms();

	const struct llist_head* ms_list() const {return &m_list;}
private:
	struct gprs_rlcmac_bts *m_bts;
	struct llist_head m_list; /* list of struct GprsMs */
};
