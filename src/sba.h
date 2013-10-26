/*
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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

#include <stdint.h>

extern "C" {
#include <osmocom/core/linuxlist.h>
}

class BTS;
class PollController;
struct gprs_rlcmac_sba;
struct gprs_rlcmac_pdch;

/*
 * single block allocation entry
 */
struct gprs_rlcmac_sba {
	struct llist_head list;
	uint8_t trx_no;
	uint8_t ts_no;
	uint32_t fn;
	uint8_t ta;
};

/**
 * I help to manage SingleBlockAssignment (SBA).
 *
 * TODO: Add a flush method..
 */
class SBAController {
	friend class PollController;
public:
	SBAController(BTS &bts);

	int alloc(uint8_t *_trx, uint8_t *_ts, uint32_t *_fn, uint8_t ta);
	gprs_rlcmac_sba *find(uint8_t trx, uint8_t ts, uint32_t fn);
	gprs_rlcmac_sba *find(const gprs_rlcmac_pdch *pdch, uint32_t fn);

	uint32_t sched(uint8_t trx, uint8_t ts, uint32_t fn, uint8_t block_nr);

	int timeout(struct gprs_rlcmac_sba *sba);
	void free_resources(struct gprs_rlcmac_pdch *pdch);

private:
	BTS &m_bts;
	llist_head m_sbas;
};
