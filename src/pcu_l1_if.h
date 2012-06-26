/* pcu_l1_if.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
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

#ifndef PCU_L1_IF_H
#define PCU_L1_IF_H

#include <stdint.h>
extern "C" {
#include <osmocom/core/write_queue.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/gsm/gsm_utils.h>
}

struct pcu_l1if_ts {
	uint8_t enable;
	uint8_t tsc;
};

struct pcu_l1if_trx {
	uint16_t arfcn;
	struct pcu_l1if_ts ts[8];
};

struct pcu_l1if_bts {
	struct pcu_l1if_trx trx[8];
};

extern struct pcu_l1if_bts pcu_l1if_bts;

int get_current_fn();
void set_current_fn(int fn);

void pcu_l1if_tx_pdtch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);
void pcu_l1if_tx_ptcch(msgb *msg, uint8_t trx, uint8_t ts, uint16_t arfcn, 
        uint32_t fn, uint8_t block_nr);
void pcu_l1if_tx_agch(bitvec * block, int len);

int pcu_l1if_open(void);
void pcu_l1if_close(void);

#endif // PCU_L1_IF_H
