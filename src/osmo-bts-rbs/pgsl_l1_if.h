/* l2tp to PCU interface */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

/* receive message from l2tp socket (called by socket_rx() in l2tp_sock.c) */
void pgsl_msg_rx(struct msgb *msg);

/* Initalize pgsl interface */
void pgsl_init(void);

/* send packet data request to L1 */
int l1if_pdch_req(void *obj, uint8_t ts, int is_ptcch, uint32_t fn,
		  uint16_t arfcn, uint8_t block_nr, uint8_t *data,
		  uint8_t len);

