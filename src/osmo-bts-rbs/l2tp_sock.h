/* Connection to l2tp deamon */

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
#include <stdbool.h>
#include <osmocom/core/msgb.h>

#define L2TP_SOCK_DEFAULT	"/tmp/pgsl"

/* Open connection to l2tp daemon */
int l2tp_sock_init(const char *path);

/* Transmit message to l2tp daemon */
int l2tp_socket_tx(struct msgb *msg);

/* Check if PCU has an l2tp daemon connection */
bool l2tp_connected(void);
