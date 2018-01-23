/* mslot_class.h
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
 * Copyright (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <stddef.h>
#include <stdbool.h>

/* 3GPP TS 05.02 Annex B.1 */

#define MS_NA	255 /* N/A */
#define MS_A	254 /* 1 with hopping, 0 without */
#define MS_B	253 /* 1 with hopping, 0 without (change Rx to Tx)*/
#define MS_C	252 /* 1 with hopping, 0 without (change Tx to Rx)*/
#define MS_TO	251 /* 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value) */

#define DEFAULT_MSLOT_CLASS 12

/* multislot class selection routines */
uint8_t mslot_class_get_ta(uint8_t ms_cl);
uint8_t mslot_class_get_tb(uint8_t ms_cl);
uint8_t mslot_class_get_ra(uint8_t ms_cl, uint8_t ta);
uint8_t mslot_class_get_rb(uint8_t ms_cl, uint8_t ta);
uint8_t mslot_class_get_tx(uint8_t ms_cl);
uint8_t mslot_class_get_rx(uint8_t ms_cl);
uint8_t mslot_class_get_sum(uint8_t ms_cl);
uint8_t mslot_class_get_type(uint8_t ms_cl);
uint8_t mslot_class_max();
