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
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* 3GPP TS 45.002 Annex B.1 */

#define MS_NA	255 /* N/A */
#define MS_A	254 /* 1 with hopping, 0 without */
#define MS_B	253 /* 1 with hopping, 0 without (change Rx to Tx)*/
#define MS_C	252 /* 1 with hopping, 0 without (change Tx to Rx)*/
#define MS_TO	251 /* 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value) */

#define DEFAULT_MSLOT_CLASS 12

#define NO_FREE_TFI 0xffffffff

enum { MASK_TT = 0, MASK_TR = 1 };

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

/* multislot allocation helper routines */
void mslot_fill_rx_mask(uint8_t mslot_class, uint8_t num_tx, uint8_t *rx_mask);
int8_t find_free_usf(uint8_t usf_map);
int8_t find_free_tfi(uint32_t tfi_map);
void masked_override_with(char *buf, uint8_t mask, char set_char);
void ts_format(char *buf, uint8_t dl_mask, uint8_t ul_mask);
uint16_t mslot_wrap_window(uint16_t win);
bool mslot_test_and_set_bit(uint32_t *bits, size_t elem);
int16_t mslot_filter_bad(uint8_t mask, uint8_t ul_slots, uint8_t dl_slots, uint16_t rx_valid_win);
