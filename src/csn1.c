/* csn1_enc.c
 * Routines for CSN1 dissection in wireshark.
 *
 * Copyright (C) 2011 Ivan Klyuchnikov
 *
 * By Vincent Helfre, based on original code by Jari Sassi
 * with the gracious authorization of STE
 * Copyright (c) 2011 ST-Ericsson
 *
 * $Id: packet-csn1.c 39140 2011-09-25 22:01:50Z wmeier $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <assert.h>
#include <string.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "csn1.h"
#include <gprs_debug.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

const unsigned char ixBitsTab[] = {0, 1, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5};

/* Returns no_of_bits (up to 8) masked with 0x2B */
guint8
get_masked_bits8(struct bitvec *vector, unsigned *readIndex, gint bit_offset,  const gint no_of_bits)
{
  static const guint8 maskBits[] = {0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF};
  //gint byte_offset = bit_offset >> 3;          /* divide by 8 */
  gint relative_bit_offset = bit_offset & 0x07;  /* modulo 8 */
  guint8 result;
  gint bit_shift = 8 - relative_bit_offset - (gint) no_of_bits;
  *readIndex -= relative_bit_offset;
  if (bit_shift >= 0)
  {
    result = (0x2B ^ ((guint8)bitvec_read_field(vector, readIndex, 8))) >> bit_shift;
    *readIndex-= bit_shift;
    result &= maskBits[no_of_bits];
  }
  else
  {
    guint8 hight_part = (0x2B ^ ((guint8)bitvec_read_field(vector, readIndex, 8))) & maskBits[8 - relative_bit_offset];
    hight_part = (guint8) (hight_part << (-bit_shift));
    result =  (0x2B ^ ((guint8)bitvec_read_field(vector, readIndex, 8))) >> (8 + bit_shift);
    *readIndex = *readIndex - (8 - (-bit_shift));
    result |= hight_part;
  }
  return result;
}

/**
 * ================================================================================================
 * set initial/start values in help data structure used for packing/unpacking operation
 * ================================================================================================
 */
void
csnStreamInit(csnStream_t* ar, gint bit_offset, gint remaining_bits_len)
{
  ar->remaining_bits_len  = remaining_bits_len;
  ar->bit_offset          = bit_offset;
  ar->direction           = CSN_DIRECTION_ENC;
}

static const struct value_string csn1_error_names[] = {
  { CSN_OK,                               "General 0" },
  { CSN_ERROR_GENERAL,                    "General -1"  },
  { CSN_ERROR_DATA_NOT_VALID,             "DATA_NOT VALID" },
  { CSN_ERROR_IN_SCRIPT,                  "IN SCRIPT" },
  { CSN_ERROR_INVALID_UNION_INDEX,        "INVALID UNION INDEX" },
  { CSN_ERROR_NEED_MORE_BITS_TO_UNPACK,   "NEED_MORE BITS TO UNPACK" },
  { CSN_ERROR_ILLEGAL_BIT_VALUE,          "ILLEGAL BIT VALUE" },
  { CSN_ERROR_INTERNAL,                   "INTERNAL" },
  { CSN_ERROR_STREAM_NOT_SUPPORTED,       "STREAM_NOT_SUPPORTED" },
  { CSN_ERROR_MESSAGE_TOO_LONG,           "MESSAGE_TOO_LONG" },
  { 0, NULL }
};


gint16 ProcessError_impl(const char *file, int line, unsigned *readIndex,
                                const char* sz, gint16 err, const CSN_DESCR* pDescr)
{
  /* Don't add trailing newline, top caller is responsible for appending it */
  if (err != CSN_OK)
    LOGPSRC(DCSN1, LOGL_ERROR, file, line, "%s: error %s (%d) at %s (idx %u)",
            sz, get_value_string(csn1_error_names, err), err,
            pDescr ? pDescr->sz : "-", *readIndex);
  return err;
}
