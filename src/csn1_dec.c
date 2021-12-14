/* csn1_dec.c
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

extern const unsigned char ixBitsTab[];
guint8 get_masked_bits8(struct bitvec *vector, unsigned *readIndex, gint bit_offset, const gint no_of_bits);

/**
 * ================================================================================================
 * Return TRUE if tag in bit stream indicates existence of next list element,
 * otherwise return FALSE.
 * Will work for tag values equal to both 0 and 1.
 * ================================================================================================
 */

static gboolean
existNextElement(struct bitvec *vector, unsigned *readIndex, guint8 Tag)
{
  int res = bitvec_get_bit_pos(vector, (*readIndex)++);
  if (Tag == STANDARD_TAG)
  {
    return (res > 0);
  }
  return (res == 0);
}


gint16
csnStreamDecoder(csnStream_t* ar, const CSN_DESCR* pDescr, struct bitvec *vector, unsigned *readIndex, void* data)
{
  gint  remaining_bits_len = ar->remaining_bits_len;
  gint  bit_offset         = ar->bit_offset;
  guint8*  pui8 = NULL;
  guint16* pui16;
  guint32* pui32;
  guint64* pui64;
  guint8 Tag = STANDARD_TAG;
  unsigned ib;

  if (remaining_bits_len < 0)
  {
    return ProcessError(readIndex, __func__, CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
  }

  do
  {
    switch (pDescr->type)
    {
      case CSN_BIT:
      {
        if (remaining_bits_len > 0)
        {
          pui8  = pui8DATA(data, pDescr->offset);
	  *pui8 = bitvec_read_field(vector, readIndex, 1);
          LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
          /* end add the bit value to protocol tree */
        }
        else if (pDescr->may_be_null)
        {
           pui8  = pui8DATA(data, pDescr->offset);
           *pui8 = 0;
           LOGPC(DCSN1, LOGL_DEBUG, "%s = NULL | ", pDescr->sz);
        }
        else
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        pDescr++;
        remaining_bits_len--;
        bit_offset++;
        break;
      }

      case CSN_NULL:
      { /* Empty member! */
        bit_offset += pDescr->i;
        pDescr++;
        break;
      }

      case CSN_UINT:
      {
        guint8 no_of_bits = (guint8) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
	    guint8 ui8 = bitvec_read_field(vector, readIndex, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
          }
          else if (no_of_bits <= 16)
          {
	    guint16 ui16 = bitvec_read_field(vector, readIndex, no_of_bits);
            pui16       = pui16DATA(data, pDescr->offset);
            *pui16      = ui16;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui16);
          }
          else if (no_of_bits <= 32)
          {
	    guint32 ui32 = bitvec_read_field(vector, readIndex, no_of_bits);
            pui32       = pui32DATA(data, pDescr->offset);
            *pui32      = ui32;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = 0x%08x | ", pDescr->sz , *pui32);
          }
          else
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
          }
          remaining_bits_len -= no_of_bits;
          bit_offset += no_of_bits;
        }
        else if (pDescr->may_be_null)
        {
          if (no_of_bits <= 8)
          {
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = 0;
          }
          else if (no_of_bits <= 16)
          {
            pui16      = pui16DATA(data, pDescr->offset);
            *pui16     = 0;
          }
          else if (no_of_bits <= 32)
          {
            pui32      = pui32DATA(data, pDescr->offset);
            *pui32     = 0;
          }
          LOGPC(DCSN1, LOGL_DEBUG, "%s = NULL | ", pDescr->sz);
        }
        else
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        pDescr++;
        break;
      }

      case CSN_UINT_OFFSET:
      {
        guint8 no_of_bits = (guint8) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
	    guint8 ui8 = bitvec_read_field(vector, readIndex, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8 + (guint8)pDescr->descr.value;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
          }
          else if (no_of_bits <= 16)
          {
	    guint16 ui16 = bitvec_read_field(vector, readIndex, no_of_bits);
            pui16       = pui16DATA(data, pDescr->offset);
            *pui16      = ui16 + (guint16)pDescr->descr.value;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui16);
          }
          else if (no_of_bits <= 32)
          {
	    guint32 ui32 = bitvec_read_field(vector, readIndex, no_of_bits);
            pui32       = pui32DATA(data, pDescr->offset);
            *pui32      = ui32 + (guint16)pDescr->descr.value;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui32);
          }
          else
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
          }
        }
        else
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_UINT_LH:
      {
        guint8 no_of_bits = (guint8) pDescr->i;

        if (remaining_bits_len >= no_of_bits)
        {
          if (no_of_bits <= 8)
          {
	    guint8 ui8 = get_masked_bits8(vector, readIndex, bit_offset, no_of_bits);
            pui8      = pui8DATA(data, pDescr->offset);
            *pui8     = ui8;
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
          }
          else
          {/* Maybe we should support more than 8 bits ? */
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
          }
        }
        else
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_UINT_ARRAY:
      {
        guint8  no_of_bits  = (guint8) pDescr->i;
        guint16 nCount = (guint16)pDescr->descr.value; /* nCount supplied by value i.e. M_UINT_ARRAY(...) */

        if (pDescr->value != 0)
        { /* nCount specified by a reference to field holding value i.e. M_VAR_UINT_ARRAY(...) */
          nCount = *pui16DATA(data, nCount);
        }

        if (remaining_bits_len >= (no_of_bits * nCount))
        {
          remaining_bits_len -= (no_of_bits*nCount);
          if (no_of_bits <= 8)
          {
            pui8 = pui8DATA(data, pDescr->offset);
            do
            {
	      *pui8 = bitvec_read_field(vector, readIndex, no_of_bits);
              LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              pui8++;
              bit_offset += no_of_bits;
            } while (--nCount > 0);
          }
          else if (no_of_bits <= 16)
          {
            return ProcessError(readIndex,"csnStreamDecoder NOTIMPLEMENTED", 999, pDescr);
          }
          else if (no_of_bits <= 32)
          {
            return ProcessError(readIndex,"csnStreamDecoder NOTIMPLEMENTED", 999, pDescr);
          }
          else
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
          }
        }
        else
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }
        pDescr++;
        break;
      }

      case CSN_VARIABLE_TARRAY_OFFSET:
      case CSN_VARIABLE_TARRAY:
      case CSN_TYPE_ARRAY:
      {
        gint16      Status;
        csnStream_t arT    = *ar;
        gint16      nCount = pDescr->i;
        guint16      nSize  = (guint16)(gint32)pDescr->value;

        pui8 = pui8DATA(data, pDescr->offset);
        if (pDescr->type == CSN_VARIABLE_TARRAY)
        { /* Count specified in field */
          nCount = *pui8DATA(data, pDescr->i);
        }
        else if (pDescr->type == CSN_VARIABLE_TARRAY_OFFSET)
        { /* Count specified in field */
          nCount = *pui8DATA(data, pDescr->i);
	  /*  nCount--; the 1 offset is already taken into account in CSN_UINT_OFFSET */
        }

        while (nCount > 0)
        { /* resulting array of length 0 is possible
           * but no bits shall be read from bitstream
           */

          LOGPC(DCSN1, LOGL_DEBUG, "%s | ", pDescr->sz);
          csnStreamInit(&arT, bit_offset, remaining_bits_len);
	  Status = csnStreamDecoder(&arT, (const CSN_DESCR*)pDescr->descr.ptr, vector, readIndex, pui8);
          if (Status >= 0)
          {
            pui8    += nSize;
            remaining_bits_len = arT.remaining_bits_len;
            bit_offset         = arT.bit_offset;
          }
          else
          {
            return Status;
          }
          nCount--;
        }

        pDescr++;
        break;
      }

      case CSN_BITMAP:
      { /* bitmap with given length. The result is left aligned! */
        guint8 no_of_bits = (guint8) pDescr->i; /* length of bitmap */

        if (no_of_bits > 0)
        {
          if (no_of_bits > remaining_bits_len)
          {
            return ProcessError(readIndex, "csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          if (no_of_bits <= 32)
          {
            for(ib = 0; ib < 4; ib++)
            {
	      guint8 ui8 = bitvec_read_field(vector, readIndex, 8);
              pui8      = pui8DATA(data, pDescr->offset+ib);
              *pui8      = ui8;
               LOGPC(DCSN1, LOGL_DEBUG, "%s[%u] = %u | ", pDescr->sz , ib, (unsigned)*pui8);
            }
          }
          else if (no_of_bits <= 64)
          {
            for(ib = 0; ib < 8; ib++)
            {
	      guint8 ui8 = bitvec_read_field(vector, readIndex, 8);
              pui8      = pui8DATA(data, pDescr->offset+ib);
              *pui8      = ui8;
               LOGPC(DCSN1, LOGL_DEBUG, "%s[%u] = %u | ", pDescr->sz , ib, (unsigned)*pui8);
            }
          }
          else
          {
          	return ProcessError(readIndex,"csnStreamDecoder NOT IMPLEMENTED", 999, pDescr);
          }

          remaining_bits_len -= no_of_bits;
          bit_offset += no_of_bits;
        }
        /* bitmap was successfully extracted or it was empty */

        pDescr++;
        break;
      }

      case CSN_TYPE:
      {
        gint16      Status;
        csnStream_t arT = *ar;
        if (pDescr->may_be_null && remaining_bits_len == 0)
        {
          LOGPC(DCSN1, LOGL_DEBUG, " : %s = NULL | ", pDescr->sz);
        } else {
          LOGPC(DCSN1, LOGL_DEBUG, " : %s | ", pDescr->sz);
          csnStreamInit(&arT, bit_offset, remaining_bits_len);
	  Status = csnStreamDecoder(&arT, (const CSN_DESCR*)pDescr->descr.ptr, vector, readIndex, pvDATA(data, pDescr->offset));
          LOGPC(DCSN1, LOGL_DEBUG, ": End %s | ", pDescr->sz);
          if (Status >= 0)
          {
            remaining_bits_len  = arT.remaining_bits_len;
            bit_offset          = arT.bit_offset;
          }
          else
          {
            /* Has already been processed: ProcessError("csnStreamDecoder", Status, pDescr);  */
            return Status;
          }
        }
        pDescr++;
        break;
      }

      case CSN_CHOICE:
      {
        gint16 count = pDescr->i;
        guint8 i     = 0;
        CSN_ChoiceElement_t* pChoice = (CSN_ChoiceElement_t*) pDescr->descr.ptr;

        /* Make sure that the list of choice items is not empty */
        if (!count)
          return ProcessError(readIndex, "csnStreamDecoder", CSN_ERROR_IN_SCRIPT, pDescr);
        else if (count > 255) /* We can handle up to 256 (UCHAR_MAX) selectors */
          return ProcessError(readIndex, "csnStreamDecoder", CSN_ERROR_IN_SCRIPT, pDescr);

        while (count > 0)
        {
          guint8 no_of_bits = pChoice->bits;
	  guint8 value = bitvec_read_field(vector, readIndex, no_of_bits);
          if (value == pChoice->value)
          {
            CSN_DESCR   descr[2];
            gint16      Status;
            csnStream_t arT = *ar;

            descr[0]      = pChoice->descr;
            memset(&descr[1], 0x00, sizeof(CSN_DESCR));
            descr[1].type = CSN_END;
            pui8          = pui8DATA(data, pDescr->offset);
            *pui8         = i;
            LOGPC(DCSN1, LOGL_DEBUG, "Choice %s = %u | ", pDescr->sz , (unsigned)value);
            if (!pChoice->keep_bits) {
              bit_offset += no_of_bits;
              remaining_bits_len -= no_of_bits;
            }

            csnStreamInit(&arT, bit_offset, remaining_bits_len);
	    Status = csnStreamDecoder(&arT, descr, vector, readIndex, data);

            if (Status >= 0)
            {
              remaining_bits_len = arT.remaining_bits_len;
              bit_offset         = arT.bit_offset;
            }
            else
            {
              return Status;
            }
            break;
          }

          *readIndex -= no_of_bits;
          count--;
          pChoice++;
          i++;
        }

        /* Neither of the choice items matched => unknown value */
        if (!count)
          return ProcessError(readIndex, "csnStreamDecoder", CSN_ERROR_STREAM_NOT_SUPPORTED, pDescr);

        pDescr++;
        break;
      }

      case CSN_SERIALIZE:
      {
        StreamSerializeFcn_t serialize = (StreamSerializeFcn_t)pDescr->aux_fn;
        csnStream_t          arT       = *ar;
        guint8 length_len              = pDescr->i;
        gint16               Status    = -1;

	guint8 length = bitvec_read_field(vector, readIndex, length_len);

        LOGPC(DCSN1, LOGL_DEBUG, "%s length = %u | ", pDescr->sz , length);
        bit_offset += length_len;
        remaining_bits_len -= length_len;

        csnStreamInit(&arT, bit_offset, length > 0 ? length : remaining_bits_len);
        arT.direction = 1;
        LOGPC(DCSN1, LOGL_DEBUG, "offset = %u | ", pDescr->offset);
	Status = serialize(&arT, vector, readIndex, pvDATA(data, pDescr->offset));

        if (Status >= 0)
        {
          if (length > 0) {
            remaining_bits_len -= length;
            bit_offset         += length;
          } else {
            remaining_bits_len = arT.remaining_bits_len;
            bit_offset         = arT.bit_offset;
          }

          /* Skip bits not handled by serialize(), if any */
          if (Status > 0) {
            LOGPC(DCSN1, LOGL_DEBUG, "skipped = %d | ", Status);
            *readIndex += Status;
          }

          pDescr++;
        }
        else
        {
          /* Has already been processed: */
          return Status;
        }

        break;
      }

      case CSN_UNION_LH:
      case CSN_UNION:
      {
        gint16           Bits;
        guint8           index;
        gint16           count      = pDescr->i;
        const CSN_DESCR* pDescrNext = pDescr;

        pDescrNext += count + 1; /* now this is next after the union */
        if ((count <= 0) || (count > 16))
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_INVALID_UNION_INDEX, pDescr);
        }

        /* Now get the bits to extract the index */
        Bits = ixBitsTab[count];
        index = 0;

        while (Bits > 0)
        {
          index <<= 1;

          if (CSN_UNION_LH == pDescr->type)
          {
            index |= get_masked_bits8(vector, readIndex, bit_offset, 1);
          }
          else
          {
	    index |= bitvec_read_field(vector, readIndex, 1);
          }
          remaining_bits_len--;
          bit_offset++;
          Bits--;
        }

        /* Assign UnionType */
        pui8  = pui8DATA(data, pDescr->offset);
        *pui8 = index;


        /* script index to continue on, limited in case we do not have a power of 2 */
        pDescr += (MIN(index + 1, count));
        LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);

        switch (pDescr->type)
        { /* get the right element of the union based on computed index */

          case CSN_BIT:
          {
            pui8  = pui8DATA(data, pDescr->offset);
            *pui8 = 0x00;
	    if (bitvec_read_field(vector, readIndex, 1) > 0)
            {
              *pui8 = 0x01;
            }
            LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
            remaining_bits_len -= 1;
            bit_offset++;
            pDescr++;
            break;
          }

          case CSN_NULL:
          { /* Empty member! */
            bit_offset += pDescr->i;
            pDescr++;
            break;
          }

          case CSN_UINT:
          {
            guint8 no_of_bits = (guint8) pDescr->i;
            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
		guint8 ui8 = bitvec_read_field(vector, readIndex,  no_of_bits);
                pui8       = pui8DATA(data, pDescr->offset);
                *pui8      = ui8;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              }
              else if (no_of_bits <= 16)
              {
		guint16 ui16 = bitvec_read_field(vector, readIndex,  no_of_bits);
                pui16        = pui16DATA(data, pDescr->offset);
                *pui16       = ui16;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui16);
              }
              else if (no_of_bits <= 32)
              {
		guint32 ui32 = bitvec_read_field(vector, readIndex,  no_of_bits);
                pui32       = pui32DATA(data, pDescr->offset);
                *pui32      = ui32;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui32);
              }
              else
              {
                return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_OFFSET:
          {
            guint8 no_of_bits = (guint8) pDescr->i;

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
		guint8 ui8 = bitvec_read_field(vector, readIndex,  no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8 + (guint8)pDescr->descr.value;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              }
              else if (no_of_bits <= 16)
              {
		guint16 ui16 = bitvec_read_field(vector, readIndex,  no_of_bits);
                pui16       = pui16DATA(data, pDescr->offset);
                *pui16      = ui16 + (guint16)pDescr->descr.value;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui16);
              }
              else if (no_of_bits <= 32)
              {
		guint32 ui32 = bitvec_read_field(vector, readIndex,  no_of_bits);
                pui32       = pui32DATA(data, pDescr->offset);
                *pui32      = ui32 + (guint16)pDescr->descr.value;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui32);
              }
              else
              {
                return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_LH:
          {
            guint8 no_of_bits = (guint8) pDescr->i;

            if (remaining_bits_len >= no_of_bits)
            {
              if (no_of_bits <= 8)
              {
		guint8 ui8 = get_masked_bits8(vector, readIndex, bit_offset, no_of_bits);
                pui8      = pui8DATA(data, pDescr->offset);
                *pui8     = ui8;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              }
              else
              { /* Maybe we should support more than 8 bits ? */
                return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
            }

            remaining_bits_len -= no_of_bits;
            bit_offset += no_of_bits;
            pDescr++;
            break;
          }

          case CSN_UINT_ARRAY:
          {
            guint8  no_of_bits  = (guint8) pDescr->i;
            guint16 nCount = (guint16)pDescr->descr.value; /* nCount supplied by value i.e. M_UINT_ARRAY(...) */

            if (pDescr->value != 0)
            { /* nCount specified by a reference to field holding value i.e. M_VAR_UINT_ARRAY(...) */
              nCount = *pui16DATA(data, nCount);
            }

            if (remaining_bits_len >= (no_of_bits * nCount))
            {
              remaining_bits_len -= (no_of_bits * nCount);
              if (no_of_bits <= 8)
              {
                pui8 = pui8DATA(data, pDescr->offset);

                while (nCount > 0)
                {
		  *pui8 = bitvec_read_field(vector, readIndex,  no_of_bits);
                  LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
                  pui8++;
                  bit_offset += no_of_bits;
                  nCount--;
                }
              }
              else if (no_of_bits <= 16)
              {
                pui16 = pui16DATA(data, pDescr->offset);

                while (nCount > 0)
                {
		 *pui16 = bitvec_read_field(vector, readIndex,  no_of_bits);
                  LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , *pui16);
                  pui16++;
                  bit_offset += no_of_bits;
                  nCount--;
                }
              }
              else if (no_of_bits <= 32)
              { /* not supported */
                return ProcessError(readIndex,"csnStreamDecoder NOT IMPLEMENTED", 999, pDescr);
              }
              else
              {
                return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_GENERAL, pDescr);
              }
            }
            else
            {
              return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
            }

            pDescr++;
            break;
          }

          case CSN_VARIABLE_TARRAY_OFFSET:
          case CSN_VARIABLE_TARRAY:
          case CSN_TYPE_ARRAY:
          {
            gint16      Status;
            csnStream_t arT    = *ar;
            guint16      nCount = (guint16) pDescr->i;
            guint16      nSize  = (guint16)(guint32)pDescr->value;

            pui8  = pui8DATA(data, pDescr->offset);

            if (CSN_VARIABLE_TARRAY == pDescr->type)
            { /* Count specified in field */
              nCount = *pui8DATA(data, pDescr->i);
            }
            else if (CSN_VARIABLE_TARRAY_OFFSET == pDescr->type)
            { /* Count specified in field */
              nCount = *pui8DATA(data, pDescr->i);
              nCount--; /* Offset 1 */
            }

            while (nCount--)    /* Changed to handle length = 0.  */
            {
              LOGPC(DCSN1, LOGL_DEBUG, "%s | ", pDescr->sz);
              csnStreamInit(&arT, bit_offset, remaining_bits_len);
	      Status = csnStreamDecoder(&arT, (const CSN_DESCR*)pDescr->descr.ptr, vector, readIndex, pui8);
              if (Status >= 0)
              {
                pui8    += nSize;
                remaining_bits_len = arT.remaining_bits_len;
                bit_offset         = arT.bit_offset;
              }
              else
              {
                return Status;
              }
            }

            pDescr++;
            break;
          }

          case CSN_BITMAP:
          { /* bitmap with given length. The result is left aligned! */
            guint8 no_of_bits = (guint8) pDescr->i; /* length of bitmap */

            if (no_of_bits > 0)
            {
              if (no_of_bits > remaining_bits_len)
              {
                return ProcessError(readIndex, "csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
              }

              if (no_of_bits <= 32)
              {
		guint32 ui32 = bitvec_read_field(vector, readIndex, no_of_bits);
                pui32       = pui32DATA(data, pDescr->offset);
                *pui32      = ui32;
              }
              else if (no_of_bits <= 64)
              {
		guint64 ui64 = bitvec_read_field(vector, readIndex, no_of_bits);
                pui64       = pui64DATA(data, pDescr->offset);
                *pui64      = ui64;
                LOGPC(DCSN1, LOGL_DEBUG, "%s = %lu | ", pDescr->sz , *pui64);
              }
              else
              {
              	return ProcessError(readIndex,"csnStreamDecoder NOT IMPLEMENTED", 999, pDescr);
              }

              remaining_bits_len -= no_of_bits;
              bit_offset += no_of_bits;
            }
            /* bitmap was successfully extracted or it was empty */

            pDescr++;
            break;
          }

          case CSN_TYPE:
          {
            gint16      Status;
            csnStream_t arT = *ar;
            if (pDescr->may_be_null && remaining_bits_len == 0)
            {
              LOGPC(DCSN1, LOGL_DEBUG, " : %s = NULL | ", pDescr->sz);
            } else {
              LOGPC(DCSN1, LOGL_DEBUG, " : %s | ", pDescr->sz);
              csnStreamInit(&arT, bit_offset, remaining_bits_len);
	      Status = csnStreamDecoder(&arT, (const CSN_DESCR*)pDescr->descr.ptr, vector, readIndex, pvDATA(data, pDescr->offset));
              LOGPC(DCSN1, LOGL_DEBUG, " : End %s | ", pDescr->sz);
              if (Status >= 0)
              {
                remaining_bits_len = arT.remaining_bits_len;
                bit_offset         = arT.bit_offset;
              }
              else
              { /* return error code Has already been processed:  */
                return Status;
              }
            }
            pDescr++;
            break;
          }

          default:
          { /* descriptions of union elements other than above are illegal */
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_IN_SCRIPT, pDescr);
          }
        }

        pDescr = pDescrNext;
        break;
      }

      case CSN_EXIST:
      case CSN_EXIST_LH:
      {
        guint8 fExist;

        pui8  = pui8DATA(data, pDescr->offset);

        if (CSN_EXIST_LH == pDescr->type)
        {
	  fExist = get_masked_bits8(vector, readIndex, bit_offset, 1);
        }
        else
        {
	  fExist = bitvec_read_field(vector, readIndex, 1);
        }

        *pui8 = fExist;
        LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
        pDescr++;
        bit_offset++;
        remaining_bits_len -= 1;

        if (!fExist)
        {
          ar->remaining_bits_len  = remaining_bits_len;
          ar->bit_offset          = bit_offset;
          return remaining_bits_len;
        }

        break;
      }

      case CSN_NEXT_EXIST:
      {
        guint8 fExist;
        guint8 isnull;

        pui8  = pui8DATA(data, pDescr->offset);

        /* this if-statement represents the M_NEXT_EXIST_OR_NULL description element */
        if ((pDescr->may_be_null) && (remaining_bits_len == 0))
        { /* no more bits to decode is fine here - end of message detected and allowed */

          /* Skip i entries + this entry */
          pDescr += pDescr->i + 1;

          /* Set the data member to "not exist" */
          *pui8 = 0;
          break;
        }

        /* the "regular" M_NEXT_EXIST description element */

        fExist = 0x00;
        isnull = 1;
	if (bitvec_read_field(vector, readIndex, 1))
        {
          fExist = 0x01;
          if (remaining_bits_len == 1) {
             /* If { 1 < end > } and all next items may be null, store it as { 0 } */
            const CSN_DESCR* pDescrNext = pDescr + 1;
            guint8 i;
            for (i = 0; i < pDescr->i; i++, pDescrNext++)
            {
              if (!pDescrNext->may_be_null)
                isnull = 0;
            }
          } else {
            isnull = 0;
          }
        }

        *pui8     = !isnull;
        remaining_bits_len -= 1;
        LOGPC(DCSN1, LOGL_DEBUG, "%s = %u%s | ", pDescr->sz, (unsigned)fExist, fExist && isnull ? " (NULL)" : "");
        ++bit_offset;

        if (isnull)
        { /* Skip 'i' entries */
          pDescr += pDescr->i;
        }

        pDescr++;
        break;
      }

      case CSN_NEXT_EXIST_LH:
      {
        guint8 fExist;
        guint8 isnull;
        pui8  = pui8DATA(data, pDescr->offset);

        /* this if-statement represents the M_NEXT_EXIST_OR_NULL_LH description element */
        if ((pDescr->descr.ptr != NULL) && (remaining_bits_len == 0))
        { /* no more bits to decode is fine here - end of message detected and allowed */

          /* skip 'i' entries + this entry */
          pDescr += pDescr->i + 1;

          /* set the data member to "not exist" */
          *pui8 = 0;
          break;
        }

        /* the "regular" M_NEXT_EXIST_LH description element */
        isnull = 1;
        if ((fExist = get_masked_bits8(vector, readIndex, bit_offset, 1)))
        {
          if (remaining_bits_len == 1) {
             /* If { 1 < end > } and all next items may be null, store it as { 0 } */
            const CSN_DESCR* pDescrNext = pDescr + 1;
            guint8 i;
            for (i = 0; i < pDescr->i; i++, pDescrNext++)
            {
              if (!pDescrNext->may_be_null)
                isnull = 0;
            }
          } else {
            isnull = 0;
          }
        }
        LOGPC(DCSN1, LOGL_DEBUG, "%s = %u%s | ", pDescr->sz , (unsigned)fExist, fExist && isnull ? " (NULL)" : "");
        *pui8++   = !isnull;
        remaining_bits_len -= 1;

        bit_offset++;

        if (isnull)
        { /* Skip 'i' entries */
          pDescr += pDescr->i;
        }
        pDescr++;

        break;
      }

      case CSN_VARIABLE_BITMAP_1:
      { /* Bitmap from here and to the end of message */

        *pui8DATA(data, (gint16)pDescr->descr.value) = (guint8) remaining_bits_len; /* length of bitmap == remaining bits */

        /*no break -
         * with a length set we have a regular variable length bitmap so we continue */
      }
      /* FALL THROUGH */
      case CSN_VARIABLE_BITMAP:
      { /* {CSN_VARIABLE_BITMAP, 0, offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * <N: bit (5)> <bitmap: bit(N + offset)>
         * Bit array with length (in bits) specified in parameter (pDescr->descr)
         * The result is right aligned!
         */
        gint16 no_of_bits = *pui8DATA(data, (gint16)pDescr->descr.value);

        no_of_bits += pDescr->i; /* adjusted by offset */

        if (no_of_bits > 0)
        {
          remaining_bits_len -= no_of_bits;

          if (remaining_bits_len < 0)
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          { /* extract bits */
            guint8* pui8 = pui8DATA(data, pDescr->offset);
            gint16 nB1  = no_of_bits & 0x07;/* no_of_bits Mod 8 */

            if (nB1 > 0)
            { /* take care of the first byte - it will be right aligned */
	      *pui8 = bitvec_read_field(vector, readIndex, nB1);
              LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              pui8++;
              no_of_bits  -= nB1;
              bit_offset += nB1; /* (nB1 is no_of_bits Mod 8) */
            }

            /* remaining no_of_bits is a multiple of 8 or 0 */
            while (no_of_bits > 0)
            {
	      *pui8 = bitvec_read_field(vector, readIndex, 8);
              LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              pui8++;
              no_of_bits -= 8;
            }
          }
        }
        pDescr++;
        break;
      }

      case CSN_LEFT_ALIGNED_VAR_BMP_1:
      { /* Bitmap from here and to the end of message */

        *pui8DATA(data, (gint16)pDescr->descr.value) = (guint8) remaining_bits_len; /* length of bitmap == remaining bits */

        /* no break -
         * with a length set we have a regular left aligned variable length bitmap so we continue
         */
      }
      /* FALL THROUGH */
      case CSN_LEFT_ALIGNED_VAR_BMP:
      { /* {CSN_LEFT_ALIGNED_VAR_BMP, _OFFSET, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * <N: bit (5)> <bitmap: bit(N + offset)>
         * bit array with length (in bits) specified in parameter (pDescr->descr)
         */
        gint16 no_of_bits = *pui8DATA(data, (gint16)pDescr->descr.value);/* Size of bitmap */

        no_of_bits += pDescr->i;/* size adjusted by offset */

        if (no_of_bits > 0)
        {
          remaining_bits_len -= no_of_bits;

          if (remaining_bits_len < 0)
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          { /* extract bits */
            guint8* pui8 = pui8DATA(data, pDescr->offset);

            while (no_of_bits >= 8)
            {
	      *pui8 = bitvec_read_field(vector, readIndex, 8);
              LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              pui8++;
              no_of_bits -= 8;
            }
            if (no_of_bits > 0)
            {
	      *pui8 = bitvec_read_field(vector, readIndex, no_of_bits);
              LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
              pui8++;
              bit_offset += no_of_bits;
              no_of_bits = 0;
            }
          }
        }

        /* bitmap was successfully extracted or it was empty */
        pDescr++;
        break;
      }

      case CSN_PADDING_BITS:
      { /* Padding from here and to the end of message */
        LOGPC(DCSN1, LOGL_DEBUG, "%s = ", pDescr->sz);
        if (remaining_bits_len > 0)
        {
          while (remaining_bits_len > 0)
          {
            guint bits_to_handle = remaining_bits_len%8;
            if (bits_to_handle > 0)
            {
              LOGPC(DCSN1, LOGL_DEBUG, "%d|", bitvec_get_uint(vector, bits_to_handle));
              remaining_bits_len -= bits_to_handle;
              bit_offset += bits_to_handle;
            }
            else if (bits_to_handle == 0)
            {
              LOGPC(DCSN1, LOGL_DEBUG, "%d|", bitvec_get_uint(vector, 8));
              remaining_bits_len -= 8;
              bit_offset += 8;
            }
          }
        }
        if (remaining_bits_len < 0)
        {
          return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
        }

        /* Padding was successfully extracted or it was empty */
        pDescr++;
        break;
      }

      case CSN_VARIABLE_ARRAY:
      { /* {int type; int i; void* descr; int offset; const char* sz; } CSN_DESCR;
         * {CSN_VARIABLE_ARRAY, _OFFSET, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * Array with length specified in parameter:
         *  <count: bit (x)>
         *  <list: octet(count + offset)>
         */
        gint16 count = *pui8DATA(data, (gint16)pDescr->descr.value);

        count += pDescr->i; /* Adjusted by offset */

        if (count > 0)
        {
          remaining_bits_len -= count * 8;

          if (remaining_bits_len < 0)
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          pui8 = pui8DATA(data, pDescr->offset);

          while (count > 0)
          {
	    *pui8 = bitvec_read_field(vector, readIndex, 8);
            LOGPC(DCSN1, LOGL_DEBUG, "%s = 0x%x | ", pDescr->sz , (unsigned)*pui8);
            pui8++;
            bit_offset += 8;
            count--;
          }
        }

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_ARRAY:
      { /* Recursive way to specify an array: <list> ::= {1 <number: bit (4)> <list> | 0}
         *  or more generally:                <list> ::= { <tag> <element> <list> | <EndTag> }
         *  where <element> ::= bit(value)
         *        <tag>     ::= 0 | 1
         *        <EndTag>  ::= reversed tag i.e. tag == 1 -> EndTag == 0 and vice versa
         * {CSN_RECURSIVE_ARRAY, _BITS, (void*)offsetof(_STRUCT, _ElementCountField), offsetof(_STRUCT, _MEMBER), #_MEMBER}
         * REMARK: recursive way to specify an array but an iterative implementation!
         */
        gint16 no_of_bits        = pDescr->i;
        guint8  ElementCount = 0;

        pui8  = pui8DATA(data, pDescr->offset);

	while (existNextElement(vector, readIndex, Tag))
        { /* tag control shows existence of next list elements */
          LOGPC(DCSN1, LOGL_DEBUG, "%s = Exist | ", pDescr->sz);
          bit_offset++;
          remaining_bits_len--;

          /* extract and store no_of_bits long element from bitstream */
	  *pui8 = bitvec_read_field(vector, readIndex, no_of_bits);
          LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned)*pui8);
          pui8++;
          remaining_bits_len -= no_of_bits;
          ElementCount++;

          if (remaining_bits_len < 0)
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          bit_offset += no_of_bits;
        }

        LOGPC(DCSN1, LOGL_DEBUG, "%s = %d | ", pDescr->sz , bitvec_get_uint(vector, 1));
        /* existNextElement() returned FALSE, 1 bit consumed */
        bit_offset++;
        remaining_bits_len--;

        /* Store the counted number of elements of the array */
        *pui8DATA(data, (gint16)pDescr->descr.value) = ElementCount;

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_TARRAY:
      { /* Recursive way to specify an array of type: <lists> ::= { 1 <type> } ** 0 ;
         *  M_REC_TARRAY(_STRUCT, _MEMBER, _MEMBER_TYPE, _ElementCountField)
         * {t, offsetof(_STRUCT, _ElementCountField), (void*)CSNDESCR_##_MEMBER_TYPE, offsetof(_STRUCT, _MEMBER), #_MEMBER, (StreamSerializeFcn_t)sizeof(_MEMBER_TYPE), (void_fn_t)ElementsOf(((_STRUCT*)0)->_MEMBER)}
         */
        gint16 nSizeElement = (gint16)(gint32)pDescr->value;
        guint32 nSizeArray = (guint32)((uintptr_t)pDescr->aux_fn);
        guint8  ElementCount = 0;
        pui8  = pui8DATA(data, pDescr->offset);

	while (existNextElement(vector, readIndex, Tag))
        { /* tag control shows existence of next list elements */
          LOGPC(DCSN1, LOGL_DEBUG, "%s = Exist | ", pDescr->sz);
          /* existNextElement() returned TRUE, 1 bit consumed */
          bit_offset++;
          remaining_bits_len--;
          ElementCount++;

          if (ElementCount > nSizeArray)
          {
            LOGPC(DCSN1, LOGL_ERROR, "error: %s: too many elements (>%u) in recursive array. Increase its size! } |", pDescr->sz, nSizeArray);
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_STREAM_NOT_SUPPORTED, pDescr);
          }

          { /* unpack the following data structure */
            csnStream_t arT = *ar;
            gint16      Status;
            csnStreamInit(&arT, bit_offset, remaining_bits_len);
	    Status = csnStreamDecoder(&arT, (const CSN_DESCR*)pDescr->descr.ptr, vector, readIndex, pui8);

            if (Status >= 0)
            { /* successful completion */
              pui8    += nSizeElement;  /* -> to next data element */
              remaining_bits_len = arT.remaining_bits_len;
              bit_offset         = arT.bit_offset;
            }
            else
            { /* something went awry */
              return Status;
            }
          }

          if (remaining_bits_len < 0)
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }
        }

        LOGPC(DCSN1, LOGL_DEBUG, "%s = %d | ", pDescr->sz , bitvec_get_uint(vector, 1));

        /* existNextElement() returned FALSE, 1 bit consumed */
        remaining_bits_len--;
        bit_offset++;

        /* Store the counted number of elements of the array */
        *pui8DATA(data, (gint16)(gint32)pDescr->i) = ElementCount;

        pDescr++;
        break;
      }

      case CSN_RECURSIVE_TARRAY_2:
      { /* Recursive way to specify an array of type: <list> ::= <type> { 0 <type> } ** 1 ; */

        Tag = REVERSED_TAG;

        /* NO break -
         * handling is exactly the same as for CSN_RECURSIVE_TARRAY_1 so we continue
         */
      }
      /* FALL THROUGH */
      case CSN_RECURSIVE_TARRAY_1:
      { /* Recursive way to specify an array of type: <lists> ::= <type> { 1 <type> } ** 0 ;
         * M_REC_TARRAY(_STRUCT, _MEMBER, _MEMBER_TYPE, _ElementCountField)
         * {t, offsetof(_STRUCT, _ElementCountField), (void*)CSNDESCR_##_MEMBER_TYPE, offsetof(_STRUCT, _MEMBER), #_MEMBER, (StreamSerializeFcn_t)sizeof(_MEMBER_TYPE), (void_fn_t)ElementsOf(((_STRUCT*)0)->_MEMBER)}
         */
        gint16      nSizeElement = (gint16)(gint32)pDescr->value;
        guint32     nSizeArray = (guint32)((uintptr_t)pDescr->aux_fn);
        guint8       ElementCount = 0;
        csnStream_t arT          = *ar;
        gboolean     EndOfList    = FALSE;
        gint16      Status;
        pui8  = pui8DATA(data, pDescr->offset);

        do
        { /* get data element */
          ElementCount++;

          if (ElementCount > nSizeArray)
          {
            LOGPC(DCSN1, LOGL_ERROR, "error: %s: too many elements (>%u) in recursive array. Increase its size! } |", pDescr->sz, nSizeArray);
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_STREAM_NOT_SUPPORTED, pDescr);
          }

          LOGPC(DCSN1, LOGL_DEBUG, "%s { | ", pDescr->sz);

          csnStreamInit(&arT, bit_offset, remaining_bits_len);
	  Status = csnStreamDecoder(&arT, (const CSN_DESCR*)pDescr->descr.ptr, vector, readIndex, pui8);

          if (Status >= 0)
          { /* successful completion */
            pui8    += nSizeElement;  /* -> to next */
            remaining_bits_len = arT.remaining_bits_len;
            bit_offset         = arT.bit_offset;
          }
          else
          { /* something went awry */
            return Status;
          }

          if (remaining_bits_len < 0)
          {
            return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
          }

          /* control of next element's tag */
          LOGPC(DCSN1, LOGL_DEBUG, "%s } | ", pDescr->sz);
	  EndOfList         = !(existNextElement(vector, readIndex, Tag));

          bit_offset++;
          remaining_bits_len--; /* 1 bit consumed (tag) */
        } while (!EndOfList);


        /* Store the count of the array */
        *pui8DATA(data, pDescr->i) = ElementCount;
        Tag = STANDARD_TAG; /* in case it was set to "reversed" */
        pDescr++;
        break;
      }

      case CSN_FIXED:
      { /* Verify the fixed bits */
        guint8  no_of_bits = (guint8) pDescr->i;
        guint32 ui32;

        if (no_of_bits <= 32)
        {
	  ui32 = bitvec_read_field(vector, readIndex, no_of_bits);
        }
        else
        {
          return ProcessError(readIndex,"no_of_bits > 32", -1, pDescr);
        }
        if (ui32 != (unsigned)(gint32)pDescr->offset)
        {
          return ProcessError(readIndex,"csnStreamDecoder FIXED value does not match", -1, pDescr);
        }

        LOGPC(DCSN1, LOGL_DEBUG, "%s = %u | ", pDescr->sz , (unsigned int)ui32);
        remaining_bits_len   -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_CALLBACK:
      {
        guint16  no_of_bits;
        DissectorCallbackFcn_t callback = (DissectorCallbackFcn_t)pDescr->aux_fn;
        LOGPC(DCSN1, LOGL_DEBUG, "CSN_CALLBACK(%s) | ", pDescr->sz);
        no_of_bits = callback(vector, readIndex, pvDATA(data, pDescr->i), pvDATA(data, pDescr->offset));
        remaining_bits_len -= no_of_bits;
        bit_offset += no_of_bits;
        pDescr++;
        break;
      }

      case CSN_TRAP_ERROR:
      {
        return ProcessError(readIndex,"csnStreamDecoder", pDescr->i, pDescr);
      }

      case CSN_END:
      {
        ar->remaining_bits_len  = remaining_bits_len;
        ar->bit_offset = bit_offset;
        return remaining_bits_len;
      }

      default:
      {
        assert(0);
      }


    }

  } while (remaining_bits_len >= 0);

  return ProcessError(readIndex,"csnStreamDecoder", CSN_ERROR_NEED_MORE_BITS_TO_UNPACK, pDescr);
}
