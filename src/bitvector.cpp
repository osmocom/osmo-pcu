/* bitvector.cpp
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

/*! \addtogroup bitvector
 *  @{
 */

/*! \file bitvector.cpp
 *  \brief Additional functions for Osmocom bit vector abstraction.
 */

#include <bitvector.h>
extern "C" {
#include <osmocom/core/talloc.h>
}

void *bv_tall_ctx;

struct bitvec *bitvec_alloc(unsigned size)
{
	struct bitvec *bv = talloc_zero(bv_tall_ctx, struct bitvec);
	bv->data_len = size;
	bv->cur_bit = 0;
	bv->data = talloc_zero_array(bv_tall_ctx, uint8_t, size);
	return bv;
}

void bitvec_free(struct bitvec *bv)
{
	talloc_free(bv->data);
	talloc_free(bv);
}

unsigned int bitvec_pack(struct bitvec *bv, uint8_t *buffer)
{
	unsigned int i = 0;
	for (i = 0; i < bv->data_len; i++)
	{
		buffer[i] = bv->data[i];
	}
	return i;
}

unsigned int bitvec_unpack(struct bitvec *bv, uint8_t *buffer)
{
	unsigned int i = 0;
	for (i = 0; i < bv->data_len; i++)
	{
		bv->data[i] = buffer[i];
	}
	return i;
}


int bitvec_unhex(struct bitvec *bv, const char* src)
{
	unsigned val;
	unsigned write_index = 0;
	unsigned digits = bv->data_len*2;
	for (unsigned i=0; i<digits; i++) {
		if (sscanf(src+i, "%1x", &val) < 1) {
			return 1;
		}
		bitvec_write_field(bv, write_index,val, 4);
	}
	return 0;
}

uint64_t bitvec_read_field(struct bitvec *bv, unsigned& read_index, unsigned len)
{
	unsigned int i;
	uint64_t ui = 0;
	bv->cur_bit = read_index;

	for (i = 0; i < len; i++) {
		int bit = bitvec_get_bit_pos((const struct bitvec *)bv, bv->cur_bit);
		if (bit < 0)
			return bit;
		if (bit)
			ui |= ((uint64_t)1 << (len - i - 1));
		bv->cur_bit++;
	}
	read_index += len;
	return ui;
}


int bitvec_write_field_lh(struct bitvec *bv, unsigned& write_index,
		uint64_t val, unsigned len)
{
	unsigned int i;
	int rc;
	bv->cur_bit = write_index;
	for (i = 0; i < len; i++) {
		bit_value bit = L;
		if (val & ((uint64_t)1 << (len - i - 1)))
			bit = H;
		rc = bitvec_set_bit(bv, bit);
		if (rc)
			return rc;
	}
	write_index += len;
	return 0;
}
