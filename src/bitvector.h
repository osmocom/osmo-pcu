/* bitvector.h
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

#ifndef BITVECTOR_H
#define BITVECTOR_H

/*! \defgroup bitvector Bit vectors
 *  @{
 */

/*! \file bitvector.h
 *  \brief Additional functions for Osmocom bit vector abstraction.
 */

extern "C" {
#include <osmocom/core/bitvec.h>
}

struct bitvec *bitvec_alloc(unsigned size);
void bitvec_free(struct bitvec *bv);
int bitvec_unhex(struct bitvec *bv, const char* src);
int bitvec_pack(struct bitvec *bv, uint8_t *buffer);
int bitvec_unpack(struct bitvec *bv, uint8_t *buffer);
uint64_t bitvec_read_field(struct bitvec *bv, unsigned& read_index, unsigned len);
int bitvec_write_field(struct bitvec *bv, unsigned& write_index, uint64_t val, unsigned len);

/*! }@ */

#endif // BITVECTOR_H
