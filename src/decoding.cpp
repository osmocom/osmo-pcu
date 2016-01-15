/* decoding
 *
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
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
#include <decoding.h>
#include <rlc.h>
#include <gprs_debug.h>

extern "C" {
#include <osmocom/core/utils.h>
}

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>

#define LENGTH_TO_END 255
/*
 * \returns num extensions fields (num frames == offset) on success,
 *          -errno otherwise.
 */
static int parse_extensions_egprs(const uint8_t *data, unsigned int data_len,
	unsigned int *offs,
	bool is_last_block,
	Decoding::RlcData *chunks, unsigned int chunks_size)
{
	const struct rlc_li_field_egprs *li;
	uint8_t e;
	unsigned int num_chunks = 0;

	e = 0;
	while (!e) {
		if (*offs > data_len) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
				"but no more data\n");
			return -EINVAL;
		}

		/* get new E */
		li = (struct rlc_li_field_egprs *)&data[*offs];
		e = li->e;
		*offs += 1;

		if (!chunks)
			continue;

		if (num_chunks == chunks_size) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
				"but no more chunks possible\n");
			return -ENOSPC;
		}
		if (li->li == 0 && num_chunks == 0 && li->e == 0) {
			/* TS 44.060, table 10.4.14a.1, row 2a */
			chunks[num_chunks].length = 0;
			chunks[num_chunks].is_complete = true;
		} else if (li->li == 0 && num_chunks == 0 && li->e == 1) {
			/* TS 44.060, table 10.4.14a.1, row 4 */
			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
		} else if (li->li == 127 && li->e == 1) {
			/* TS 44.060, table 10.4.14a.1, row 3 & 5 */
			/* only filling bytes left */
			break;
		} else if (li->li > 0) {
			/* TS 44.060, table 10.4.14a.1, row 1 & 2b */
			chunks[num_chunks].length = li->li;
			chunks[num_chunks].is_complete = true;
		} else {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI contains "
				"invalid extension octet: LI=%d, E=%d, count=%d\n",
				li->li, li->e, num_chunks);
			return -EINVAL;
		}

		num_chunks += 1;

		if (e == 1) {
			/* There is space after the last chunk, add a final one */
			if (num_chunks == chunks_size) {
				LOGP(DRLCMACUL, LOGL_NOTICE,
					"UL DATA LI possibly extended, "
					"but no more chunks possible\n");
				return -ENOSPC;
			}

			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
			num_chunks += 1;
		}
	}

	return num_chunks;
}

static int parse_extensions_gprs(const uint8_t *data, unsigned int data_len,
	unsigned int *offs,
	bool is_last_block,
	Decoding::RlcData *chunks, unsigned int chunks_size)
{
	const struct rlc_li_field *li;
	uint8_t m, e;
	unsigned int num_chunks = 0;

	e = 0;
	while (!e) {
		if (*offs > data_len) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
				"but no more data\n");
			return -EINVAL;
		}

		/* get new E */
		li = (const struct rlc_li_field *)&data[*offs];
		e = li->e;
		m = li->m;
		*offs += 1;

		if (li->li == 0) {
			/* TS 44.060, 10.4.14, par 6 */
			e = 1;
			m = 0;
		}

		/* TS 44.060, table 10.4.13.1 */
		if (m == 0 && e == 0) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA "
				"ignored, because M='0' and E='0'.\n");
			return 0;
		}

		if (!chunks)
			continue;

		if (num_chunks == chunks_size) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
				"but no more chunks possible\n");
			return -ENOSPC;
		}

		if (li->li == 0)
			/* e is 1 here */
			chunks[num_chunks].length = LENGTH_TO_END;
		else
			chunks[num_chunks].length = li->li;

		chunks[num_chunks].is_complete = li->li || is_last_block;

		num_chunks += 1;

		if (e == 1 && m == 1) {
			if (num_chunks == chunks_size) {
				LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
					"but no more chunks possible\n");
				return -ENOSPC;
			}
			/* TS 44.060, 10.4.13.1, row 4 */
			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
			num_chunks += 1;
		}
	}

	return num_chunks;
}

int Decoding::rlc_data_from_ul_data(
	const struct gprs_rlc_data_block_info *rdbi, GprsCodingScheme cs,
	const uint8_t *data, RlcData *chunks, unsigned int chunks_size,
	uint32_t *tlli)
{
	uint8_t e;
	unsigned int data_len = rdbi->data_len;
	int num_chunks = 0, i;
	unsigned int offs = 0;
	bool is_last_block = (rdbi->cv == 0);

	if (!chunks)
		chunks_size = 0;

	e = rdbi->e;
	if (e) {
		if (chunks_size > 0) {
			chunks[num_chunks].offset = offs;
			chunks[num_chunks].length = LENGTH_TO_END;
			chunks[num_chunks].is_complete = is_last_block;
			num_chunks += 1;
		} else if (chunks) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "No extension, "
				"but no more chunks possible\n");
			return -ENOSPC;
		}
	} else if (cs.isEgprs()) {
		/* if E is not set (LI follows), EGPRS */
		num_chunks = parse_extensions_egprs(data, data_len, &offs,
			is_last_block,
			chunks, chunks_size);
	} else {
		/* if E is not set (LI follows), GPRS */
		num_chunks = parse_extensions_gprs(data, data_len, &offs,
			is_last_block,
			chunks, chunks_size);
	}

	if (num_chunks < 0)
		return num_chunks;

	/* TLLI */
	if (rdbi->ti) {
		uint32_t tlli_enc;
		if (offs + 4 > data_len) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TLLI out of block "
				"border\n");
			return -EINVAL;
		}

		memcpy(&tlli_enc, data + offs, sizeof(tlli_enc));
		if (cs.isGprs())
			/* The TLLI is encoded in big endian for GPRS (see
			 * TS 44.060, figure 10.2.2.1, note) */
			*tlli = be32toh(tlli_enc);
		else
			/* The TLLI is encoded in little endian for EGPRS (see
			 * TS 44.060, figure 10.3a.2.1, note 2) */
			*tlli = le32toh(tlli_enc);

		offs += sizeof(tlli_enc);
	} else {
		*tlli = 0;
	}

	/* PFI */
	if (rdbi->pi) {
		LOGP(DRLCMACUL, LOGL_ERROR, "ERROR: PFI not supported, "
			"please disable in SYSTEM INFORMATION\n");
		return -ENOTSUP;

		/* TODO: Skip all extensions with E=0 (see TS 44.060, 10.4.11 */
	}

	if (chunks_size == 0)
		return num_chunks;

	/* LLC */
	for (i = 0; i < num_chunks; i++) {
		chunks[i].offset = offs;
		if (chunks[i].length == LENGTH_TO_END) {
			if (offs == data_len) {
				/* There is no place for an additional chunk,
				 * so drop it (this may happen with EGPRS since
				 * there is no M flag. */
				num_chunks -= 1;
				break;;
			}
			chunks[i].length = data_len - offs;
		}
		offs += chunks[i].length;
		if (offs > data_len) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA out of block "
				"border, chunk idx: %d, size: %d\n",
				i, chunks[i].length);
			return -EINVAL;
		}
	}

	return num_chunks;
}

uint8_t Decoding::get_ms_class_by_capability(MS_Radio_Access_capability_t *cap)
{
	int i;

	for (i = 0; i < cap->Count_MS_RA_capability_value; i++) {
		if (!cap->MS_RA_capability_value[i].u.Content.Exist_Multislot_capability)
			continue;
		if (!cap->MS_RA_capability_value[i].u.Content.Multislot_capability.Exist_GPRS_multislot_class)
			continue;
		return cap->MS_RA_capability_value[i].u.Content.Multislot_capability.GPRS_multislot_class;
	}

	return 0;
}

uint8_t Decoding::get_egprs_ms_class_by_capability(MS_Radio_Access_capability_t *cap)
{
	int i;

	for (i = 0; i < cap->Count_MS_RA_capability_value; i++) {
		if (!cap->MS_RA_capability_value[i].u.Content.Exist_Multislot_capability)
			continue;
		if (!cap->MS_RA_capability_value[i].u.Content.Multislot_capability.Exist_EGPRS_multislot_class)
			continue;
		return cap->MS_RA_capability_value[i].u.Content.Multislot_capability.EGPRS_multislot_class;
	}

	return 0;
}

/**
 * show_rbb needs to be an array with 65 elements
 * The index of the array is the bit position in the rbb
 * (show_rbb[63] relates to BSN ssn-1)
 */
void Decoding::extract_rbb(const uint8_t *rbb, char *show_rbb)
{
	for (int i = 0; i < 64; i++) {
		uint8_t bit;

		bit = !!(rbb[i/8] & (1<<(7-i%8)));
		show_rbb[i] = bit ? 'R' : 'I';
	}

	show_rbb[64] = '\0';
}

void Decoding::extract_rbb(const struct bitvec *rbb, char *show_rbb)
{
	unsigned int i;
	for (i = 0; i < rbb->cur_bit; i++) {
		uint8_t bit;
		bit = bitvec_get_bit_pos(rbb, i);
		show_rbb[i] = bit == 1 ? 'R' : 'I';
	}

	show_rbb[i] = '\0';
}

int Decoding::rlc_parse_ul_data_header(struct gprs_rlc_data_info *rlc,
	const uint8_t *data, GprsCodingScheme cs)
{
	const struct gprs_rlc_ul_header_egprs_3 *egprs3;
	const struct rlc_ul_header *gprs;
	unsigned int e_ti_header;
	unsigned int cur_bit = 0;
	unsigned int data_len = 0;

	rlc->cs = cs;

	data_len = cs.maxDataBlockBytes();

	switch(cs.headerTypeData()) {
	case GprsCodingScheme::HEADER_GPRS_DATA:
		gprs = static_cast<struct rlc_ul_header *>
			((void *)data);
		rlc->r      = gprs->r;
		rlc->si     = gprs->si;
		rlc->tfi    = gprs->tfi;
		rlc->cps    = 0;
		rlc->rsb    = 0;

		rlc->num_data_blocks = 1;
		rlc->block_info[0].cv  = gprs->cv;
		rlc->block_info[0].pi  = gprs->pi;
		rlc->block_info[0].bsn = gprs->bsn;
		rlc->block_info[0].e   = gprs->e;
		rlc->block_info[0].ti  = gprs->ti;
		rlc->block_info[0].spb = 0;

		cur_bit += 3 * 8;

		rlc->data_offs_bits[0] = cur_bit;
		rlc->block_info[0].data_len = data_len;
		cur_bit += data_len * 8;

		break;
	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_3:
		egprs3 = static_cast<struct gprs_rlc_ul_header_egprs_3 *>
			((void *)data);
		rlc->r      = egprs3->r;
		rlc->si     = egprs3->si;
		rlc->tfi    = (egprs3->tfi_a << 0)  | (egprs3->tfi_b << 2);
		rlc->cps    = (egprs3->cps_a << 0)  | (egprs3->cps_b << 2);
		rlc->rsb    = egprs3->rsb;

		rlc->num_data_blocks = 1;
		rlc->block_info[0].cv  = egprs3->cv;
		rlc->block_info[0].pi  = egprs3->pi;
		rlc->block_info[0].spb = egprs3->spb;
		rlc->block_info[0].bsn =
			(egprs3->bsn1_a << 0) | (egprs3->bsn1_b << 5);

		cur_bit += 3 * 8 + 7;

		e_ti_header = (data[3] + (data[4] << 8)) >> 7;
		rlc->block_info[0].e   = !!(e_ti_header & 0x01);
		rlc->block_info[0].ti  = !!(e_ti_header & 0x02);
		cur_bit += 2;

		rlc->data_offs_bits[0] = cur_bit;
		rlc->block_info[0].data_len = data_len;
		cur_bit += data_len * 8;

		break;

	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_1:
	case GprsCodingScheme::HEADER_EGPRS_DATA_TYPE_2:
		/* TODO: Support both header types */
		/* fall through */
	default:
		LOGP(DRLCMACDL, LOGL_ERROR,
			"Decoding of uplink %s data blocks not yet supported.\n",
			cs.name());
		return -ENOTSUP;
	};

	return cur_bit;
}

/**
 * \brief Copy LSB bitstream RLC data block to byte aligned buffer.
 *
 * Note that the bitstream is encoded in LSB first order, so the two octets
 * 654321xx xxxxxx87 contain the octet 87654321 starting at bit position 3
 * (LSB has bit position 1). This is a different order than the one used by
 * CSN.1.
 *
 * \param data_block_idx  The block index, 0..1 for header type 1, 0 otherwise
 * \param src     A pointer to the start of the RLC block (incl. the header)
 * \param buffer  A data area of a least the size of the RLC block
 * \returns  the number of bytes copied
 */
unsigned int Decoding::rlc_copy_to_aligned_buffer(
	const struct gprs_rlc_data_info *rlc,
	unsigned int data_block_idx,
	const uint8_t *src, uint8_t *buffer)
{
	unsigned int hdr_bytes;
	unsigned int extra_bits;
	unsigned int i;

	uint8_t c, last_c;
	uint8_t *dst;
	const struct gprs_rlc_data_block_info *rdbi;

	OSMO_ASSERT(data_block_idx < rlc->num_data_blocks);
	rdbi = &rlc->block_info[data_block_idx];

	hdr_bytes = rlc->data_offs_bits[data_block_idx] >> 3;
	extra_bits = (rlc->data_offs_bits[data_block_idx] & 7);

	if (extra_bits == 0) {
		/* It is aligned already */
		memmove(buffer, src + hdr_bytes, rdbi->data_len);
		return rdbi->data_len;
	}

	dst = buffer;
	src = src + hdr_bytes;
	last_c = *(src++);

	for (i = 0; i < rdbi->data_len; i++) {
		c = src[i];
		*(dst++) = (last_c >> extra_bits) | (c << (8 - extra_bits));
		last_c = c;
	}

	return rdbi->data_len;
}

/**
 * \brief Get a pointer to byte aligned RLC data.
 *
 * Since the RLC data may not be byte aligned to the RLC block data such that a
 * single RLC data byte is spread over two RLC block bytes, this function
 * eventually uses the provided buffer as data storage.
 *
 * \param src     A pointer to the start of the RLC block (incl. the header)
 * \param buffer  A data area of a least the size of the RLC block
 * \returns A pointer to the RLC data start within src if it is aligned, and
 *          buffer otherwise.
 */
const uint8_t *Decoding::rlc_get_data_aligned(
	const struct gprs_rlc_data_info *rlc,
	unsigned int data_block_idx,
	const uint8_t *src, uint8_t *buffer)
{
	unsigned int hdr_bytes;
	unsigned int extra_bits;

	OSMO_ASSERT(data_block_idx < ARRAY_SIZE(rlc->data_offs_bits));

	hdr_bytes = rlc->data_offs_bits[data_block_idx] >> 3;
	extra_bits = (rlc->data_offs_bits[data_block_idx] & 7);

	if (extra_bits == 0)
		/* It is aligned already, return a pointer that refers to the
		 * original data. */
		return src + hdr_bytes;

	Decoding::rlc_copy_to_aligned_buffer(rlc, data_block_idx, src, buffer);
	return buffer;
}

int Decoding::decode_egprs_acknack_bits(const EGPRS_AckNack_Desc_t *desc,
	bitvec *bits, int *bsn_begin, int *bsn_end, gprs_rlc_dl_window *window)
{
	int urbb_len = desc->URBB_LENGTH;
	int crbb_len = 0;
	int num_blocks = 0;
	struct bitvec urbb;
	int i;
	bool have_bitmap;
	int implicitly_acked_blocks;
	int ssn = desc->STARTING_SEQUENCE_NUMBER;

	if (desc->FINAL_ACK_INDICATION) {
		num_blocks = window->mod_sns(window->v_s() - window->v_a());
		for (i = 0; i < num_blocks; i++)
			bitvec_set_bit(bits, ONE);

		*bsn_begin = window->v_a();
		*bsn_end   = window->mod_sns(*bsn_begin + num_blocks);
		return num_blocks;
	}

	if (desc->Exist_CRBB)
		crbb_len = desc->CRBB_LENGTH;

	have_bitmap = (urbb_len + crbb_len > 0);

	/*
	 * bow & bitmap present:
	 *   V(A)-> [ 11111...11111 0 SSN-> BBBBB...BBBBB ] (SSN+Nbits) .... V(S)
	 * bow & not bitmap present:
	 *   V(A)-> [ 11111...11111 ] . SSN .... V(S)
	 * not bow & bitmap present:
	 *   V(A)-> ... [ 0 SSN-> BBBBB...BBBBB ](SSN+N) .... V(S)
	 * not bow & not bitmap present:
	 *   V(A)-> ... [] . SSN .... V(S)
	 */

	if (desc->BEGINNING_OF_WINDOW) {
		implicitly_acked_blocks = window->mod_sns(ssn - 1 - window->v_a());

		for (i = 0; i < implicitly_acked_blocks; i++)
			bitvec_set_bit(bits, ONE);

		num_blocks += implicitly_acked_blocks;
	}

	if (have_bitmap) {
		/* next bit refers to V(Q) and thus is always zero (and not
		 * transmitted) */
		bitvec_set_bit(bits, ZERO);
		num_blocks += 1;

		if (crbb_len > 0) {
			int old_len = bits->cur_bit;
			/*
			decode_t4_rle(bits, desc->CRBB, desc->CRBB_LENGTH,
					desc->CRBB_STARTING_COLOR_CODE);
			 */

			num_blocks += (bits->cur_bit - old_len);
		}

		urbb.cur_bit = 0;
		urbb.data = (uint8_t *)desc->URBB;
		urbb.data_len = sizeof(desc->URBB);

		for (i = urbb_len; i > 0; i--) {
			/*
			 * Set bit at the appropriate position (see 3GPP TS
			 * 44.060 12.3.1)
			 */
			int is_ack = bitvec_get_bit_pos(&urbb, i-1);
			bitvec_set_bit(bits, is_ack == 1 ? ONE : ZERO);
		}
		num_blocks += urbb_len;
	}

	*bsn_begin = window->v_a();
	*bsn_end   = window->mod_sns(*bsn_begin + num_blocks);

	return num_blocks;
}

int Decoding::decode_gprs_acknack_bits(const Ack_Nack_Description_t *desc,
	bitvec *bits, int *bsn_begin, int *bsn_end, gprs_rlc_dl_window *window)
{
	int urbb_len = RLC_GPRS_WS;
	int num_blocks;
	struct bitvec urbb;

	num_blocks = urbb_len;

	*bsn_end   = desc->STARTING_SEQUENCE_NUMBER;
	*bsn_begin = window->v_a();

	num_blocks = window->mod_sns(*bsn_end - *bsn_begin);

	if (num_blocks < 0 || num_blocks > urbb_len) {
		*bsn_end  = *bsn_begin;
		LOGP(DRLCMACUL, LOGL_NOTICE,
			"Invalid GPRS Ack/Nack window %d:%d (length %d)\n",
			*bsn_begin, *bsn_end, num_blocks);
		return -EINVAL;
	}

	urbb.cur_bit = 0;
	urbb.data = (uint8_t *)desc->RECEIVED_BLOCK_BITMAP;
	urbb.data_len = sizeof(desc->RECEIVED_BLOCK_BITMAP);

	/*
	 * TS 44.060, 12.3:
	 * BSN = (SSN - bit_number) modulo 128, for bit_number = 1 to 64.
	 * The BSN values represented range from (SSN - 1) mod 128 to (SSN - 64) mod 128.
	 *
	 * We are only interested in the range from V(A) to SSN-1 which is
	 * num_blocks large. The RBB is laid out as
	 *   [SSN-1] [SSN-2] ... [V(A)] ... [SSN-64]
	 * so we want to start with [V(A)] and go backwards until we reach
	 * [SSN-1] to get the needed BSNs in an increasing order.
	 */
	for (int i = num_blocks; i > 0; i--) {
		int is_ack = bitvec_get_bit_pos(&urbb, i-1);
		bitvec_set_bit(bits, is_ack == 1 ? ONE : ZERO);
	}

	return num_blocks;
}
