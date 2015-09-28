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

#include <arpa/inet.h>

#include <errno.h>
#include <string.h>


int Decoding::tlli_from_ul_data(const uint8_t *data, uint8_t len,
					uint32_t *tlli)
{
	struct rlc_ul_header *rh = (struct rlc_ul_header *)data;
	struct rlc_li_field *li;
	uint8_t e;
	uint32_t _tlli;

	if (!rh->ti)
		return -EINVAL;
	
	data += 3;
	len -= 3;
	e = rh->e;
	/* if E is not set (LI follows) */
	while (!e) {
		if (!len) {
			LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA LI extended, "
				"but no more data\n");
			return -EINVAL;
		}
		/* get new E */
		li = (struct rlc_li_field *)data;
		if (li->e == 0) /* if LI==0, E is interpreted as '1' */
			e = 1;
		else
			e = li->e;
		data++;
		len--;
	}
	if (len < 4) {
		LOGP(DRLCMACUL, LOGL_NOTICE, "UL DATA TLLI out of frame "
			"border\n");
		return -EINVAL;
	}
	memcpy(&_tlli, data, 4);
	*tlli = ntohl(_tlli);

	return 0;
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
