/*
 * ta.cpp timing advance handling
 * Copyright (C) 2012 Ivan Klyuchnikov
 * Copyright (C) 2012 Andreas Eversberg <jolly@eversberg.eu>
 * Copyright (C) 2013 by Holger Hans Peter Freyther
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

#include <ta.h>
#include <gprs_rlcmac.h>

extern "C" {
	#include <osmocom/core/talloc.h>
}

#include <errno.h>

extern void *tall_pcu_ctx;

/*
 * timing advance memory
 */

/* enable to debug timing advance memory */
//#define DEBUG_TA

struct gprs_rlcmac_ta {
	struct llist_head	list;
	uint32_t		tlli;
	uint8_t			ta;
};

TimingAdvance::TimingAdvance()
	: m_ta_len(0)
{
	INIT_LLIST_HEAD(&m_ta_list);
}

/* remember timing advance of a given TLLI */
int TimingAdvance::remember(uint32_t tlli, uint8_t ta)
{
	struct gprs_rlcmac_ta *ta_entry;

	/* check for existing entry */
	llist_for_each_entry(ta_entry, &m_ta_list, list) {
		if (ta_entry->tlli == tlli) {
#ifdef DEBUG_TA
			fprintf(stderr, "update %08x %d\n", tlli, ta);
#endif
			ta_entry->ta = ta;
			/* relink to end of list */
			llist_del(&ta_entry->list);
			llist_add_tail(&ta_entry->list, &m_ta_list);
			return 0;
		}
	}

#ifdef DEBUG_TA
	fprintf(stderr, "remember %08x %d\n", tlli, ta);
#endif
	/* if list is full, remove oldest entry */
	if (m_ta_len == 30) {
		ta_entry = llist_entry(m_ta_list.next,
			struct gprs_rlcmac_ta, list);
	        llist_del(&ta_entry->list);
		talloc_free(ta_entry);
		m_ta_len--;
	}

	/* create new TA entry */
	ta_entry = talloc_zero(tall_pcu_ctx, struct gprs_rlcmac_ta);
	if (!ta_entry)
		return -ENOMEM;

	ta_entry->tlli = tlli;
	ta_entry->ta = ta;
	llist_add_tail(&ta_entry->list, &m_ta_list);
	m_ta_len++;

	return 0;
}

int TimingAdvance::recall(uint32_t tlli)
{
	struct gprs_rlcmac_ta *ta_entry;
	uint8_t ta;

	llist_for_each_entry(ta_entry, &m_ta_list, list) {
		if (ta_entry->tlli == tlli) {
			ta = ta_entry->ta;
#ifdef DEBUG_TA
			fprintf(stderr, "recall %08x %d\n", tlli, ta);
#endif
			return ta;
		}
	}
#ifdef DEBUG_TA
	fprintf(stderr, "no entry for %08x\n", tlli);
#endif

	return -EINVAL;
}

int TimingAdvance::flush()
{
	struct gprs_rlcmac_ta *ta_entry;
	int count = 0;

	while (!llist_empty(&m_ta_list)) {
		ta_entry = llist_entry(m_ta_list.next,
			struct gprs_rlcmac_ta, list);
#ifdef DEBUG_TA
		fprintf(stderr, "flush entry %08x %d\n", ta_entry->tlli,
			ta_entry->ta);
#endif
	        llist_del(&ta_entry->list);
		talloc_free(ta_entry);
		count++;
	}
	m_ta_len = 0;

	return count;
}

