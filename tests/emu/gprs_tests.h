/* (C) 2013 by Holger Hans Peter Freyther
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef tests_h
#define tests_h

#ifdef __cplusplus
extern "C" {
#endif

#include <osmocom/core/msgb.h>
#include <string.h>

struct gprs_bssgp_pcu;
struct tlv_parsed;
struct msgb;

struct gprs_test {
	gprs_test(const char *name, const char *description,
			void (*start)(struct gprs_bssgp_pcu *),
			void (*data) (struct gprs_bssgp_pcu *, struct msgb *, struct tlv_parsed *parsed))
		: name(name)
		, description(description)
		, start(start)
		, data(data)
	{}

	const char *name;
	const char *description;
	void (*start)(struct gprs_bssgp_pcu *);
	void (*data) (struct gprs_bssgp_pcu *, struct msgb *, struct tlv_parsed *);
};

void gprs_test_success(struct gprs_bssgp_pcu *);

static inline struct msgb *create_msg(const uint8_t *data, size_t len)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "create msg");
	msg->l3h = msgb_put(msg, len);
	memcpy(msg->l3h, data, len);
	return msg;
}


#ifdef __cplusplus
}
#endif

#endif
