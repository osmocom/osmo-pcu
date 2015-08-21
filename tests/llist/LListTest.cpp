/*
 * LListTest.cpp
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
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

#include "cxx_linuxlist.h"

extern "C" {
#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
}

#include <errno.h>


struct TestElem {
	const char *str;
	LListHead<TestElem> list;

	TestElem(const char *s) : str(s), list(this) {};
};

static void test_linux_list()
{
	LListHead<TestElem> elems, *pos, *tmp;
	TestElem elem1("number one");
	TestElem elem2("number two");
	TestElem elem3("number three");
	int count = 0;

	printf("=== start %s ===\n", __func__);

	OSMO_ASSERT(llist_empty(&elems));

	llist_add_tail(&elem1.list, &elems);
	llist_add_tail(&elem2.list, &elems);
	llist_add_tail(&elem3.list, &elems);

	OSMO_ASSERT(!llist_empty(&elems));

	llist_for_each(pos, &elems) {
		count += 1;
		printf(" %i -> %s\n", count, pos->entry()->str);
	}
	OSMO_ASSERT(count == 3);

	count = 0;
	llist_for_each_safe(pos, tmp, &elems) {
		count += 1;
		if (count == 2)
			llist_del(pos);

		printf(" %i -> %s\n", count, pos->entry()->str);
	}
	OSMO_ASSERT(count == 3);

	count = 0;
	llist_for_each(pos, &elems) {
		count += 1;
		OSMO_ASSERT(pos != &elem2.list);
		printf(" %i -> %s\n", count, pos->entry()->str);
	}
	OSMO_ASSERT(count == 2);

	printf("=== end %s ===\n", __func__);
}

int main(int argc, char **argv)
{
	test_linux_list();

	return EXIT_SUCCESS;
}
