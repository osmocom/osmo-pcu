/* cxx_linuxlist.h
 *
 * Copyright (C) 2015 by Sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
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

#pragma once

extern "C" {
	#include <osmocom/core/linuxlist.h>
}

template <typename T>
struct LListHead {
	typedef T entry_t;

	/* This must match the declaration of struct llist_head */
	LListHead<T> *next;
	LListHead<T> *prev;

	LListHead() : m_back(0) { INIT_LLIST_HEAD(this); }
	LListHead(T* entry) : m_back(entry) {
		next = (LListHead<T> *)LLIST_POISON1;
		prev = (LListHead<T> *)LLIST_POISON2;
	}

	T *entry() {return m_back;}
	const T *entry() const {return m_back;}

	llist_head &llist() {
		return *static_cast<llist_head *>(static_cast<void *>(this));
	}
	const llist_head &llist() const {
		return *static_cast<llist_head *>(static_cast<void *>(this));
	}

private:
	T *const m_back;
};

/* Define a family of casting functions */
template <typename T>
llist_head &llist(LListHead<T> &l)
{
	return l->llist();
}

template <typename T>
const llist_head &llist(const LListHead<T> &l)
{
	return l->llist();
}

template <typename T>
llist_head *llptr(LListHead<T> *l)
{
	return &(l->llist());
}

template <typename T>
const llist_head *llptr(const LListHead<T> *l)
{
	return &(l->llist());
}

/* Define type-safe wrapper for the existing linux_list.h functions */
template <typename T>
inline void llist_add(LListHead<T> *new_, LListHead<T> *head)
{
	llist_add(llptr(new_), llptr(head));
}

template <typename T>
inline void llist_add_tail(LListHead<T> *new_, LListHead<T> *head)
{
	llist_add_tail(llptr(new_), llptr(head));
}

template <typename T>
inline void llist_del(LListHead<T> *entry)
{
	llist_del(llptr(entry));
}

template <typename T>
inline void llist_del_init(LListHead<T> *entry)
{
	llist_del_init(llptr(entry));
}

template <typename T>
inline void llist_move(LListHead<T> *list, LListHead<T> *head)
{
	llist_move(llptr(list), llptr(head));
}

template <typename T>
inline void llist_move_tail(LListHead<T> *list, LListHead<T> *head)
{
	llist_move_tail(llptr(list), llptr(head));
}

template <typename T>
inline int llist_empty(const LListHead<T> *head)
{
	return llist_empty(llptr(head));
}

template <typename T>
inline void llist_splice(LListHead<T> *list, LListHead<T> *head)
{
	llist_splice(llptr(list), llptr(head));
}

template <typename T>
inline void llist_splice_init(LListHead<T> *list, LListHead<T> *head)
{
	llist_splice_init(llptr(list), llptr(head));
}
