/* wireshark_compat.h
 * Copyright (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

/* This header contains a few definitions required by rlcmac and csn1 files
 * originally imported from wireshark packet-gsm_rlcmac.* and package-csn1.*,
 * in order to keep code as similar as possible to ease maintainability and port
 * of patches.
*/
#pragma once

#define MIN(a,b) (((a)<(b))?(a):(b))

#define FALSE (0)
#define TRUE  (1)
typedef signed int gint32;
typedef signed short gint16;
typedef int gint;
typedef unsigned int guint;
typedef gint gboolean;
typedef unsigned char guint8;
typedef unsigned short guint16;
typedef unsigned int guint32;
typedef unsigned long guint64;
