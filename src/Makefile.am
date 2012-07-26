#
# Copyright 2008, 2009 Free Software Foundation, Inc.
#
# This software is distributed under the terms of the GNU Public License.
# See the COPYING file in the main directory for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

AM_CPPFLAGS = $(STD_DEFINES_AND_INCLUDES) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGB_CFLAGS) $(LIBOSMOGSM_CFLAGS)
AM_CXXFLAGS = -Wall -ldl -pthread

noinst_LTLIBRARIES = libgprs.la

libgprs_la_SOURCES = \
	gprs_debug.c \
	csn1.cpp \
	gsm_rlcmac.c \
	gprs_bssgp_pcu.cpp \
	gprs_rlcmac.c \
	gprs_rlcmac_data.c \
	gprs_rlcmac_ctrl.cpp \
	gprs_rlcmac_sched.c \
	gsm_timer.c \
	bitvector.cpp \
	pcu_l1_if.c \
	pcu_vty.c

if ENABLE_SYSMOBTS
libgprs_la_SOURCES += \
	sysmo_sock.c
else
libgprs_la_SOURCES += \
	openbts_sock.c
endif

noinst_PROGRAMS = \
	RLCMACTest

bin_PROGRAMS = \
	osmo-pcu

noinst_HEADERS = \
	gprs_debug.h \
	csn1.h \
	gsm_rlcmac.h \
	gprs_bssgp_pcu.h \
	gprs_rlcmac.h \
	gprs_rlcmac_ctrl.h \
	pcuif_proto.h \
	pcu_l1_if.h \
	gsm_timer.h \
	bitvector.h \
	pcu_vty.h

RLCMACTest_SOURCES = RLCMACTest.cpp
RLCMACTest_LDADD = \
	libgprs.la \
	$(LIBOSMOCORE_LIBS) \
	$(COMMON_LA)

osmo_pcu_SOURCES = pcu_main.cpp
osmo_pcu_LDADD = \
	libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(COMMON_LA)

#MOSTLYCLEANFILES += testSource testDestination
