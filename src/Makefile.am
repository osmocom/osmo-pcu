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

# FIXME: This has to go!!
OPENBSC_DIR = $(top_srcdir)/../openbsc/openbsc
OPENGGSN_DIR = $(top_srcdir)/../openggsn

AM_CPPFLAGS = $(STD_DEFINES_AND_INCLUDES) -I$(OPENBSC_DIR)/include
AM_CXXFLAGS = -Wall -ldl -pthread -lgtp

noinst_LTLIBRARIES = libgprs.la

libgprs_la_SOURCES = \
	gprs_debug.cpp \
	csn1.cpp \
	gsm_rlcmac.cpp \
	gprs_bssgp_pcu.cpp \
	gprs_rlcmac.cpp \
	gsm_timer.cpp \
	bitvector.cpp

if ENABLE_SYSMOBTS
libgprs_la_SOURCES += \
	sysmo_l1_if.cpp
else
libgprs_la_SOURCES += \
	pcu_l1_if.cpp
endif

noinst_PROGRAMS = \
	RLCMACTest \
	pcu

noinst_HEADERS = \
	gprs_debug.h \
	csn1.h \
	gsm_rlcmac.h \
	gprs_bssgp_pcu.h \
	gprs_rlcmac.h \
	pcu_l1_if.h \
	gsm_timer.h \
	bitvector.h

RLCMACTest_SOURCES = RLCMACTest.cpp
RLCMACTest_LDADD = \
	libgprs.la \
	$(LIBOSMOCORE_LIBS) \
	$(COMMON_LA)

pcu_SOURCES = pcu_main.cpp
pcu_LDADD = \
	libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(COMMON_LA)

#MOSTLYCLEANFILES += testSource testDestination
