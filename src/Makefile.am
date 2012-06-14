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

include $(top_srcdir)/Makefile.common

AM_CPPFLAGS = $(STD_DEFINES_AND_INCLUDES)
AM_CXXFLAGS = -Wall -ldl -pthread

noinst_LTLIBRARIES = libgprs.la

libgprs_la_SOURCES = \
	gprs_debug.cpp \
	csn1.cpp \
	gsm_rlcmac.cpp \
	gprs_bssgp_pcu.cpp \
	gprs_rlcmac.cpp \
	pcu_l1_if.cpp \
	gsm_timer.cpp \
	bitvector.cpp

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

OPENBSC_DIR = /home/ivan/work/openbsc/openbsc/openbsc
OPENGGSN_DIR = /home/ivan/work/openbsc/openggsn
OSMOCORE_DIR = /home/ivan/work/openbsc/libosmocore

RLCMACTest_SOURCES = RLCMACTest.cpp
RLCMACTest_LDADD = \
	libgprs.la \
	-losmocore \
	$(COMMON_LA)

pcu_SOURCES = pcu_main.cpp
pcu_LDADD = \
	libgprs.la \
	$(OPENBSC_DIR)/src/libgb/gprs_ns.o \
	$(OPENBSC_DIR)/src/libgb/gprs_bssgp.o \
	$(OPENBSC_DIR)/src/libgb/gprs_bssgp_bss.o \
	$(OPENBSC_DIR)/src/libgb/gprs_bssgp_util.o \
	$(OPENBSC_DIR)/src/libgb/gprs_ns_frgre.o \
	$(OPENGGSN_DIR)/gtp/queue.o \
	$(OPENGGSN_DIR)/gtp/lookupa.o \
	$(OPENGGSN_DIR)/gtp/pdp.o \
	$(OPENGGSN_DIR)/gtp/gtpie.o \
	$(OPENGGSN_DIR)/gtp/gtp.o \
	$(OPENBSC_DIR)/src/gprs/sgsn_libgtp.o \
	$(OPENBSC_DIR)/src/gprs/gprs_sndcp.o \
	$(OPENBSC_DIR)/src/gprs/crc24.o \
	$(OPENBSC_DIR)/src/gprs/gprs_llc.o \
	$(OPENBSC_DIR)/src/gprs/gprs_gmm.o \
	$(OPENBSC_DIR)/src/gprs/gprs_sgsn.o \
	$(OPENBSC_DIR)/src/libcommon/socket.o \
	$(OPENBSC_DIR)/src/libcommon/debug.o \
	$(OSMOCORE_DIR)/src/bitvec.o \
	$(OSMOCORE_DIR)/src/talloc.o \
	-losmocore \
	-losmogsm \
	$(COMMON_LA)

#MOSTLYCLEANFILES += testSource testDestination
