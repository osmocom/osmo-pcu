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

AUTOMAKE_OPTIONS = subdir-objects
AM_CPPFLAGS = -I$(top_srcdir)/include $(STD_DEFINES_AND_INCLUDES) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGB_CFLAGS) $(LIBOSMOGSM_CFLAGS)

if ENABLE_SYSMODSP
AM_CPPFLAGS += -DENABLE_DIRECT_PHY
endif

if ENABLE_LC15BTS_PHY
AM_CPPFLAGS += -DENABLE_DIRECT_PHY
endif

AM_CXXFLAGS = -Wall -ldl -pthread
AM_LDFLAGS = -lrt

noinst_LTLIBRARIES = libgprs.la

libgprs_la_SOURCES = \
	gprs_debug.cpp \
	csn1.cpp \
	gsm_rlcmac.cpp \
	gprs_bssgp_pcu.cpp \
	gprs_rlcmac.cpp \
	gprs_rlcmac_sched.cpp \
	gprs_rlcmac_meas.cpp \
	gprs_rlcmac_ts_alloc.cpp \
	gprs_ms.cpp \
	gprs_ms_storage.cpp \
	gsm_timer.cpp \
	bitvector.cpp \
	pcu_l1_if.cpp \
	pcu_vty.c \
	pcu_vty_functions.cpp \
	tbf.cpp \
	tbf_ul.cpp \
	tbf_dl.cpp \
	bts.cpp \
	poll_controller.cpp \
	encoding.cpp \
	sba.cpp \
	decoding.cpp \
	llc.cpp \
	rlc.cpp \
	osmobts_sock.cpp \
	gprs_codel.c \
	gprs_coding_scheme.cpp \
	egprs_rlc_compression.cpp

bin_PROGRAMS = \
	osmo-pcu

noinst_PROGRAMS =

noinst_HEADERS = \
	gprs_debug.h \
	csn1.h \
	gsm_rlcmac.h \
	gprs_bssgp_pcu.h \
	gprs_rlcmac.h \
	gprs_ms.h \
	gprs_ms_storage.h \
	pcu_l1_if.h \
	gsm_timer.h \
	bitvector.h \
	pcu_vty.h \
	pcu_vty_functions.h \
	tbf.h \
	bts.h \
	poll_controller.h \
	encoding.h \
	sba.h \
	rlc.h \
	decoding.h \
	llc.h \
	pcu_utils.h \
	cxx_linuxlist.h \
	gprs_codel.h \
	gprs_coding_scheme.h \
	egprs_rlc_compression.h

nobase_include_HEADERS =
	osmocom/pcu/pcuif_proto.h

osmo_pcu_SOURCES = pcu_main.cpp

if ENABLE_SYSMODSP
AM_CPPFLAGS += -I$(srcdir)/osmo-bts-sysmo

EXTRA_DIST = \
	osmo-bts-sysmo/sysmo_l1_if.c \
        osmo-bts-sysmo/sysmo_l1_if.h \
        osmo-bts-sysmo/sysmo_l1_hw.c \
        osmo-bts-sysmo/femtobts.c \
        osmo-bts-sysmo/femtobts.h

noinst_HEADERS += \
        osmo-bts-sysmo/sysmo_l1_if.h \
        osmo-bts-sysmo/femtobts.h

noinst_PROGRAMS += \
	osmo-pcu-remote

osmo_pcu_SOURCES += \
	osmo-bts-sysmo/sysmo_l1_if.c \
	osmo-bts-sysmo/sysmo_l1_hw.c \
	osmo-bts-sysmo/femtobts.c

osmo_pcu_remote_SOURCES = \
	pcu_main.cpp \
	osmo-bts-sysmo/sysmo_l1_if.c \
	osmo-bts-sysmo/sysmo_l1_fwd.c \
	osmo-bts-sysmo/femtobts.c

osmo_pcu_remote_LDADD = \
	libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(COMMON_LA)
endif

if ENABLE_LC15BTS_PHY
AM_CPPFLAGS += -I$(LITECELL15_INCDIR) -I$(srcdir)/osmo-bts-litecell15

EXTRA_DIST = \
	osmo-bts-litecell15/lc15_l1_if.c \
        osmo-bts-litecell15/lc15_l1_if.h \
        osmo-bts-litecell15/lc15_l1_hw.c \
        osmo-bts-litecell15/lc15bts.c \
        osmo-bts-litecell15/lc15bts.h

noinst_HEADERS += \
        osmo-bts-litecell15/lc15_l1_if.h \
        osmo-bts-litecell15/lc15bts.h

osmo_pcu_SOURCES += \
	osmo-bts-litecell15/lc15_l1_if.c \
	osmo-bts-litecell15/lc15_l1_hw.c \
	osmo-bts-litecell15/lc15bts.c
endif

if ENABLE_RBS
AM_CPPFLAGS += -I$(RBS_INCDIR) -I$(srcdir)/osmo-bts-rbs
AM_CPPFLAGS += -DENABLE_ERICSSON_RBS

EXTRA_DIST = \
	osmo-bts-rbs/pgsl_l1_if.c \
        osmo-bts-rbs/pgsl_l1_if.h \
        osmo-bts-rbs/pgsl.c \
        osmo-bts-rbs/pgsl.h \
        osmo-bts-rbs/l2tp_sock.c \
        osmo-bts-rbs/l2tp_sock.h

noinst_HEADERS += \
        osmo-bts-rbs/pgsl_l1_if.h \
        osmo-bts-rbs/pgsl.h \
        osmo-bts-rbs/l2tp_sock.h

osmo_pcu_SOURCES += \
	osmo-bts-rbs/pgsl_l1_if.c \
	osmo-bts-rbs/pgsl.c \
        osmo-bts-rbs/l2tp_sock.c
endif

osmo_pcu_LDADD = \
	libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(COMMON_LA)

#MOSTLYCLEANFILES += testSource testDestination
