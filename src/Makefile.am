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
AM_CPPFLAGS = -I$(top_srcdir)/include $(STD_DEFINES_AND_INCLUDES) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGB_CFLAGS) $(LIBOSMOCTRL_CFLAGS) $(LIBOSMOGSM_CFLAGS)

if ENABLE_SYSMODSP
AM_CPPFLAGS += -DENABLE_DIRECT_PHY
endif

if ENABLE_LC15BTS_PHY
AM_CPPFLAGS += -DENABLE_DIRECT_PHY
endif

if ENABLE_OC2GBTS_PHY
AM_CPPFLAGS += -DENABLE_DIRECT_PHY
endif

AM_CXXFLAGS = -Wall
AM_LDFLAGS = -lrt

noinst_LTLIBRARIES = libgprs.la

libgprs_la_SOURCES = \
	alloc_algo.cpp \
	gprs_debug.c \
	csn1.c \
	csn1_dec.c \
	csn1_enc.c \
	gsm_rlcmac.c \
	gprs_bssgp_pcu.c \
	gprs_bssgp_rim.c \
	gprs_rlcmac.cpp \
	gprs_rlcmac_sched.cpp \
	gprs_rlcmac_meas.cpp \
	gprs_ms.c \
	gprs_ms_storage.cpp \
	gprs_pcu.c \
	pcu_l1_if.cpp \
	pcu_vty.c \
	pcu_vty_functions.cpp \
	mslot_class.c \
	nacc_fsm.c \
	neigh_cache.c \
	tbf.cpp \
	tbf_fsm.c \
	tbf_ul.cpp \
	tbf_ul_fsm.c \
	tbf_ul_ack_fsm.c \
	tbf_ul_ass_fsm.c \
	tbf_dl.cpp \
	tbf_dl_fsm.c \
	tbf_dl_ass_fsm.c \
	bts.cpp \
	bts_pch_timer.c \
	pdch.cpp \
	pdch_ul_controller.c \
	encoding.cpp \
	sba.c \
	decoding.cpp \
	llc.c \
	rlc.cpp \
	osmobts_sock.c \
	gprs_codel.c \
	coding_scheme.c \
	egprs_rlc_compression.cpp \
	gprs_rlcmac_sched.cpp

bin_PROGRAMS = \
	osmo-pcu

noinst_PROGRAMS =

noinst_HEADERS = \
	alloc_algo.h \
	gprs_debug.h \
	csn1.h \
	gsm_rlcmac.h \
	gprs_bssgp_pcu.h \
	gprs_bssgp_rim.h \
	gprs_rlcmac.h \
	gprs_ms.h \
	gprs_ms_storage.h \
	gprs_pcu.h \
	pcu_l1_if.h \
	pcu_vty.h \
	pcu_vty_functions.h \
	mslot_class.h \
	nacc_fsm.h \
	neigh_cache.h \
	tbf.h \
	tbf_fsm.h \
	tbf_ul.h \
	tbf_ul_ack_fsm.h \
	tbf_ul_ass_fsm.h \
	tbf_dl.h \
	tbf_dl_ass_fsm.h \
	bts.h \
	bts_pch_timer.h \
	pdch.h \
	pdch_ul_controller.h \
	encoding.h \
	sba.h \
	rlc.h \
	decoding.h \
	llc.h \
	pcu_utils.h \
	cxx_linuxlist.h \
	gprs_codel.h \
	coding_scheme.h \
	egprs_rlc_compression.h \
	wireshark_compat.h

osmo_pcu_SOURCES = pcu_main.cpp

if ENABLE_SYSMODSP
AM_CPPFLAGS += -I$(srcdir)/osmo-bts-sysmo -I$(SYSMOBTS_INCDIR)

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
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
endif

if ENABLE_LC15BTS_PHY
AM_CPPFLAGS += $(LITECELL15_CFLAGS) -I$(srcdir)/osmo-bts-litecell15

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

if ENABLE_OC2GBTS_PHY
AM_CPPFLAGS += -I$(OC2G_INCDIR) -I$(srcdir)/osmo-bts-oc2g

EXTRA_DIST = \
	osmo-bts-oc2g/oc2g_l1_if.c \
        osmo-bts-oc2g/oc2g_l1_if.h \
        osmo-bts-oc2g/oc2g_l1_hw.c \
        osmo-bts-oc2g/oc2gbts.c \
        osmo-bts-oc2g/oc2gbts.h

noinst_HEADERS += \
        osmo-bts-oc2g/oc2g_l1_if.h \
        osmo-bts-oc2g/oc2gbts.h

osmo_pcu_SOURCES += \
	osmo-bts-oc2g/oc2g_l1_if.c \
	osmo-bts-oc2g/oc2g_l1_hw.c \
	osmo-bts-oc2g/oc2gbts.c
endif

osmo_pcu_LDADD = \
	libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)

#MOSTLYCLEANFILES += testSource testDestination
