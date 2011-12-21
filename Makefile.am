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
	csn1.cpp \
	gsm_rlcmac.cpp

noinst_PROGRAMS = \
	RLCMACTest

noinst_HEADERS = \
	csn1.h \
	gsm_rlcmac.h

RLCMACTest_SOURCES = RLCMACTest.cpp
RLCMACTest_LDADD = $(COMMON_LA) 
#MOSTLYCLEANFILES += testSource testDestination


