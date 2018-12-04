AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

SUBDIRS = include src doc tests contrib
EXTRA_DIST = osmoappdesc.py README.md

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

@RELMAKE@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = osmo-pcu.pc
