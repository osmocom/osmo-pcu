AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

SUBDIRS = include src doc tests contrib
EXTRA_DIST = \
	     README.md \
	     contrib/osmo-pcu.spec.in \
	     debian \
	     osmoappdesc.py \
	     $(NULL)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

@RELMAKE@
