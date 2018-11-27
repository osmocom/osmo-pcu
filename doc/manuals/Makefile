TOPDIR = ..

ASCIIDOC = osmopcu-usermanual.adoc osmopcu-gb.adoc
include $(TOPDIR)/build/Makefile.asciidoc.inc
osmopcu-gb.pdf: gb/*.adoc gb/*.msc
osmopcu-usermanual.pdf: chapters/*.adoc

VTY_REFERENCE = osmopcu-vty-reference.xml
include $(TOPDIR)/build/Makefile.vty-reference.inc

include $(TOPDIR)/build/Makefile.common.inc
