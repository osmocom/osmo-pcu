EXTRA_DIST = osmopcu-gb.adoc \
    osmopcu-gb-docinfo.xml \
    osmopcu-usermanual.adoc \
    osmopcu-usermanual-docinfo.xml \
    osmopcu-vty-reference.xml \
    regen_doc.sh \
    chapters \
    gb \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmopcu-usermanual.adoc osmopcu-gb.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmopcu-gb.pdf: $(srcdir)/gb/*.adoc $(srcdir)/gb/*.msc
  osmopcu-usermanual.pdf: $(srcdir)/chapters/*.adoc

  VTY_REFERENCE = osmopcu-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-pcu
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
