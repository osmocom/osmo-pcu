# XSL stylesheets downloaded from http://docbook.sourceforge.net/release/xsl/current/html/
# Makefile from BitBake/OpenEmbedded manuals

EXTRA_DEPS = gen-vty-docbook

topdir = .
pcu_reference = $(topdir)/osmopcu-vty-reference.xml
manuals = $(bts_manual) $(pcu_reference)
# types = pdf txt rtf ps xhtml html man tex texi dvi
# types = pdf txt
types = $(docbooktotypes)
docbooktotypes = pdf
# htmlcssfile =
# htmlcss =

TOPDIR := ..
ASCIIDOCS := osmopcu-usermanual osmopcu-gb

include $(TOPDIR)/build/Makefile.asciidoc.inc
include $(TOPDIR)/build/Makefile.inc

osmopcu-gb.pdf: gb/*.adoc gb/*.msc
osmopcu-usermanual.pdf: chapters/*.adoc

clean:
	rm -rf $(cleanfiles)
	rm -rf gen-vty-docbook
	rm -rf osmopcu-usermanual__*.{svg,png,check}

gen-vty-docbook: FORCE
	$(call command,xsltproc -o generated/combined1.xml \
		--stringparam with $(PWD)/../common/vty_additions.xml \
		$(MERGE_DOC) vty/osmo-pcu_vty_reference.xml, \
		XSLTPROC,Merging Common VTY)
	$(call command,xsltproc -o generated/combined2.xml \
		--stringparam with $(PWD)/vty/osmo-pcu_vty_additions.xml \
		$(MERGE_DOC) generated/combined1.xml, \
		XSLTPROC,Merging PCU VTY)
	$(call command,xsltproc ../vty_reference.xsl generated/combined2.xml > generated/docbook_vty.xml, \
		XSLTPROC,Converting PCU VTY to DocBook)



