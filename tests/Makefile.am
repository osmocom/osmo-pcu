AM_CPPFLAGS = $(STD_DEFINES_AND_INCLUDES) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOCTRL_CFLAGS) $(LIBOSMOGB_CFLAGS) $(LIBOSMOGSM_CFLAGS) -I$(top_srcdir)/src/ -I$(top_srcdir)/include/
AM_LDFLAGS = -no-install

LDADD = \
	$(LIBOSMOCORE_LIBS) \
	-lrt \
	$(NULL)

check_PROGRAMS = \
	rlcmac/RLCMACTest \
	alloc/AllocTest \
	alloc/MslotTest \
	tbf/TbfTest \
	types/TypesTest \
	ms/MsTest \
	llist/LListTest \
	llc/LlcTest \
	codel/codel_test \
	edge/EdgeTest \
	bitcomp/BitcompTest \
	fn/FnTest \
	app_info/AppInfoTest \
	ulc/PdchUlcTest \
	$(NULL)

noinst_PROGRAMS = emu/pcu_emu

rlcmac_RLCMACTest_SOURCES = rlcmac/RLCMACTest.cpp
rlcmac_RLCMACTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LDADD) \
	$(NULL)

alloc_AllocTest_SOURCES = alloc/AllocTest.cpp
alloc_AllocTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)
alloc_AllocTest_LDFLAGS = \
	-Wl,--wrap=pcu_sock_send \
	$(AM_LDFLAGS) \
	$(NULL)

alloc_MslotTest_SOURCES = alloc/MslotTest.cpp
alloc_MslotTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

tbf_TbfTest_SOURCES = tbf/TbfTest.cpp
tbf_TbfTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)
tbf_TbfTest_LDFLAGS = \
	-Wl,--wrap=pcu_sock_send \
	$(AM_LDFLAGS) \
	$(NULL)

bitcomp_BitcompTest_SOURCES = bitcomp/BitcompTest.cpp ../src/egprs_rlc_compression.cpp
bitcomp_BitcompTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

edge_EdgeTest_SOURCES = edge/EdgeTest.cpp
edge_EdgeTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

emu_pcu_emu_SOURCES = emu/pcu_emu.cpp emu/test_replay_gprs_attach.cpp \
	emu/openbsc_clone.c emu/openbsc_clone.h emu/gprs_tests.h \
	emu/test_pdp_activation.cpp
emu_pcu_emu_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

types_TypesTest_SOURCES = types/TypesTest.cpp
types_TypesTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

ms_MsTest_SOURCES = ms/MsTest.cpp
ms_MsTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

ms_MsTest_LDFLAGS = \
	-Wl,-u,bssgp_prim_cb \
	$(AM_LDFLAGS) \
	$(NULL)

llc_LlcTest_SOURCES = llc/LlcTest.cpp
llc_LlcTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

llc_LlcTest_LDFLAGS = \
	-Wl,-u,bssgp_prim_cb \
	$(AM_LDFLAGS) \
	$(NULL)

llist_LListTest_SOURCES = llist/LListTest.cpp
llist_LListTest_LDADD = \
	$(LDADD) \
	$(NULL)

codel_codel_test_SOURCES = codel/codel_test.c
codel_codel_test_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

fn_FnTest_SOURCES = fn/FnTest.cpp
fn_FnTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

app_info_AppInfoTest_SOURCES = app_info/AppInfoTest.cpp
app_info_AppInfoTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)
app_info_AppInfoTest_LDFLAGS = \
	-Wl,--wrap=pcu_sock_send \
	$(AM_LDFLAGS) \
	$(NULL)

ulc_PdchUlcTest_SOURCES = ulc/PdchUlcTest.cpp
ulc_PdchUlcTest_LDADD = \
	$(top_builddir)/src/libgprs.la \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LDADD) \
	$(NULL)

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE)	\
	rlcmac/RLCMACTest.ok rlcmac/RLCMACTest.err \
	alloc/AllocTest.ok alloc/AllocTest.err \
	tbf/TbfTest.err \
	bitcomp/BitcompTest.ok bitcomp/BitcompTest.err \
	types/TypesTest.ok types/TypesTest.err \
	ms/MsTest.ok ms/MsTest.err alloc/MslotTest.ok \
	llc/LlcTest.ok llc/LlcTest.err \
	llist/LListTest.ok llist/LListTest.err \
	codel/codel_test.ok \
	edge/EdgeTest.ok \
	fn/FnTest.ok \
	app_info/AppInfoTest.ok app_info/AppInfoTest.err \
	ulc/PdchUlcTest.ok ulc/PdchUlcTest.err \
	$(NULL)

DISTCLEANFILES = atconfig

TESTSUITE = $(srcdir)/testsuite

update_exp: $(check_PROGRAMS)
	rlcmac/RLCMACTest \
		>$(srcdir)/rlcmac/RLCMACTest.ok \
		2>$(srcdir)/rlcmac/RLCMACTest.err
	alloc/MslotTest \
		>$(srcdir)/alloc/MslotTest.ok
	alloc/AllocTest \
		>$(srcdir)/alloc/AllocTest.ok \
		2>$(srcdir)/alloc/AllocTest.err
	tbf/TbfTest \
		2>$(srcdir)/tbf/TbfTest.err
	bitcomp/BitcompTest \
		>$(srcdir)/bitcomp/BitcompTest.ok \
		2>$(srcdir)/bitcomp/BitcompTest.err
	edge/EdgeTest \
		>$(srcdir)/edge/EdgeTest.ok
	types/TypesTest \
		>$(srcdir)/types/TypesTest.ok \
		2>$(srcdir)/types/TypesTest.err
	ms/MsTest \
		>$(srcdir)/ms/MsTest.ok \
		2>$(srcdir)/ms/MsTest.err
	llc/LlcTest \
		>$(srcdir)/llc/LlcTest.ok \
		2>$(srcdir)/llc/LlcTest.err
	llist/LListTest \
		>$(srcdir)/llist/LListTest.ok \
		2>$(srcdir)/llist/LListTest.err
	codel/codel_test \
		>$(srcdir)/codel/codel_test.ok
	fn/FnTest \
		>$(srcdir)/fn/FnTest.ok
	app_info/AppInfoTest \
		>$(srcdir)/app_info/AppInfoTest.ok \
		2>$(srcdir)/app_info/AppInfoTest.err
	ulc/PdchUlcTest \
		>$(srcdir)/ulc/PdchUlcTest.ok \
		2>$(srcdir)/ulc/PdchUlcTest.err

# Python testing
if ENABLE_VTY_TESTS
python-tests: $(top_builddir)/src/osmo-pcu
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v

else
python-tests:
	@echo "Not running python-based tests (determined at configure-time)"
endif

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
