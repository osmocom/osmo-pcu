dnl Process this file with autoconf to produce a configure script
AC_INIT([osmo-pcu],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[osmocom-net-gprs@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl checks for header files
AC_HEADER_STDC

dnl Checks for typedefs, structures and compiler characteristics

dnl checks for libraries
PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore  >= 0.3.9)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.3.3)
PKG_CHECK_MODULES(LIBOSMOGB, libosmogb >= 0.5.1.4)

AC_MSG_CHECKING([whether to enable direct DSP access for PDCH of sysmocom-bts])
AC_ARG_ENABLE(sysmocom-dsp,
		AC_HELP_STRING([--enable-sysmocom-dsp],
				[enable code for sysmocom DSP [default=no]]),
		[enable_sysmocom_dsp="$enableval"],[enable_sysmocom_dsp="no"])
AC_MSG_RESULT([$enable_sysmocom_dsp])
AM_CONDITIONAL(ENABLE_SYSMODSP, test "x$enable_sysmocom_dsp" = "xyes")

AC_MSG_CHECKING([whether to enable direct PHY access for PDCH of NuRAN Wireless Litecell 1.5 BTS])
AC_ARG_ENABLE(lc15bts-phy,
                AC_HELP_STRING([--enable-lc15bts-phy],
                                [enable code for Litecell 1.5 PHY [default=no]]),
                [enable_lc15bts_phy="$enableval"],[enable_lc15bts_phy="no"])
AC_ARG_WITH([litecell15], [AS_HELP_STRING([--with-litecell15=INCLUDE_DIR], [Location of the litecell 1.5 API header files])],
			 [litecell15_cflags="-I$withval"],[litecell15_cflags=""])
AC_SUBST([LITECELL15_CFLAGS], $litecell15_cflags)
AC_MSG_RESULT([$enable_lc15bts_phy])
AM_CONDITIONAL(ENABLE_LC15BTS_PHY, test "x$enable_lc15bts_phy" = "xyes")
if test "$enable_litecell15" = "yes"; then
	oldCPPFLAGS=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS $LITECELL15_CFLAGS -I$srcdir/include $LIBOSMOCORE_CFLAGS"
	AC_CHECK_HEADER([nrw/litecell15/litecell15.h],[],
			[AC_MSG_ERROR([nrw/litecell15/litecell15.h can not be found using $litecell15_cflags])],
			[#include <nrw/litecell15/litecell15.h>])
	CPPFLAGS=$oldCPPFLAGS
fi

AC_ARG_ENABLE([vty_tests],
		AC_HELP_STRING([--enable-vty-tests],
				[Include the VTY tests in make check [default=no]]),
		[enable_vty_tests="$enableval"],[enable_vty_tests="no"])
if test "x$enable_vty_tests" = "xyes" ; then
	AM_PATH_PYTHON
	AC_CHECK_PROG(OSMOTESTVTY_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTVTY_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install osmocom-python to run the vty tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY tests])
AC_MSG_RESULT([$enable_vty_tests])
AM_CONDITIONAL(ENABLE_VTY_TESTS, test "x$enable_vty_tests" = "xyes")

STD_DEFINES_AND_INCLUDES="-Wall"
AC_SUBST(STD_DEFINES_AND_INCLUDES)

AC_OUTPUT(
    osmo-pcu.pc
    include/Makefile
    src/Makefile
    examples/Makefile
    tests/Makefile
    Makefile)
