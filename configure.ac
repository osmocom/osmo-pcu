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

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

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

AC_ARG_ENABLE(sanitize,
		[AS_HELP_STRING([--enable-sanitize], [Compile with address sanitizer enabled], )],
		[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
	LDFLAGS="$LDFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

AC_ARG_ENABLE(profile,
		[AS_HELP_STRING([--enable-profile], [Compile with profiling support enabled], )],
		[profile=$enableval], [profile="no"])
if test x"$profile" = x"yes"
then
	CFLAGS="$CFLAGS -pg"
	CPPFLAGS="$CPPFLAGS -pg"
fi

dnl checks for libraries
PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.12.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.12.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.12.0)
PKG_CHECK_MODULES(LIBOSMOGB, libosmogb >= 0.12.0)

AC_MSG_CHECKING([whether to enable direct DSP access for PDCH of sysmocom-bts])
AC_ARG_ENABLE(sysmocom-dsp,
	      AC_HELP_STRING([--enable-sysmocom-dsp],
			     [enable code for direct sysmocom DSP access[default=no]]),
	      [enable_sysmocom_dsp="$enableval"], [enable_sysmocom_dsp="unset"])
AC_ARG_WITH([sysmobts],
	    [AS_HELP_STRING([--with-sysmobts=INCLUDE_DIR],
			    [Location of the sysmobts API header files, implies --enable-sysmocom-dsp])],
	    [sysmobts_incdir="$withval"], [sysmobts_incdir=""])
if test "x$sysmobts_incdir" != "x"; then
	# --with-sysmobts was passed, imply enable_sysmocom_dsp
	if test "x$enable_sysmocom_dsp" = "xno"; then
		AC_MSG_RESULT([error])
		AC_MSG_ERROR([--with-sysmobts does not work with --disable-sysmocom-dsp])
	fi
	enable_sysmocom_dsp="yes"
	# 'readlink' should make an absolute path, but must not return empty if the path does not exist,
	# so we can still report on it below.
	sysmobts_incdir="$(readlink -fm "$sysmobts_incdir")"
	AC_SUBST([SYSMOBTS_INCDIR], $sysmobts_incdir)
	AC_MSG_RESULT([yes, using -I$SYSMOBTS_INCDIR])
else
	AC_SUBST([SYSMOBTS_INCDIR], "")
	AC_MSG_RESULT([$enable_sysmocom_dsp])
fi
AM_CONDITIONAL(ENABLE_SYSMODSP, test "x$enable_sysmocom_dsp" = "xyes")
if test "x$enable_sysmocom_dsp" = "xyes"; then
	oldCPPFLAGS="$CPPFLAGS"
	_sysmobts_include=""
	_sysmobts_include_msg=""
	if test -n "$SYSMOBTS_INCDIR"; then
		_sysmobts_include="-I$SYSMOBTS_INCDIR"
		_sysmobts_include_msg=" in -I$SYSMOBTS_INCDIR"
	fi
	CPPFLAGS="$CPPFLAGS $_sysmobts_include -I$srcdir/include $LIBOSMOCORE_CFLAGS"
	AC_CHECK_HEADER([sysmocom/femtobts/superfemto.h],[],
			[AC_MSG_ERROR([sysmocom/femtobts/superfemto.h can not be found$_sysmobts_include_msg, see --with-sysmobts])],
			[#include <sysmocom/femtobts/superfemto.h>])
	CPPFLAGS="$oldCPPFLAGS"
fi

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
	oldCPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $LITECELL15_CFLAGS -I$srcdir/include $LIBOSMOCORE_CFLAGS"
	AC_CHECK_HEADER([nrw/litecell15/litecell15.h],[],
			[AC_MSG_ERROR([nrw/litecell15/litecell15.h can not be found using $litecell15_cflags])],
			[#include <nrw/litecell15/litecell15.h>])
	CPPFLAGS="$oldCPPFLAGS"
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

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_OUTPUT(
    osmo-pcu.pc
    include/Makefile
    src/Makefile
    examples/Makefile
    tests/Makefile
    Makefile)
