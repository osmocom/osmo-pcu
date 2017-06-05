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
	CXXFLAGS="$CXXFLAGS -fsanitize=address -fsanitize=undefined"
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

AC_MSG_CHECKING([whether to enable direct PHY access for PDCH of NuRAN Wireless OC-2G BTS])
AC_ARG_ENABLE(oc2gbts-phy,
                AC_HELP_STRING([--enable-oc2gbts-phy],
                                [enable code for OC-2G PHY [default=no]]),
                [enable_oc2gbts_phy="$enableval"],[enable_oc2gbts_phy="no"])
AC_ARG_WITH([oc2g], [AS_HELP_STRING([--with-oc2g=INCLUDE_DIR], [Location of the OC-2G API header files])],
			 [oc2g_incdir="$withval"],[oc2g_incdir="$incdir"])
AC_SUBST([OC2G_INCDIR], $oc2g_incdir)
AC_MSG_RESULT([$enable_oc2gbts_phy])
AM_CONDITIONAL(ENABLE_OC2GBTS_PHY, test "x$enable_oc2gbts_phy" = "xyes")
if test "$enable_oc2g" = "yes"; then
	oldCPPFLAGS=$CPPFLAGS
	CPPFLAGS="$CPPFLAGS -I$OC2G_INCDIR -I$srcdir/include $LIBOSMOCORE_CFLAGS"
	AC_CHECK_HEADER([nrw/oc2g/oc2g.h],[],
			[AC_MSG_ERROR([nrw/oc2g/oc2g.h can not be found in $oc2g_incdir])],
			[#include <nrw/oc2g/oc2g.h>])
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

# Generate manuals
AC_ARG_ENABLE(manuals,
	[AS_HELP_STRING(
		[--enable-manuals],
		[Generate manual PDFs [default=no]],
	)],
	[osmo_ac_build_manuals=$enableval], [osmo_ac_build_manuals="no"])
AM_CONDITIONAL([BUILD_MANUALS], [test x"$osmo_ac_build_manuals" = x"yes"])
AC_ARG_VAR(OSMO_GSM_MANUALS_DIR, [path to common osmo-gsm-manuals files, overriding pkg-config and "../osmo-gsm-manuals"
	fallback])
if test x"$osmo_ac_build_manuals" = x"yes"
then
	# Find OSMO_GSM_MANUALS_DIR (env, pkg-conf, fallback)
	if test -n "$OSMO_GSM_MANUALS_DIR"; then
		echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from env)"
	else
		OSMO_GSM_MANUALS_DIR="$($PKG_CONFIG osmo-gsm-manuals --variable=osmogsmmanualsdir 2>/dev/null)"
		if test -n "$OSMO_GSM_MANUALS_DIR"; then
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from pkg-conf)"
		else
			OSMO_GSM_MANUALS_DIR="../osmo-gsm-manuals"
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (fallback)"
		fi
	fi
	if ! test -d "$OSMO_GSM_MANUALS_DIR"; then
		AC_MSG_ERROR("OSMO_GSM_MANUALS_DIR does not exist! Install osmo-gsm-manuals or set OSMO_GSM_MANUALS_DIR.")
	fi

	# Find and run check-depends
	CHECK_DEPENDS="$OSMO_GSM_MANUALS_DIR/check-depends.sh"
	if ! test -x "$CHECK_DEPENDS"; then
		CHECK_DEPENDS="osmo-gsm-manuals-check-depends"
	fi
	if ! $CHECK_DEPENDS; then
		AC_MSG_ERROR("missing dependencies for --enable-manuals")
	fi

	# Put in Makefile with absolute path
	OSMO_GSM_MANUALS_DIR="$(realpath "$OSMO_GSM_MANUALS_DIR")"
	AC_SUBST([OSMO_GSM_MANUALS_DIR])
fi

# https://www.freedesktop.org/software/systemd/man/daemon.html
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])
AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CXXFLAGS="$CXXFLAGS"])
AC_MSG_RESULT([LDFLAGS="$LDFLAGS"])

AC_OUTPUT(
    include/Makefile
    src/Makefile
    doc/Makefile
    doc/examples/Makefile
    tests/Makefile
    doc/manuals/Makefile
    contrib/Makefile
    contrib/systemd/Makefile
    Makefile)
