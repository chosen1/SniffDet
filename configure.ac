dnl Process this file with autoconf to produce a configure script.

AC_INIT(sniffdet, 0.9svn, sniffdet-devel@lists.sourceforge.net, sniffdet)
AC_PREREQ(2.58)

AC_CONFIG_SRCDIR([src/sniffdet.c])
AC_CONFIG_AUX_DIR([aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([dist-bzip2 foreign])
AM_MAINTAINER_MODE

AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
AC_PROG_CC

dnl Check if pkg-config is installed
AC_CHECK_PROG(PKGCONFIG, pkg-config, yes, no)
if test $PKGCONFIG = "no"; then
    AC_MSG_ERROR("*** pkg-config not found! ***")
fi


dnl Checks for header files.
AC_CHECK_HEADERS([limits.h netdb.h netinet/in.h stdlib.h string.h sys/time.h unistd.h dlfcn.h syslog.h sys/param.h])
AC_CHECK_HEADERS([pcap.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_TIME
AC_TYPE_SIGNAL
AC_STRUCT_TM

AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm gettimeofday memset strndup inet_ntoa])
AC_CHECK_FUNCS([strstr select strerror])

dnl Checks for libraries.

AC_CHECK_PROG(LIBNETCONFIG, libnet-config, yes, no)
if test $LIBNETCONFIG = "yes"; then
    LIBNET_DEFINES=`libnet-config --defines`
    AC_SUBST(LIBNET_DEFINES)
else
    AC_MSG_ERROR("*** libnet-config not found! You need libnet 1.0 to build $PACKAGE_NAME! ***")
fi

AC_CHECK_LIB(net, libnet_open_link_interface, [ LIBNET_LIBS="-lnet" ], \
    AC_MSG_ERROR("*** libnet 1.0 not found! You need it to build $PACKAGE_NAME. ***"))
AC_SUBST(LIBNET_LIBS)
AC_CHECK_LIB(pcap, pcap_open_live, [ LIBPCAP_LIBS="-lpcap" ], \
    AC_MSG_ERROR("*** libpcap not found! You need it to build $PACKAGE_NAME. ***"))
AC_SUBST(LIBPCAP_LIBS)
AC_CHECK_LIB(ltdl, dlopen, [ LIBLTDL_LIBS="-lltdl" ], \
    AC_MSG_ERROR("*** libltd not found! You need it to build $PACKAGE_NAME. ***"))
AC_SUBST(LIBLTDL_LIBS)

ACX_PTHREAD(, [AC_MSG_ERROR("*** POSIX threads support not found! You need it to build $PACKAGE_NAME ***")])

# enable configure options and automake conditionals useful for developers
# look at auxdevel.m4 for detailed documentation
AC_SUBST(csourcedir, $srcdir/src)
AC_SUBST(headerdir, "")
AC_SUBST(utestdir, $srcdir/utest)
AC_SUBST(docdir, $srcdir/doc)
AC_DEVEL_MACROS
AC_DEVEL_ABSDIRS
AC_DEVEL_DEFINE_INSTALL_DIRS

AC_ARG_WITH(uid, AS_HELP_STRING([--with-uid=UID],
			[UID to use when dropping root privs (default: 280)]),
			[SNDET_DEFAULT_UID=$withval], [SNDET_DEFAULT_UID=280])
if ! test "$SNDET_DEFAULT_UID" -gt "0" 2> /dev/null; then
	AC_MSG_ERROR([invalid UID: ${SNDET_DEFAULT_UID}])
fi

AC_ARG_WITH(gid, AS_HELP_STRING([--with-gid=GID],
			[GID to use when dropping root privs (default: 280)]),
			[SNDET_DEFAULT_GID=$withval], [SNDET_DEFAULT_GID=280])
if ! test "$SNDET_DEFAULT_GID" -gt "0" 2> /dev/null; then
	AC_MSG_ERROR([invalid GID: ${SNDET_DEFAULT_GID} (must be an integer)])
fi

AC_DEFINE_UNQUOTED([SNDET_DEFAULT_UID], [${SNDET_DEFAULT_UID}],
				   "UID to be used when dropping root privs")
AC_DEFINE_UNQUOTED([SNDET_DEFAULT_GID], [${SNDET_DEFAULT_GID}],
				   "GID to be used when dropping root privs")

AC_ARG_WITH(pluginsdir, AS_HELP_STRING([--with-pluginsdir=PATH],
			[Directory to store sniffdet plugins (default:
			 ${LIBDIR}/sniffdet/plugins)]),
			 [SNDET_PLUGINSDIR="$withval"],
			 [SNDET_PLUGINSDIR="${LIBDIR}/sniffdet/plugins"])

AC_SUBST(SNDET_PLUGINSDIR)
AC_DEFINE_UNQUOTED(SNDET_PLUGINSDIR, ["${SNDET_PLUGINSDIR}"],
				   [sniffdet plugins directory])

# not configurable, at least by now
AC_SUBST(SNDET_CONFIG, "${SYSCONFDIR}/sniffdet.conf")
AC_DEFINE_UNQUOTED(SNDET_CONFIG, ["${SYSCONFDIR}/sniffdet.conf"],
				   [default config file location])

AC_CONFIG_FILES([Makefile
                 Doxyfile
                 libsniffdet.pc
                 sniffdet.spec
                 sniffdet.conf
                 libsniffdet-uninstalled.pc])

AC_OUTPUT


echo "
$PACKAGE_NAME $PACKAGE_VERSION configuration:
-----------------------------
  Source code location:       ${srcdir}
  Host System Type:           ${host}
  Compiler:                   ${CC}
  CFLAGS:                     ${CFLAGS} ${ac_devel_default_warnings}
  Libraries:                  ${LIBPCAP_LIBS} ${LIBNET_LIBS} ${LIBLTDL_LIBS}
  Pthread support:            ${PTHREAD_CC} ${PTHREAD_LIBS} ${PTHREAD_CFLAGS}
  Install path (prefix):      ${prefix}

  UID to be used by sniffdet: ${SNDET_DEFAULT_UID}
  GID to be used by sniffdet: ${SNDET_DEFAULT_GID}
  Plugins directory:          ${SNDET_PLUGINSDIR}

  Now type 'make' to build $PACKAGE_NAME $PACKAGE_VERSION.
"
