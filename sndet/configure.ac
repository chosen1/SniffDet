dnl Process this file with autoconf to produce a configure script.

AC_INIT(SniffDet, 0.9, sniffdet-devel@lists.sourceforge.net, sniffdet)
AC_PREREQ(2.58)

AC_CONFIG_SRCDIR([src/sniffdet.c])
AC_CONFIG_AUX_DIR([aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.7.9 foreign])

AC_CONFIG_HEADERS([config.h])

AC_GNU_SOURCE

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_CC

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
    AC_MSG_ERROR("*** libnet-config not found! You need it to build $PACKAGE_NAME! ***")
fi

AC_CHECK_LIB(net, libnet_open_link_interface,, \
    AC_MSG_ERROR("*** libnet not found! You need it to build $PACKAGE_NAME! ***"))
AC_CHECK_LIB(pcap, pcap_open_live,, \
    AC_MSG_ERROR("*** libpcap not found! You need it to build $PACKAGE_NAME! ***"))

# borrowed from xmms configure.in:
PTHREAD_LIBS=error
AC_MSG_CHECKING(for old style FreeBSD -pthread flag)
AC_EGREP_CPP(yes,
    [#if defined(__FreeBSD_cc_version) && __FreeBSD_cc_version <= 500001
      yes
    #endif
    ], AC_MSG_RESULT(yes)
    CFLAGS="$CFLAGS -D_THREAD_SAFE" PTHREAD_LIBS="-pthread",
    AC_MSG_RESULT(no))
if test "x$PTHREAD_LIBS" = xerror; then
    AC_CHECK_LIB(pthread, pthread_create,
        PTHREAD_LIBS="-lpthread")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(pthreads, pthread_create,
        PTHREAD_LIBS="-lpthreads")
fi
if test "x$PTHREAD_LIBS" = xerror; then
        AC_CHECK_LIB(c_r, pthread_create,
        PTHREAD_LIBS="-lc_r")
fi
if test "x$PTHREAD_LIBS" = xerror; then
    AC_CHECK_FUNC(pthread_create, PTHREAD_LIBS="")
fi
if test "x$PTHREAD_LIBS" = xerror; then
    AC_MSG_ERROR("*** Unable to locate working posix thread library. You need it to build $PACKAGE_NAME! ***")
fi
AC_SUBST(PTHREAD_LIBS)

dnl Configure libltdl
AC_CHECK_LIB(ltdl, dlopen)

# FIXME:
# create --uid and --gid
sndet_uid=280
sndet_gid=280
AC_DEFINE_UNQUOTED(SNDET_DEFAULT_UID, ${sndet_uid}, UID to be used when dropping root privs)
AC_DEFINE_UNQUOTED(SNDET_DEFAULT_GID, ${sndet_gid}, GID to be used when dropping root privs)

PACKAGE_URL="http://sniffdet.sourceforge.net"
AC_SUBST(PACKAGE_URL)

# look at devel.m4 for detailed documentation
AC_DEVEL_MACROS

## set this to the directory in which actual source files are kept.
AC_SUBST(csourcedir, $srcdir/src)

## if your package install header files, set this to the directory
## relative to $srcdir where you keep them
#AC_SUBST(headerdir, $srcdir/headers)
AC_SUBST(headerdir, "")

## set this to the directory for Check unit tests
AC_SUBST(utestdir, $srcdir/utest)

## set this to the directory where static documentation is kept
AC_SUBST(docdir, $srcdir/doc)

## this generates absolute versions of the above five variables
## (abs_csourcedir, abs_headerdir, etc.)
## it's needed for "make lcov"
AC_DEVEL_ABSDIRS

## this macro adds variables with expanded installation
## directories. The variables are upper-case versions of
## the standard ones defined by autoconf
AC_DEVEL_DEFINE_INSTALL_DIRS

# FIXME:
# create --plugins-dir or something like that
AC_SUBST(SNDET_PLUGINSDIR, "${LIBDIR}/sniffdet/plugins")
AC_DEFINE_UNQUOTED(SNDET_PLUGINSDIR, "${LIBDIR}/sniffdet/plugins/", plugins directory)

AC_CONFIG_FILES([Makefile
                 Doxyfile
                 libsniffdet.pc
                 libsniffdet-uninstalled.pc])

AC_OUTPUT


echo "
$PACKAGE_NAME $PACKAGE_VERSION configuration:
-----------------------------
  Source code location:       ${srcdir}
  Host System Type:           ${host}
  Compiler:                   ${CC}
  CFLAGS:                     ${CFLAGS}
  Libraries:                  ${LIBS}
  Pthread flag:               ${PTHREAD_LIBS}
  Install path (prefix):      ${prefix}

  UID to be used by sniffdet: ${sndet_uid}
  GID to be used by sniffdet: ${sndet_gid}
  Plugins directory:          ${SNDET_PLUGINSDIR}

  Now type 'make' to build $PACKAGE_NAME $PACKAGE_VERSION.
"
