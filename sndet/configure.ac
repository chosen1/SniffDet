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
AC_PROG_CC
AC_LANG_C
AC_LN_S

dnl Checks for libraries.

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h netdb.h netinet/in.h stdlib.h string.h sys/time.h unistd.h dlfcn.h syslog.h sys/param.h])
AC_CHECK_HEADERS([pcap.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_HEADER_TIME
AC_TYPE_SIGNAL
AC_STRUCT_TM

AC_FUNC_MALLOC
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm gettimeofday memset strndup inet_ntoa])
AC_CHECK_FUNCS([strstr select strerror])

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


dnl freeBSD doesn't have libdl...
dnl AC_CHECK_LIB([dl], [dlopen],, \
dnl    AC_MSG_ERROR(\
dnl "*** libdl not found! You need it to build $PACKAGE_NAME! (plugins support) ***"))
dnl but linux does...

AC_CHECK_LIB([dl], [dlopen],,)

dnl FIXME:
dnl create --uid and --gid
sndet_uid=280
sndet_gid=280
AC_DEFINE_UNQUOTED(SNDET_DEFAULT_UID, ${sndet_uid}, UID to be used when dropping root privs)
AC_DEFINE_UNQUOTED(SNDET_DEFAULT_GID, ${sndet_gid}, GID to be used when dropping root privs)


dnl FIXME:
dnl create --plugins-dir or something like that
sndet_pluginsdir="${prefix}/lib/sniffdet/plugins"
AC_DEFINE_UNQUOTED(SNDET_PLUGINSDIR, "${sndet_pluginsdir}", Plugins directory)

PACKAGE_URL="http://sniffdet.sourceforge.net"
AC_SUBST(PACKAGE_URL)

# look at devel.m4 for detailed documentation
AC_DEVEL_MACROS

## set this to the directory in which actual source files are kept.
AC_SUBST(csourcedir, $srcdir/src)

## if your package install header files, set this to the directory
## relative to $srcdir where you keep them
#AC_SUBST(headerdir, $srcdir/headers)

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

AC_CONFIG_FILES([Makefile
                 Doxyfile])

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
  Install path:               ${prefix}

  UID to be used by sniffdet: ${sndet_uid}
  GID to be used by sniffdet: ${sndet_gid}
  Plugins directory:          ${sndet_pluginsdir}

  Now type 'make' to build $PACKAGE_NAME $PACKAGE_VERSION.
"
