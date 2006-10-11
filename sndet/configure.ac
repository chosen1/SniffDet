dnl Process this file with autoconf to produce a configure script.

AC_INIT(sniffdet, 0.10, sniffdet-devel@lists.sourceforge.net, sniffdet)
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
# look at devel.m4 for detailed documentation
AC_SUBST(csourcedir, $srcdir/src)
AC_SUBST(headerdir, "")
AC_SUBST(utestdir, $srcdir/utest)
AC_SUBST(docdir, $srcdir/doc)
AC_DEVEL_MACROS
AC_DEVEL_ABSDIRS
AC_DEVEL_DEFINE_INSTALL_DIRS

# XXX
# create --uid and --gid
sndet_uid=280
sndet_gid=280
AC_DEFINE_UNQUOTED(SNDET_DEFAULT_UID, ${sndet_uid}, UID to be used when dropping root privs)
AC_DEFINE_UNQUOTED(SNDET_DEFAULT_GID, ${sndet_gid}, GID to be used when dropping root privs)

# XXX
# create --plugins-dir or something like that
AC_SUBST(SNDET_PLUGINSDIR, "${LIBDIR}/sniffdet/plugins")
AC_DEFINE_UNQUOTED(SNDET_PLUGINSDIR, "${LIBDIR}/sniffdet/plugins/", plugins directory)

AC_SUBST(SNDET_CONFIG, "${SYSCONFDIR}/sniffdet.conf")
AC_DEFINE_UNQUOTED(SNDET_CONFIG, "${SYSCONFDIR}/sniffdet.conf", default config file location)

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

  UID to be used by sniffdet: ${sndet_uid}
  GID to be used by sniffdet: ${sndet_gid}
  Plugins directory:          ${SNDET_PLUGINSDIR}

  Now type 'make' to build $PACKAGE_NAME $PACKAGE_VERSION.
"
