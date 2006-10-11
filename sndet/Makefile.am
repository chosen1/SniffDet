## Please note that prog_CFLAGS and prog_LDADD overwrite AM_CFLAGS and LDADD, set
## by the included file mk/auxdevel.am.  If you want to use program-specific
## flags, do something like frobnicator_CFLAGS = -march=athlon $(AM_CFLAGS)

# libsniffdet
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsniffdet.pc
libmandir = $(mandir)/man3
libman_DATA = libsniffdet.3
lib_LTLIBRARIES = libsniffdet.la
include_HEADERS = $(csourcedir)/lib/libsniffdet.h
libsniffdet_la_SOURCES = $(csourcedir)/lib/arptest.c \
                         $(csourcedir)/lib/dnstest.c \
                         $(csourcedir)/lib/icmptest.c \
                         $(csourcedir)/lib/latencytest.c \
                         $(csourcedir)/lib/helpers.c \
                         $(csourcedir)/lib/ping.c \
                         $(csourcedir)/lib/init.c
libsniffdet_la_CC = $(PTHREAD_CC)
libsniffdet_la_CPPFLAGS = -I$(csourcedir)/lib/ $(LIBNET_DEFINES)
libsniffdet_la_CFLAGS = $(PTHREAD_CFLAGS) $(AM_CFLAGS)
libsniffdet_la_LIBADD = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS) $(LIBLTDL_LIBS) $(LIBNET_LIBS) $(LIBPCAP_LIBS)

# sniffdet itself
confdir = $(sysconfdir)
conf_DATA = sniffdet.conf
sndetmandir = $(mandir)/man1
sndetman_DATA = sniffdet.1
bin_PROGRAMS = sniffdet
sniffdet_SOURCES = $(csourcedir)/sniffdet.c \
                   $(csourcedir)/sniffdet.h \
                   $(csourcedir)/log.c \
                   $(csourcedir)/log.h \
                   $(csourcedir)/config_file.c \
                   $(csourcedir)/util.c \
                   $(csourcedir)/util.h
sniffdet_CC = $(PTHREAD_CC)
sniffdet_LDADD = libsniffdet.la $(PTHREAD_CFLAGS)
sniffdet_CPPFLAGS = $(libsniffdet_la_CPPFLAGS) $(AM_CPPFLAGS)
sniffdet_CFLAGS = $(PTHREAD_CFLAGS) $(AM_CFLAGS)

noinst_PROGRAMS = test-config
test_config_SOURCES = $(csourcedir)/test-config.c \
                      $(csourcedir)/config_file.c
test_config_CPPFLAGS = $(libsniffdet_la_CPPFLAGS) $(AM_CPPFLAGS)

# plugins

# unit-tests
if CHECK
#TESTS = utest_frobnicator
#noinst_PROGRAMS += utest_frobnicator
#utest_frobnicator_SOURCES = $(csourcedir)/sniffdet.c \
#utest_frobnicator_CPPFLAGS = $(CHECK_FLAGS) $(AM_CPPFLAGS) -I$(utestdir)
#utest_frobnicator_LDADD = $(CHECK_LIBS) $(LDADD)
endif

EXTRA_DIST = $(srcdir)/m4/auxdevel.m4 $(srcdir)/m4/check.m4 \
             $(srcdir)/m4/acx_pthread.m4 \
             $(srcdir)/mk/auxdevel.am $(srcdir)/mk/auxdevel-libtool.am \
             $(srcdir)/README \
             $(srcdir)/TODO \
             libsniffdet-uninstalled.pc \
             Doxyfile \
             sniffdet.spec \
             sniffdet.conf \
             sniffdet.1 \
             libsniffdet.3


DISTCHECK_CONFIGURE_FLAGS = --enable-efence --enable-debug \
                            --enable-warnings --enable-check

# this variable is scanned by autoreconf and needs to be static (no expansion)
ACLOCAL_AMFLAGS = -I m4

include $(srcdir)/mk/auxdevel.am
