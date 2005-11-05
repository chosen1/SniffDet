## Please note that prog_CFLAGS and prog_LDADD overwrite AM_CFLAGS and LDADD, set
## by the included file mk/auxdevel.am.  If you want to use program-specific
## flags, do something like frobnicator_CFLAGS = -march=athlon $(AM_CFLAGS)

## $Id$

# libsniffdet
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsniffdet.pc
lib_LTLIBRARIES = libsniffdet.la
include_HEADERS = $(csourcedir)/lib/libsniffdet.h
libsniffdet_la_SOURCES = $(csourcedir)/lib/arptest.c \
                         $(csourcedir)/lib/dnstest.c \
                         $(csourcedir)/lib/icmptest.c \
                         $(csourcedir)/lib/latencytest.c \
                         $(csourcedir)/lib/helpers.c \
                         $(csourcedir)/lib/ping.c \
                         $(csourcedir)/lib/init.c
libsniffdet_la_CPPFLAGS = -I$(csourcedir)/lib/ $(LIBNET_DEFINES)

# sniffdet itself
bin_PROGRAMS = sniffdet
sniffdet_SOURCES = $(csourcedir)/sniffdet.c \
                   $(csourcedir)/sniffdet.h \
                   $(csourcedir)/log.c \
                   $(csourcedir)/log.h \
                   $(csourcedir)/config_file.c \
                   $(csourcedir)/util.c \
                   $(csourcedir)/util.h
sniffdet_LDADD = libsniffdet.la $(PTHREAD_LIBS)
sniffdet_CPPFLAGS = $(libsniffdet_la_CPPFLAGS) $(AM_CPPFLAGS)

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
             $(srcdir)/mk/auxdevel.am $(srcdir)/mk/auxdevel-libtool.am

DISTCHECK_CONFIGURE_FLAGS = --enable-efence --enable-debug \
                            --enable-warnings --enable-lcov --enable-check

# this variable is scanned by autoreconf and needs to be static (no expansion)
ACLOCAL_AMFLAGS = -I m4

include $(srcdir)/mk/auxdevel.am
