## Please note that prog_CFLAGS and prog_LDADD overwrite AM_CFLAGS and LDADD, set
## by the included file mk/auxdevel.am.  If you want to use program-specific
## flags, do something like frobnicator_CFLAGS = -march=athlon $(AM_CFLAGS)

## Example program configuration.  Headers in $(csourcedir) won't be installed,
## but it is a good idea to list them in _SOURCES.
bin_PROGRAMS = sniffdet
sniffdet_SOURCES = $(csourcedir)/sniffdet.c $(csourcedir)/log.c \
                   $(csourcedir)/config_file.c $(csourcedir)/util.c

noinst_PROGRAMS = test-config
test_config_SOURCES = $(csourcedir)/test-config.c \
                      $(csourcedir)/config_file.c

## You need nobase_ for headers if you want them to be included without
## stripping the relative path.
# nobase_include_HEADERS = $(headerdir)/csyncml.h $(headerdir)/builder.h


if CHECK
TESTS = utest_sniffdet
noinst_PROGRAMS += utest_sniffdet
utest_frobnicator_SOURCES = $(csourcedir)/sniffdet.c \
utest_frobnicator_CPPFLAGS = $(CHECK_FLAGS) $(AM_CPPFLAGS) -I$(utestdir)
utest_frobnicator_LDADD = $(CHECK_LIBS) $(LDADD)
endif

EXTRA_DIST = $(srcdir)/m4/auxdevel.m4 $(srcdir)/m4/check.m4 \
             $(srcdir)/mk/auxdevel.am $(srcdir)/mk/auxdevel-libtool.am

DISTCHECK_CONFIGURE_FLAGS = --enable-efence --enable-lcov --enable-debug \
    --enable-check --enable-warnings

# this variable is scanned by autoreconf and needs to be static (no expansion)
ACLOCAL_AMFLAGS = -I m4

include $(srcdir)/mk/auxdevel.am
