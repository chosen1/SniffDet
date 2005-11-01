SHELL = /bin/sh
CC = gcc
CTAGS = ctags -R
INSTALLCMD = /usr/bin/install -c

srcdir=.
prefix=/usr/local
includedir=${prefix}/include
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libdir=${exec_prefix}/lib
mandir=${prefix}/man

DESTDIR=

LIBNET_OPTIONS=-D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN

CFLAGS = -g -O2 -Wall  $(LIBNET_OPTIONS)

LIBS = -Llib -lsniffdet -ldl -lpcap -lnet  -lpthread
INCLUDES = -Ilib

all: do-it-all libsniffdet sniffdet

ifeq (.depend,$(wildcard .depend))
include .depend
do-it-all:
else
#do-it-all: .depend
do-it-all:
endif

OBJECTS = log.o util.o config_file.o

libsniffdet:
	$(MAKE) -C lib all

sniffdet: sniffdet.o $(OBJECTS) lib/libsniffdet.a
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) $(OBJECTS) $(INCLUDES) $< -o $@ $(LIBS)
	$(MAKE) -C plugins all

.c.o:
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) $(INCLUDES) -c -o $@ $<

test-config: test-config.c config_file.o
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) $(INCLUDES) -lefence $< config_file.o -o $@

install: sniffdet
	$(INSTALLCMD) -d -m 755 $(DESTDIR)${sbindir}
	$(INSTALLCMD) -m 755 sniffdet $(DESTDIR)${sbindir}
	$(MAKE) DESTDIR=$(DESTDIR) $@ -C lib
	$(MAKE) DESTDIR=$(DESTDIR) $@ -C plugins

.depend dep:
	for i in *.c; do $(CPP) -M $(LIBNET_OPTIONS) $$i; done > .depend
	$(MAKE) $@ -C lib
	$(MAKE) $@ -C plugins

tags:
	$(CTAGS)
	$(MAKE) $@ -C lib
	$(MAKE) $@ -C plugins

clean:
	rm -f *.o core.* core sniffdet test-config
	$(MAKE) $@ -C lib
	$(MAKE) $@ -C plugins

lclean:
	rm -f *.o core.* core sniffdet

distclean: clean
	rm -f config.h .depend Makefile
	$(MAKE) $@ -C lib
	$(MAKE) $@ -C plugins

.PHONY: all clean dep distclean tags libsniffdet
.SUFFIXES: .c .o
