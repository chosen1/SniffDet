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

pluginsdir=${libdir}/sniffdet/plugins

DESTDIR=

LIBNET_OPTIONS=-D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN

CFLAGS = -g -O2 -Wall  $(LIBNET_OPTIONS)

LIBS = -ldl -lpcap -lnet 

INCLUDES = -I..

all: do-it-all plugins

ifeq (.depend,$(wildcard .depend))
include .depend
do-it-all:
else
#do-it-all: .depend
do-it-all:
endif

.c.o:
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) $(INCLUDES) -fpic -c -o $@ $<

.o.so:
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) $(INCLUDES) -shared -lc -o $@ $<

plugins: null.so stdout.so xml.so

install: plugins
	$(INSTALLCMD) -d -m 0755 $(DESTDIR)${pluginsdir}
	$(INSTALLCMD) null.so $(DESTDIR)${pluginsdir}
	$(INSTALLCMD) stdout.so $(DESTDIR)${pluginsdir}
	$(INSTALLCMD) xml.so $(DESTDIR)${pluginsdir}

.depend dep:
	for i in *.c; do $(CPP) -M $(LIBNET_OPTIONS) $$i; done > .depend

tags:
	$(CTAGS)

clean:
	rm -f *.o *.so

distclean: clean
	rm -f .depend Makefile

.PHONY: all clean dep distclean tags
.SUFFIXES: .c .o .so
