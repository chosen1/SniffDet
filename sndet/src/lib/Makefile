SHELL = /bin/sh
CC = gcc
CTAGS = ctags -R
INSTALLCMD = /usr/bin/install -c
LIBNET_OPTIONS = -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN

srcdir=.
prefix=/usr/local
includedir=${prefix}/include
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libdir=${exec_prefix}/lib
mandir=${prefix}/man

DESTDIR=

CFLAGS = -g -O2 -Wall  $(LIBNET_OPTIONS)

LIBS = -ldl -lpcap -lnet 

all: do-it-all libsniffdet.a

ifeq (.depend,$(wildcard .depend))
include .depend
do-it-all:
else
#do-it-all: .depend
do-it-all:
endif

OBJECTS = icmptest.o latencytests.o arptest.o dnstest.o init.o helpers.o ping.o

libsniffdet.a: $(OBJECTS)
	ar rcs $@ $(OBJECTS)

test: test.o $(OBJECTS)
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) $< $(OBJECTS) -o $@ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(DEBUG_OPTIONS) -c -o $@ $<

.depend dep:
	for i in *.c; do $(CPP) -M $(LIBNET_OPTIONS) $$i; done > .depend

install: libsniffdet.a
	${INSTALLCMD} -d -m 755 $(DESTDIR)${libdir}
	${INSTALLCMD} -d -m 755 $(DESTDIR)${includedir}
	${INSTALLCMD} -m 644 libsniffdet.a $(DESTDIR)${libdir}
	${INSTALLCMD} -m 644 libsniffdet.h $(DESTDIR)${includedir}

tags:
	$(CTAGS)

clean:
	rm -f *.o *.a core.* core test libsniffdet.a

distclean: clean
	rm -f config.h .depend Makefile

.PHONY: all clean dep distclean tags
.SUFFIXES: .c .o
