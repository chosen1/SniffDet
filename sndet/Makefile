CTAGS = ctags -R
INSTALLCMD = /usr/bin/install -c

VERSION = 0.9

srcdir=.
prefix=/usr/local
includedir=${prefix}/include
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libdir=${exec_prefix}/lib
mandir=${prefix}/man
sysconfdir=${prefix}/etc

DESTDIR=

all clean dep .depend:
	$(MAKE) $@ -C src

distclean:
	rm -f pi sniffdet.3 config.cache config.log config.status Makefile
	$(MAKE) $@ -C src

install:
	$(INSTALLCMD) -d -m 755 $(DESTDIR)${mandir}/man1
	$(INSTALLCMD) -d -m 755 $(DESTDIR)${mandir}/man3
	$(INSTALLCMD) -d -m 755 $(DESTDIR)${mandir}/man5
	$(INSTALLCMD) -d $(DESTDIR)${sysconfdir}
	$(INSTALLCMD) -m 644 sniffdet.1 $(DESTDIR)${mandir}/man1
	$(INSTALLCMD) -m 644 libsniffdet.3 $(DESTDIR)${mandir}/man3
	$(INSTALLCMD) -m 644 sniffdet.conf.5 $(DESTDIR)${mandir}/man5
	$(INSTALLCMD) -m 600 sniffdet.conf $(DESTDIR)${sysconfdir}
	$(MAKE) DESTDIR=$(DESTDIR) $@ -C src

tags:
	$(CTAGS)
	$(MAKE) $@ -C src

.PHONY: tags
