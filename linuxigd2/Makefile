# 
# This file is part of igd2-for-linux project
# Copyright © 2011-2016 France Telecom / Orange.
# Contact: fabrice.fontaine@orange.com
# Developer(s): fabrice.fontaine@orange.com, rmenard.ext@orange-ftgroup.com
#  
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation, either version 2 of the License, or 
# (at your option) any later version. 
# 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
# GNU General Public License for more details. 
# 
# You should have received a copy of the GNU General Public License 
# along with this program, see the /doc directory of this program. If 
# not, see http://www.gnu.org/licenses/. 
# 

PREFIX=/usr
LIBUPNP_PREFIX=/usr/local
#LIBIPTC_PREFIX=/usr


PACKAGE = linuxigd2
VERSION = 1.1
DISTDIR = $(PACKAGE)-$(VERSION)
DISTFILES = Makefile Doxyfile bin/ configs/ doc/ src/ 

CC=gcc
INCLUDES= -I$(LIBUPNP_PREFIX)/include -I../include 
LIBS= -lpthread -lupnp -lixml -lthreadutil -L$(LIBUPNP_PREFIX)/lib -L../libs
FILES= gatedevice.o pmlist.o util.o config.o lanhostconfig.o pinholev6.o wanipv6fw.o

BIN=bin/
DOC=doc/

CFLAGS += -Wall -g -O2

ifdef HAVE_LIBIPTC
ifdef LIBIPTC_PREFIX
LIBS += -L$(LIBIPTC_PREFIX)/lib
INCLUDES += -I$(LIBIPTC_PREFIX)/include
endif

LIBS += -liptc -lip4tc -lip6tc
INCLUDES += -DHAVE_LIBIPTC
FILES += iptc.o
endif


all: upnpd

upnpd: $(FILES) main.o
	$(CC) $(CFLAGS) $^ $(LIBS) -o $(BIN)$@
	@echo "make $@ finished on `date`"

%.o:	src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -D_GNU_SOURCE -c $< -o $@

unittest: test
test: $(FILES)
	$(CC) $(CFLAGS) $(INCLUDES) -D_GNU_SOURCE -c src/unittest.c -o unittest.o
	$(CC) $(CFLAGS) $^ unittest.o $(LIBS) -lcunit -o $(BIN)$@

clean:
	rm -f *.o $(COMMON_DIR)/*.o $(BIN)upnpd $(BIN)test
	rm -rf $(DOC)doxygen

dist: clean
	tar --transform 's,^,/$(DISTDIR)/,' --exclude=*.o --exclude=.* --exclude=*.tar.gz -pzcf $(DISTDIR).tar.gz $(DISTFILES)

install: upnpd
	install -d /etc/linuxigd
	install configs/ligd.png /etc/linuxigd
	install configs/gatedesc.xml /etc/linuxigd
	install configs/gatedesc1.xml /etc/linuxigd
	install configs/gateconnSCPD.xml  /etc/linuxigd
	install configs/gateicfgSCPD.xml /etc/linuxigd
	install configs/lanhostconfigSCPD.xml /etc/linuxigd
	install configs/gateEthlcfgSCPD.xml /etc/linuxigd
	install configs/wanipv6fwctrlSCPD.xml /etc/linuxigd
	install configs/dummy.xml /etc/linuxigd
	install $(BIN)upnpd $(PREFIX)/sbin
	install doc/upnpd.8 $(PREFIX)/share/man/man8
	if [ ! -f /etc/upnpd.conf ]; then install configs/upnpd.conf /etc; fi

uninstall:
	rm -Rf /etc/linuxigd*
	rm /etc/upnpd.conf
	rm /usr/sbin/upnpd
	rm /usr/share/man/man8/upnpd.8
