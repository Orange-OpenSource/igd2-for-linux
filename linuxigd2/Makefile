PREFIX=/usr
LIBUPNP_PREFIX=/usr
#LIBIPTC_PREFIX=/usr

CC=gcc
INCLUDES= -I$(LIBUPNP_PREFIX)/include -I../include
LIBS= -lpthread -lupnp -lixml -lthreadutil -L$(LIBUPNP_PREFIX)/lib -L../libs
FILES= gatedevice.o pmlist.o util.o config.o
BIN=bin/

CFLAGS += -Wall -g -O2

ifdef HAVE_LIBIPTC
ifdef LIBIPTC_PREFIX
LIBS += -L$(LIBIPTC_PREFIX)/lib
INCLUDES += -I$(LIBIPTC_PREFIX)/include
endif

LIBS += -liptc
INCLUDES += -DHAVE_LIBIPTC
FILES += iptc.o
endif


all: upnpd

upnpd: $(FILES) main.o
	$(CC) $(CFLAGS) $^ $(LIBS) `pkg-config --libs glib-2.0` -o $(BIN)$@
	@echo "make $@ finished on `date`"

%.o:	src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) `pkg-config --cflags glib-2.0` -D_GNU_SOURCE -c $< -o $@

unittest: test
test: $(FILES)
	$(CC) $(CFLAGS) $(INCLUDES) `pkg-config --cflags glib-2.0` -D_GNU_SOURCE -c src/unittest.c -o unittest.o
	$(CC) $(CFLAGS) $^ unittest.o $(LIBS) -lcunit `pkg-config --libs glib-2.0` -o $(BIN)$@

clean:
	rm -f *.o $(BIN)upnpd

install: upnpd
	install -d /etc/linuxigd
	install configs/gatedesc.xml /etc/linuxigd
	install configs/gateconnSCPD.xml  /etc/linuxigd
	install configs/gateicfgSCPD.xml /etc/linuxigd
	install configs/dummy.xml /etc/linuxigd
	install $(BIN)upnpd $(PREFIX)/sbin
	install doc/upnpd.8 $(PREFIX)/share/man/man8
	if [ ! -f /etc/upnpd.conf ]; then install configs/upnpd.conf /etc; fi
