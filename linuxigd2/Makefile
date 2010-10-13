PREFIX=/usr
LIBUPNP_PREFIX=/usr
#LIBIPTC_PREFIX=/usr

CC=gcc
INCLUDES= -I$(LIBUPNP_PREFIX)/include -I../include
LIBS= -lpthread -lupnp -lixml -lthreadutil -L$(LIBUPNP_PREFIX)/lib -L../libs
FILES= main.o gatedevice.o pmlist.o util.o config.o

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

upnpd: $(FILES)
	$(CC) $(CFLAGS) $(FILES) $(LIBS) -o $@
	@echo "make $@ finished on `date`"

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDES) -D_GNU_SOURCE -c $<

clean:
	rm -f *.o upnpd

install: upnpd
	install -d /etc/linuxigd
	install etc/gatedesc.xml /etc/linuxigd
	install etc/gateconnSCPD.xml  /etc/linuxigd
	install etc/gateicfgSCPD.xml /etc/linuxigd
	install etc/dummy.xml /etc/linuxigd
	install upnpd $(PREFIX)/sbin
	install upnpd.8 $(PREFIX)/share/man/man8
	if [ ! -f /etc/upnpd.conf ]; then install etc/upnpd.conf /etc; fi
