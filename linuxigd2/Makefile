PREFIX=/usr
LIBUPNP_PREFIX=/usr
#LIBIPTC_PREFIX=/usr

#COMMON_DIR = ./sc_common

PACKAGE = linuxigd2
VERSION = 1.0
DISTDIR = $(PACKAGE)-$(VERSION)
DISTFILES = Makefile Doxyfile bin/ configs/ doc/ inc/ lib/ src/ 

CC=gcc
INCLUDES= -I$(LIBUPNP_PREFIX)/include -I../include -I$(COMMON_DIR)/inc
LIBS= -lupnp -lixml -lthreadutil -lgnutls -lgcrypt -lgpg-error -lz -L$(LIBUPNP_PREFIX)/lib -L../libs
FILES= gatedevice.o pmlist.o util.o config.o lanhostconfig.o
#applicationlevelsecurity.o \
#	$(COMMON_DIR)/scmessage.o \
#	$(COMMON_DIR)/message_utilities.o \
#	$(COMMON_DIR)/sccryptoutil.o \
#	$(COMMON_DIR)/dh.o \
#	$(COMMON_DIR)/base64mem.o \
#	$(COMMON_DIR)/sha256.o \
#	$(COMMON_DIR)/common.o \
#	$(COMMON_DIR)/statectl.o \
#	$(COMMON_DIR)/list.o \
#	$(COMMON_DIR)/hexprint.o \
#	$(COMMON_DIR)/enrollee_state_machine.o \
#	$(COMMON_DIR)/enrollee_states.o \
#	$(COMMON_DIR)/enrollee_utilities.o \
#	$(COMMON_DIR)/debug.o \
#	$(COMMON_DIR)/crypto.o
BIN=bin/
DOC=doc/

CFLAGS += -Wall -g -O2

ifdef HAVE_LIBIPTC
ifdef LIBIPTC_PREFIX
LIBS += -L$(LIBIPTC_PREFIX)/lib
INCLUDES += -I$(LIBIPTC_PREFIX)/include
endif

LIBS += -liptc
INCLUDES += -I/usr/src/linux-headers-$(shell uname -r)/include -DHAVE_LIBIPTC
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
	install configs/gatedesc.xml /etc/linuxigd
	install configs/gateconnSCPD.xml  /etc/linuxigd
	install configs/gateicfgSCPD.xml /etc/linuxigd
	install configs/lanhostconfigSCPD.xml /etc/linuxigd
	install configs/gateEthlcfgSCPD.xml /etc/linuxigd
	install configs/dummy.xml /etc/linuxigd
	install $(BIN)upnpd $(PREFIX)/sbin
	install doc/upnpd.8 $(PREFIX)/share/man/man8
	if [ ! -f /etc/upnpd.conf ]; then install configs/upnpd.conf /etc; fi
