# 
# This file is part of igd2-for-linux project
# Copyright © 2011-2021 France Telecom / Orange.
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

bin_PROGRAMS = upnpd
upnpd_SOURCES = $(FILES) $(THREADUTIL) src/main.c
FILES = \
    src/gatedevice.c \
    src/pmlist.c \
    src/util.c \
    src/config.c \
    src/lanhostconfig.c \
    src/pinholev6.c \
    src/wanipv6fw.c
THREADUTIL = \
    src/threadutil/FreeList.c \
    src/threadutil/LinkedList.c \
    src/threadutil/ThreadPool.c \
    src/threadutil/TimerThread.c

upnpd_CFLAGS  = $(LIBUPNP_CFLAGS)
upnpd_LDADD = $(LIBUPNP_LIBS)

if ENABLE_IPTC
upnpd_SOURCES += src/iptc.c
upnpd_CFLAGS  += $(LIBIPTC_CFLAGS)
upnpd_LDADD += $(LIBIPTC_LIBS)
endif

upnpdconfdir = $(sysconfdir)/linuxigd
upnpdconf_DATA = \
    configs/ligd.png \
    configs/gatedesc.xml \
    configs/gatedesc1.xml \
    configs/gateconnSCPD.xml \
    configs/gateicfgSCPD.xml \
    configs/lanhostconfigSCPD.xml \
    configs/gateEthlcfgSCPD.xml \
    configs/wanipv6fwctrlSCPD.xml \
    configs/dummy.xml \
    configs/upnpd.conf

man_MANS = doc/upnpd.8

if ENABLE_TEST
unittest_PROGRAMS = unittest
unittestdir = src
unittest_SOURCES = $(FILES) $(THREADUTIL) src/unittest.c
unittest_CFLAGS = $(CUNIT_CFLAGS) $(LIBUPNP_CFLAGS)
unittest_LDADD = $(CUNIT_LIBS) $(LIBUPNP_LIBS)
endif
