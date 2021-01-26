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

AC_INIT([igd2-for-linux], 2.1)
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_PROG_CC
AC_CONFIG_FILES(Makefile)
PKG_CHECK_MODULES([LIBUPNP], [libupnp])

AC_ARG_ENABLE([iptc],
    AS_HELP_STRING([--enable-iptc], [Enable iptc support]),
    enable_iptc=$enableval, enable_iptc=no)

AS_IF([test "x$enable_iptc" != "xno"], [
    PKG_CHECK_MODULES([LIBIPTC], [libiptc])
])
AM_CONDITIONAL([ENABLE_IPTC], [test x$enable_iptc = xyes])

AC_ARG_ENABLE([test],
    AS_HELP_STRING([--disable-test], [Disable test]),
    enable_test=$enableval, enable_test=no)

AS_IF([test "x$enable_test" != "xno"], [
    PKG_CHECK_MODULES([CUNIT], [cunit])
])
AM_CONDITIONAL([ENABLE_TEST], [test x$enable_test = xyes])

AC_OUTPUT
