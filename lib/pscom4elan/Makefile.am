#
# ParaStation
#
# Copyright (C) 2012 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
# Authors:      Thomas Moschny <moschny@par-tec.com>
#               Jens Hauke <hauke@par-tec.com>
#
include $(top_srcdir)/common.am

AM_LDFLAGS += -avoid-version
AM_CPPFLAGS += -DLIBDIR=\"$(libdir)\" -I$(top_srcdir)/lib/pscom

lib_LTLIBRARIES = libpscom4elan.la

libpscom4elan_la_SOURCES = pscom_elan.c pscom_elan.h pselan.c pselan.h
libpscom4elan_la_CPPFLAGS = $(AM_CPPFLAGS) $(ELAN_CPPFLAGS)
libpscom4elan_la_LDFLAGS = $(AM_LDFLAGS) $(ELAN_LDFLAGS)
libpscom4elan_la_LIBADD = -lelan $(top_builddir)/lib/pscom/libpscom.la
