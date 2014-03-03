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

lib_LTLIBRARIES = libpscom4openib.la

libpscom4openib_la_SOURCES = pscom_openib.c pscom_openib.h psoib.c psoib.h
libpscom4openib_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENIB_CPPFLAGS)
libpscom4openib_la_LDFLAGS = $(AM_LDFLAGS) $(OPENIB_LDFLAGS)
libpscom4openib_la_LIBADD = -libverbs $(top_builddir)/lib/pscom/libpscom.la
