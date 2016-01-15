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

lib_LTLIBRARIES = libpscom4dapl.la

noinst_LTLIBRARIES = libpsdapl.la

libpscom4dapl_la_SOURCES = pscom_dapl.c pscom_dapl.h psdapl.c psdapl.h
noinst_HEADERS = psdapl_rdma.c
libpscom4dapl_la_CPPFLAGS = $(AM_CPPFLAGS) $(DAPL_CPPFLAGS)
libpscom4dapl_la_LDFLAGS = $(AM_LDFLAGS) $(DAPL_LDFLAGS)
libpscom4dapl_la_LIBADD = -ldat $(top_builddir)/lib/pscom/libpscom.la

# intermediate libs needed elsewhere, in bin
libpsdapl_la_SOURCES = psdapl.c psdapl.h

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
