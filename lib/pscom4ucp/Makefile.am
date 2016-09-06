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

lib_LTLIBRARIES = libpscom4ucp.la

libpscom4ucp_la_SOURCES = pscom_ucp.c pscom_ucp.h psucp.c psucp.h
# noinst_HEADERS = psucp_mregion_cache.c
libpscom4ucp_la_CPPFLAGS = $(AM_CPPFLAGS) $(UCP_CPPFLAGS)
libpscom4ucp_la_LDFLAGS = $(AM_LDFLAGS) $(UCP_LDFLAGS)
libpscom4ucp_la_LIBADD = -lucp $(top_builddir)/lib/pscom/libpscom.la

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
