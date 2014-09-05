#
# ParaStation
#
# Copyright (C) 2012,2014 ParTec Cluster Competence Center GmbH, Munich
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

lib_LTLIBRARIES = libpscom4mxm.la

libpscom4mxm_la_SOURCES = pscom_mxm.c pscom_mxm.h psmxm.c psmxm.h
libpscom4mxm_la_CPPFLAGS = $(AM_CPPFLAGS) $(MXM_CPPFLAGS)
libpscom4mxm_la_LDFLAGS = $(AM_LDFLAGS) $(MXM_LDFLAGS)
libpscom4mxm_la_LIBADD = -lmxm $(top_builddir)/lib/pscom/libpscom.la

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
