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

lib_LTLIBRARIES = libpscom4psm.la

libpscom4psm_la_SOURCES = pscom_psm.c pscom_psm.h pspsm.h
libpscom4psm_la_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS)
libpscom4psm_la_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
libpscom4psm_la_LIBADD = -lpsm_infinipath $(top_builddir)/lib/pscom/libpscom.la

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
