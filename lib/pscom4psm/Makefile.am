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

if PSM2_ENABLED
PSM_CPPFLAGS_EXTRA=
else
PSM_CPPFLAGS_EXTRA=-DPSM1
endif

lib_LTLIBRARIES = libpscom4psm.la

libpscom4psm_la_SOURCES = pscom_psm.c pscom_psm.h pspsm.h
libpscom4psm_la_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS) $(PSM_CPPFLAGS_EXTRA)
libpscom4psm_la_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
if PSM2_ENABLED
libpscom4psm_la_LIBADD = -lpsm2 $(top_builddir)/lib/pscom/libpscom.la
else
libpscom4psm_la_LIBADD = -lpsm_infinipath $(top_builddir)/lib/pscom/libpscom.la
endif

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
