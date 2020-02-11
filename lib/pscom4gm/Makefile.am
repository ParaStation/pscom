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

lib_LTLIBRARIES = libpscom4gm.la

libpscom4gm_la_SOURCES = pscom_gm.c psgm.c psgm.h
libpscom4gm_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden -flto
libpscom4gm_la_CPPFLAGS = $(AM_CPPFLAGS) $(GM_CPPFLAGS)
libpscom4gm_la_LDFLAGS = $(AM_LDFLAGS) $(GM_LDFLAGS)
libpscom4gm_la_LIBADD = -lgm $(top_builddir)/lib/pscom/libpscom.la

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
