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

lib_LTLIBRARIES = libpscom4ofed.la

libpscom4ofed_la_SOURCES = pscom_ofed.c pscom_ofed.h psofed.c psofed.h
libpscom4ofed_la_CPPFLAGS = $(AM_CPPFLAGS) $(OFED_CPPFLAGS)
libpscom4ofed_la_LDFLAGS = $(AM_LDFLAGS) $(OFED_LDFLAGS)
libpscom4ofed_la_LIBADD = -libverbs
