#
# ParaStation
#
# Copyright (C) 2012 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
# Author:       Thomas Moschny <moschny@par-tec.com>
#
include $(top_srcdir)/common.am

LIBPSCOM = $(top_builddir)/lib/pscom/libpscom.la

noinst_PROGRAMS = pscom_dispatch
pscom_dispatch_SOURCES = pscom_dispatch.c
pscom_dispatch_LDADD = $(LIBPSCOM) -lpopt
