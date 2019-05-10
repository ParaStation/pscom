#
# ParaStation
#
# Copyright (C) 2019 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
# Author:       Simon Pickartz <pickartz@par-tec.com>
#
include $(top_srcdir)/common.am

if UTEST_ENABLED

ACLOCAL_AMFLAGS = -I m4

noinst_PROGRAMS = pscom_utest

pscom_utest_LDADD = \
	$(top_builddir)/lib/pscom/libpscom.la

pscom_utest_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/pscom

pscom_utest_LDFLAGS= \
	-static \
	-lcmocka \
	-lcuda -lcudart

pscom_utest_SOURCES = \
	pscom_utest.c \
	\
	pscom/test_cuda.c


utest: pscom_utest
	$(abs_builddir)/pscom_utest

endif #UTEST_ENABLED
