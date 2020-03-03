#
# ParaStation
#
# Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
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
	$(top_builddir)/lib/pscom/libpscom_utest.la

pscom_utest_CPPFLAGS = \
	-I./pscom \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/pscom

pscom_utest_LDFLAGS = \
	-Wl,--wrap=memcpy \
	-static \
	-lcmocka

pscom_utest_SOURCES = \
	mocks/pscom_mocks.c \
	mocks/misc_mocks.c \
	pscom_utest.c \
	pscom/test_io.c \
	util/test_utils_con.c

# Mocked functions
pscom_utest_LDFLAGS  += -Wl,--wrap=pscom_unlock

# CUDA-related configuration
if CUDA_ENABLED
pscom_utest_CPPFLAGS += -DPSCOM_CUDA_AWARENESS $(CUDA_CPPFLAGS)
pscom_utest_SOURCES  += pscom/test_cuda.c mocks/cuda_mocks.c
pscom_utest_LDFLAGS  += $(CUDA_LDFLAGS) -lcuda \
						-Wl,--wrap=cuInit \
						-Wl,--wrap=cuDeviceGetCount \
						-Wl,--wrap=cuDeviceGetAttribute \
						-Wl,--wrap=cuGetErrorName \
						-Wl,--wrap=cuPointerSetAttribute \
						-Wl,--wrap=cuPointerGetAttributes \
						-Wl,--wrap=cuMemcpy \
						-Wl,--wrap=cuMemcpyDtoH_v2 \
						-Wl,--wrap=cuMemcpyHtoD_v2
endif #CUDA_ENABLED


utest: pscom_utest
	$(abs_builddir)/pscom_utest

endif #UTEST_ENABLED
