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

AM_CPPFLAGS += -DLIBDIR=\"$(libdir)\"
AM_CPPFLAGS += -I$(top_builddir)/include

lib_LTLIBRARIES = libpscom.la

noinst_LTLIBRARIES = libpslib.la libpscom_env.la libpscom_dprint.la	\
	libperf.la

libpscom_la_SOURCES = pscom.c pscom_con.c pscom_debug.c			\
	pscom_dprint.c pscom_env.c pscom_group.c pscom_group_bcast.c	\
	pscom_io.c pscom_listener.c pscom_ondemand.c pscom_p4s.c	\
	pscom_plugin.c pscom_queues.c pscom_req.c pscom_shm.c		\
	pscom_sock.c pscom_str_util.c pscom_tcp.c pscom_ufd.c pslib.c	\
	psshmalloc.c pscom_precon.c pscom_async.c pscom_suspend.c pscom_cuda.c

noinst_HEADERS = getid.c list.h pscom_con.h pscom_debug.h pscom_env.h	\
	pscom_gm.h pscom_group.h pscom_io.h pscom_p4s.h			\
	pscom_plugin.h pscom_priv.h pscom_queues.h pscom_req.h		\
	pscom_shm.h pscom_sock.h pscom_str_util.h pscom_tcp.h		\
	pscom_types.h pscom_ufd.h pscom_util.h psshmalloc.h pscom_cuda.h

libpscom_la_LDFLAGS = -version-info 2:0:0
libpscom_la_LIBADD = -ldl
libpscom_la_CFLAGS = $(AM_CFLAGS) -pthread

if CUDA_ENABLED
libpscom_la_LIBADD += $(CUDA_LDFLAGS) -lcuda
endif

# intermediate libs needed elsewhere, in bin
libpslib_la_SOURCES = pslib.c pslib.h
libpslib_la_LIBADD = -ldl
libpscom_env_la_SOURCES = pscom_env.c pscom_env.h
libpscom_dprint_la_SOURCES = pscom_dprint.c
libperf_la_SOURCES = perf.c perf.h

if CUDA_ENABLED
libpslib_la_LIBADD += $(CUDA_LDFLAGS) -lcuda
endif


install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(RM) $(lib_LTLIBRARIES)
