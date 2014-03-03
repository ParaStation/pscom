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

AM_LDFLAGS += -avoid-version
AM_CPPFLAGS += -DLIBDIR=\"$(libdir)\"

lib_LTLIBRARIES = libpsport4.la libpsport4switch.la libpsport4std.la

if MELLANOX_ENABLED
  lib_LTLIBRARIES += libpsport4mvapi.la
if OPENIB_ENABLED
    lib_LTLIBRARIES += libpsport4all.la
endif
endif

if OPENIB_ENABLED
  lib_LTLIBRARIES += libpsport4openib.la
if GM_ENABLED
    lib_LTLIBRARIES += libpsport4all.la
endif
endif

if GM_ENABLED
  lib_LTLIBRARIES += libpsport4gm.la
if MELLANOX_ENABLED
    lib_LTLIBRARIES += libpsport4all.la
endif
endif

noinst_HEADERS = list.h psport_types.h psport_priv.h getid.c

libpsport4_la_SOURCES = psport4b.c psport_tcp.c psport_tcp.h		\
	psport_ufd.c psport_ufd.h psport_shm.c psport_shm.h perf.c	\
	perf.h psport_p4s.c psport_p4s.h

libpsport4switch_la_SOURCES = psport4switch.c
libpsport4switch_la_LIBADD = -ldl

libpsport4std_la_SOURCES = psport4std.c

# initial values for the psport4all lib. specific options are added
# below.
libpsport4all_la_SOURCES = $(libpsport4_la_SOURCES)
libpsport4all_la_CPPFLAGS = $(AM_CPPFLAGS)
libpsport4all_la_LDFLAGS = $(AM_LDFLAGS)
libpsport4all_la_LIBADD =

# -- mellanox -- 

libpsport4mvapi_la_SOURCES = $(libpsport4_la_SOURCES)	\
	mellanox/psport_mvapi.c mellanox/psport_mvapi.h
libpsport4mvapi_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/mellanox	\
	$(MELLANOX_CPPFLAGS) -DENABLE_MVAPI -D__LINUX__			\
	-DMT_LITTLE_ENDIAN -pthread
libpsport4mvapi_la_LDFLAGS = $(AM_LDFLAGS) $(MELLANOX_LDFLAGS)	\
	-pthread
libpsport4mvapi_la_LIBADD = -lvapi -lmtl_common -lmosal -lmpga

if MELLANOX_ENABLED
  libpsport4all_la_SOURCES += mellanox/psport_mvapi.c	\
	mellanox/psport_mvapi.h
  libpsport4all_la_CPPFLAGS += -I$(srcdir)/mellanox	\
	$(MELLANOX_CPPFLAGS) -DENABLE_MVAPI -D__LINUX__	\
	-DMT_LITTLE_ENDIAN -pthread
  libpsport4all_la_LDFLAGS += $(MELLANOX_LDFLAGS) -pthread
  libpsport4all_la_LIBADD += -lvapi -lmtl_common -lmosal -lmpga
endif

# -- openib --

libpsport4openib_la_SOURCES = $(libpsport4_la_SOURCES)	\
	openib/psport_openib.c openib/psport_openib.h
libpsport4openib_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/openib	\
	$(OPENIB_CPPFLAGS) -DENABLE_OPENIB -I$(top_srcdir)/lib/pscom	\
	-I$(top_srcdir)/lib/pscom/openib
libpsport4openib_la_LDFLAGS = $(AM_LDFLAGS) $(OPENIB_LDFLAGS)
libpsport4openib_la_LIBADD = -libverbs

if OPENIB_ENABLED
  libpsport4all_la_SOURCES += openib/psport_openib.c	\
	openib/psport_openib.h
  libpsport4all_la_CPPFLAGS += -I$(srcdir)/openib $(OPENIB_CPPFLAGS)	\
	-DENABLE_OPENIB -I$(top_srcdir)/lib/pscom			\
	-I$(top_srcdir)/lib/pscom/openib
  libpsport4all_la_LDFLAGS += $(OPENIB_LDFLAGS)
  libpsport4all_la_LIBADD += -libverbs
endif

# -- gm --

libpsport4gm_la_SOURCES = $(libpsport4_la_SOURCES) gm/psport_gm.c	\
	gm/psport_gm.h
libpsport4gm_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/gm	\
	$(GM_CPPFLAGS) -DENABLE_GM
libpsport4gm_la_LDFLAGS = $(AM_LDFLAGS) $(GM_LDFLAGS)
libpsport4gm_la_LIBADD = -lgm

if GM_ENABLED
  libpsport4all_la_SOURCES += gm/psport_gm.c gm/psport_gm.h
  libpsport4all_la_CPPFLAGS += -I$(srcdir)/gm $(GM_CPPFLAGS)	\
	-DENABLE_GM
  libpsport4all_la_LDFLAGS += $(GM_LDFLAGS)
  libpsport4all_la_LIBADD += -lgm
endif
