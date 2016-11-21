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

# -- file lists

SUBDIRS = simul_p4sock examples

noinst_PROGRAMS = p4logd porttest psock_test pscom_test		\
	   pscom_ondemand pscom_bcast_test pscom_request_create	\
	   pscom_bcast_pp port_pp pscom_maxcon \
	   pscom_test_fault

check_PROGRAMS = list_test

TESTS = list_test

bin_PROGRAMS = pscom_pp p4stat pspipe p4tcp psport4_pp psock_pp

noinst_HEADERS = dump.c psport_util.h

EXTRA_DIST = gm/gm_sr.c gm/gm_test.c

bin_SCRIPTS = pscom_debug
EXTRA_DIST += pscom_debug.sh
dist_config_DATA = pscom.gdb

CLEANFILES = $(bin_SCRIPTS) list_test.ok

if MELLANOX_ENABLED
  noinst_PROGRAMS += ps4_ib ps4_ib_pp ps4_ib_pp_rdma psport4mvapi_pp
endif

if GM_ENABLED
  noinst_PROGRAMS += gm_pp
endif

if OPENIB_ENABLED
  noinst_PROGRAMS += openib_pp openib_ud_pp
endif

if UCP_ENABLED
  noinst_PROGRAMS += ucp_pp
endif

if PSM1_ENABLED
  noinst_PROGRAMS += psm_pp
endif

if PSM2_ENABLED
  noinst_PROGRAMS += psm2_pp pscom4psm_pp
endif

bin_PROGRAMS += test_nodes

if PSMGMT_ENABLED
  bin_PROGRAMS += pscp
endif

if DAPL_ENABLED
  noinst_PROGRAMS += dapl_pp dapl_pp_lowlevel
endif

if ELAN_ENABLED
# noinst_PROGRAMS += elan_pp
  noinst_PROGRAMS += elan_pp_lowlevel
endif

if EXTOLL_ENABLED
  noinst_PROGRAMS += extoll_pp_lowlevel extoll_pp_velo extoll_one_message
endif

if MXM_ENABLED
  noinst_PROGRAMS += mxm_pp
endif

# -- /file lists

libpsport4 = $(top_builddir)/lib/psport4/libpsport4std.la
libpscom = $(top_builddir)/lib/pscom/libpscom.la $(top_builddir)/lib/psmalloc/libpsmalloc.la

# -- psport --

p4stat_SOURCES = p4stat.c
p4stat_LDADD = -lpopt

p4tcp_SOURCES = p4tcp.c
p4tcp_LDADD = -lpopt

p4logd_SOURCES = p4logd.c
p4logd_LDADD = -lpopt

porttest_SOURCES = porttest.c
porttest_LDADD = $(libpsport4) -lpopt

psock_pp_SOURCES = psock_pp.c
psock_pp_LDADD = -lpopt

psock_test_SOURCES = psock_test.c
psock_test_LDADD = -lpopt

psport4_pp_SOURCES = psport4_pp.c
psport4_pp_LDADD = $(libpsport4) -lpopt

pspipe_SOURCES = pspipe.c psport_util.c
pspipe_LDADD = $(libpsport4) -lpopt

port_pp_SOURCES = port_pp.c
port_pp_LDADD = -lpopt

# -- pscom --

pscom_test_SOURCES = pscom_test.c
pscom_test_LDADD = $(libpscom) -lpopt

list_test_SOURCES = list_test.c

pscom_ondemand_SOURCES = pscom_ondemand.c
pscom_ondemand_LDADD = $(libpscom) -lpopt

pscom_pp_SOURCES = pscom_pp.c
pscom_pp_LDADD = $(libpscom) -lpopt

pscom_bcast_test_SOURCES = pscom_bcast_test.c
pscom_bcast_test_LDADD = $(libpscom) -lpopt

pscom_request_create_SOURCES = pscom_request_create.c
pscom_request_create_LDADD = $(libpscom) -lpopt

pscom_bcast_pp_SOURCES = pscom_bcast_pp.c
pscom_bcast_pp_LDADD = $(libpscom) -lpopt

pscom_maxcon_SOURCES = pscom_maxcon.c
pscom_maxcon_LDADD = $(libpscom)

pscom_test_fault_SOURCES = pscom_test_fault.c
pscom_test_fault_LDADD = $(libpscom) -lpopt

# -- mellanox --

libpsport4mvapi = $(top_builddir)/lib/psport4/libpsport4mvapi.la
cppflags_mellanox = $(AM_CPPFLAGS) $(MELLANOX_CPPFLAGS) -D__LINUX__	\
	-DMT_LITTLE_ENDIAN -pthread
ldflags_mellanox = $(AM_LDFLAGS) $(MELLANOX_LDFLAGS) -pthread
ldadd_mellanox = -lvapi -lmtl_common -lmosal -lmpga

ps4_ib_SOURCES = mellanox/ps4_ib.c
ps4_ib_CPPFLAGS = $(cppflags_mellanox)
ps4_ib_LDFLAGS = $(ldflags_mellanox)
ps4_ib_LDADD = $(ldadd_mellanox)

ps4_ib_pp_SOURCES = mellanox/ps4_ib_pp.c
ps4_ib_pp_CPPFLAGS = $(cppflags_mellanox)
ps4_ib_pp_LDFLAGS = $(ldflags_mellanox)
ps4_ib_pp_LDADD = $(ldadd_mellanox) -lpopt

ps4_ib_pp_rdma_SOURCES = mellanox/ps4_ib_pp_rdma.c
ps4_ib_pp_rdma_CPPFLAGS = $(cppflags_mellanox)
ps4_ib_pp_rdma_LDFLAGS = $(ldflags_mellanox)
ps4_ib_pp_rdma_LDADD = $(ldadd_mellanox) -lpopt

psport4mvapi_pp_SOURCES = psport4_pp.c
psport4mvapi_pp_CPPFLAGS = $(cppflags_mellanox)
psport4mvapi_pp_LDFLAGS = $(ldflags_mellanox)
psport4mvapi_pp_LDADD = $(libpsport4mvapi) $(ldadd_mellanox) -lpopt

# -- gm --

gm_pp_SOURCES = gm/gm_pp.c
gm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(GM_CPPFLAGS)
gm_pp_LDFLAGS = $(AM_LDFLAGS) $(GM_LDFLAGS)
gm_pp_LDADD = -lgm -lpopt

# -- openib --

cppflags_openib = $(AM_CPPFLAGS) $(OPENIB_CPPFLAGS)		\
	-I$(top_srcdir)/lib/pscom 				\
	-I$(top_srcdir)/lib/pscom4openib
ldflags_openib = $(AM_LDFLAGS) $(OPENIB_LDFLAGS)
ldadd_openib = $(top_builddir)/lib/pscom/libpscom_env.la	\
	$(top_builddir)/lib/pscom/libpslib.la			\
	$(top_builddir)/lib/pscom/libpscom_dprint.la -libverbs	\
	-lpopt

openib_pp_SOURCES = openib/openib_pp.c
openib_pp_CPPFLAGS = $(cppflags_openib)
openib_pp_LDFLAGS = $(ldflags_openib) 
openib_pp_LDADD = $(ldadd_openib)

openib_ud_pp_SOURCES = openib/openib_ud_pp.c
openib_ud_pp_CPPFLAGS = $(cppflags_openib)
openib_ud_pp_LDFLAGS = $(ldflags_openib) 
openib_ud_pp_LDADD = $(ldadd_openib)

# -- ucp --

cppflags_ucp = $(AM_CPPFLAGS) $(UCP_CPPFLAGS)			\
	-I$(top_srcdir)/lib/pscom 				\
	-I$(top_srcdir)/lib/pscom4ucp
ldflags_ucp = $(AM_LDFLAGS) $(UCP_LDFLAGS)
ldadd_ucp = -lpopt -lucp

ucp_pp_SOURCES = ucp/ucp_pp.c
ucp_pp_CPPFLAGS = $(cppflags_ucp)
ucp_pp_LDFLAGS = $(ldflags_ucp)
ucp_pp_LDADD = $(ldadd_ucp)

# -- psm --
if PSM1_ENABLED
PSM_CPPFLAGS_EXTRA=-DPSM1
else
PSM_CPPFLAGS_EXTRA=
endif

psm_pp_SOURCES = psm/psm_pp.c
psm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS)
psm_pp_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
psm_pp_LDADD = -lpsm_infinipath -lpopt

psm2_pp_SOURCES = psm/psm2_pp.c
psm2_pp_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS)
psm2_pp_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
psm2_pp_LDADD = -lpsm2 -lpopt

pscom4psm_pp_SOURCES = psm/pscom4psm_pp.c
pscom4psm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS) $(PSM_CPPFLAGS_EXTRA) \
	-I$(top_srcdir)/lib/pscom4psm \
	-I$(top_srcdir)/lib/pscom
pscom4psm_pp_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
pscom4psm_pp_LDADD = -lpsm2 -lpopt

# -- psmgmt --

test_nodes_SOURCES = test_nodes.c
if PSMGMT_ENABLED
test_nodes_CPPFLAGS = $(AM_CPPFLAGS) $(PSMGMT_CPPFLAGS) -DPSMGMT_ENABLED
test_nodes_LDFLAGS = $(AM_LDFLAGS) $(PSMGMT_LDFLAGS)
test_nodes_LDADD = $(libpscom) -lpse -lpsi  -lpopt
else
test_nodes_CPPFLAGS = $(AM_CPPFLAGS)
test_nodes_LDADD = $(libpscom) -lpopt
endif

pscp_SOURCES = pscp.c  psport_util.c
pscp_CPPFLAGS = $(AM_CPPFLAGS) $(PSMGMT_CPPFLAGS)
pscp_LDFLAGS = $(AM_LDFLAGS) $(PSMGMT_LDFLAGS)
pscp_LDADD = $(libpsport4) -lpse -lpsi -lpopt

# -- dapl --

cppflags_dapl = $(AM_CPPFLAGS) $(DAPL_CPPFLAGS)			\
	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4dapl
ldflags_dapl = $(AM_LDFLAGS) $(DAPL_LDFLAGS)

dapl_pp_SOURCES = dapl/dapl_pp.c
dapl_pp_CPPFLAGS = $(cppflags_dapl)
dapl_pp_LDFLAGS = $(ldflags_dapl)
dapl_pp_LDADD = $(top_builddir)/lib/pscom/libperf.la		\
	$(top_builddir)/lib/pscom4dapl/libpsdapl.la 		\
	-ldat -lpopt

dapl_pp_lowlevel_SOURCES = dapl/dapl_pp_lowlevel.c
dapl_pp_lowlevel_CPPFLAGS = $(cppflags_dapl)
dapl_pp_lowlevel_LDFLAGS = $(ldflags_dapl)
dapl_pp_lowlevel_LDADD = -ldat -lpopt

# -- elan --

elan_pp_lowlevel_SOURCES = elan/elan_pp_lowlevel.c
elan_pp_lowlevel_CPPFLAGS = $(AM_CPPFLAGS) $(ELAN_CPPFLAGS)	\
	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4elan
elan_pp_lowlevel_LDFLAGS = $(AM_LDFLAGS) $(ELAN_LDFLAGS)
elan_pp_lowlevel_LDADD = -lelan -lpopt

# -- extoll -- 

extoll_pp_lowlevel_SOURCES = extoll/extoll_pp_lowlevel.c
extoll_pp_lowlevel_CPPFLAGS = $(AM_CPPFLAGS) $(EXTOLL_CPPFLAGS)
extoll_pp_lowlevel_LDFLAGS = $(AM_LDFLAGS) $(EXTOLL_LDFLAGS)
extoll_pp_lowlevel_LDADD = -lrma2 -lpopt

extoll_pp_velo_SOURCES = extoll/extoll_pp_velo.c
extoll_pp_velo_CPPFLAGS = $(AM_CPPFLAGS) $(EXTOLL_CPPFLAGS)
extoll_pp_velo_LDFLAGS = $(AM_LDFLAGS) $(EXTOLL_LDFLAGS)
extoll_pp_velo_LDADD = -lvelo2 -lpopt

extoll_one_message_SOURCES = extoll/extoll_one_message.c
extoll_one_message_CPPFLAGS = $(AM_CPPFLAGS) $(EXTOLL_CPPFLAGS)
extoll_one_message_LDFLAGS = $(AM_LDFLAGS) $(EXTOLL_LDFLAGS)
extoll_one_message_LDADD = -lrma2 -lpopt

# -- mxm -- 

mxm_pp_SOURCES = mxm/mxm_pp.c
noinst_HEADERS += mxm/mxm_util.c
mxm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(MXM_CPPFLAGS)
mxm_pp_LDFLAGS = $(AM_LDFLAGS) $(MXM_LDFLAGS)
mxm_pp_LDADD = -lmxm -lpopt

# -- mem usage diagnostics --

if OPENIB_ENABLED
  noinst_PROGRAMS += pscom_memusage_openib
endif

if OFED_ENABLED
  noinst_PROGRAMS += pscom_memusage_ofed
endif

if EXTOLL_ENABLED
  noinst_PROGRAMS += pscom_memusage_extoll
endif

if EXTOLL_ENABLED
  noinst_PROGRAMS += pscom_memusage_velo
endif

pscom_memusage_openib_SOURCES = pscom_memusage.c
pscom_memusage_openib_CPPFLAGS = $(AM_CPPFLAGS) -DOPENIB=1	\
	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4openib
pscom_memusage_openib_LDFLAGS = $(AM_LDFLAGS) $(OPENIB_LDFLAGS)
pscom_memusage_openib_LDADD = -libverbs $(libpscom)

pscom_memusage_ofed_SOURCES = pscom_memusage.c
pscom_memusage_ofed_CPPFLAGS = $(AM_CPPFLAGS) -DOFED=1		\
	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4ofed
pscom_memusage_ofed_LDFLAGS = $(AM_LDFLAGS) $(OFED_LDFLAGS)
pscom_memusage_ofed_LDADD = -libverbs

pscom_memusage_extoll_SOURCES = pscom_memusage.c
pscom_memusage_extoll_CPPFLAGS = $(AM_CPPFLAGS) -DEXTOLL=1	\
	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4extoll \
	$(EXTOLL_CPPFLAGS)
pscom_memusage_extoll_LDFLAGS = $(AM_LDFLAGS) $(EXTOLL_LDFLAGS)
pscom_memusage_extoll_LDADD = -lrma2

pscom_memusage_velo_SOURCES = pscom_memusage.c
pscom_memusage_velo_CPPFLAGS = $(AM_CPPFLAGS) -DVELO=1	\
	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4velo \
	$(EXTOLL_CPPFLAGS)
pscom_memusage_velo_LDFLAGS = $(AM_LDFLAGS) $(EXTOLL_LDFLAGS)
pscom_memusage_velo_LDADD = -lrma2 -lvelo2

# -- additional rules --

test: pscom_test
	$(builddir)/pscom_test

# Local Variables:
#  compile-command: "cd .. && automake"
# End:
