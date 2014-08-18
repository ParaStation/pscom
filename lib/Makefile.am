#
# ParaStation
#
# Copyright (C) 2012 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
# Author:       Jens Hauke <hauke@par-tec.com>
#

include $(top_srcdir)/common.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS =
SUBDIRS += pscom
SUBDIRS += psmalloc

# - dapl -
if DAPL_ENABLED
    SUBDIRS += pscom4dapl
endif

# -- elan --
if ELAN_ENABLED
    SUBDIRS += pscom4elan
endif

# -- extoll --
if EXTOLL_ENABLED
    SUBDIRS += pscom4extoll
    SUBDIRS += pscom4velo
endif

# - gm -
if GM_ENABLED
    SUBDIRS += pscom4gm
endif

# -- ofed --
if OFED_ENABLED
    SUBDIRS += pscom4ofed
endif

# -- openib --
if OPENIB_ENABLED
    SUBDIRS += pscom4openib
endif

# -- psm --
if PSM_ENABLED
    SUBDIRS += pscom4psm
endif

SUBDIRS += psport4
SUBDIRS += p4tcp
