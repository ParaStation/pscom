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

include_HEADERS = pscom.h
noinst_HEADERS = gm_compat.h p4io.h p4log.h p4sockets.h psockt.h	\
	ps_perf.h

# ---- vc_version.h ----
#
noinst_HEADERS += vc_version.h

.PHONY: vc_version.h

# modify vc_version.h only if $(VC_VERSION) has changed:
vc_version.h:
	@echo "#define VC_VERSION \"$(VC_VERSION)\"" > $@~
	@if cmp -s "$@~" "$@"; then \
		rm $@~; \
	else \
		mv $@~ $@; \
	fi;

CLEANFILES = vc_version.h
