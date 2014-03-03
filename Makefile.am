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

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include lib bin doc scripts

EXTRA_DIST = .gitignore lib/bcast
EXTRA_DIST += dist/.gitignore dist/Makefile dist/Makefile.sources	\
         dist/pscom.spec.templ

dist_doc_DATA = LICENSE.QPL ChangeLog

# ---- VERSION.pscom ----
#
nodist_doc_DATA = VERSION.pscom

.PHONY: VERSION.pscom
VERSION.pscom:
	@echo "$(PACKAGE_NAME) $(VC_VERSION) ($(shell LC_ALL=C date))" > $@

CLEANFILES = VERSION.pscom

# ---- VERSION ----
#
dist-hook:
	@echo "$(VC_VERSION)" > $(top_distdir)/VERSION

# ---- proxy to dist/Makefile
#
.PHONY: tar rpm srpm tag version
tar rpm srpm tag version:
	TOP_SRCDIR=$(abs_top_srcdir) $(MAKE) -C dist $@

CLEANFILES += dist/Makefile
