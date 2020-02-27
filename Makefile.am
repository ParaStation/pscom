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

SUBDIRS = include lib bin doc scripts test

EXTRA_DIST = .gitignore lib/bcast
EXTRA_DIST += dist/.gitignore dist/Makefile dist/Makefile.sources	\
         dist/pscom.spec.templ

dist_doc_DATA = LICENSE.QPL ChangeLog

# ---- Target for unit testing ----
.PHONY: utest
if UTEST_ENABLED
utest: all
	@make -C test utest
endif


# ---- Target for code coverage analysis ----
.PHONY: coverage
if COVERAGE_ENABLED
TEST_NAME=pscom_utest
coverage:
	lcov -t "${TEST_NAME}" -o ${TEST_NAME}.info -c -d $(top_builddir)/test -d $(top_builddir)/lib
	genhtml -o pscom_coverage ${TEST_NAME}.info
endif

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
if CUDA_ENABLED
  AM_CONFIGARGS := $(AM_CONFIGARGS) -with cuda
endif

.PHONY: tar rpm srpm tag version
tar rpm srpm tag version:
	TOP_SRCDIR=$(abs_top_srcdir) $(MAKE) CONFIGARGS="$(AM_CONFIGARGS) $(CONFIGARGS)" -C dist $@
