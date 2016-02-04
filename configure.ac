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

AC_PREREQ([2.68])

AC_INIT([ParaStation Communication Library],[5],
  [support@par-tec.com],[pscom],[http://par-tec.com/])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([scripts])
AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT([/usr])

AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability silent-rules subdir-objects no-define])
AM_MAINTAINER_MODE
AM_SILENT_RULES([yes])

# enable runpath. this has to be set before LT_INIT.
LDFLAGS="$LDFLAGS -Wl,--enable-new-dtags"

# autoconf's CFLAGS default is "-O2 -g", this would override -O3 from
# AM_CFLAGS (see below), so change the default to "-g" only
CFLAGS="${CFLAGS-"-g"}"

AC_PROG_CC
AM_PROG_CC_C_O

LT_INIT([dlopen disable-static])

# -- ParaStation Management --

# fixme: brute force current standard search path
PSMGMT_CPPFLAGS="${PSMGMT_CPPFLAGS-"-I/opt/parastation/include"}"
PSMGMT_LDFLAGS="${PSMGMT_LDFLAGS-"-L/opt/parastation/lib64"}"

AC_ARG_ENABLE([psmgmt],[AS_HELP_STRING([--disable-psmgmt],
	      [disable ParaStation Management support])])
AS_IF([test "x$enable_psmgmt" != xno],
      [AX_CHECK_LIBRARY([PSMGMT], [psi.h], [psi],
      [have_psmgmt=yes], [have_psmgmt=no])])
AS_IF([test "x$have_psmgmt" = xno -a "x$enable_psmgmt" = xyes],
      [AC_MSG_ERROR([psmgmt support requested but not found])])
AM_CONDITIONAL([PSMGMT_ENABLED],
	       [test "x$enable_psmgmt" != xno -a "x$have_psmgmt" = xyes])

# -- QLogic Infinipath --

AC_ARG_ENABLE([psm],[AS_HELP_STRING([--disable-psm],
	      [disable QLogic infinipath support])])
AS_IF([test "x$enable_psm" != xno],
      [AX_CHECK_LIBRARY([PSM], [psm.h], [psm_infinipath],
      [have_psm=yes], [have_psm=no])])
AS_IF([test "x$have_psm" = xno -a "x$enable_psm" = xyes],
      [AC_MSG_ERROR([infinipath support requested but not found])])
AM_CONDITIONAL([PSM_ENABLED],
	       [test "x$enable_psm" != xno -a "x$have_psm" = xyes])

# -- Myrinet GM --

AC_ARG_ENABLE([gm],[AS_HELP_STRING([--disable-gm],
	      [disable Myrinet support])])
AS_IF([test "x$enable_gm" != xno],
      [AX_CHECK_LIBRARY([GM], [gm.h], [gm],
      [have_gm=yes], [have_gm=no])])
AS_IF([test "x$have_gm" = xno -a "x$enable_gm" = xyes],
      [AC_MSG_ERROR([gm support requested but not found])])
AM_CONDITIONAL([GM_ENABLED],
	       [test "x$enable_gm" != xno -a "x$have_gm" = xyes])

# -- Mellanox --

AC_ARG_ENABLE([mellanox],[AS_HELP_STRING([--disable-mellanox],
	      [disable Mellanox support])])
AS_IF([test "x$enable_mellanox" != xno],
      [AX_CHECK_LIBRARY([MELLANOX], [evapi.h], [vapi],
      [have_mellanox=yes], [have_mellanox=no])])
AS_IF([test "x$have_mellanox" = xno -a "x$enable_mellanox" = xyes],
      [AC_MSG_ERROR([mellanox support requested but not found])])
AM_CONDITIONAL([MELLANOX_ENABLED],
	       [test "x$enable_mellanox" != xno -a "x$have_mellanox" = xyes])

# -- OpenIB --

AC_ARG_ENABLE([openib],[AS_HELP_STRING([--disable-openib],
	      [disable Infiniband OFED with RC support])])
AS_IF([test "x$enable_openib" != xno],
      [AX_CHECK_LIBRARY([OPENIB], [infiniband/verbs.h], [ibverbs],
      [have_openib=yes], [have_openib=no])])
AS_IF([test "x$have_openib" = xno -a "x$enable_openib" = xyes],
      [AC_MSG_ERROR([openib support requested but not found])])
AM_CONDITIONAL([OPENIB_ENABLED],
	       [test "x$enable_openib" != xno -a "x$have_openib" = xyes])

# -- OFED --

AC_ARG_ENABLE([ofed],[AS_HELP_STRING([--disable-ofed],
	      [disable Infiniband OFED with UD support])])
AS_IF([test "x$have_openib" = xno -a "x$enable_ofed" = xyes],
      [AC_MSG_ERROR([ofed support requested but openib not found])])
AM_CONDITIONAL([OFED_ENABLED],
	       [test "x$enable_ofed" != xno -a "x$have_openib" = xyes])

# -- DAPL --

AC_ARG_ENABLE([dapl],[AS_HELP_STRING([--disable-dapl],
	      [disable DAPL support])])
AS_IF([test "x$enable_dapl" != xno],
      [AX_CHECK_LIBRARY([DAPL], [dat/udat.h], [dat],
      [have_dapl=yes], [have_dapl=no])])
AS_IF([test "x$have_dapl" = xno -a "x$enable_dapl" = xyes],
      [AC_MSG_ERROR([dapl support requested but not found])])
AM_CONDITIONAL([DAPL_ENABLED],
	       [test "x$enable_dapl" != xno -a "x$have_dapl" = xyes])

# -- ELAN --

AC_ARG_ENABLE([elan],[AS_HELP_STRING([--disable-elan],
	      [disable ELAN support])])
AS_IF([test "x$enable_elan" != xno],
      [AX_CHECK_LIBRARY([ELAN], [elan/elan.h], [elan],
      [have_elan=yes], [have_elan=no])])
AS_IF([test "x$have_elan" = xno -a "x$enable_elan" = xyes],
      [AC_MSG_ERROR([elan support requested but not found])])
AM_CONDITIONAL([ELAN_ENABLED],
	       [test "x$enable_elan" != xno -a "x$have_elan" = xyes])

# -- EXTOLL --

# fixme: brute force current standard search path
EXTOLL_CPPFLAGS="${EXTOLL_CPPFLAGS-"-I/extoll2/include"}"
EXTOLL_LDFLAGS="${EXTOLL_LDFLAGS-"-L/extoll2/lib"}"

AC_ARG_ENABLE([extoll],[AS_HELP_STRING([--disable-extoll],
	      [disable EXTOLL support])])
AS_IF([test "x$enable_extoll" != xno],
      [AX_CHECK_LIBRARY([EXTOLL], [rma2.h], [rma2],
      [have_extoll=yes], [have_extoll=no])])
AS_IF([test "x$have_extoll" = xno -a "x$enable_extoll" = xyes],
      [AC_MSG_ERROR([extoll support requested but not found])])
AM_CONDITIONAL([EXTOLL_ENABLED],
	       [test "x$enable_extoll" != xno -a "x$have_extoll" = xyes])

# -- MXM --

# fixme: brute force current standard search path
MXM_CPPFLAGS="${MXM_CPPFLAGS-"-I/opt/mellanox/mxm/include"}"
MXM_LDFLAGS="${MXM_LDFLAGS-"-L/opt/mellanox/mxm/lib"}"

AC_ARG_ENABLE([mxm],[AS_HELP_STRING([--disable-mxm],
	      [disable MXM support])])
AS_IF([test "x$enable_mxm" != xno],
      [AX_CHECK_LIBRARY([MXM], [mxm/api/mxm_api.h], [mxm],
      [have_mxm=yes], [have_mxm=no])])
AS_IF([test "x$have_mxm" = xno -a "x$enable_mxm" = xyes],
      [AC_MSG_ERROR([mxm support requested but not found])])
AM_CONDITIONAL([MXM_ENABLED],
	       [test "x$enable_mxm" != xno -a "x$have_mxm" = xyes])

AX_CHECK_COMPILE_FLAG([-O3],
  [AM_CFLAGS="$AM_CFLAGS -O3"])

AX_CHECK_COMPILE_FLAG([-Wall -Wextra -Wno-unused -Wno-unused-parameter],
  [AM_CFLAGS="$AM_CFLAGS -Wall -Wextra -Wno-unused -Wno-unused-parameter"])

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(bin/Makefile)
AC_CONFIG_FILES(bin/examples/Makefile)
AC_CONFIG_FILES(bin/simul_p4sock/Makefile)
AC_CONFIG_FILES(doc/Makefile)
AC_CONFIG_FILES(include/Makefile)
AC_CONFIG_FILES(lib/Makefile)
AC_CONFIG_FILES(lib/p4tcp/Makefile)
AC_CONFIG_FILES(lib/pscom/Makefile)
AC_CONFIG_FILES(lib/pscom4dapl/Makefile)
AC_CONFIG_FILES(lib/pscom4elan/Makefile)
AC_CONFIG_FILES(lib/pscom4extoll/Makefile)
AC_CONFIG_FILES(lib/pscom4velo/Makefile)
AC_CONFIG_FILES(lib/pscom4mxm/Makefile)
AC_CONFIG_FILES(lib/pscom4gm/Makefile)
AC_CONFIG_FILES(lib/pscom4ofed/Makefile)
AC_CONFIG_FILES(lib/pscom4openib/Makefile)
AC_CONFIG_FILES(lib/pscom4psm/Makefile)
AC_CONFIG_FILES(lib/psmalloc/Makefile)
AC_CONFIG_FILES(lib/psport4/Makefile)
AC_CONFIG_FILES(scripts/Makefile)
AC_CONFIG_LINKS(dist/Makefile:dist/Makefile)


AC_OUTPUT

AC_MSG_NOTICE([=====================])
AM_COND_IF([PSMGMT_ENABLED],
  [AC_MSG_NOTICE([PSMGMT_ENABLED:   yes])],
  [AC_MSG_NOTICE([PSMGMT_ENABLED:   no])])
AM_COND_IF([PSM_ENABLED],
  [AC_MSG_NOTICE([PSM_ENABLED:      yes])],
  [AC_MSG_NOTICE([PSM_ENABLED:      no])])
AM_COND_IF([GM_ENABLED],
  [AC_MSG_NOTICE([GM_ENABLED:       yes])],
  [AC_MSG_NOTICE([GM_ENABLED:       no])])
AM_COND_IF([MELLANOX_ENABLED],
  [AC_MSG_NOTICE([MELLANOX_ENABLED: yes])],
  [AC_MSG_NOTICE([MELLANOX_ENABLED: no])])
AM_COND_IF([OPENIB_ENABLED],
  [AC_MSG_NOTICE([OPENIB_ENABLED:   yes])],
  [AC_MSG_NOTICE([OPENIB_ENABLED:   no])])
AM_COND_IF([OFED_ENABLED],
  [AC_MSG_NOTICE([OFED_ENABLED:     yes])],
  [AC_MSG_NOTICE([OFED_ENABLED:     no])])
AM_COND_IF([DAPL_ENABLED],
  [AC_MSG_NOTICE([DAPL_ENABLED:     yes])],
  [AC_MSG_NOTICE([DAPL_ENABLED:     no])])
AM_COND_IF([ELAN_ENABLED],
  [AC_MSG_NOTICE([ELAN_ENABLED:     yes])],
  [AC_MSG_NOTICE([ELAN_ENABLED:     no])])
AM_COND_IF([EXTOLL_ENABLED],
  [AC_MSG_NOTICE([EXTOLL_ENABLED:   yes])],
  [AC_MSG_NOTICE([EXTOLL_ENABLED:   no])])
AM_COND_IF([MXM_ENABLED],
  [AC_MSG_NOTICE([MXM_ENABLED:      yes])],
  [AC_MSG_NOTICE([MXM_ENABLED:      no])])
AC_MSG_NOTICE([=====================])

# Local Variables:
#  compile-command: "autoreconf -vif"
# End:
