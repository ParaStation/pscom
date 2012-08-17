#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_INIT([pscom],[],[hauke@par-tec.com])
AC_CONFIG_SRCDIR([configure.ac])


AC_CONFIG_AUX_DIR(["scripts"])
AC_CANONICAL_TARGET([])

AC_PROG_INSTALL
AC_PROG_RANLIB

path_cleanup()
{
	case $1 in
	[[\\/]]* | ?:[[\\/]]* ) # Absolute path.
      		echo $1 ;;
	*) # Relative path.
		echo `pwd`/$1 ;;
	esac
}

TOP_SRCDIR=`cd \`dirname $0\`;pwd`
TOP_BUILDDIR=`pwd`

AC_SUBST([CONFIGARGS])

case $target_os in
linux|linux-gnu)
	CFLAG_WALL="-W -Wall -Wno-unused-parameter"
	CFLAG_G=-g
	CPPFLAG_MMD=-MMD
	LIB_DIRNAME=lib
	CPPFLAG_MARCH=
	case $target_cpu in
	i386)
		;;
	i486)
		;;
	i586)
		CPPFLAG_MARCH=-march=i586
		;;
	i686)
		CPPFLAG_MARCH=-march=i586
		;;
	ia64)
		;;
	x86_64)
		LIB_DIRNAME=lib64
		;;
	ppc64)
		;;
	powerpc64)
		case $target_vendor in
		redhat)
			LIB_DIRNAME=lib64
			;;
		suse)
			LIB_DIRNAME=lib
			;;
		esac
		;;
	*)
		echo "Warning: Unknown cpu ($target_cpu)"
		;;
	esac
	DEPEXTENSION=.d
	TRU64FILEADD=
	LIBCURSES=ncurses
	;;
osf5.1)
	CFLAG_WALL="-w0  -msg_disable incomparry,unreachcode"
	CFLAG_G=-g3
	CFLAG_COMPAT="-FIcompat_tru64.h"
	CPPFLAG_MMD=-MD
	CPPFLAG_MARCH=
	DEPEXTENSION=.o.d
	TRU64FILEADD=_tru64
	LIBCURSES=curses
#	AC_CONFIG_FILES([kern/OSF1/Makefile])
	;;
*)
	echo "Unknown os ($target_os)"
	exit 1
	;;
esac


#
# Mellanox section
#

AC_SUBST([MELLANOX_HOME])
AC_ARG_WITH([mellanoxhome], [AS_HELP_STRING([--with-mellanoxhome=dir], [home of mellanox (libs and includes)])] ,
[
	MELLANOX_HOME=`path_cleanup $withval`
],[
	MELLANOX_HOME=`path_cleanup /usr/mellanox`
])

AC_SUBST([MELLANOX_INCLUDE_DIR])
AC_ARG_WITH([mellanoxincl], [AS_HELP_STRING([--with-mellanoxincl=dir], [(dir with vapi.h, evapi.h, vapi_common.h)])] ,
[
	MELLANOX_INCLUDE_DIR=`path_cleanup $withval`
],[
	if      test -r "${MELLANOX_HOME}/include/vapi/evapi.h" ; then
	        MELLANOX_INCLUDE_DIR="$MELLANOX_HOME/include/vapi"
	else
	        MELLANOX_INCLUDE_DIR="$MELLANOX_HOME/include"
	fi
])

AC_SUBST([MELLANOX_LIB_DIR])
AC_ARG_WITH([mellanoxlib], [AS_HELP_STRING([--with-mellanoxlib=dir], [(dir with libvapi.so, libmtl_common.so ...)])] ,
[
	MELLANOX_LIB_DIR=`path_cleanup $withval`
],[
	MELLANOX_LIB_DIR="$MELLANOX_HOME/$LIB_DIRNAME"
])


AC_SUBST([MELLANOX_ENABLED])
# default is yes, if MELLANOX_HOME is valid
AC_ARG_ENABLE([mellanox], [AS_HELP_STRING([--enable-mellanox], [(default: auto)])] ,
[
	MELLANOX_ENABLED=$enableval
],[
	echo "checking for Mellanox"
	MELLANOX_ENABLED="yes"

	echo -n "  test ${MELLANOX_INCLUDE_DIR}/evapi.h    "
	if test -r "${MELLANOX_INCLUDE_DIR}/evapi.h" ; then
		echo "found"
	else
		echo "NO"
		MELLANOX_ENABLED="no"
	fi

	echo -n "  test ${MELLANOX_LIB_DIR}/libvapi.so     "
	if test -r "${MELLANOX_LIB_DIR}/libvapi.so" ; then
		echo "found"
	else
		echo "NO"
		MELLANOX_ENABLED="no"
	fi

	if test "${MELLANOX_ENABLED}" = "yes" ; then
		echo "  MELLANOX_ENABLED"
	else
		echo "  mellanox not available - Infiniband with mellanox VAPI is now disabled!"
	fi
])


#
# OpenIB section
#
AC_SUBST([OPENIB_INCLUDE_DIR])
AC_ARG_WITH([openibincl], [AS_HELP_STRING([--with-openibincl=dir], [includes for OpenIB (infiniband/verbs.h)])] ,
[
	OPENIB_INCLUDE_DIR=`path_cleanup $withval`
],[
	OPENIB_INCLUDE_DIR=`path_cleanup /usr/include`
	if test ! -r "${OPENIB_INCLUDE_DIR}/infiniband/verbs.h" ; then
		OPENIB_INCLUDE_DIR=`path_cleanup /usr/local/ofed/include`
		if test ! -r "${OPENIB_INCLUDE_DIR}/infiniband/verbs.h" ; then
			OPENIB_INCLUDE_DIR=`path_cleanup /usr/include`
		fi
	fi

])

AC_SUBST([OPENIB_LIB_DIR])
AC_ARG_WITH([openiblib], [AS_HELP_STRING([--with-openiblib=dir], [libs for OpenIB (libibverbs.so)])] ,
[
	OPENIB_LIB_DIR=`path_cleanup $withval`
],[
	OPENIB_LIB_DIR=`path_cleanup /usr/$LIB_DIRNAME`
	if test ! -r "${OPENIB_LIB_DIR}/libibverbs.so" ; then
	 OPENIB_LIB_DIR=`path_cleanup /usr/local/ofed/$LIB_DIRNAME`
	 if test ! -r "${OPENIB_LIB_DIR}/libibverbs.so" ; then
	  OPENIB_LIB_DIR=`path_cleanup /usr/$LIB_DIRNAME`
	 fi
	fi
])


AC_SUBST([OPENIB_ENABLED])
AC_ARG_ENABLE([openib], [AS_HELP_STRING([--enable-openib], [infiniband OFED stack with RC (default: auto)])] ,
[
	OPENIB_ENABLED=$enableval
],[
	echo "checking for OpenIB"
	OPENIB_ENABLED="yes"

	echo -n "  test ${OPENIB_INCLUDE_DIR}/infiniband/verbs.h  "
	if test -r "${OPENIB_INCLUDE_DIR}/infiniband/verbs.h" ; then
		echo "found"
	else
		echo "NO"
		OPENIB_ENABLED="no"
	fi

	echo -n "  test ${OPENIB_LIB_DIR}/libibverbs.so           "
	if test -r "${OPENIB_LIB_DIR}/libibverbs.so" ; then
		echo "found"
	else
		echo "NO"
		OPENIB_ENABLED="no"
	fi

	if test "${OPENIB_ENABLED}" = "yes" ; then
		echo "  OPENIB_ENABLED"
	else
		echo "  OpenIB not available - Infiniband with OpenIB is now disabled!"
	fi
])

if test "${OPENIB_ENABLED}" = "yes"; then
   AC_CHECK_LIB([ibverbs], [ibv_wc_status_str], [ HAS_ibv_wc_status_str=1 ], [ HAS_ibv_wc_status_str=0 ])
   AC_SUBST([HAS_ibv_wc_status_str])
fi

#
# OFED section (using OPENIB settings)
#

OFED_INCLUDE_DIR="$OPENIB_INCLUDE_DIR"
AC_SUBST([OFED_INCLUDE_DIR])

OFED_LIB_DIR="$OPENIB_LIB_DIR"
AC_SUBST([OFED_LIB_DIR])

AC_SUBST([OFED_ENABLED])
AC_ARG_ENABLE([ofed], [AS_HELP_STRING([--enable-ofed], [infiniband OFED stack with UD (default: auto)])] ,
[
	OFED_ENABLED=$enableval
],[
	echo "checking for OFED (using OPENIB settings)"

	OFED_ENABLED="$OPENIB_ENABLED"

	if test "${OFED_ENABLED}" = "yes" ; then
		echo "  OFED_ENABLED"
	else
		echo "  OFED not available - Infiniband with OFED is now disabled!"
	fi
])

#
# gm (myrinet) section
#

AC_SUBST([GM_HOME])
AC_ARG_WITH([gmhome], [AS_HELP_STRING([--with-gmhome=file], [home of gm(myricom) (libs and includes)])] ,
[
	GM_HOME=`path_cleanup $withval`
],[
	GM_HOME=`path_cleanup $GM_HOME`
])

AC_SUBST([GM_ENABLED])
# default is yes, if GM_HOME is valid
AC_ARG_ENABLE([gm], [AS_HELP_STRING([--enable-gm], [(default: auto)])] ,
[
	GM_ENABLED=$enableval
],[
	echo "checking for gm"

	GM_ENABLED="yes"

	echo -n "  test $GM_HOME/include/gm.h      "
	if test -r "${GM_HOME}/include/gm.h" ; then
		echo "found"
	else
		echo "NO"
		GM_ENABLED="no"
	fi

	if test "${GM_ENABLED}" = "yes" ; then
		echo "  GM_ENABLED"
	else
		echo "  gm not available - GM communication is now disabled!"
	fi
])

#
# Tools with dependencies to psmgmt
#

AC_SUBST([PSMGMT_HOME])
AC_ARG_WITH([psmgmthome], [AS_HELP_STRING([--with-psmgmthome=dir], [home of psmgmt (libs and includes)])] ,
[
	PSMGMT_HOME=`path_cleanup $withval`
],[
	if test -r "/opt/parastation/include/pse.h" ; then
		PSMGMT_HOME="/opt/parastation";
	elif test -r "../mgmt/include/pse.h" ; then
		PSMGMT_HOME=`path_cleanup ../mgmt`
	else
		PSMGMT_HOME="";
	fi
])

AC_SUBST([PSMGMT_ENABLED])
# default is yes, if PSMGMT_HOME is valid
AC_ARG_ENABLE([psmgmt], [AS_HELP_STRING([--enable-psmgmt], [(default: auto)])] ,
[
	PSMGMT_ENABLED=$enableval
],[
	echo "checking for psmgmt"
	PSMGMT_ENABLED="yes"

	echo -n "  test ${PSMGMT_HOME}/include/pse.h    "
	if test -r "${PSMGMT_HOME}/include/pse.h" ; then
		echo "found"
	else
		echo "NO"
		PSMGMT_ENABLED="no"
	fi

	if test "${PSMGMT_ENABLED}" = "yes" ; then
		echo "  PSMGMT_ENABLED"
	else
		echo "psmgmt not available"
		echo "###############################################################"
		echo "WARNING: psmgmt tools are disabled (missing includes)."
		echo "try --with-psmgmthome=../mgmt/dist_mgmt/build/opt/parastation ?"
		echo "###############################################################"
	fi
])

AC_SUBST([PSCOM_ENABLED])
# default is no
AC_ARG_ENABLE([pscom], [  --enable-pscom          (default: yes)] ,
[
	PSCOM_ENABLED=$enableval
],[
	PSCOM_ENABLED="yes"
])


AC_SUBST([CFLAG_WALL])
AC_SUBST([CFLAG_G])
AC_SUBST([CFLAG_COMPAT])
AC_SUBST([CPPFLAG_MMD])
AC_SUBST([CPPFLAG_MARCH])
AC_SUBST([LIB_DIRNAME])
AC_SUBST([DEPEXTENSION])
AC_SUBST([TRU64FILEADD])
AC_SUBST([LIBCURSES])
AC_SUBST([TOP_SRCDIR])
AC_SUBST([TOP_BUILDDIR])



#
# DAPL section
#

AC_SUBST([DAPL_HOME])
AC_ARG_WITH([daplhome], [AS_HELP_STRING([--with-daplhome=dir], [home of DAPL (libs and includes)])] ,
[
	DAPL_HOME=`path_cleanup $withval`
],[
	DAPL_HOME=`path_cleanup /usr`
])

AC_SUBST([DAT_INCLUDE_DIR])
AC_ARG_WITH([datincl], [AS_HELP_STRING([--with-datincl=dir], [(dir with dat/udat.h, default: {daplhome}/include)])] ,
[
	DAT_INCLUDE_DIR=`path_cleanup $withval`
],[
	DAT_INCLUDE_DIR="${DAPL_HOME}/include"
	if test ! -r "${DAT_INCLUDE_DIR}/dat/udat.h"; then
	    DAT_INCLUDE_DIR="${NES_DAPL_HOME}/include"
	    if test ! -r "${DAT_INCLUDE_DIR}/dat/udat.h"; then
		DAT_INCLUDE_DIR="${DAPL_HOME}/include"
	    fi
	fi
	DAT_INCLUDE_DIR=`path_cleanup "${DAT_INCLUDE_DIR}"`
])

AC_SUBST([DAT_LIB_DIR])
AC_ARG_WITH([datlib], [AS_HELP_STRING([--with-datlib=dir], [(dir with libdat.so, default: {daplhome}/${LIB_DIRNAME})])] ,
[
	DAT_LIB_DIR=`path_cleanup $withval`
],[
	DAT_LIB_DIR="${DAPL_HOME}/${LIB_DIRNAME}"
	if test ! -r "${DAT_LIB_DIR}/libdat.so"; then
	    DAT_LIB_DIR="${NES_DAPL_LIB}"
	    if test ! -r "${DAT_LIB_DIR}/libdat.so"; then
		DAT_LIB_DIR="${DAPL_HOME}/${LIB_DIRNAME}"
	    fi
	fi
	DAT_LIB_DIR=`path_cleanup "${DAT_LIB_DIR}"`
])


AC_SUBST([DAPL_ENABLED])
# default is yes, if DAPL_HOME is valid
AC_ARG_ENABLE([dapl], [AS_HELP_STRING([--enable-dapl], [(default: auto)])] ,
[
	DAPL_ENABLED=$enableval
],[
	echo "checking for DAPL"
	DAPL_ENABLED="yes"

	TMP="${DAT_INCLUDE_DIR}/dat/udat.h"
	if test -r "$TMP" ; then
	   	echo "  found $TMP."
	else
		echo "  missing $TMP."
		DAPL_ENABLED="no"
	fi

	TMP="${DAT_LIB_DIR}/libdat.so"
	if test -r "$TMP" ; then
		echo "  found $TMP"
	else
		echo "  missing $TMP."
		DAPL_ENABLED="no"
	fi

	if test "${DAPL_ENABLED}" = "yes" ; then
		echo "  DAPL_ENABLED"
	else
		echo "  DAPL not available. (--with-datincl and --with-datlib?)"
	fi
])

#
# ELAN
#

AC_SUBST([ELAN_INCLUDE_DIR])
AC_ARG_WITH([elanincl], [AS_HELP_STRING([--with-elanincl=dir], [(dir with elan/elan.h, default: /usr/include)])] ,
[
	ELAN_INCLUDE_DIR=`path_cleanup $withval`
],[
	ELAN_INCLUDE_DIR="/usr/include"
])

AC_SUBST([ELAN_ENABLED])
# default is yes, if ${ELAN_INCLUDE_DIR}/elan/elan.h is available
AC_ARG_ENABLE([elan], [AS_HELP_STRING([--enable-elan], [(default: auto)])] ,
[
	ELAN_ENABLED=$enableval
],[
	echo "checking for ELAN"
	ELAN_ENABLED="yes"

	TMP="${ELAN_INCLUDE_DIR}/elan/elan.h"
	if test -r "$TMP" ; then
	   	echo "  found $TMP."
	else
		echo "  missing $TMP."
		ELAN_ENABLED="no"
	fi

	if test "${ELAN_ENABLED}" = "yes" ; then
		echo "  ELAN_ENABLED"
	else
		echo "  ELAN not available. (--with-datincl and --with-datlib?)"
	fi
])

#
# EXTOLL
#

AC_SUBST([EXTOLL_INCLUDE_DIR])
AC_ARG_WITH([extollincl], [AS_HELP_STRING([--with-extollincl=dir], [(dir with rma2.h, default: /usr/include)])] ,
[
	EXTOLL_INCLUDE_DIR=`path_cleanup $withval`
],[
	echo "Searching for extolls rma2.h"
	for TMP in "/extoll2/include" "/usr/include"; do
		if test -r "$TMP/rma2.h" ; then
			echo "  $TMP/rma2.h	yes"
			break;
		else
			echo "  $TMP/rma2.h	no"
		fi
	done
	EXTOLL_INCLUDE_DIR="$TMP"
])

AC_SUBST([EXTOLL_ENABLED])
# default is yes, if ${EXTOLL_INCLUDE_DIR}/rma2.h is available
AC_ARG_ENABLE([extoll], [AS_HELP_STRING([--enable-extoll], [(default: auto)])] ,
[
	EXTOLL_ENABLED=$enableval
],[
	echo "checking for EXTOLL"
	EXTOLL_ENABLED="yes"

	TMP="${EXTOLL_INCLUDE_DIR}/rma2.h"
	if test -r "$TMP" ; then
		echo "  found $TMP."
	else
		echo "  missing $TMP."
		EXTOLL_ENABLED="no"
	fi

	if test "${EXTOLL_ENABLED}" = "yes" ; then
		echo "  EXTOLL_ENABLED"
	else
		echo "  EXTOLL not available. (--with-extollincl?)"
	fi
])


#
# QLogic psm
#

AC_SUBST([PSM_INCLUDE_DIR])
AC_ARG_WITH([psmincl], [AS_HELP_STRING([--with-psmincl=dir], [(dir with psm.h, default: /usr/include)])] ,
[
	PSM_INCLUDE_DIR=`path_cleanup $withval`
],[
	echo "Searching for qlogics psm.h"
	for TMP in "/usr/include"; do
		if test -r "$TMP/psm.h" ; then
			echo "  $TMP/psm.h	yes"
			break;
		else
			echo "  $TMP/psm.h	no"
		fi
	done
	PSM_INCLUDE_DIR="$TMP"
])

AC_SUBST([PSM_ENABLED])
# default is yes, if ${PSM_INCLUDE_DIR}/psm.h is available
AC_ARG_ENABLE([psm], [AS_HELP_STRING([--enable-psm], [(default: auto)])] ,
[
	PSM_ENABLED=$enableval
],[
	echo "checking for PSM"
	PSM_ENABLED="yes"

	TMP="${PSM_INCLUDE_DIR}/psm.h"
	if test -r "$TMP" ; then
		echo "  found $TMP."
	else
		echo "  missing $TMP."
		PSM_ENABLED="no"
	fi

	if test "${PSM_ENABLED}" = "yes" ; then
		echo "  PSM_ENABLED"
	else
		echo "  PSM not available. (--with-psmincl?)"
	fi
])

AC_CONFIG_FILES([Makefile])


   AC_CONFIG_FILES([lib/Makefile])
   AC_CONFIG_FILES([lib/Makefile.staticlib])
   AC_CONFIG_FILES([lib/Makefile.sharedlib])
   AC_CONFIG_FILES([lib/psport4/Makefile])
   AC_CONFIG_FILES([lib/psport4multi/Makefile])
   AC_CONFIG_FILES([lib/psport4switch/Makefile])
   AC_CONFIG_FILES([lib/psport4std/Makefile])
   if test x"$MELLANOX_ENABLED" == x"yes"; then
      AC_CONFIG_FILES([lib/psport4mvapi/Makefile])
   fi
   if test x"$OPENIB_ENABLED" == x"yes"; then
      AC_CONFIG_FILES([lib/psport4openib/Makefile])
   fi
   if test x"$GM_ENABLED" == x"yes"; then
      AC_CONFIG_FILES([lib/psport4gm/Makefile])
      if test x"$MELLANOX_ENABLED" == x"yes" -o
      	 test x"$OPENIB_ENABLED" == x"yes"; then
      	 AC_CONFIG_FILES([lib/psport4all/Makefile])
      fi
   fi
   if test x"$PSCOM_ENABLED" == x"yes"; then
      AC_CONFIG_FILES([lib/pscom/Makefile])
      if test x"$OPENIB_ENABLED" == x"yes"; then
      	 AC_CONFIG_FILES([lib/pscom4openib/Makefile])
      fi
      if test x"$OFED_ENABLED" == x"yes"; then
      	 AC_CONFIG_FILES([lib/pscom4ofed/Makefile])
      fi
      if test x"$GM_ENABLED" == x"yes"; then
      	    AC_CONFIG_FILES([lib/pscom4gm/Makefile])
      fi
      if test x"$DAPL_ENABLED" == x"yes"; then
            AC_CONFIG_FILES([lib/pscom4dapl/Makefile])
      fi
      if test x"$ELAN_ENABLED" == x"yes"; then
      	    AC_CONFIG_FILES([lib/pscom4elan/Makefile])
      fi
      if test x"$PSM_ENABLED" == x"yes"; then
	    AC_CONFIG_FILES([lib/pscom4psm/Makefile])
      fi
      if test x"$EXTOLL_ENABLED" == x"yes"; then
	    AC_CONFIG_FILES([lib/pscom4extoll/Makefile])
      fi
   fi
   AC_CONFIG_FILES([lib/p4tcp/Makefile])
   AC_CONFIG_FILES([bin/Makefile])
   AC_CONFIG_FILES([bin/examples/Makefile])
   AC_CONFIG_FILES([doc/Makefile])
   AC_CONFIG_FILES([scripts/parastation-config])

AC_CONFIG_FILES([dist/Makefile.install])

AC_OUTPUT

cat <<DOK
=========================================
MELLANOX_ENABLED: ${MELLANOX_ENABLED}
OPENIB_ENABLED:	  ${OPENIB_ENABLED}
OFED_ENABLED:	  ${OFED_ENABLED}
GM_ENABLED:	  ${GM_ENABLED}
DAPL_ENABLED:	  ${DAPL_ENABLED}
ELAN_ENABLED:	  ${ELAN_ENABLED}
PSM_ENABLED:	  ${PSM_ENABLED}
EXTOLL_ENABLED:	  ${EXTOLL_ENABLED}
PSMGMT_ENABLED:	  ${PSMGMT_ENABLED}
DOK


chmod +x ${TOP_BUILDDIR}/scripts/parastation-config

#
# Local Variables:
#  compile-command: "autoconf"
# End:
#
#
