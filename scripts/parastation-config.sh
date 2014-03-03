#! /bin/sh

PS_LIBDIR=${PS_LIBDIR-@libdir@}
PS_DOCDIR=${PS_DOCDIR-@docdir@}
PS_INCLUDEDIR=${PS_INCLUDEDIR-@includedir@}

usage()
{
    cat <<EOF
Usage: parastation-config [OPTIONS] [LIBRARIES]
Options:
	[--version]
	[--libs]
	[--cflags]
	[--static]	# for static libs

	[--with-mellanox[={DIR|"no"}]]
	[--with-topspin[={DIR|"no"}]]
	[--with-gm[={DIR|"no"}]]
Libraries:
	psport4
	pscom
	psi
	pse
EOF
    exit $1
}

if test $# -eq 0; then
    usage 1 1>&2
fi

lib_all=yes

if test -n "${MTHOME}"; then
    with_mellanox=auto
    mellanox_home=${MTHOME}
elif test -n "${TSHOME}" -o -d "/usr/local/topspin"; then
    # Topspin dont set any variable. Assume topspin configuration
    # when /usr/local/topspin exists. You can disable infiniband
    # detection by setting TSHOME to an nonexisting directory.
    with_mellanox=auto
    mellanox_home=${TSHOME-"/usr/local/topspin"}
else
    with_mellanox=no
fi

if test -n "${GM_HOME}"; then
    with_gm=auto
    gm_home=${GM_HOME}
else
    with_gm=no
fi

with_static=no

while test $# -gt 0; do
    case "$1" in
	-*=*) optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
	*) optarg= ;;
    esac

    case $1 in
	--version)
	    cat /opt/parastation/VERSION* # backwards compatibility
	    cat ${PS_DOCDIR}/VERSION*
	    exit 0
	    ;;
	--cflags)
	    echo_cflags=yes
	    ;;
	--libs)
	    echo_libs=yes
	    ;;
	--static)
	    with_static=yes
	    ;;
	--with-mellanox=*|--with-topspin=*)
	    if test "$optarg" = "no"; then
		with_mellanox=no
	    else
		with_mellanox=yes
		mellanox_home=$optarg
	    fi
	    ;;
	--with-mellanox)
	    mellanox_home=${MTHOME-"/usr/mellanox"}
	    with_mellanox=yes
	    ;;
	--with-topspin)
	    mellanox_home=${TSHOME-"/usr/local/topspin"}
	    with_mellanox=yes
	    ;;
	--with-gm=*)
	    if test "$optarg" = "no"; then
		with_gm=no
	    else
		with_gm=yes
		gm_home=$optarg
	    fi
	    ;;
	--with-gm)
	    gm_home=${GM_HOME-"/opt/gm/"}
	    with_gm=yes
	    ;;
	psport4)
	    lib_psport4=yes
	    lib_all=no
	    ;;
	pscom)
	    lib_pscom=yes
	    lib_all=no
	    ;;
	psi)
	    lib_psi=yes
	    lib_all=no
	    ;;
	pse)
	    lib_pse=yes
	    lib_all=no
	    ;;
	*)
	    usage 1 1>&2
	    ;;
    esac
    shift
done

#
# Mellanox
#

if test "$with_mellanox" = "auto"; then
    # prefere lib64 folders (opteron only?)
    if test -r $mellanox_home/lib64/libvapi.so \
	-a  -r $mellanox_home/lib64/libmtl_common.so \
	-a  -r $mellanox_home/lib64/libmosal.so \
	-a  -r $mellanox_home/lib64/libmpga.so \
	-a  -r ${PS_LIBDIR}/libpsport4mvapi.so ; then
	with_mellanox=yes;
	mellanox_libdir="$mellanox_home/lib64"
    elif test -r $mellanox_home/lib/libvapi.so \
	-a  -r $mellanox_home/lib/libmtl_common.so \
	-a  -r $mellanox_home/lib/libmosal.so \
	-a  -r $mellanox_home/lib/libmpga.so \
	-a  -r ${PS_LIBDIR}/libpsport4mvapi.so ; then
	with_mellanox=yes;
    else
	with_mellanox=no;
    fi
fi

mellanox_libdir=${mellanox_libdir-"$mellanox_home/lib"}

#
# GM
#

if test "$with_gm" = "auto"; then
    # prefere lib64 folders (opteron only?)
    if test -r $gm_home/lib64/libgm.so \
	-a  -r ${PS_LIBDIR}/libpsport4gm.so ; then
	with_gm=yes;
	gm_libdir="$gm_home/lib64"
    elif test -r $gm_home/lib/libgm.so \
	-a  -r ${PS_LIBDIR}/libpsport4gm.so ; then
	with_gm=yes;
    else
	with_gm=no;
    fi
fi

gm_libdir=${gm_libdir-"$gm_home/lib"}

#
# general
#

if test "$lib_all" = "yes"; then
    lib_psport4=yes
    lib_psi=yes
    lib_pse=yes
fi

if test "$echo_cflags" = "yes"; then
    cflags="-I${PS_INCLUDEDIR}"

    if test "$with_mellanox" = "yes"; then
	cflags="$cflags -DENABLE_MVAPI"
    elif test "$with_gm" = "yes"; then
	cflags="$cflags -DENABLE_GM"
    else
	cflags="$cflags"
    fi

    echo $cflags
fi

if test "$echo_libs" = "yes"; then
    libs=""
    if test "$with_static" = "yes"; then
	if test "$lib_psport4" = "yes"; then
	    if test "$with_mellanox" = "yes"; then
		if test "$with_gm" = "yes"; then
		    libs="$libs -lpsport4all"
		    libs="$libs -L$gm_libdir -lgm"
		else
		    libs="$libs -lpsport4mvapi"
		fi
		libs="$libs -L$mellanox_libdir -lvapi -lmtl_common -lmosal -lmpga"
		libs="$libs -lpthread"
	    elif test "$with_gm" = "yes"; then
		libs="$libs -lpsport4gm"
		libs="$libs -L$gm_libdir -lgm"
	    else
		libs="$libs -lpsport4"
	    fi
	fi
    else
	libs="-Wl,-rpath,${PS_LIBDIR} -Wl,--enable-new-dtags $libs"
	# using psport4std instead of psport4, because mpich should not use the static version.
	if test "$lib_psport4" = "yes"; then
	    libs="$libs -lpsport4std"
	fi
    fi

    if test "$lib_pscom" = "yes"; then
	libs="$libs -lpscom"
    fi
    if test "$lib_pse" = "yes"; then
	libs="$libs -lpse"
    fi
    if test "$lib_psi" = "yes"; then
	libs="$libs -lpsi"
    fi

    libs="-L${PS_LIBDIR} $libs"

    echo $libs
fi
