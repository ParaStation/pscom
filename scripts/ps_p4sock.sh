#!/bin/sh
#
# ParaStation
#
# Copyright (C) 2012-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2023 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#
# p4sock Driver for Parastation4
#
# Script to load/unload the module
#

#defaults
PS_BINDIR=${PS_BINDIR-@bindir@}
PSP4STAT=${PS_BINDIR}/p4stat
PSP4TCP=${PS_BINDIR}/p4tcp

case "$1" in
    start)
	modprobe p4sock || { echo "psmodules_install called? "; exit 1; }

        # Try "glue Modules" ignore errors
	lsmod |grep -q -e "^e1000" && modprobe e1000_glue	> /dev/null 2>&1
	lsmod |grep -q -e "^bcm5700" && modprobe bcm5700_glue	> /dev/null 2>&1

	# Configure p4tcp
	if [ "${PS_TCP}" != "" ] ; then
	    modprobe p4tcp
	    echo ${PS_TCP}| tr " " "\n"| tr "-" " " | grep -v -e '^$' | while read from to ; do
		${PSP4TCP} -a $from $to
	    done
	fi
	;;

    stop)
	# Delete p4tcp config
	${PSP4TCP} -d 0.0.0.0 255.255.255.255	> /dev/null 2>&1
	rmmod p4tcp		> /dev/null 2>&1

	rmmod e1000_glue	> /dev/null 2>&1
	rmmod bcm5700_glue	> /dev/null 2>&1
	rmmod p4sock
	;;

    statusheader)
	echo
	${PSP4STAT} -n | head -1
	;;

    status)
	echo
	${PSP4STAT} -n | tail -n +2
	;;

    *)
	echo "Usage: $0 {start|stop|statusheader|status}"
	exit 1
	;;
esac

exit 0
