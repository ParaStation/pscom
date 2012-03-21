#!/bin/sh
#
# Script to get some ethernet statistics
#
# Author: Jens Hauke <hauke@par-tec.com>
#
# $Id$
#

case "$1" in
    start)
	;;

    stop)
	;;

    statusheader)
	# No Header
	/bin/echo -n ' '
	;;

    status)
	echo
	ifconfig | grep -e "Link " -e "packets"
	;;

    *)
	echo "Usage: $0 {start|stop|statusheader|status}"
	exit 1
	;;
esac

exit 0
