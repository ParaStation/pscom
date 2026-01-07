#!/bin/sh
#
# ParaStation
#
# Copyright (C) 2012-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2026 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
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
