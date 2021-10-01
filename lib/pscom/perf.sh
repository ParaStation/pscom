#!/bin/bash
#
# ParaStation
#
# Copyright (C) 2015-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021      ParTec AG, Karlsruhe
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

logfile="${1-log}"

gnuplot <(
    cat <<EOF
set title "$logfile"
#set style data linespoints
set ylabel "Event"
set xrange [0:10]

plot '$logfile' using 2:4:yticlabel(5) notitle

EOF
) -

# Local Variables:
#  compile-command: "./perf.sh"
# End:
