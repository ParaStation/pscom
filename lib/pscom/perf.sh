#!/bin/bash
#
#                   ParaStation
#
#  Copyright (C) 2015 ParTec Cluster Competence Center GmbH, Munich
#  All rights reserved.
#
#
#  author:
#   Jens Hauke <hauke@par-tec.com>
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
