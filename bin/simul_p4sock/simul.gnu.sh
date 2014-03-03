#!/bin/sh

#!/usr/bin/gnuplot -persist

./simul > ./simul.dat

gnuplot -persist <<'DOK'

#GNUSTART

set grid
#set xrange [500:600]
set yrange [:20]
plot "<cat ./simul.dat | grep conn1" us 2: ($5 - $4) title "SendQSize"  w lp
replot "<cat ./simul.dat | grep conn1" us 2: ($10) title "PipeSize"  w lp
replot "<cat ./simul.dat | grep conn1execpre" us 2: ($10) title "PipeSizepre"  w l
replot "<cat ./simul.dat | grep conn1execpost" us 2: ($10) title "PipeSizepost"  w l

replot "<cat ./simul.dat | grep conn1rack" us 2: (00) title "RecvAck"  w p
replot "<cat ./simul.dat | grep conn1sack" us 2: (-2) title "SendAck"  w p
replot "<cat ./simul.dat | grep conn1sdat" us 2: (-4) title "SendDAT"  w p
replot "<cat ./simul.dat | grep conn1rdat" us 2: (-6) title "RecvDAT"  w p
DOK


echo Bye