/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "p4log.h"

#include "ps_perf.h"
#include <sys/time.h>

static inline
unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_usec+tv.tv_sec*1000000);
}



#define LOGSIZE 8192
struct logentry_s logbuf[LOGSIZE];

double mHZ = 1.0;

void calc_time(void)
{
    unsigned long time;
    unsigned long ptime1, ptime2;

    time = -getusec();
    GET_CPU_CYCLES(ptime1);
    usleep(100000);
    GET_CPU_CYCLES(ptime2);
    time += getusec();
    mHZ = (0.001 * (double)time) / (double)(ptime2 - ptime1);
    printf("# MHZ %10.3f\n", 0.001 / mHZ);
    printf("# type time[ms] value\n");
}

int main(int argc, char **argv)
{
    int lfd;
    long long firsttime = 0;
    int len;
    int i;

    calc_time();

    lfd = open("/proc/sys/p4log/log", O_RDONLY);
    if (lfd < 0) goto err_fopen;

//      do {
//	len = read(lfd, logbuf, sizeof(logbuf[0]));
//      } while (!len || logbuf[0].type == LOG_OVERRUN);
//      firsttime = logbuf[0].time;
    GET_CPU_CYCLES_LL(firsttime);


    while (1) {
	len = (int)read(lfd, logbuf, sizeof(logbuf[0]) * LOGSIZE);
	len = len / (unsigned)sizeof(logbuf[0]);
	for (i = 0; i < len; i++) {
	    printf("%d\t%13.5f\t%ld\n",
		   logbuf[i].type,
		   (double)(logbuf[i].time - firsttime) * mHZ,
		   logbuf[i].value);
	}
    }

    return 0;

 err_fopen:
    perror("open /proc/sys/p4log/log");
    exit(1);
    return 1;
}
