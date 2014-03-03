#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "perf.h"
#include "ps_perf.h"

static char vcid[] __attribute__(( unused )) =
"$Id$";

#include <sys/time.h>

unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec*1000000+tv.tv_usec;
}


double cycles_us;
void cycles_cal(void)
{
    unsigned long t1, t2, rt1, rt2;
    t1 = getusec();
    GET_CPU_CYCLES(rt1);
    /* usleep call kapm-idled and slowdown the cpu! */
    while (getusec() - 1000 < t1);
    GET_CPU_CYCLES(rt2);
    t2 = getusec();

    t2 -= t1;
    rt2 -= rt1;
    cycles_us = 1.0 * t2 / rt2;
    printf("# %ld usec = %ld cycles, 1 usec = %f\n", t2, rt2, 1 / cycles_us);
}

#define LOG_SIZE (1024 * 32)

typedef struct log_s {
    unsigned long time;
    char *id;
} log_t;


static log_t perf_log[LOG_SIZE];

static log_t *logpos = perf_log;



void perf_print(void)
{
    int i;
    unsigned long lasttime = 0;
    unsigned long firsttime = perf_log[0].time;
    int pid = getpid();

    cycles_cal();
    for (i = 0; i < LOG_SIZE; i++) {
	log_t *cur = &perf_log[i];

	printf("%6d %12.2f %12.2f %20s %lu\n", pid,
	       (cur->time - firsttime)* cycles_us,
	       (cur->time - lasttime) * cycles_us,
	       cur->id,
	       cur->time);
	lasttime = cur->time;
    }
    logpos = perf_log;
}

#if 0
void perf_add(char *id)
{
    GET_CPU_CYCLES(logpos->time);
    logpos->id = id;
    logpos++;
    if (logpos == &perf_log[LOG_SIZE]) {
	perf_print();
    }
}

#else
void perf_add(char *id)
{
}
#endif
