/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "perf.h"
#include "pscom_util.h"

#ifdef ENABLE_PERF
#include "ps_perf.h"

#include <sys/time.h>


double cycles_us;

static void cycles_cal(void)
{
    unsigned long t1, t2, rt1, rt2;
    t1 = pscom_wtime_usec();
    GET_CPU_CYCLES(rt1);
    /* usleep call kapm-idled and slowdown the cpu! */
    while (pscom_wtime_usec() - 1000 < t1)
        ;
    GET_CPU_CYCLES(rt2);
    t2 = pscom_wtime_usec();

    t2 -= t1;
    rt2 -= rt1;
    cycles_us = 1.0 * t2 / rt2;
    printf("# %ld usec = %ld cycles, 1 usec = %f\n", t2, rt2, 1 / cycles_us);
}

#define LOG_SIZE      (1024 * 32)
#define ID_INDEX_SIZE 1024

typedef struct log_s {
    unsigned long time;
    char *id;
} log_t;


static log_t perf_log[LOG_SIZE];

static log_t *logpos = perf_log;

static const char *id_index[ID_INDEX_SIZE];

static unsigned get_id_index(const char *id)
{
    unsigned idx = 0;
    for (idx = 0; id_index[idx]; idx++) {
        if (strcmp(id, id_index[idx]) == 0) { return idx; }
    }
    if (idx < ID_INDEX_SIZE) { id_index[idx] = id; }
    return idx;
}

void perf_print(void)
{
    int i;
    unsigned long lasttime  = 0;
    unsigned long firsttime = perf_log[0].time;
    int pid                 = getpid();

    cycles_cal();
    printf("#%5s %12s %12s %2s %20s %s\n", "pid", "dtime", "dtime prev", "#id",
           "id", "abs time");
    for (i = 0; i < LOG_SIZE; i++) {
        log_t *cur = &perf_log[i];
        if (!cur->id) { break; }
        while (1) {
            printf("pid_%06d %12.2f %12.2f %2u %20s %lu\n", pid,
                   (unsigned /*long*/)(cur->time - firsttime) * cycles_us,
                   (unsigned /*long*/)(cur->time - lasttime) * cycles_us,
                   get_id_index(cur->id), cur->id, cur->time);
            lasttime = cur->time;

            if (strncmp(cur->id, "reset_", 6) == 0 && firsttime != cur->time) {
                firsttime = cur->time;
                printf("\n");
                continue;
            }
            break;
        };
    }
    fflush(stdout);
    logpos = perf_log;
}


void perf_add(char *id)
{
    GET_CPU_CYCLES(logpos->time);
    logpos->id = id;
    logpos++;
    if (logpos == &perf_log[LOG_SIZE]) { perf_print(); }
}

#endif /* ENABLE_PERF */
