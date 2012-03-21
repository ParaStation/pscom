/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * ps_develop.c: some debugging functions
 */

//#include <stdio.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include "p4s_debug.h"

char *dumpstr(void *buf, int size)
{
    static char ret[200];
    char *tmp;
    int s;
    char *b;
    if (size * 5 + 4 > sizeof(ret)) {
	size = (sizeof(ret) - 4) / 5;
    }
    tmp = ret;
    s = size; b = (char *)buf;
    for (; s ; s--, b++){
	    tmp += sprintf(tmp, "<%02x>", (unsigned char)*b);
    }
    *tmp++ = '\'';
    s = size; b = (char *)buf;
    for (; s ; s--, b++){
	    *tmp++ =
		((' ' <= *b) && (*b <= '~')) ? *b: '.';
    }
    *tmp++ = '\'';
    *tmp++ = 0;
    return ret;
}

#ifdef ENABLE_LOCK_CHECK
#include "ps_perf.h"

int lock_check(rwlock_t *rwlock, char *desc)
{
    unsigned long t1, t2;
    GET_CPU_CYCLES(t1);
    while (rwlock->lock != RW_LOCK_BIAS) {
	GET_CPU_CYCLES(t2);
	if ((t2 - t1) > 800 * 1000 * 1000 /* 1sec at 800MHz */) {
	    printk(KERN_ERR "ERROR: %s\n", desc);
	    return 1;
	}
    }
    return 0;
}

int slock_check(p4_spinlock_t *slock, char *desc)
{
    unsigned long t1, t2;
    GET_CPU_CYCLES(t1);
    while (!slock->lock) {
	GET_CPU_CYCLES(t2);
	if ((t2 - t1) > 800 * 1000 * 1000 /* 1sec at 800MHz */) {
	    printk(KERN_ERR "ERROR: %s\n", desc);
	    return 1;
	}
    }
    return 0;
}

#endif
