/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <sys/time.h>
#include <stdarg.h>
#include "pscom.h"


static inline
unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_usec+tv.tv_sec*1000000);
}


static
void exit_on_error(pscom_err_t rc, char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
static
void exit_on_error(pscom_err_t rc, char *fmt, ...)
{
	if (rc == PSCOM_SUCCESS) return;

	va_list arg;
	va_start(arg, fmt);
	vfprintf(stderr, fmt, arg);
	va_end(arg);
	fprintf(stderr, " : %s\n", pscom_err_str(rc));
	exit(1);
}


int main(int argc, char **argv)
{
	int rc;

	rc = pscom_init(PSCOM_VERSION);
	exit_on_error(rc, "pscom_init()");

	pscom_request_t *req;
	unsigned i;
	unsigned cnt = 1000;
	unsigned loop = 10;

	unsigned long t1;

	printf("cnt\tusec\n");
	while (loop--) {
		t1 = -getusec();

		for (i = 0; i < cnt; i++)  {
			req = pscom_request_create(100,0);
			pscom_request_free(req);
		}

		t1 += getusec();
		printf("%4u\t%8.3f\n", cnt, (double)t1 / cnt);
	}

	return 0;
}
