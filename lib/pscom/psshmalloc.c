/*
 * ParaStation
 *
 * Copyright (C) 2013 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include <sys/ipc.h>
#include <sys/shm.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "psshmalloc.h"
#include "pscom_env.h"


struct Psshm psshm_info = {
	.base = NULL,
	.tail = NULL,
	.size = 0,
	.shmid = -1,
	.msg = "libpsmalloc.so not linked.",
};


struct Psshm_config {
	size_t	min_size;
	size_t	max_size;
};


static
struct Psshm_config psshm_config = {
	.min_size = 32UL * 1024 * 1024 /* 32MiB */,
	.max_size = 64UL * 1024 * 1024 * 1024, /* 64 GiB */

};

/* Initialize base pointer with a shared mem segment. Return 0 on success, -1 else */
static
int psshm_init_base(void)
{
	int shmid;
	void *buf;
	size_t size = psshm_config.max_size;

	while (1) {
		shmid = shmget(/*key*/0, size,  /*SHM_HUGETLB |*/ SHM_NORESERVE | IPC_CREAT | 0777);
		if (shmid != -1) break; // success with size bytes
		if (errno != ENOSPC && errno != EINVAL) goto err; // error, but not "No space left on device" or EINVAL
		size = size * 3 / 4; // reduce allocated size
		if (size < psshm_config.min_size) break;
	}
	if (shmid == -1) goto err;

	buf = shmat(shmid, 0, 0 /*SHM_RDONLY*/);
	if (((long)buf == -1) || !buf) goto err_shmat;

	shmctl(shmid, IPC_RMID, NULL); /* remove shmid after usage */

	psshm_info.base = psshm_info.tail = buf;
	psshm_info.end = buf + size;
	psshm_info.shmid = shmid;
	psshm_info.size = size;

	return 0;
err:
	return -1;
err_shmat:
	shmctl(shmid, IPC_RMID, NULL);
	return -1;
}


/* Allocate INCREMENT more bytes of data space,
   and return the start of data space, or NULL on errors.
   If INCREMENT is negative, shrink data space.  */
static
void *psshm_morecore (ptrdiff_t increment)
{
	void * oldtail = psshm_info.tail;
	// printf("Increase mem : %ld\n", increment);

	assert(psshm_info.base);
	if (increment <= 0) {
		psshm_info.tail += increment;
	} else {
		if ((psshm_info.tail + increment) >= psshm_info.end) {
			// fprintf(stderr, "Out of mem\n");
			// errno = ENOMEM;
			return NULL;
		}
		psshm_info.tail += increment;
	}

	return oldtail;
}


static
void getenv_ulong(unsigned long *val, const char *name)
{
	char *aval;
	aval = getenv(name);
	if (aval) {
		*val = atol(aval);
	}
}


void psshm_init()
{
	/* Hook into the malloc handler with __morecore... */

#ifndef PSCOM_ALLIN
	unsigned long enabled = 1;
#else
	unsigned long enabled = 0;
#endif

	/* Disabled by "PSP_MALLOC=0, PSP_SHAREDMEM=0 or PSP_SHM=0? */
	getenv_ulong(&enabled, ENV_MALLOC);
	if (!enabled) goto out_disabled;

	getenv_ulong(&enabled, ENV_ARCH_OLD_SHM);
	getenv_ulong(&enabled, ENV_ARCH_NEW_SHM);
	if (!enabled) goto out_disabled_shm;

	/* Get parameters from the environment */
	getenv_ulong(&psshm_config.min_size, ENV_MALLOC_MIN);
	getenv_ulong(&psshm_config.max_size, ENV_MALLOC_MAX);

	/* Initialize shared mem region */
	if (psshm_init_base()) goto err_init_base;

//	mallopt(M_MMAP_THRESHOLD, 0/* psshm_config.max_size*/); // always use our psshm_morecore()
	mallopt(M_MMAP_MAX, 0); // Do not use mmap(). Always use psshm_morecore()
//	mallopt(M_TOP_PAD, 64*1024); // stepsize to increase brk.

	__morecore = psshm_morecore;

	return;
out_disabled:
#ifndef PSCOM_ALLIN
	psshm_info.msg = "disabled by " ENV_MALLOC " = 0";
#else
	psshm_info.msg = "not enabled by " ENV_MALLOC " = 1";
#endif
	return;
out_disabled_shm:
	psshm_info.msg = "disabled by " ENV_ARCH_NEW_SHM " = 0";
	return;
err_init_base:
	{
		static char msg[170];
		snprintf(msg, sizeof(msg), "failed. "
			 ENV_MALLOC_MIN " = %lu " ENV_MALLOC_MAX " = %lu : %s (\"/proc/sys/kernel/shmmax\" to small?)",
			 psshm_config.min_size, psshm_config.max_size,
			 strerror(errno));
		psshm_info.msg = msg;
	}
	// fprintf(stderr, "psshm_init failed : %s\n", strerror(errno));
	return;
}
