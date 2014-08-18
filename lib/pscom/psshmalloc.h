/*
 * ParaStation
 *
 * Copyright (C) 2013 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _SHMMALLOC_H_
#define _SHMMALLOC_H_

struct Psshm {
	void *base; /* base pointer of shared mem segment */
	void *end;  /* = base + size */
	void *tail;
	size_t size;
	int shmid; /* shmid of shared mem segment at base */
	const char *msg; /* Message if initialization failed */
};

/* Get the Psshm of the shared memory. */
extern struct Psshm psshm_info;


/* Check if the Pointer ptr is part of the shared memory */
static inline
int is_psshm_ptr(void *ptr)
{
	return psshm_info.base <= ptr && ptr < psshm_info.end;
}


/* If psshm is enabled? */
static inline
int is_psshm_enabled()
{
	return !!psshm_info.base;
}


/* Hook into the malloc handler with __morecore for direct shared mem.
   To use direct shared mem, this should be called early by the
   __malloc_initialize_hook:

   void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook) (void) = psshm_init;

   (See libpsmalloc.so)
 */
void psshm_init();


/*
# always overcommit, never check
echo 1 > /proc/sys/vm/overcommit_memory
# allow up to 32GiB shm
echo 34359738368 > /proc/sys/kernel/shmmax
*/


#endif /* _SHMMALLOC_H_ */
