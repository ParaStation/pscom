/*
 * ParaStation
 *
 * Copyright (C) 2014 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include <malloc.h>

#include "psshmalloc.h"

/* GNU libc 2.14 defines this macro to declare hook variables as volatile.
   Define it as empty for older libc versions.  */
#ifndef __MALLOC_HOOK_VOLATILE
# define __MALLOC_HOOK_VOLATILE
#endif

/* Override initializing hook from the C library. */
void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook) (void) = psshm_init;


/*
 * Local Variables:
 *  compile-command: "gcc shmmalloc.c -Wall -W -Wno-unused -O2 -fpic -shared -o libshmmalloc.so"
 * End:
 *
 */
