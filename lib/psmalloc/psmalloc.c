/*
 * ParaStation
 *
 * Copyright (C) 2014-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <malloc.h>

#include "psshmalloc.h"

/* GNU libc 2.14 defines this macro to declare hook variables as volatile.
   Define it as empty for older libc versions.  */
#ifndef __MALLOC_HOOK_VOLATILE
#define __MALLOC_HOOK_VOLATILE
#endif

/* Override initializing hook from the C library. */
void (*__MALLOC_HOOK_VOLATILE __malloc_initialize_hook)(void) = psshm_init;

/* clang-format off
 *
 * Local Variables:
 *  compile-command: "gcc shmmalloc.c -Wall -W -Wno-unused -O2 -fpic -shared -o * libshmmalloc.so"
 * End:
 *
 * clang-format on
 */
