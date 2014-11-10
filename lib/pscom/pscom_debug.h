/*
 * ParaStation
 *
 * Copyright (C) 2007-2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_DEBUG_H_
#define _PSCOM_DEBUG_H_

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include "perf.h"

int pscom_dprintf(const char *fmt, ...)
        __attribute__ ((__format__ (__printf__, 1, 2)));

int pscom_dwrite(const char *_msg, size_t len);

#define DPRINT(level,fmt,arg... ) do{		\
    if ((level)<=pscom.env.debug){		\
	pscom_dprintf(fmt "\n",##arg);		\
    }						\
}while(0)

// Use this stream for debug output. (automic create pre/postfix on each line)
FILE *pscom_debug_stream(void);

// Used debug output stream. stderr will be used, if set to NULL (default).
extern FILE *pscom_debug_file;

// set filename for debug output. (will set pscom_debug_file)
// if expand, expand shell variables in filename (see wordexp(3))
// Use stderr in case of filename == NULL
void pscom_debug_set_filename(const char *filename, int expand);

// Set prefix if output goes to stderr. Default to $hostname:$pid.
void pscom_debug_set_prefix(const char *prefix);

#if 1
#define D_TR(code) do { } while (0)
#else
#define D_TR(code) do { code; } while (0)
#endif


void pscom_debug_init(void);

#endif /* _PSCOM_DEBUG_H_ */
