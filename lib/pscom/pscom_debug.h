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
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include "perf.h"
int pscom_dprintf(const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 1, 2)));

int pscom_dwrite(const char *_msg, size_t len);

#ifndef DPRINT
#define DPRINT(level,fmt,arg... ) do{		\
    if ((level)<=pscom.env.debug){		\
	pscom_dprintf(fmt "\n",##arg);		\
    }						\
}while(0)
#endif

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

const char *pscom_msgtype_str(uint8_t msg_type);

// return an id string for the req and some state
typedef struct PSCOM_req pscom_req_t;
char *pscom_debug_req_str(pscom_req_t *req);

#if 1
#define D_TR(code) do { } while (0)
#else
#define D_TR(code) do { code; } while (0)
#endif


void pscom_debug_init(void);

/* Debug Level */
#define D_FATAL	0
#define D_BUG_EXT 0	/* Bug: External invalid usage (e.g. Usage before pscom_init()) */
#define D_BUG	0

#define D_ERR	1
#define D_WARNONCE 1	/* Warning, printed only once (usually "not implemented") */

#define D_WARN	2

#define D_INFO	3

#define D_DBG	4	/* Debug */

#define D_DBG_V	5	/* Debug verbose */

#define D_TRACE	6

/* Debug topic masks */
#define D_VERSION	(D_INFO * !pscom.env.debug_version)
#define D_CONTYPE	(D_INFO * !pscom.env.debug_contype)
#define D_SUSPEND	(D_INFO * !pscom.env.debug_precon)
#define D_SUSPEND_DBG	(D_DBG * (pscom.env.debug_precon < 2))
#define D_PRECON_TRACE	(D_TRACE * !pscom.env.debug_precon)
#define D_STATS		(D_DBG * !pscom.env.debug_stats)	/* Statistics */

#endif /* _PSCOM_DEBUG_H_ */
