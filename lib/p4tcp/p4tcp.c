/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#define _GNU_SOURCE
#include "psockt.h"
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <dlfcn.h>

static int (*orig_socket)(int, int, int) = NULL;

static int debug_level = 0;

static void check_init(void)
{
    static int init = 0;
    char *aval;

    if (init) {
	return;
    }
    init = 1;

    aval = getenv("PSP_DEBUG");
    if (aval) debug_level = atoi(aval);

    /* get original socket() address */
    orig_socket = dlsym(RTLD_NEXT, "socket");
    if (!(orig_socket)) {
	fprintf(stderr, "libp4tcp.so: socket() not found!\n");
	exit(1);
    }
}


int socket(int domain, int type, int protocol)
{
    check_init();

    if (domain == PF_INET && type == SOCK_STREAM) {
	int ret;
	int save_errno = errno;

	ret = orig_socket(PF_TINET, type, protocol);
	if (debug_level > 1) {
	    fprintf(stderr,
		    "libp4tcp.so: socket(PF_TINET,%d,%d) = %d. %s\n",
		    type, protocol, ret, ret < 0 ? strerror(errno) : "");
	}

	if (ret >= 0) return ret;

	if (debug_level > 0) {
	    fprintf(stderr,
		    "libp4tcp.so: redirect socket(PF_INET,%d,%d) failed. (Module p4tcp not loaded?)\n",
		    type, protocol);
	}
	/* some apps (e.g. nc) need that */
	errno = save_errno;
    }

    /* fallback to original TCP socket */

    return orig_socket(domain, type, protocol);
}
