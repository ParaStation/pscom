/*
 * ParaStation
 *
 * Copyright (C) 2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>

#include "psport4.h"

#define ENV_DEBUG     "PSP_DEBUG"
#define ENV_LIB	      "PSP_LIB"

static PSP_Err_t (*__PSP_Init)(void) = NULL;
static char **(*__PSP_HWList)(void) = NULL;
static int env_debug = 0;

#define DPRINT(level,fmt,arg... ) do{				\
    if ((level)<=env_debug){					\
	fprintf(stderr, "<PSP%5d:"fmt">\n",getpid() ,##arg);	\
        fflush(stderr);						\
    }								\
}while(0);


static void
intgetenv(int *val, char *name)
{
    char *aval;

    aval = getenv(name);
    if (aval) {
	*val = atoi(aval);
	DPRINT(1, "set %s = %d", name, *val);
    } else {
	DPRINT(2, "default %s = %d", name, *val);
    }
}


static
int load_lib(char *lib)
{
    void *libh;
    char *errstr;

    DPRINT(3, "Loading %s", lib);
    libh = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);

    if (libh) {
	__PSP_Init = dlsym(libh, "PSP_Init");
	__PSP_HWList = dlsym(libh, "PSP_HWList");

	if (__PSP_Init && __PSP_HWList) {
	    DPRINT(1, "Using %s.", lib);
	    return 1;
	} else {
	    if (!__PSP_Init) DPRINT(3, "%s : Undefined symbol %s.", lib, "PSP_Init");
	    if (!__PSP_HWList) DPRINT(3, "%s : Undefined symbol %s.", lib, "PSP_HWList");
	    dlclose(libh);
	}
    }

    errstr = dlerror();
    DPRINT(2, "Loading %s failed : %s", lib, errstr ? errstr : "unknown error");

    return 0;
}


static
void init_final(void)
{
    char *libname;
    char *libnames[] = {
	"libpsport4all.so",
	"libpsport4gm.so",
	"libpsport4openib.so",
	"libpsport4mvapi.so",
	"libpsport4.so",
	NULL
    };
    char *libdirs[] = {
	"",
#if defined( __x86_64 )
	"/opt/parastation/lib64/",
#endif
	"/opt/parastation/lib/",
	NULL
    };
    char **ln_p;
    char **ld_p;
    char buf[400];

    static int initialized = 0;
    if (initialized) {
	return;
    }
    initialized = 1;

    intgetenv(&env_debug, ENV_DEBUG);
    libname = getenv(ENV_LIB);

    if (libname) {
	DPRINT(1, "set %s = %s", ENV_LIB, libname);
	if (load_lib(libname)) return;
	DPRINT(1, "loading %s failed!", libname);
    } else {
	DPRINT(2, "%s not set", ENV_LIB);
    }

    for (ln_p = libnames; *ln_p; ln_p++) {
	for (ld_p = libdirs; *ld_p; ld_p++) {
	    strcpy(buf, *ld_p);
	    strcat(buf, *ln_p);

	    if (load_lib(buf)) return;
	}
    }

    fprintf(stderr, "Cant load one of ");
    for (ln_p = libnames; *ln_p; ln_p++) {
	fprintf(stderr, "%s ", *ln_p);
    }
    fprintf(stderr, ".\n");
    exit(1);
}

/*
void _init(void)
{
    fprintf(stderr, "%s() called\n", __func__);
    init_final();
}
*/

PSP_Err_t PSP_Init(void)
{
    init_final();
//    fprintf(stderr, "%s() called (%p to %p)\n",
//	    __func__, PSP_Init, __PSP_Init);
    return __PSP_Init();
}


char **PSP_HWList(void)
{
    init_final();
//    fprintf(stderr, "%s() called\n", __func__);
    return __PSP_HWList();
}

#if 1
/* libmpich.a need this symbols very early....: */
int PSP_RecvAny(PSP_Header_Net_t* header, int from, void *param)
{
    return 1;
}

int PSP_RecvFrom(PSP_Header_Net_t* header, int from, void *param)
{
    PSP_RecvFrom_Param_t *p = (PSP_RecvFrom_Param_t *)param;
    return from == p->from;
}
#endif
