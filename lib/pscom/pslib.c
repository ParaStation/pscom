/*
 * ParaStation
 *
 * Copyright (C) 2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <wordexp.h>
#include <errno.h>
#include <ctype.h>
#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_debug.h"

typedef struct psinfo_s psinfo_t;

static
struct {
	psinfo_t *(*psinfo_connect)(const char *url);
	int (*psinfo_close)(psinfo_t *info);
	int (*psinfo_set)(psinfo_t *info, const char *path, const char *value);

	void (*psconfig_read_files)(const char *files);
	void (*psconfig_cleanup)(void);

	char *(*psconfig_get)(const char *name);
	int (*psconfig_set)(const char *name, const char *value, int overwrite);

	psinfo_t *info;
} pslib;

int pscom_pslib_available = 0;


void pscom_pslib_init(const char *configfiles)
{
	void *libh;

	libh = dlopen("libpslib.so", RTLD_NOW | RTLD_GLOBAL);
#define GETSYM(symbolname)				\
	do {						\
		void *sym = dlsym(libh, #symbolname);	\
		if (sym) pslib.symbolname = sym;	\
	} while (0)

	memset(&pslib, 0, sizeof(pslib));
	if (libh) {
		GETSYM(psinfo_connect);
		GETSYM(psinfo_close);
		GETSYM(psinfo_set);
		GETSYM(psconfig_read_files);
		GETSYM(psconfig_cleanup);
		GETSYM(psconfig_get);
		GETSYM(psconfig_set);

		pscom_pslib_available = 1;
	}
}


void pscom_pslib_read_config(const char *configfiles)
{
	if (!pslib.psconfig_read_files) return;

	pslib.psconfig_read_files(configfiles);
	if (pslib.psconfig_get) pscom_env_get = pslib.psconfig_get;
	if (pslib.psconfig_set) pscom_env_set = pslib.psconfig_set;
}


void pscom_pslib_cleanup(void)
{
	if (pslib.psconfig_cleanup) {
		pslib.psconfig_cleanup();
	}
	if (pslib.info && pslib.psinfo_close) {
		pslib.psinfo_close(pslib.info);
		pslib.info = NULL;
	}
}


void pscom_info_connect(const char *url)
{
	if (!pslib.psinfo_connect || !url) return;

	wordexp_t p;
	int rc;

	rc = wordexp(url, &p, WRDE_NOCMD);
	if (!rc && (p.we_wordc == 1)) {
		// No error and only one result
		url = p.we_wordv[0];
	}

	pslib.info = pslib.psinfo_connect(url);
	if (!pslib.info) {
		DPRINT(1, "psinfo_connect(\"%s\") : %s", url, strerror(errno));
	}

	wordfree(&p);
}


void pscom_info_set(const char *path, const char *value)
{
	if (!pslib.info || !pslib.psinfo_set) return;

	if (!value) value = "";

	// lowercase key:
	char *i, *key = strdup(path);
	for (i = key; *i; i++) *i = (char)tolower(*i);

	pslib.psinfo_set(pslib.info, key, value);

	free(key);
}


void pscom_info_set_uint(const char *path, unsigned value)
{
	if (!pslib.info || !pslib.psinfo_set) return;
	char buf[16];
	snprintf(buf, sizeof(buf), "%u", value);
	pscom_info_set(path, buf);
}


void pscom_info_set_int(const char *path, int value)
{
	if (!pslib.info || !pslib.psinfo_set) return;
	char buf[16];
	snprintf(buf, sizeof(buf), "%d", value);
	pscom_info_set(path, buf);
}
