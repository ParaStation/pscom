/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#define _GNU_SOURCE
#include "pscom_priv.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include "pscom_env.h"

LIST_HEAD(pscom_plugins);

static
char *strtoupper(char *name)
{
	while (*name) {
		*name = (char)toupper(*name);
		name++;
	}
	return name;
}


static
unsigned int pscom_plugin_uprio(const char *arch)
{
	char env_name[100];
	unsigned res;
#define ENV_EX_UNSET ((unsigned)~0U)
	static int env_extoll_initialized = 0;
	static unsigned env_extoll;
	static unsigned env_velo;

	strcpy(env_name, ENV_ARCH_PREFIX);
	strcat(env_name, arch);
	strtoupper(env_name);

	res = 1;
	if (strcmp(arch, "elan") == 0 ||
	    strcmp(arch, "mxm") == 0 ||
	    strcmp(arch, "ucp") == 0 ||
	    strcmp(arch, "ofed") == 0) {
		/* default of ELAN is 'off'. mpiexec will switch
		   it on, after setting up the elan environment.*/
		/* ToDo: Check for ELAN environment variables inside
		   elan plugin! And remove this if. */
		/* default for MXM is 'off', but with a higher minor
		   priority than OPENIB. With PSP_MXM=1 mxm will be used
		   preferred. */
		/* default for UCP is 'off', but with a higher minor
		   priority than OPENIB. With PSP_UCP=1 ucp will be used
		   preferred. */
		/* default for ofed is 'off'. Until ofed support
		   resends for lost messages. */
		res = 0;
	}
	if ((strcmp(env_name, ENV_ARCH_NEW_SHM) == 0) &&
	    !getenv(ENV_ARCH_NEW_SHM) && getenv(ENV_ARCH_OLD_SHM)) {
		/* old style shm var */
		pscom_env_get_uint(&res, ENV_ARCH_OLD_SHM);
	} else if ((strcmp(env_name, ENV_ARCH_NEW_P4S) == 0) &&
		   !getenv(ENV_ARCH_NEW_P4S) && getenv(ENV_ARCH_OLD_P4S)) {
		/* old style p4s var */
		pscom_env_get_uint(&res, ENV_ARCH_OLD_P4S);
	} else if ((strcmp(env_name, ENV_ARCH_PREFIX "EXTOLL") == 0) ||
		   (strcmp(env_name, ENV_ARCH_PREFIX "VELO") == 0)) {
		/* Extoll rma or velo? */
		if (!env_extoll_initialized) {
			env_extoll_initialized = 1;

			env_velo = ENV_UINT_AUTO;
			pscom_env_get_uint(&env_velo, ENV_ARCH_PREFIX "VELO");

			env_extoll = ENV_UINT_AUTO;
			pscom_env_get_uint(&env_extoll, ENV_ARCH_PREFIX "EXTOLL");

			if (env_extoll == ENV_UINT_AUTO) {
				// auto: enable "extoll" only if "velo" is disabled.
				env_extoll = (env_velo == 0) ? 1 : 0;
			}
			if (env_velo == ENV_UINT_AUTO) {
				// auto: enable "velo" only if "extoll" is disabled (or was auto).
				env_velo = (env_extoll == 0) ? 1 : 0;
			}
			if (env_extoll && env_velo) {
				DPRINT(D_WARN, "'" ENV_ARCH_PREFIX "VELO' and '"
				       ENV_ARCH_PREFIX "EXTOLL' are mutually exclusive! Disabling '"
				       ENV_ARCH_PREFIX "EXTOLL'");
				env_extoll = 0;
			}
		}
		if ((strcmp(env_name, ENV_ARCH_PREFIX "EXTOLL") == 0)) {
			res = env_extoll;
		} else {
			res = env_velo;
		}
	} else {
		pscom_env_get_uint(&res, env_name);
	}
	return res;
}


static
void pscom_plugin_register(pscom_plugin_t *plugin, unsigned int user_prio)
{
	if (!user_prio) {
		DPRINT(D_DBG_V, "Arch %s is disabled", plugin->name);
		return; // disabled arch
	}
	plugin->user_prio = user_prio;

	if (pscom_plugin_by_name(plugin->name)) {
		DPRINT(D_DBG_V, "Arch %s already registered", plugin->name);
		return; // disabled arch
	}

	pscom_plugin_t *tmpp = pscom_plugin_by_archid(plugin->arch_id);
	if (tmpp) {
		DPRINT(D_DBG_V, "Arch id %d already registered (registered:%s, disabled:%s)",
		       plugin->arch_id, tmpp->name, plugin->name);
		return; // disabled arch
	}


	DPRINT(D_DBG_V, "Register arch %s with priority %02d.%02d",
	       plugin->name, plugin->user_prio, plugin->priority);

	struct list_head *pos, *inc;
	inc = &pscom_plugins;
	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);

		if ((p->user_prio < plugin->user_prio) ||
		    ((p->user_prio == plugin->user_prio) &&
		     (p->priority < plugin->priority))) {
			inc = pos;
			break;
		}
	}

	list_add_tail(&plugin->next, inc);

	// Debug:
//	list_for_each(pos, &pscom_plugins) {
//		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);
//		printf("%02d.%02d %s\n", p->user_prio, p->priority, p->name);
//	}
}


static
pscom_plugin_t *load_plugin_lib(char *lib)
{
	void *libh;
	char *errstr;

	libh = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);

	if (libh) {
		pscom_plugin_t *plugin = dlsym(libh, "pscom_plugin");

		if (plugin) {
			if (plugin->version == PSCOM_PLUGIN_VERSION) {
				DPRINT(D_DBG, "Using   %s", lib);
				// OK
				return plugin;
			} else {
				// Error
				DPRINT(D_ERR,
				       "Loading %s failed : Version mismatch (0x%04x != expected 0x%04x)",
				       lib, plugin->version, PSCOM_PLUGIN_VERSION);
			}
		} else {
			// Error
			DPRINT(D_ERR, "Loading %s failed : No symbol 'pscom_plugin'", lib);
		}
		// all errors
		dlclose(libh);

		return NULL;
	}

	errstr = dlerror();
	DPRINT(D_DBG_V, "Loading %s failed : %s", lib, errstr ? errstr : "unknown error");

	return NULL;
}


static
const char *pscom_libdir_self(void) {
	static const char *libdir;
	Dl_info info;

	if (libdir) return libdir; // return cached one

	if (dladdr(pscom_init, &info) && info.dli_fname) {
		char *fname = strdup(info.dli_fname);
		char *dirend = rindex(fname, '/');
		if (dirend) dirend[1] = 0; // like dirname(), but keep '/'
		libdir = fname;
	} else {
		// Fall back to compile time dir:
		libdir = LIBDIR "/";
	}
	return libdir;
}

static
void pscom_plugin_load(const char *arch)
{
	unsigned int uprio = pscom_plugin_uprio(arch);
	if (!uprio) {
		DPRINT(D_DBG_V, "Arch %s is disabled", arch);
		return; // disabled arch
	}

	const char *libdirs[] = {
		pscom.env.plugindir, // "" or environ,
		pscom_libdir_self(),
		NULL
	};
	unsigned cnt = 0;

	const char **ld_p;
	for (ld_p = libdirs; *ld_p; ld_p++) {
		char libpath[400];
		pscom_plugin_t *plugin;
		struct stat statbuf;

		snprintf(libpath, sizeof(libpath), "%slibpscom4%s.so",
			 *ld_p, arch);

		if ((*ld_p)[0] && stat(libpath, &statbuf) && errno == ENOENT) {
			continue;
		}
		cnt++;
		plugin = load_plugin_lib(libpath);

		if (plugin) {
			assert(strcmp(arch, plugin->name) == 0);

			pscom_plugin_register(plugin, uprio);
			break;
		}
	}
	if (!cnt) DPRINT(D_DBG_V, "libpscom4%s.so not available", arch);
}


pscom_plugin_t *pscom_plugin_by_archid(unsigned int arch_id)
{
	struct list_head *pos;

	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);
		if (p->arch_id == arch_id) return p;
	}
	return NULL;
}


pscom_plugin_t *pscom_plugin_by_name(const char *arch)
{
	struct list_head *pos;

	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);
		if (strcmp(arch, p->name) == 0) return p;
	}
	return NULL;
}


static
int plugins_loaded = 0;

void pscom_plugins_destroy(void)
{
	if (!plugins_loaded) return;
	plugins_loaded = 0;

	while (!list_empty(&pscom_plugins)) {
		pscom_plugin_t *p = list_entry(pscom_plugins.next, pscom_plugin_t, next);
		if (p->destroy) p->destroy();
		list_del(&p->next);
	}
}


void pscom_plugins_init(void)
{
	if (plugins_loaded) return;
	plugins_loaded = 1;

	pscom_plugin_register(&pscom_plugin_tcp, pscom_plugin_uprio("tcp"));
	pscom_plugin_register(&pscom_plugin_shm, pscom_plugin_uprio("shm"));
	pscom_plugin_register(&pscom_plugin_p4s, pscom_plugin_uprio("p4s"));
#ifdef PSCOM_ALLIN_PSM2
	pscom_plugin_register(&pscom_plugin_psm, pscom_plugin_uprio("psm"));
#endif
#ifdef PSCOM_ALLIN_OPENIB
	pscom_plugin_register(&pscom_plugin_openib, pscom_plugin_uprio("openib"));
#endif
#ifdef PSCOM_ALLIN_GATEWAY
	pscom_plugin_register(&pscom_plugin_gateway, pscom_plugin_uprio("gateway"));
#endif

	// ToDo: Use file globbing!
	char *pls[] = {
#ifndef PSCOM_ALLIN_PSM2
		"psm",
#endif
#ifndef PSCOM_ALLIN_OPENIB
		"openib",
#endif
		"ofed",
		"mvapi",
		"gm",
		"elan",
		"extoll",
		"velo",
		"dapl",
		"mxm",
		"ucp",
#ifndef PSCOM_ALLIN_GATEWAY
		"gateway",
#endif
		NULL };
	char **tmp;

	for (tmp = pls; *tmp; tmp++) {
		pscom_plugin_load(*tmp);
	}

	struct list_head *pos;
	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);
		if (p->init) p->init();
	}
}


void pscom_plugins_sock_init(pscom_sock_t *sock)
{
	pscom_plugins_init();

	struct list_head *pos;
	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);
		if (p->sock_init) p->sock_init(sock);
	}
}


void pscom_plugins_sock_destroy(pscom_sock_t *sock)
{
	struct list_head *pos;
	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);
		if (p->sock_destroy) p->sock_destroy(sock);
	}
}


pscom_plugin_t *pscom_plugin_next(pscom_plugin_t *cur)
{
	if (!cur) return NULL;
	if (&pscom_plugins == cur->next.next) return NULL;

	return list_entry(cur->next.next, pscom_plugin_t, next);
}


pscom_plugin_t *pscom_plugin_first(void)
{
	if (list_empty(&pscom_plugins)) return NULL;

	return list_entry(pscom_plugins.next, pscom_plugin_t, next);
}
