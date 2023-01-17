/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
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
unsigned int pscom_plugin_uprio(const pscom_con_type_t con_type)
{
	unsigned res;
#define ENV_EX_UNSET ((unsigned)~0U)
	static int env_extoll_initialized = 0;
	static unsigned env_extoll;
	static unsigned env_velo;

	if ((con_type == PSCOM_CON_TYPE_EXTOLL) ||
	    (con_type == PSCOM_CON_TYPE_VELO)) {
		/* Extoll rma or velo? */
		if (!env_extoll_initialized) {
			env_extoll_initialized = 1;

			env_velo = pscom.env.user_prio[PSCOM_CON_TYPE_VELO];
			env_extoll = pscom.env.user_prio[PSCOM_CON_TYPE_EXTOLL];

			if (env_extoll == PSCOM_ENV_UINT_AUTO) {
				// auto: enable "extoll" only if "velo" is disabled.
				env_extoll = (env_velo == 0) ? 1 : 0;
			}
			if (env_velo == PSCOM_ENV_UINT_AUTO) {
				// auto: enable "velo" only if "extoll" is disabled (or was auto).
				env_velo = (env_extoll == 0) ? 1 : 0;
			}
			if (env_extoll && env_velo) {
				DPRINT(D_WARN, "'PSP_VELO' and 'PSP_EXTOLL' are mutually exclusive! Disabling 'PSP_EXTOLL'");
				env_extoll = 0;
			}
		}
		if (con_type == PSCOM_CON_TYPE_EXTOLL) {
			res = env_extoll;
		} else {
			res = env_velo;
		}
	} else {
		res = pscom.env.user_prio[con_type];
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


#if ENABLE_PLUGIN_LOADING
static
pscom_plugin_t *load_plugin_lib(char *lib, const char *arch)
{
	void *libh;
	char *errstr;

	libh = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);

	if (libh) {
		char plugin_name[128];
		snprintf(plugin_name, sizeof(plugin_name), "pscom_plugin_%s",
			 arch);
		pscom_plugin_t *plugin = dlsym(libh, plugin_name);

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
			DPRINT(D_ERR, "Loading %s failed : No symbol '%s'", lib,
			       plugin_name);
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
void pscom_plugin_load(const pscom_con_type_t con_type)
{
	unsigned int uprio = pscom_plugin_uprio(con_type);
	const char *arch = pscom_con_type_str(con_type);
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
		plugin = load_plugin_lib(libpath, arch);

		if (plugin) {
			assert(strcmp(arch, plugin->name) == 0);

			pscom_plugin_register(plugin, uprio);
			break;
		}
	}
	if (!cnt) DPRINT(D_DBG_V, "libpscom4%s.so not available", arch);
}
#endif


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

	pscom_plugin_register(&pscom_plugin_tcp, pscom_plugin_uprio(PSCOM_CON_TYPE_TCP));
	pscom_plugin_register(&pscom_plugin_shm, pscom_plugin_uprio(PSCOM_CON_TYPE_SHM));
	pscom_plugin_register(&pscom_plugin_p4s, pscom_plugin_uprio(PSCOM_CON_TYPE_P4S));
#ifdef PSCOM_ALLIN_PSM2
	pscom_plugin_register(&pscom_plugin_psm, pscom_plugin_uprio(PSCOM_CON_TYPE_PSM));
#endif
#ifdef PSCOM_ALLIN_OPENIB
	pscom_plugin_register(&pscom_plugin_openib, pscom_plugin_uprio(PSCOM_CON_TYPE_OPENIB));
#endif
#ifdef PSCOM_ALLIN_UCP
	pscom_plugin_register(&pscom_plugin_ucp, pscom_plugin_uprio(PSCOM_CON_TYPE_UCP));
#endif
#ifdef PSCOM_ALLIN_GATEWAY
	pscom_plugin_register(&pscom_plugin_gateway, pscom_plugin_uprio(PSCOM_CON_TYPE_GW));
#endif

#if ENABLE_PLUGIN_LOADING
	// ToDo: Use file globbing!
	pscom_con_type_t pls[] = {
#ifndef PSCOM_ALLIN_PSM2
		PSCOM_CON_TYPE_PSM,
#endif
#ifndef PSCOM_ALLIN_OPENIB
		PSCOM_CON_TYPE_OPENIB,
#endif
		PSCOM_CON_TYPE_OFED,
		PSCOM_CON_TYPE_MVAPI,
		PSCOM_CON_TYPE_GM,
		PSCOM_CON_TYPE_ELAN,
		PSCOM_CON_TYPE_EXTOLL,
		PSCOM_CON_TYPE_VELO,
		PSCOM_CON_TYPE_DAPL,
		PSCOM_CON_TYPE_MXM,
#ifndef PSCOM_ALLIN_UCP
		PSCOM_CON_TYPE_UCP,
#endif
#ifndef PSCOM_ALLIN_GATEWAY
		PSCOM_CON_TYPE_GW,
#endif
		PSCOM_CON_TYPE_PORTALS,
		PSCOM_CON_TYPE_NONE };
	pscom_con_type_t *tmp;

	for (tmp = pls; *tmp != PSCOM_CON_TYPE_NONE; tmp++) {
		pscom_plugin_load(*tmp);
	}
#endif

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
