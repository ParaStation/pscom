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

#include "pscom_env.h"
#include <stdlib.h>
#include "pscom_priv.h"
#include "vc_version.h"
#include "pslib.h"

char *(*pscom_env_get)(const char *name) = getenv;
int (*pscom_env_set)(const char *name, const char *value, int overwrite) = setenv;


void pscom_env_get_int(int *val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = atoi(aval);
		DPRINT(D_DBG, "set %s = %d", name, *val);
	} else {
		DPRINT(D_DBG_V, "default %s = %d", name, *val);
	}
	pscom_info_set_int(name, *val);
}


void pscom_env_get_uint(unsigned int *val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = atoi(aval);
		DPRINT(D_DBG, "set %s = %u", name, *val);
	} else {
		if (*val != ENV_UINT_AUTO) {
			DPRINT(D_DBG_V, "default %s = %u", name, *val);
		} else {
			DPRINT(D_DBG_V, "default %s = auto", name);
		}
	}
	pscom_info_set_uint(name, *val);
}


void pscom_env_get_size_t(size_t *val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = atoll(aval);
		DPRINT(D_DBG, "set %s = %zu", name, *val);
	} else {
		if (*val != ENV_SIZE_T_AUTO) {
			DPRINT(D_DBG_V, "default %s = %zu", name, *val);
		} else {
			DPRINT(D_DBG_V, "default %s = auto", name);
		}
	}
	pscom_info_set_size_t(name, *val);
}


void pscom_env_get_str(char **val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = aval;
		DPRINT(D_DBG, "set %s = %s", name, *val);
	} else {
		DPRINT(D_DBG_V, "default %s = %s", name, *val ? *val : "<null>");
	}
	pscom_info_set(name, *val);
}


void pscom_env_get_dir(char **val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		size_t len = strlen(aval);
		if (len && (aval[len-1] != '/')) {
			// append a '/'
			*val = malloc(len + 2);
			strcpy(*val, aval);
			strcat(*val,"/");
		} else {
			*val = strdup(aval);
		}

		DPRINT(D_DBG, "set %s = %s", name, *val);
	} else {
		DPRINT(D_DBG_V, "default %s = %s", name, *val ? *val : "<null>");
	}
	pscom_info_set(name, *val);
}


void pscom_env_init(void)
{
	pscom_pslib_read_config(ENV_CONFIG_FILES);

	pscom_debug_set_filename(pscom_env_get(ENV_DEBUG_OUT), 1);
	if (pscom.env.debug == -1) { // only set if pscom_set_debug() was not called before.
		pscom.env.debug = D_ERR; // Default: show errors.
		pscom_env_get_int(&pscom.env.debug, ENV_DEBUG);
	}

	pscom_env_get_str(&pscom.env.debug_timing, ENV_DEBUG_TIMING);
	pscom_dtime_init();

	if (pscom_pslib_available) {
		pscom_env_get_str(&pscom.env.info, ENV_INFO);
		if (pscom.env.info) pscom_info_connect(pscom.env.info);
	}
	pscom_env_get_int(&pscom.env.debug_version, ENV_DEBUG_VERSION);

	DPRINT(D_VERSION, "# Version(PSCOM): %s (%s)" PSCOM_IF_CUDA("+cuda", ""),
	       __DATE__, VC_VERSION);
	pscom_env_get_uint(&pscom.env.so_sndbuf, ENV_SO_SNDBUF);
	pscom_env_get_uint(&pscom.env.so_rcvbuf, ENV_SO_RCVBUF);
	pscom_env_get_int(&pscom.env.tcp_nodelay, ENV_TCP_NODELAY);
	pscom_env_get_uint(&pscom.env.tcp_backlog, ENV_TCP_BACKLOG);

	// pscom_env_get_int(&env.nobgthread, ENV_NOBGTHREAD);
	pscom_env_get_int(&pscom.env.sched_yield, ENV_SCHED_YIELD);
	pscom_env_get_int(&pscom.env.unexpected_receives, ENV_UNEXPECTED_RECEIVES);
	pscom_env_get_uint(&pscom.env.rendezvous_size, ENV_RENDEZVOUS);

#ifdef PSCOM_CUDA_AWARENESS
	pscom_env_get_int(&pscom.env.cuda, ENV_CUDA);

	pscom_env_get_uint(&pscom.env.cuda_sync_memops, ENV_CUDA_SYNC_MEMOPS);

	pscom_env_get_uint(&pscom.env.cuda_aware_shm, ENV_CUDA_AWARE_SHM);
	pscom_env_get_uint(&pscom.env.cuda_aware_openib, ENV_CUDA_AWARE_OPENIB);
	pscom_env_get_uint(&pscom.env.cuda_aware_ucp, ENV_CUDA_AWARE_UCP);

	/* one environment variable disabling CUDA-awareness of all plugins */
	pscom_env_get_uint(&pscom.env.cuda_aware_plugins, ENV_CUDA_AWARE_PLUGINS);
	if (pscom.env.cuda_aware_plugins == 0) {
		pscom.env.cuda_aware_shm    = 0;
		pscom.env.cuda_aware_openib = 0;
		pscom.env.cuda_aware_ucp    = 0;
	}
#endif

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_shm = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_shm, ENV_RENDEZVOUS_SHM);

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_dapl = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_dapl, ENV_RENDEZVOUS_DAPL);

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_elan = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_elan, ENV_RENDEZVOUS_ELAN);

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_extoll = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_extoll, ENV_RENDEZVOUS_EXTOLL);

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_velo = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_velo, ENV_RENDEZVOUS_VELO);

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_openib = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_openib, ENV_RENDEZVOUS_OPENIB);

	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_ucp = pscom.env.rendezvous_size;
	pscom_env_get_uint(&pscom.env.rendezvous_size_ucp, ENV_RENDEZVOUS_UCP);

	pscom_env_get_int(&pscom.env.sigquit, ENV_SIGQUIT);
	pscom_env_get_int(&pscom.env.sigsuspend, ENV_SIGSUSPEND);
	pscom_env_get_uint(&pscom.env.readahead, ENV_READAHEAD);
	pscom_env_get_uint(&pscom.env.retry, ENV_RETRY);
	pscom.env.readahead = pscom_max(pscom.env.readahead, (unsigned)sizeof(pscom_header_net_t));

	pscom_env_get_uint(&pscom.env.guard, ENV_GUARD);

	pscom_env_get_str(&pscom.env.network, ENV_NETWORK);
	pscom_env_get_dir(&pscom.env.plugindir, ENV_PLUGINDIR);

	pscom_env_get_int(&pscom.env.debug_req, ENV_DEBUG_REQ);
	pscom_env_get_int(&pscom.env.debug_stats, ENV_DEBUG_STATS);
	pscom_env_get_int(&pscom.env.debug_contype, ENV_DEBUG_CONTYPE);
	pscom_env_get_int(&pscom.env.debug_suspend, ENV_DEBUG_SUSPEND);
	pscom_env_get_int(&pscom.env.debug_precon, ENV_DEBUG_PRECON);

	pscom_env_get_uint(&pscom.env.iprobe_count, ENV_IPROBE_COUNT);
}
