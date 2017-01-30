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
		DPRINT(1, "set %s = %d", name, *val);
	} else {
		DPRINT(2, "default %s = %d", name, *val);
	}
	pscom_info_set_int(name, *val);
}


void pscom_env_get_uint(unsigned int *val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = atoi(aval);
		DPRINT(1, "set %s = %u", name, *val);
	} else {
		if (*val != ENV_UINT_AUTO) {
			DPRINT(2, "default %s = %u", name, *val);
		} else {
			DPRINT(2, "default %s = auto", name);
		}
	}
	pscom_info_set_uint(name, *val);
}


void pscom_env_get_str(char **val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = aval;
		DPRINT(1, "set %s = %s", name, *val);
	} else {
		DPRINT(2, "default %s = %s", name, *val ? *val : "<null>");
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

		DPRINT(1, "set %s = %s", name, *val);
	} else {
		DPRINT(2, "default %s = %s", name, *val ? *val : "<null>");
	}
	pscom_info_set(name, *val);
}


void pscom_env_init(void)
{
	pscom_pslib_read_config(ENV_CONFIG_FILES);

	pscom_debug_set_filename(pscom_env_get(ENV_DEBUG_OUT), 1);
	if (!pscom.env.debug) { // only set debug once!
		pscom_env_get_int(&pscom.env.debug, ENV_DEBUG);
	}

	if (pscom_pslib_available) {
		pscom_env_get_str(&pscom.env.info, ENV_INFO);
		if (pscom.env.info) pscom_info_connect(pscom.env.info);
	}

	DPRINT(1,"# Version(PSCOM): %s (%s)", __DATE__, VC_VERSION);
	pscom_env_get_uint(&pscom.env.so_sndbuf, ENV_SO_SNDBUF);
	pscom_env_get_uint(&pscom.env.so_rcvbuf, ENV_SO_RCVBUF);
	pscom_env_get_int(&pscom.env.tcp_nodelay, ENV_TCP_NODELAY);
	pscom_env_get_uint(&pscom.env.tcp_backlog, ENV_TCP_BACKLOG);

	// pscom_env_get_int(&env.nobgthread, ENV_NOBGTHREAD);
	pscom_env_get_int(&pscom.env.sched_yield, ENV_SCHED_YIELD);
	pscom_env_get_int(&pscom.env.unexpected_receives, ENV_UNEXPECTED_RECEIVES);
	pscom_env_get_uint(&pscom.env.rendezvous_size, ENV_RENDEZVOUS);

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

	if (pscom.env.debug >= 2) pscom.env.debug_stats = 1;
	pscom_env_get_int(&pscom.env.debug_stats, ENV_DEBUG_STATS);
	pscom_env_get_uint(&pscom.env.iprobe_count, ENV_IPROBE_COUNT);
}
