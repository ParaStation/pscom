/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_util.h"
#include <errno.h>
#include <stdlib.h>
#include "pscom_priv.h"
#include "vc_version.h"
#include "pslib.h"


static pscom_env_table_entry_t pscom_env_table [] = {
	{"DEBUG",  PSCOM_MAKE_STRING(D_ERR),
	 "Logging level defining which messages will be printed:\n"
	 "  PSP_DEBUG=0 only fatal conditions (like detected bugs)\n"
	 "  PSP_DEBUG=1 fatal conditions + errors (default)\n"
	 "  PSP_DEBUG=2 + warnings\n"
	 "  PSP_DEBUG=3 + information\n"
	 "  PSP_DEBUG=4 + debug\n"
	 "  PSP_DEBUG=5 + verbose debug\n"
	 "  PSP_DEBUG=6 + tracing calls\n",
	 &pscom.env.debug, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"DEBUG_OUT", NULL,
	 "Debug file name with shell-like expansion of the value (wordexp(8)). "
	 "(e.g., 'log_${PMI_RANK}_$$')",
	 &pscom.env.debug_out, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_STR},

	{"DEBUG_REQ", "0",
	 "Manage a list of all requests for debug dumps. This has a "
	 "performance impact if enabled.",
	 &pscom.env.debug_req, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"TCP_BACKLOG", "262144",
	 "The TCP backlog of the listening socket.",
	 &pscom.env.tcp_backlog, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"UNEXPECTED_RECEIVES", "0",
	 "Enabled/disable receive from connections without outstaing receive "
	 "requests.",
	 &pscom.env.unexpected_receives, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"SCHED_YIELD", "0",
	 "Schedule with sched_yield() instead of busy polling.",
	 &pscom.env.sched_yield, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"RENDEZVOUS", PSCOM_ENV_UINT_INF_STR,
	 "The global rendezvous threshold (may be overwritten by "
	 "plugin-specific configuration).",
	 &pscom.env.rendezvous_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_SHM", "inf",
	 "The rendezvous threshold for pscom4shm.",
	 &pscom.env.rendezvous_size_shm, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_DAPL", "inf",
	 "The rendezvous threshold for pscom4dapl.",
	 &pscom.env.rendezvous_size_dapl, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_ELAN", "inf",
	 "The rendezvous threshold for pscom4elan.",
	 &pscom.env.rendezvous_size_elan, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_EXTOLL", "inf",
	 "The rendezvous threshold for pscom4extoll.",
	 &pscom.env.rendezvous_size_extoll, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_VELO", "1024",
	 "The rendezvous threshold for pscom4velo.",
	 &pscom.env.rendezvous_size_velo, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_OPENIB", "40000",
	 "The rendezvous threshold for pscom4openib.",
	 &pscom.env.rendezvous_size_openib, PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS_UCP", "inf",
	 "The rendezvous threshold for pscom4ucp.",
	 &pscom.env.rendezvous_size_ucp, PSCOM_ENV_PARSER_UINT},

	{"PSM_UNIQ_ID", "0",
	 "Unsigned integer used to seed the PSM UUID. If unset or zero, PMI_ID "
	 "is checked. If also unset or zero, a constant seed is used.",
	 &pscom.env.psm_uniq_id, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},
/*
	{"PSM_DEVCHECK", "1",
	 "Enable/disable checking for any of the following device files:"
	 "/dev/ipath{,0,1},/dev/hfi{1,2}{,_0,_1,_2}",
	 NULL, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"MXM_DEVCHECK", "1",
	 "Enable/disable checking for any of the following device files:"
	 "/sys/class/infiniband/mlx5_{0,1,2}",
	 NULL, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},
*/
	{"PSM_FASTINIT", "1",
	 "If enabled, psm2_init() is called from within pscom4psm plugin init, "
	 "otherwise on first usage of a pscom4psm connection.",
	 &pscom.env.psm_fastinit, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"PSM_CLOSE_DELAY", "1000",
	 "Delayed call to psm2_ep_disconnect2() in milliseconds.",
	 &pscom.env.psm_close_delay, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"UCP_MAX_RECV", "inf",
	 "Limit the number of outstanding receive requests that are handled by "
	 "the pscom4ucp plugin concurrently.",
	 &pscom.env.ucp_max_recv, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"UCP_FASTINIT", "1",
	 "If enabled, ucp_init() is called from within pscom4ucp plugin init, "
	 "otherwise on first usage of a pscom4ucp connection.",
	 &pscom.env.ucp_fastinit, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"SIGQUIT", "0",
	 "Debug output on signal SIGQUIT.",
	 &pscom.env.sigquit, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"SIGSUSPEND", "0",
	 "Signal number to listen on for connection suspend.",
	 &pscom.env.sigsuspend, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"SIGSEGV", "1",
	 "Dump stack backtrace on SIGSEGV.",
	 &pscom.env.sigsegv, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"READAHEAD", "350",
	 "Size of the connections' readahead buffer in byte",
	 &pscom.env.readahead, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"SKIPBLOCKSIZE", "8192",
	 "---- TODO ----",
	 &pscom.env.skipblocksize, PSCOM_ENV_ENTRY_HIDDEN,
	 PSCOM_ENV_PARSER_UINT},

	{"RETRY", "10",
	 "Retry counter for connect() calls.",
	 &pscom.env.retry, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"GUARD", "1",
	 "Enable/disable the connection guards for the detection of failing "
	 "peer processes",
	 &pscom.env.guard, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"IPROBE_COUNT", "0",
	 "Number of iterations that pscom_iprobe() will iterate without "
	 "progess.",
	 &pscom.env.iprobe_count, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"NETWORK", NULL,
	 "Chose a network (i.e., netmask) for TCP communication.",
	 &pscom.env.network, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_STR},

	{"INFO", NULL,
	 "---- TODO ----",
	 &pscom.env.info, PSCOM_ENV_ENTRY_HIDDEN,
	 PSCOM_ENV_PARSER_STR},

	{"PLUGINDIR", "",
	 "The path were to find pscom plugins to be loaded.",
	 &pscom.env.plugindir, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_DIR},

	{"DEBUG_TIMING", NULL,
	 "Optional debug output with timing:\n"
	 "  0       off (default)\n"
	 "  1/'us'  'ssss.uuuuuu' seconds and microseconds since pscom_init\n"
	 "  'date'  'YYYY-MM-DD_hh:mm:ss.uuuuuu' in localtime\n"
	 "  'wall'  'ssss.uuuuuu' seconds and microseconds since the Epoch\n"
	 "  'delta' 'ssss.uuuuuu' seconds and microseconds since last log",
	 &pscom.env.debug_timing, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_STR},

	{"DEBUG_VERSION", "0",
	 "Always show the pscom version string.",
	 &pscom.env.debug_version, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"DEBUG_STATS", "0",
	 "Collect and print statistics on exit.",
	 &pscom.env.debug_stats, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"DEBUG_CONTYPE", "0",
	 "Show the connection types being used.",
	 &pscom.env.debug_contype, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"DEBUG_SUSPEND", "0",
	 "Show suspend information (possible values: 1 or 2).",
	 &pscom.env.debug_suspend, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"DEBUG_PRECON", "0",
	 "Trace the pre-connection handshake.",
	 &pscom.env.debug_precon, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

#ifdef PSCOM_CUDA_AWARENESS
	{"CUDA", "0",
	 "Enable/disable CUDA awareness.",
	 &pscom.env.cuda, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},
#endif /* PSCOM_CUDA_AWARENESS */

	{NULL},
};

PSCOM_API_EXPORT
char *(*pscom_env_get)(const char *name) = getenv;

PSCOM_API_EXPORT
int (*pscom_env_set)(const char *name, const char *value, int overwrite) = setenv;


PSCOM_API_EXPORT
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


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_set_config_int(void *buf,
					    const char *config_val)
{
	int *config_var = (int*)(buf);
	pscom_err_t ret = PSCOM_SUCCESS;

	if (sscanf(config_val, "%d", config_var) <= 0) {
		ret = PSCOM_ERR_INVALID;
	}

	return ret;
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_get_config_int(void *buf, char *val,
					    size_t max_len)
{
	int *config_var = (int*)(buf);
	snprintf(val, max_len, "%d", *config_var);

	return PSCOM_SUCCESS;
}


PSCOM_API_EXPORT
void pscom_env_get_uint(unsigned int *val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = atoi(aval);
		DPRINT(D_DBG, "set %s = %u", name, *val);
	} else {
		if (*val != PSCOM_ENV_UINT_AUTO) {
			DPRINT(D_DBG_V, "default %s = %u", name, *val);
		} else {
			DPRINT(D_DBG_V, "default %s = auto", name);
		}
	}
	pscom_info_set_uint(name, *val);
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_set_config_uint(void *buf,
					     const char *config_val)
{
	unsigned int *config_var = (unsigned int*)(buf);
	pscom_err_t ret = PSCOM_SUCCESS;

	if (!strcasecmp(config_val, PSCOM_ENV_UINT_INF_STR)) {
		*config_var = PSCOM_ENV_UINT_INF;
	} else if (!strcasecmp(config_val, PSCOM_ENV_UINT_AUTO_STR)) {
		*config_var = PSCOM_ENV_UINT_AUTO;
	} else {
		if (sscanf(config_val, "%u", config_var) <= 0) {
			ret = PSCOM_ERR_INVALID;
		}
	}

	return ret;
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_get_config_uint(void *buf,
					     char *val, size_t max_len)
{
	unsigned int *config_var = (unsigned int*)(buf);

	if (*config_var == PSCOM_ENV_UINT_INF) {
		snprintf(val, max_len, PSCOM_ENV_UINT_INF_STR);
	} else if (*config_var == PSCOM_ENV_UINT_AUTO) {
		snprintf(val, max_len, PSCOM_ENV_UINT_AUTO_STR);
	} else {
		snprintf(val, max_len, "%u", *config_var);
	}

	return PSCOM_SUCCESS;
}


PSCOM_API_EXPORT
void pscom_env_get_size_t(size_t *val, const char *name)
{
	char *aval;

	aval = pscom_env_get(name);
	if (aval) {
		*val = atoll(aval);
		DPRINT(D_DBG, "set %s = %zu", name, *val);
	} else {
		if (*val != PSCOM_ENV_SIZE_T_AUTO) {
			DPRINT(D_DBG_V, "default %s = %zu", name, *val);
		} else {
			DPRINT(D_DBG_V, "default %s = auto", name);
		}
	}
	pscom_info_set_size_t(name, *val);
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_set_config_size_t(void *buf,
					       const char *config_val)
{
	size_t *config_var = (size_t*)(buf);
	pscom_err_t ret = PSCOM_SUCCESS;

	if (sscanf(config_val, "%lu", config_var) <= 0) {
		ret = PSCOM_ERR_INVALID;
	}

	return ret;
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_get_config_size_t(void *buf,
					       char *val, size_t max_len)
{
	size_t *config_var = (size_t*)(buf);
	snprintf(val, max_len, "%lu", *config_var);

	return PSCOM_SUCCESS;
}


PSCOM_API_EXPORT
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


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_set_config_str(void *buf,
					    const char *config_val)
{
	char **config_var = (char**)(buf);

	*config_var = (char*)config_val;

	return 0;
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_get_config_str(void *buf,
					    char *val, size_t max_len)
{
	char **config_var = (char**)(buf);
	snprintf(val, max_len, "%s", *config_var ? *config_var : "(null)");

	return PSCOM_SUCCESS;
}


PSCOM_API_EXPORT
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


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_set_config_dir(void *buf,
					    const char *config_val)
{
	char **config_var = (char**)(buf);
	size_t len = 0;

	if ((len = strlen(config_val)) && (config_val[len - 1] != '/')) {
		// append a '/'
		*config_var = malloc(len + 2);
		strcpy(*config_var, config_val);
		strcat(*config_var, "/");
	} else {
		*config_var = strdup(config_val);
	}

	return PSCOM_SUCCESS;
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_parser_get_config_dir(void *buf,
					    char *val, size_t max_len)
{
	char **config_var = (char**)(buf);
	snprintf(val, max_len, "%s", *config_var ? *config_var : "(null)");

	return PSCOM_SUCCESS;
}


PSCOM_API_EXPORT
void pscom_env_psm_fastinit_set(unsigned int psm_fastinit)
{
	pscom.env.psm_fastinit = psm_fastinit;
}


PSCOM_API_EXPORT
void pscom_env_ucp_fastinit_set(unsigned int ucp_fastinit)
{
	pscom.env.ucp_fastinit = ucp_fastinit;
}


void pscom_env_init(void)
{
	pscom_pslib_read_config(ENV_CONFIG_FILES);

	pscom_env_table_register_and_parse("pscom general", NULL,
					   pscom_env_table);
	pscom_debug_set_filename(pscom.env.debug_out, 1);

	pscom_dtime_init();

	if (pscom_pslib_available) {
		pscom_env_get_str(&pscom.env.info, ENV_INFO);
		if (pscom.env.info) pscom_info_connect(pscom.env.info);
	}

	DPRINT(D_VERSION, "# Version(PSCOM): %s (%s)" PSCOM_IF_CUDA("+cuda", "")
#ifdef PSCOM_ALLIN
	       "+allin"
#endif
	       ,__DATE__, VC_VERSION);



	/* TODO:
	 * Move pluging-specific configuration parameters to the respective
	 * plugins. Then we can avoid reading these environment variables again
	 */
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

	/* the readahead buffer has to store the pscom_header_net  at least*/
	pscom.env.readahead = pscom_max(pscom.env.readahead,
					(unsigned)sizeof(pscom_header_net_t));
}


void pscom_env_cleanup(void)
{
	pscom_env_table_list_clear();
}


static
pscom_err_t pscom_env_entry_parse(pscom_env_table_entry_t *env_entry,
				  const char *env_val)
{
	pscom_err_t ret = PSCOM_SUCCESS;

	/* some error checking */
	if (env_entry->config_var == NULL) {
		DPRINT(D_ERR, "The configuration variable for '%s' is missing.",
		       env_entry->name);
		goto err_out;
	} else if (env_entry->parser.set == NULL) {
		DPRINT(D_ERR, "A valid setter for '%s' is missing.",
		       env_entry->name);
		goto err_out;
	}

	/* determine if an env_val was given or the default shall be used */
	const char *val_to_parse = env_val ? env_val : env_entry->default_val;

	/* parse the value */
        ret = env_entry->parser.set(env_entry->config_var, val_to_parse);

	return ret;
	/* --- */
err_out:
	return PSCOM_ERR_INVALID;
}

static
char *pscom_env_get_with_prefix(const char *prefix,
			        const char *sub_prefix,
                                const char *name,
				char *env_var_str,
				size_t env_var_str_len)
{
	char env_var[PSCOM_ENV_MAX_ENV_LEN];

	/* generate the environment variable string */
	snprintf(env_var, sizeof(env_var), "%s%s%s",
		 prefix ? prefix : "",
		 sub_prefix ? sub_prefix : "", name);

	/* copy environment variable string if requested */
	if (env_var_str) {
		strncpy(env_var_str, env_var, env_var_str_len);
	}

	return getenv(env_var);
}

pscom_err_t pscom_env_table_parse(pscom_env_table_entry_t *table,
				  const char *prefix,
				  const char *sub_prefix,
				  const char *name)
{
	char env_var[PSCOM_ENV_MAX_ENV_LEN];
	char *env_val;
	char *env_val_parent;
	pscom_env_table_entry_t *cur_entry;
	pscom_err_t ret = PSCOM_SUCCESS;

	if (table == NULL) {
		goto err_out;
	}

	for (cur_entry = table; cur_entry->name != NULL; ++cur_entry) {
		pscom_err_t parse_ret = PSCOM_SUCCESS;

		/* retrieve environment variable and potential parent */
		env_val = pscom_env_get_with_prefix(prefix, sub_prefix,
						    cur_entry->name, env_var,
						    sizeof(env_var));
		env_val_parent = pscom_env_get_with_prefix(prefix, NULL,
							   cur_entry->name,
							   NULL, 0);

		if (env_val) {
			/* use the value from the environment */
			parse_ret = pscom_env_entry_parse(cur_entry, env_val);
		} else if ((cur_entry->flags & PSCOM_ENV_ENTRY_HAS_PARENT) &&
			   env_val_parent) {
			/* use the value from the environment (parent) */
			parse_ret = pscom_env_entry_parse(cur_entry,
							  env_val_parent);
		}
		ret = (ret != PSCOM_SUCCESS) ? ret : parse_ret;


		if (parse_ret != PSCOM_SUCCESS) {
                        DPRINT(D_WARN, "Could not parse '%s' for '%s': %d",
                               env_val ? env_val : env_val_parent, env_var,
                               ret);
                }

		/*
		 * use the default value if no environment variable is set or
		 * something went wrong
		 */
		if ((parse_ret != PSCOM_SUCCESS) ||
		    !(env_val || env_val_parent)) {
			parse_ret = pscom_env_entry_parse(cur_entry, NULL);

			DPRINT(D_DBG_V, "default %s = %s", env_var,
					cur_entry->default_val);
		} else {
			/* retrieve the actual value */
			char val_str[PSCOM_ENV_MAX_VAL_LEN];
			cur_entry->parser.get((void *)cur_entry->config_var,
					      val_str, PSCOM_ENV_MAX_VAL_LEN);

			DPRINT(D_DBG, "set %s = %s (%sdefault: %s)", env_var,
			       val_str,
			       env_val ? "" : "via parent; ",
			       cur_entry->default_val);

		}

		ret = (ret != PSCOM_SUCCESS) ? ret : parse_ret;
	}

	if (ret != PSCOM_SUCCESS) {
		goto err_out;
	}

	return ret;
	/* --- */

err_out:
	DPRINT(D_ERR, "Error while parsing table '%s'.", name);
	return PSCOM_ERR_INVALID;
}


pscom_err_t pscom_env_table_register(const char *name, const char *prefix,
				     pscom_env_table_entry_t *table)
{
	/* temporary list for initialization of const members */
	pscom_env_list_entry_t tmp_entry = {
		.name = name,
		.prefix = prefix,
		.table = table,
	};

	/* create a new list entry */
	pscom_env_list_entry_t *list_entry;
	list_entry = (pscom_env_list_entry_t*)malloc(sizeof(*list_entry));
	if (!list_entry) {
		goto err_nomem;
	}

	/* initialize the list entry */
	memcpy(list_entry, &tmp_entry, sizeof(pscom_env_list_entry_t));
	INIT_LIST_HEAD(&list_entry->next);

	/* add the list entry to the global list */
	list_add_tail(&list_entry->next, &pscom.env_config);

	return PSCOM_SUCCESS;
	/* --- */

err_nomem:
	errno = ENOMEM;
	return PSCOM_ERR_STDERROR;
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_env_table_register_and_parse(const char *name,
					       const char *prefix,
					       pscom_env_table_entry_t *table)
{
	pscom_err_t ret = PSCOM_SUCCESS;

	/* first register the table with the global list */
	ret = pscom_env_table_register(name, prefix, table);
	if (ret != PSCOM_SUCCESS) {
		goto out;
	}

	/* now parse it to actually set the configuration paramters */
	ret = pscom_env_table_parse(table, PSCOM_ENV_GLOBAL_PREFIX,
				    prefix, name);

out:
	return ret;
}


void pscom_env_table_list_clear(void)
{
	struct list_head *pos, *next;

	/* cycle through the list and release the tables */
	list_for_each_safe(pos, next, &pscom.env_config) {
		pscom_env_list_entry_t *list_entry =
			list_entry(pos, pscom_env_list_entry_t, next);

		list_del_init(&list_entry->next);
		free(list_entry);
	}

	/* re-initialize the global list */
	INIT_LIST_HEAD(&pscom.env_config);
}


void pscom_env_entry_print(pscom_env_table_entry_t *entry, const char *prefix,
			   pscom_env_print_flags_t flags)
{
	char entry_and_value[PSCOM_ENV_MAX_ENV_LEN+PSCOM_ENV_MAX_VAL_LEN];
	char val_str[PSCOM_ENV_MAX_VAL_LEN];
	char default_val_str[PSCOM_ENV_MAX_ENV_LEN+PSCOM_ENV_MAX_VAL_LEN];

	/* retrieve the current and default value of the entry */
	entry->parser.get((void *)entry->config_var, val_str,
			  PSCOM_ENV_MAX_VAL_LEN);

	if (flags & PSCOM_ENV_PRINT_DOC) {
		pscom_dwrite(stdout, "#", 1, _pscom_debug_linefmt_disabled());
		pscom_dwrite(stdout, entry->help_str, strlen(entry->help_str),
			     _pscom_debug_linefmt_custom("# ", NULL));
		pscom_dwrite(stdout, "#", 1, _pscom_debug_linefmt_disabled());

		/* print the default value */
		snprintf(default_val_str, sizeof(default_val_str),
			 "# default: %s", entry->default_val);
		pscom_dwrite(stdout, default_val_str, sizeof(default_val_str),
			     _pscom_debug_linefmt_disabled());

		/* print inheritance information */
		if (entry->flags & PSCOM_ENV_ENTRY_HAS_PARENT) {
			snprintf(default_val_str, sizeof(default_val_str),
				"# inherits from: %s%s",
				PSCOM_ENV_GLOBAL_PREFIX, entry->name);
			pscom_dwrite(stdout, default_val_str,
				     sizeof(default_val_str),
				     _pscom_debug_linefmt_disabled());
		}

		pscom_dwrite(stdout, "#", 1, _pscom_debug_linefmt_disabled());
	}

	/* print the current configuration value */
	snprintf(entry_and_value, sizeof(entry_and_value), "%s%s%s=%s\n",
		 PSCOM_ENV_GLOBAL_PREFIX, prefix ? prefix : "",
		 entry->name, val_str);
	pscom_dwrite(stdout, entry_and_value, sizeof(entry_and_value),
		     _pscom_debug_linefmt_disabled());

	/* add a newline if we print the documentation */
	if (flags & PSCOM_ENV_PRINT_DOC) {
		pscom_dwrite(stdout, " ", 1, _pscom_debug_linefmt_disabled());
	}
}


void pscom_env_table_print(const char *name, const char *prefix,
			   pscom_env_table_entry_t *table,
			   pscom_env_print_flags_t flags)
{
	/* print the table header */
	char table_header[100];
	snprintf(table_header, sizeof(table_header),
		 "##\n"
		 "### %s\n"
		 "##\n"
		 " \n",
		 name);
	pscom_dwrite(stdout, table_header, strlen(table_header),
		     _pscom_debug_linefmt_disabled());

	/* print the table entries */
	pscom_env_table_entry_t *cur_entry;
	for (cur_entry = table; cur_entry->name != NULL; ++cur_entry) {
		if ((flags & PSCOM_ENV_PRINT_HIDDEN) ||
		    !(cur_entry->flags & PSCOM_ENV_ENTRY_HIDDEN)) {
			pscom_env_entry_print(cur_entry, prefix, flags);
		}
	}

	/* add a new line after each table */
	pscom_dwrite(stdout, " \n", 2,
		     _pscom_debug_linefmt_disabled());
}


PSCOM_API_EXPORT
void pscom_env_table_list_print(pscom_env_print_flags_t flags)
{
	struct list_head *pos, *next;

	/* check if the configuration shall be printed at all */
	if (!(flags & PSCOM_ENV_PRINT_CONFIG)) return;

	/* cycle through the list and release the tables */
	list_for_each_safe(pos, next, &pscom.env_config) {
		pscom_env_list_entry_t *list_entry =
			list_entry(pos, pscom_env_list_entry_t, next);

		pscom_env_table_print(list_entry->name, list_entry->prefix,
				      list_entry->table, flags);
	}

}
