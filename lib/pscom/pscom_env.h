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

#ifndef _PSCOM_ENV_H_
#define _PSCOM_ENV_H_

#include "pscom.h"
#include "list.h"

/* Set debuglevel */
#define ENV_DEBUG     "PSP_DEBUG"
/* output filename */
#define ENV_DEBUG_OUT "PSP_DEBUG_OUT"

/* Add timing to debug output:
   0		off (default),
   1,"us"	"ssss.uuuuuu" seconds and microseconds since pscom_init
   "date"	"YYYY-MM-DD_hh:mm:ss.uuuuuu" in localtime
   "wall"	"ssss.uuuuuu" seconds and microseconds since the Epoch
   "delta"	"ssss.uuuuuu" seconds and microseconds since last log
*/
#define ENV_DEBUG_TIMING "PSP_DEBUG_TIMING"
#define ENV_INFO "PSP_INFO"

#define ENV_CONFIG_FILES "/dev/environment:.parastation:$HOME/.parastation:/etc/pscom.conf"

#define ENV_NETWORK "PSP_NETWORK"

/* Socket options */
#define ENV_SO_SNDBUF "PSP_SO_SNDBUF"
#define ENV_SO_RCVBUF "PSP_SO_RCVBUF"
#define ENV_TCP_NODELAY "PSP_TCP_NODELAY"
#define ENV_TCP_BACKLOG "PSP_TCP_BACKLOG"
#define ENV_TCP_ACCEPT_BACKLOG "PSP_TCP_ACCEPT_BACKLOG"

/* Receive from a connection without receives posted? 0: No 1: Yes */
#define ENV_UNEXPECTED_RECEIVES "PSP_UNEXPECTED_RECEIVES"
/* Call sched_yield() inside idle loop? 0: No 1: Yes. Default: 0 */
#define ENV_SCHED_YIELD "PSP_SCHED_YIELD"
/* Start rendezvous at messagesize x. Default ~0 = never */
#define ENV_RENDEZVOUS "PSP_RENDEZVOUS"
/* ENV_RENDEZVOUS_xxx: Messagesize for arch xxx.
   Default to ENV_RENDEZVOUS */
#define ENV_RENDEZVOUS_SHM "PSP_RENDEZVOUS_SHM"
#define ENV_RENDEZVOUS_DAPL "PSP_RENDEZVOUS_DAPL"
#define ENV_RENDEZVOUS_ELAN "PSP_RENDEZVOUS_ELAN"
#define ENV_RENDEZVOUS_EXTOLL "PSP_RENDEZVOUS_EXTOLL"
#define ENV_RENDEZVOUS_VELO "PSP_RENDEZVOUS_VELO"
#define ENV_RENDEZVOUS_OPENIB "PSP_RENDEZVOUS_OPENIB"
#define ENV_RENDEZVOUS_UCP "PSP_RENDEZVOUS_UCP"

/* Used in constructing the UUID for QLogic */
#define ENV_PSM_UNIQ_ID "PSP_PSM_UNIQ_ID"
#define ENV_PSM_DEVCHECK "PSP_PSM_DEVCHECK"
#define ENV_PSM_FASTINIT "PSP_PSM_FASTINIT"
#define ENV_PSM_CLOSE_DELAY "PSP_PSM_CLOSE_DELAY"
#define ENV_PMI_ID "PMI_ID"

/* UCP */
#define ENV_UCP_MAX_RECV "PSP_UCP_MAX_RECV"
#define ENV_UCP_FASTINIT "PSP_UCP_FASTINIT"

/* MXM */
#define ENV_MXM_DEVCHECK "PSP_MXM_DEVCHECK"

/* Debugoutput on signal SIGQUIT (i386:3) (key: ^\) */
#define ENV_SIGQUIT "PSP_SIGQUIT"
/* signal number to listen on for connection suspend */
#define ENV_SIGSUSPEND "PSP_SIGSUSPEND"
/* Dump stack backtrace on SIGSEGV */
#define ENV_SIGSEGV "PSP_SIGSEGV"
#define ENV_READAHEAD "PSP_READAHEAD"
#define ENV_RETRY "PSP_RETRY"
/* reconnect a precon after a connect() error after PSP_RECONNECT_TIMEOUT [ms] */
#define ENV_RECONNECT_TIMEOUT	"PSP_RECONNECT_TIMEOUT"
/* Declare after (PSP_CONNECT_STALLED * PSP_RECONNECT_TIMEOUT)[ms] without any received bytes the connect() as failed. Retry. */
#define ENV_CONNECT_STALLED_MAX	"PSP_CONNECT_STALLED"

/* Enable/Disable the connection guard */
#define ENV_GUARD "PSP_GUARD"

#define ENV_PLUGINDIR "PSP_PLUGINDIR"
#define ENV_ARCH_PREFIX "PSP_"

/* Use this, if ENV_ARCH_NEW_SHM is not set */
#define ENV_ARCH_OLD_SHM "PSP_SHAREDMEM"
#define ENV_ARCH_NEW_SHM ENV_ARCH_PREFIX "SHM"

/* Use this, if ENV_ARCH_NEW_P4S is not set */
#define ENV_ARCH_OLD_P4S "PSP_P4SOCK"
#define ENV_ARCH_NEW_P4S ENV_ARCH_PREFIX "P4S"

/* The DAPL Provider to use */
#define ENV_DAPL_PROVIDER "PSP_DAPL_PROVIDER"

/* OpenIB HCA and port */
#define ENV_OPENIB_HCA "PSP_OPENIB_HCA"   /* default: first hca */
#define ENV_OPENIB_PORT "PSP_OPENIB_PORT" /* default: port 1 */
#define ENV_OPENIB_PATH_MTU "PSP_OPENIB_PATH_MTU" /* default: 3
						     1 : IBV_MTU_256
						     2 : IBV_MTU_512
						     3 : IBV_MTU_1024 */
#define ENV_OPENIB_SENDQ_SIZE "PSP_OPENIB_SENDQ_SIZE"
#define ENV_OPENIB_RECVQ_SIZE "PSP_OPENIB_RECVQ_SIZE"
#define ENV_OPENIB_COMPQ_SIZE "PSP_OPENIB_COMPQ_SIZE"
#define ENV_OPENIB_PENDING_TOKENS "PSP_OPENIB_PENDING_TOKENS"
#define ENV_OPENIB_GLOBAL_SENDQ "PSP_OPENIB_GLOBAL_SENDQ" /* bool: Use one sendq for all connections? default: 0(no) */
#define ENV_OPENIB_EVENT_CNT "PSP_OPENIB_EVENT_CNT" /* bool: Be busy if outstanding_cq_entries is to high? default: 1(yes) */
#define ENV_OPENIB_IGNORE_WRONG_OPCODES "PSP_OPENIB_IGNORE_WRONG_OPCODES" /* bool: ignore wrong cq opcodes */
#define ENV_OPENIB_LID_OFFSET "PSP_OPENIB_LID_OFFSET" /* int: offset to base LID (adaptive routing) */
#define ENV_OPENIB_MCACHE_SIZE "PSP_OPENIB_MCACHE_SIZE" /* uint: max #entries in the memory registration cache. 0:disable cache */
#define ENV_OPENIB_MALLOC_OPTS "PSP_OPENIB_MALLOC_OPTS" /* bool: Set special options for malloc in favor of the registration cache  */
#define ENV_OPENIB_RNDV_FALLBACKS "PSP_OPENIB_RNDV_FALLBACKS" /* bool: Use eager/sw-rndv if memory cannot be registered for rndv? default: 1(yes)*/


/* OFED HCA and port */
#define ENV_OFED_HCA "PSP_OFED_HCA"   /* default: first hca */
#define ENV_OFED_PORT "PSP_OFED_PORT" /* default: port 1 */
#define ENV_OFED_PATH_MTU "PSP_OFED_PATH_MTU" /* default: 3
						 1 : IBV_MTU_256
						 2 : IBV_MTU_512
						 3 : IBV_MTU_1024 */
#define ENV_OFED_SENDQ_SIZE "PSP_OFED_SENDQ_SIZE"
#define ENV_OFED_RECVQ_SIZE "PSP_OFED_RECVQ_SIZE"
#define ENV_OFED_COMPQ_SIZE "PSP_OFED_COMPQ_SIZE"
#define ENV_OFED_PENDING_TOKENS "PSP_OFED_PENDING_TOKENS"
#define ENV_OFED_WINSIZE "PSP_OFED_WINSIZE"
#define ENV_OFED_RESEND_TIMEOUT "PSP_OFED_RESEND_TIMEOUT"
#define ENV_OFED_RESEND_TIMEOUT_SHIFT "PSP_OFED_RESEND_TIMEOUT_SHIFT"


#define ENV_OFED_EVENT_CNT "PSP_OFED_EVENT_CNT" /* bool: Be busy if outstanding_cq_entries is to high? default: 1(yes) */
#define ENV_OFED_LID_OFFSET "PSP_OFED_LID_OFFSET" /* int: offset to base LID (adaptive routing) */

/* Extoll */
#define ENV_EXTOLL_RECVQ_SIZE "PSP_EXTOLL_RECVQ_SIZE"
#define ENV_EXTOLL_SENDQ_SIZE "PSP_EXTOLL_SENDQ_SIZE"
#define ENV_EXTOLL_GLOBAL_SENDQ "PSP_EXTOLL_GLOBAL_SENDQ" /* bool: Use one sendq for all connections? default: 0(no) */
#define ENV_EXTOLL_EVENT_CNT "PSP_EXTOLL_EVENT_CNT" /* bool: Be busy on empty global sendq? default: 0(no) */
#define ENV_EXTOLL_PENDING_TOKENS "PSP_EXTOLL_PENDING_TOKENS"
#define ENV_EXTOLL_MCACHE_SIZE "PSP_EXTOLL_MCACHE_SIZE"

/* Gateway */
#define ENV_GW_SERVER "PSP_GW_SERVER"
#define ENV_GW_MTU "PSP_GW_MTU"
#define ENV_GW_TOKENS "PSP_GW_TOKENS" /* int: # Flow control tokens. 0=disable flow control */
#define ENV_GW_PENDING_TOKENS "PSP_GW_PENDING_TOKENS" /* int: Max pending tokens */

/* Allocate memory in a shared mem segment */
/* "PSP_MALLOC*" settings have to be known already in the __malloc_initialize_hook() before we
   run through pscom_pslib_init(). Therefore they are not printed with PSP_DEBUG > 0 and can only set from
   the environment (not from pslib). */
#define ENV_MALLOC "PSP_MALLOC" /* bool: Use a hook into glibc malloc (__morecore())? default: 1(yes) */
#define ENV_MALLOC_MIN "PSP_MALLOC_MIN" /* ulong: minimum size of the shared mem segment */
#define ENV_MALLOC_MAX "PSP_MALLOC_MAX" /* ulong: maximum size of the shared mem segment */

/* Use shm direct for messages >= PSP_SHM_DIRECT. Set PSP_SHM_DIRECT=-1 to disable shm direct. */
#define ENV_SHM_DIRECT "PSP_SHM_DIRECT" /* min message size to use shm direct */
#define ENV_SHM_INDIRECT "PSP_SHM_INDIRECT" /* min message size for indirect shm (when direct shm fails) */

/* CUDA */
#define ENV_CUDA "PSP_CUDA"
#define ENV_MEMCACHE "PSP_MEMCACHE"
#define ENV_CUDA_SYNC_MEMOPS "PSP_CUDA_SYNC_MEMOPS"
#define ENV_CUDA_ENFORCE_STAGING "PSP_CUDA_ENFORCE_STAGING"
#define ENV_CUDA_AWARE_SHM "PSP_CUDA_AWARE_SHM"
#define ENV_CUDA_AWARE_OPENIB "PSP_CUDA_AWARE_OPENIB"
#define ENV_CUDA_AWARE_UCP "PSP_CUDA_AWARE_UCP"
#define ENV_CUDA_AWARE_VELO "PSP_CUDA_AWARE_VELO"
#define ENV_CUDA_AWARE_EXTOLL "PSP_CUDA_AWARE_EXTOLL"

/* Manage a list of all requests for debug dumps (decrease performance!) */
#define ENV_DEBUG_REQ     "PSP_DEBUG_REQ"

/* Show pscom version */
#define ENV_DEBUG_VERSION "PSP_DEBUG_VERSION"

/* Print statistic at the end. */
#define ENV_DEBUG_STATS   "PSP_DEBUG_STATS"

/* Show connection types */
#define ENV_DEBUG_CONTYPE "PSP_DEBUG_CONTYPE"

/* Show suspend/resume signals and messages */
#define ENV_DEBUG_SUSPEND "PSP_DEBUG_SUSPEND"

/* Trace precon calls */
#define ENV_DEBUG_PRECON "PSP_DEBUG_PRECON"


/* make progress every count itteration in iprobe */
#define ENV_IPROBE_COUNT "PSP_IPROBE_COUNT"

#define PSCOM_ENV_SIZE_T_AUTO ((size_t)-1)

#define PSCOM_ENV_UINT_AUTO ((unsigned)-1)
#define PSCOM_ENV_UINT_INF  ((unsigned)-2)

#define PSCOM_ENV_UINT_AUTO_STR "auto"
#define PSCOM_ENV_UINT_INF_STR  "inf"

/* definitions w.r.t. environment variables */
#define PSCOM_ENV_MAX_ENV_LEN    (128)
#define PSCOM_ENV_MAX_VAL_LEN    (32)
#define PSCOM_ENV_MAX_PREFIX_LEN (32)

#define PSCOM_ENV_GLOBAL_PREFIX  "PSP_"

/* forward declarations */
typedef struct pscom_env_table_entry pscom_env_table_entry_t;
typedef struct pscom_env_list_entry pscom_env_list_entry_t;

typedef enum {
	PSCOM_ENV_PRINT_CONFIG         = (1ul << 0),
	PSCOM_ENV_PRINT_DEFAULT_VALUE  = (1ul << 1),
	PSCOM_ENV_PRINT_DOC            = (1ul << 2),
	PSCOM_ENV_PRINT_HIDDEN         = (1ul << 3)
} pscom_env_print_flags_t;

/**
 * @brief Flags influencing the parsing of environment configuration entries
 */
typedef enum pscom_env_table_entry_flags {
	PSCOM_ENV_ENTRY_FLAGS_EMPTY = 0,          /**< No flags set */
	PSCOM_ENV_ENTRY_HAS_PARENT  = (1ul << 0), /**< Entry listens to a parent
	                                               with the same name but no
						       prefix */
	PSCOM_ENV_ENTRY_HIDDEN      = (1ul << 1)  /**< Entry shall not be printed
	                                               by pscom_info without
						       further measures */
} pscom_env_table_entry_flags_t;


/**
 * @brief A routine for setting a configuration variable
 *
 * This routine parses a given string w.r.t. the definitions made in
 * @a env_entry and sets the corresponding configuration variable. It has to be
 * capable of dealing with NULL pointers to the default value.
 *
 * @param [in] buf         Address of the configuration variable to be set.
 * @param [in] config_val  The string value to be parsed.
 *
 * @return 0 If @a config_val could be parsed successfully.
 */
typedef int (*pscom_env_parser_set_t)(void *buf, const char *config_val);

/**
 * @brief A routine for reading a configuration variable
 *
 * This routine parses a given string w.r.t. the definitions made in
 * @a env_entry. It has to be capable of dealing with NULL pointers to the
 * default value.
 *
 * @param [in]  buf     Address of the configuration variable
 *                      definition table.
 * @param [out] val     A string representing the current value of the
 *                      configuration variable.
 * @param [in]  max_len The maximum length of the output buffers.
 *
 * @return 0 If @a config_val could be parsed successfully.
 */
typedef int (*pscom_env_parser_get_t)(void *buf, char *val, size_t max_len);

/**
 * @brief Object for parsing configuration value strings.
 *
 * Each member corresponds to an operation of the parser.
 *
 */
typedef struct pscom_env_parser {
	pscom_env_parser_set_t set; /**< Set the variable corresponding to the
	                                 environment variable */
	pscom_env_parser_get_t get; /**< Get the value of the variable
	                                 corresponding to the environment
					 variable */
} pscom_env_parser_t;

/**
 * @brief An entry of a configuration definition table.
 */
struct pscom_env_table_entry {
	const char *name;                    /**< Name of the environment
	                                          variable excluding the
						  prefix */
	const char *default_val;             /**< Default value */
	const char *help_str;                /**< Documentation of the
	                                          environment variable */
	void *config_var;                    /**< A pointer to the configuration
	                                          variable */
	pscom_env_table_entry_flags_t flags; /**< Flags affecting the parsing */
	pscom_env_parser_t parser;           /**< The parse to be used for
	                                          parsing this configuration
						  parameter */
};

/**
 * @brief An entry in a list of configuration definition tables
 *
 */
struct pscom_env_list_entry {
	const char *name;               /**< Name of the configuration table */
	const char *prefix;             /**< Prefix to be prepended to the table
	                                     entries */
	pscom_env_table_entry_t *table; /**< The actual configuration definition
	                                     table */
	struct list_head next;          /**< Next configuration definition table
	                                     in the list */
};

struct PSCOM_env {
	int		debug;
	int		debug_req;
	char		*debug_out;
	unsigned int	so_sndbuf;
	unsigned int	so_rcvbuf;
	int		tcp_nodelay;
	unsigned int	tcp_backlog;
	unsigned int	precon_reconnect_timeout;
	unsigned int	precon_connect_stalled_max;
	int		unexpected_receives;
	int		sched_yield;
	unsigned int	rendezvous_size;
	unsigned int	rendezvous_size_shm;
	unsigned int	rendezvous_size_dapl;
	unsigned int	rendezvous_size_elan;
	unsigned int	rendezvous_size_extoll;
	unsigned int	rendezvous_size_velo;
	unsigned int	rendezvous_size_openib;
	unsigned int	rendezvous_size_ucp;
	unsigned int	psm_uniq_id;
	unsigned int	psm_fastinit;
	unsigned int	psm_close_delay;
	unsigned int	ucp_max_recv;
	unsigned int	ucp_fastinit;
	int		sigquit;
	int		sigsuspend;
	int		sigsegv;
	unsigned int	readahead;
	unsigned int	retry;
	unsigned int	connect_timeout;
	unsigned int	guard;
	unsigned int	skipblocksize;
	unsigned int	iprobe_count;

	char		*network;
	char		*info;
	char		*plugindir;

	char		*debug_timing;
	int		debug_version;
	int		debug_stats;
	int		debug_contype;
	int		debug_suspend;
	int		debug_precon;
#ifdef PSCOM_CUDA_AWARENESS
	int             cuda;
	unsigned int 	cuda_sync_memops;
	unsigned int 	cuda_enforce_staging;
	unsigned int 	cuda_aware_shm;
	unsigned int 	cuda_aware_openib;
	unsigned int 	cuda_aware_ucp;
	unsigned int 	cuda_aware_velo;
	unsigned int 	cuda_aware_extoll;
#endif
};


#ifdef PSCOM_CUDA_AWARENESS
#define PSCOM_ENV_CUDA		 \
	.cuda                 = 0, \
	.cuda_sync_memops     = 1, \
	.cuda_enforce_staging = 0, \
	.cuda_aware_shm       = 1, \
	.cuda_aware_openib    = 1, \
	.cuda_aware_ucp       = 1, \
	.cuda_aware_velo      = 1, \
	.cuda_aware_extoll    = 1
#else
#define PSCOM_ENV_CUDA
#endif


#define PSCOM_ENV_defaults {						\
	.debug = -1, /* default D_ERR set in pscom_env_init()! */	\
	.debug_req = 0,							\
									\
	.so_sndbuf = 32768,						\
	.so_rcvbuf = 32768,						\
	.tcp_nodelay = 1,						\
	.tcp_backlog = 262144 /*SOMAXCONN = 128 */,			\
	.precon_reconnect_timeout = 2000, /* try reconnect in [ms] */	\
	.precon_connect_stalled_max = 6,				\
									\
	.unexpected_receives = 0,					\
	.sched_yield = 0,						\
	.rendezvous_size = ~0U,						\
	.rendezvous_size_shm = ~0U, /* default rendezvous_size for shm */ \
	.rendezvous_size_dapl = ~0U, /* default rendezvous_size for dapl */ \
	.rendezvous_size_elan = ~0U, /* default rendezvous_size for elan */ \
	.rendezvous_size_extoll = ~0U, /* default rendezvous_size for extoll */ \
	.rendezvous_size_velo = 1024, /* default rendezvous_size for velo */ \
	.rendezvous_size_openib = 40000, /* default rendezvous_size for openib */ \
	.rendezvous_size_ucp = ~0U, /* default rendezvous_size for ucp */ \
	.psm_uniq_id = 0,						\
	.psm_fastinit = 1,						\
	.psm_close_delay = 1000,					\
	.ucp_max_recv = ~0U,						\
	.ucp_fastinit = 1,						\
	.sigquit = 0,							\
	.sigsuspend = 0,						\
	.sigsegv = 1,							\
	.readahead = 350,						\
	.skipblocksize = 8192,						\
	.retry = 10,							\
	.guard = 1,							\
	.iprobe_count = 0,						\
									\
	.network = NULL,						\
	.info = NULL,							\
	.plugindir = "",						\
									\
	.debug_timing = NULL,						\
	.debug_version = 0,						\
	.debug_stats = 0,						\
	.debug_contype = 0,						\
	.debug_suspend = 0,						\
	.debug_precon = 0,						\
	 PSCOM_ENV_CUDA                                                 \
}


void pscom_env_init(void);
void pscom_env_table_list_clear(void);


void pscom_env_cleanup(void);

pscom_err_t pscom_env_parser_set_config_uint(void *buf,
					     const char *config_val);
pscom_err_t pscom_env_parser_set_config_int(void *env_entry,
					    const char *config_val);
pscom_err_t pscom_env_parser_set_config_str(void *env_entry,
					    const char *config_val);
pscom_err_t pscom_env_parser_set_config_dir(void *env_entry,
					    const char *config_val);
pscom_err_t pscom_env_parser_set_config_size_t(void *env_entry,
					       const char *config_val);

pscom_err_t pscom_env_parser_get_config_uint(void *env_entry,
					     char *val, size_t max_len);
pscom_err_t pscom_env_parser_get_config_int(void *env_entry,
					    char *val, size_t max_len);
pscom_err_t pscom_env_parser_get_config_str(void *env_entry,
					    char *val, size_t max_len);
pscom_err_t pscom_env_parser_get_config_dir(void *env_entry,
					    char *val, size_t max_len);
pscom_err_t pscom_env_parser_get_config_size_t(void *env_entry,
					       char *val, size_t max_len);


#define PSCOM_ENV_PARSER_UINT	{pscom_env_parser_set_config_uint, \
				 pscom_env_parser_get_config_uint}

#define PSCOM_ENV_PARSER_INT	{pscom_env_parser_set_config_int, \
				 pscom_env_parser_get_config_int}

#define PSCOM_ENV_PARSER_STR	{pscom_env_parser_set_config_str, \
				 pscom_env_parser_get_config_str}

#define PSCOM_ENV_PARSER_DIR	{pscom_env_parser_set_config_dir, \
				 pscom_env_parser_get_config_dir}

#define PSCOM_ENV_PARSER_SIZE_T {pscom_env_parser_set_config_size_t, \
				 pscom_env_parser_get_config_size_t}

/**
 * @brief Parse an environment definition table
 *
 * This routine cycles through a NULL-terminated array of
 * @ref pscom_env_table_entry_t and parses the specified configuration
 * parameters.
 *
 * @param [in] table       The configuration defintion table to be parsed.
 * @param [in] prefix      A prefix that is prepended to the environment names.
 * @param [in] sub_prefix  A prefix that is appended to the @a prefix
 *                         (optional).
 * @param [in] name        A name used for specifying the table in debug
 *                         outputs.
 *
 * @return PSCOM_SUCCESS     If all table fields could be parsed successfully.
 *
 * @return PSCOM_ERR_INVALID If @a table is an invalid parameter
 */
pscom_err_t pscom_env_table_parse(pscom_env_table_entry_t *table,
				  const char *prefix,
				  const char *sub_prefix,
				  const char *name);

/**
 * @brief Register a configuration definition table with the global list
 *
 * This routine registers a configuration definition table with the global list
 * of configuration definitions stored within the pscom structure.
 *
 * @param [in] name   Name of the table
 * @param [in] prefix Prefix to be prepended to the environment variables
 * @param [in] table  The table containing the configuration definitions
 *
 * @return PSCOM_SUCCESS      If the table could be registered successfully.
 * @return PSCOM_ERR_STDERROR If an error occurred during initialization; errno
 *                            will be set appropriately.
 */
pscom_err_t pscom_env_table_register(const char *name, const char *prefix,
				     pscom_env_table_entry_t *table);

/**
 * @brief Register and parse a configuration definition table
 *
 * This convenience routine first registers a given configuration definition
 * table and subsequently parses its entries to set the respective configuration
 * parameters.
 *
 * @param [in] name   Name of the table
 * @param [in] prefix Prefix to be prepended to the environment variables
 * @param [in] table  The table containing the configuration definitions
 *
 * @return PSCOM_SUCCESS      If the table could be registered and parsed
 *                            successfully.
 * @return PSCOM_ERR_STDERROR If an error occurred during initialization; errno
 *                            will be set appropriately.
 * @return PSCOM_ERR_INVALID  If @a table is an invalid parameter
 */
pscom_err_t pscom_env_table_register_and_parse(const char *name,
					       const char *prefix,
					       pscom_env_table_entry_t *table);

/**
 * @brief Clears the global list of configuration tables
 */
void pscom_env_table_list_clear(void);

/**
 * @brief Print the global table list
 */
void pscom_env_table_list_print(pscom_env_print_flags_t flags);
#endif /* _PSCOM_ENV_H_ */
