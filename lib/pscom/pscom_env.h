/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_ENV_H_
#define _PSCOM_ENV_H_

#include <stddef.h>
#include <stdint.h>

#include "pscom.h"
#include "list.h"


#define ENV_CONFIG_FILES                                                       \
    "/dev/environment:.parastation:$HOME/.parastation:/etc/pscom.conf"

#define ENV_INFO "PSP_INFO"

#define ENV_RENDEZVOUS_SHM    "PSP_RENDEZVOUS_SHM"
#define ENV_RENDEZVOUS_DAPL   "PSP_RENDEZVOUS_DAPL"
#define ENV_RENDEZVOUS_ELAN   "PSP_RENDEZVOUS_ELAN"
#define ENV_RENDEZVOUS_EXTOLL "PSP_RENDEZVOUS_EXTOLL"
#define ENV_RENDEZVOUS_VELO   "PSP_RENDEZVOUS_VELO"
#define ENV_RENDEZVOUS_OPENIB "PSP_RENDEZVOUS_OPENIB"

#define ENV_PSM_UNIQ_ID     "PSP_PSM_UNIQ_ID"
#define ENV_PSM_DEVCHECK    "PSP_PSM_DEVCHECK"
#define ENV_PSM_FASTINIT    "PSP_PSM_FASTINIT"
#define ENV_PSM_CLOSE_DELAY "PSP_PSM_CLOSE_DELAY"

#define ENV_PMI_ID "PMI_ID"

#define ENV_PLUGINDIR "PSP_PLUGINDIR"

#define ENV_ARCH_PREFIX "PSP_"

/* Use this, if ENV_ARCH_NEW_SHM is not set */
#define ENV_ARCH_OLD_SHM "PSP_SHAREDMEM"
#define ENV_ARCH_NEW_SHM ENV_ARCH_PREFIX "SHM"

/* The DAPL Provider to use */
#define ENV_DAPL_PROVIDER "PSP_DAPL_PROVIDER"

/* OpenIB HCA and port */
#define ENV_OPENIB_HCA  "PSP_OPENIB_HCA"  /* default: first hca */
#define ENV_OPENIB_PORT "PSP_OPENIB_PORT" /* default: port 1 */
#define ENV_OPENIB_PATH_MTU                                                    \
    "PSP_OPENIB_PATH_MTU" /* default: 3                                        \
                             1 : IBV_MTU_256                                   \
                             2 : IBV_MTU_512                                   \
                             3 : IBV_MTU_1024 */
#define ENV_OPENIB_SENDQ_SIZE     "PSP_OPENIB_SENDQ_SIZE"
#define ENV_OPENIB_RECVQ_SIZE     "PSP_OPENIB_RECVQ_SIZE"
#define ENV_OPENIB_COMPQ_SIZE     "PSP_OPENIB_COMPQ_SIZE"
#define ENV_OPENIB_PENDING_TOKENS "PSP_OPENIB_PENDING_TOKENS"
#define ENV_OPENIB_GLOBAL_SENDQ                                                \
    "PSP_OPENIB_GLOBAL_SENDQ" /* bool: Use one sendq for all connections?      \
                                 default: 0(no) */
#define ENV_OPENIB_EVENT_CNT                                                   \
    "PSP_OPENIB_EVENT_CNT" /* bool: Be busy if outstanding_cq_entries is to    \
                              high? default: 1(yes) */
#define ENV_OPENIB_IGNORE_WRONG_OPCODES                                        \
    "PSP_OPENIB_IGNORE_WRONG_OPCODES" /* bool: ignore wrong cq opcodes */
#define ENV_OPENIB_LID_OFFSET                                                  \
    "PSP_OPENIB_LID_OFFSET" /* int: offset to base LID (adaptive routing) */
#define ENV_OPENIB_MCACHE_SIZE                                                 \
    "PSP_OPENIB_MCACHE_SIZE" /* uint: max #entries in the memory registration  \
                                cache. 0:disable cache */
#define ENV_OPENIB_MALLOC_OPTS                                                 \
    "PSP_OPENIB_MALLOC_OPTS" /* bool: Set special options for malloc in favor  \
                                of the registration cache  */
#define ENV_OPENIB_RNDV_FALLBACKS                                              \
    "PSP_OPENIB_RNDV_FALLBACKS" /* bool: Use eager/sw-rndv if memory cannot be \
                                   registered for rndv? default: 1(yes)*/


/* OFED HCA and port */
#define ENV_OFED_HCA  "PSP_OFED_HCA"  /* default: first hca */
#define ENV_OFED_PORT "PSP_OFED_PORT" /* default: port 1 */
#define ENV_OFED_PATH_MTU                                                      \
    "PSP_OFED_PATH_MTU" /* default: 3                                          \
                           1 : IBV_MTU_256                                     \
                           2 : IBV_MTU_512                                     \
                           3 : IBV_MTU_1024 */
#define ENV_OFED_SENDQ_SIZE           "PSP_OFED_SENDQ_SIZE"
#define ENV_OFED_RECVQ_SIZE           "PSP_OFED_RECVQ_SIZE"
#define ENV_OFED_COMPQ_SIZE           "PSP_OFED_COMPQ_SIZE"
#define ENV_OFED_PENDING_TOKENS       "PSP_OFED_PENDING_TOKENS"
#define ENV_OFED_WINSIZE              "PSP_OFED_WINSIZE"
#define ENV_OFED_RESEND_TIMEOUT       "PSP_OFED_RESEND_TIMEOUT"
#define ENV_OFED_RESEND_TIMEOUT_SHIFT "PSP_OFED_RESEND_TIMEOUT_SHIFT"


#define ENV_OFED_EVENT_CNT                                                     \
    "PSP_OFED_EVENT_CNT" /* bool: Be busy if outstanding_cq_entries is to      \
                            high? default: 1(yes) */
#define ENV_OFED_LID_OFFSET                                                    \
    "PSP_OFED_LID_OFFSET" /* int: offset to base LID (adaptive routing) */

/* Extoll */
#define ENV_EXTOLL_RECVQ_SIZE "PSP_EXTOLL_RECVQ_SIZE"
#define ENV_EXTOLL_SENDQ_SIZE "PSP_EXTOLL_SENDQ_SIZE"
#define ENV_EXTOLL_GLOBAL_SENDQ                                                \
    "PSP_EXTOLL_GLOBAL_SENDQ" /* bool: Use one sendq for all connections?      \
                                 default: 0(no) */
#define ENV_EXTOLL_EVENT_CNT                                                   \
    "PSP_EXTOLL_EVENT_CNT" /* bool: Be busy on empty global sendq? default:    \
                              0(no) */
#define ENV_EXTOLL_PENDING_TOKENS "PSP_EXTOLL_PENDING_TOKENS"
#define ENV_EXTOLL_MCACHE_SIZE    "PSP_EXTOLL_MCACHE_SIZE"

/* Gateway */
#define ENV_GW_SERVER "PSP_GW_SERVER"
#define ENV_GW_MTU    "PSP_GW_MTU"
#define ENV_GW_TOKENS                                                          \
    "PSP_GW_TOKENS" /* int: # Flow control tokens. 0=disable flow control */
#define ENV_GW_PENDING_TOKENS                                                  \
    "PSP_GW_PENDING_TOKENS" /* int: Max pending tokens */

/* Allocate memory in a shared mem segment */
/* "PSP_MALLOC*" settings have to be known already in the
   __malloc_initialize_hook() before we run through pscom_pslib_init().
   Therefore they are not printed with PSP_DEBUG > 0 and can only set from the
   environment (not from pslib). */
#define ENV_MALLOC                                                             \
    "PSP_MALLOC" /* bool: Use a hook into glibc malloc (__morecore())?         \
                    default: 1(yes) */
#define ENV_MALLOC_MIN                                                         \
    "PSP_MALLOC_MIN" /* ulong: minimum size of the shared mem segment */
#define ENV_MALLOC_MAX                                                         \
    "PSP_MALLOC_MAX" /* ulong: maximum size of the shared mem segment */

/* Use shm direct for messages >= PSP_SHM_DIRECT. Set PSP_SHM_DIRECT=-1 to
 * disable shm direct. */
#define ENV_SHM_DIRECT                                                         \
    "PSP_SHM_DIRECT" /* min message size to use shm direct                     \
                      */
#define ENV_SHM_INDIRECT                                                       \
    "PSP_SHM_INDIRECT" /* min message size for indirect shm (when direct shm   \
                          fails) */


#define PSCOM_ENV_SIZE_T_AUTO ((size_t)-1)

#define PSCOM_ENV_UINT_AUTO ((unsigned)-1)
#define PSCOM_ENV_UINT_INF  ((unsigned)-2)

#define PSCOM_ENV_UINT_AUTO_STR "auto"
#define PSCOM_ENV_UINT_INF_STR  "inf"

/* definitions w.r.t. environment variables */
#define PSCOM_ENV_MAX_ENV_LEN    (128)
#define PSCOM_ENV_MAX_VAL_LEN    (32)
#define PSCOM_ENV_MAX_PREFIX_LEN (32)
#define PSCOM_ENV_ARCH_COUNT                                                   \
    (0x15) /* number of entries in pscom_con_type_t                            \
            */

#define PSCOM_ENV_GLOBAL_PREFIX "PSP_"

/* forward declarations */
typedef struct pscom_env_table_entry pscom_env_table_entry_t;
typedef struct pscom_env_list_entry pscom_env_list_entry_t;

typedef enum {
    PSCOM_ENV_PRINT_CONFIG        = (1ul << 0),
    PSCOM_ENV_PRINT_DEFAULT_VALUE = (1ul << 1),
    PSCOM_ENV_PRINT_DOC           = (1ul << 2),
    PSCOM_ENV_PRINT_HIDDEN        = (1ul << 3)
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
typedef pscom_err_t (*pscom_env_parser_get_t)(void *buf, char *val,
                                              size_t max_len);

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
    const char *name;          /**< Name of the environment
                                    variable excluding the
                                    prefix */
    const char *default_val;   /**< Default value */
    const char *help_str;      /**< Documentation of the
                                    environment variable */
    void *config_var;          /**< A pointer to the configuration
                                    variable */
    uint32_t flags;            /**< Flags affecting the parsing */
    pscom_env_parser_t parser; /**< The parse to be used for
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
    int debug;
    int debug_req;
    char *debug_out;
    unsigned int tcp_so_sndbuf;
    unsigned int tcp_so_rcvbuf;
    int tcp_nodelay;
    unsigned int tcp_backlog;
    unsigned int precon_tcp_reconnect_timeout;
    unsigned int precon_tcp_connect_stalled_max;
    int unexpected_receives;
    int sched_yield;
    unsigned int rendezvous_size;
    unsigned int rendezvous_size_shm;
    unsigned int rendezvous_size_dapl;
    unsigned int rendezvous_size_elan;
    unsigned int rendezvous_size_extoll;
    unsigned int rendezvous_size_velo;
    unsigned int rendezvous_size_openib;
    unsigned int rendezvous_size_portals;
    unsigned int rendezvous_size_ucp;
    unsigned int psm_uniq_id;
    unsigned int psm_fastinit;
    unsigned int psm_close_delay;
    unsigned int ucp_max_recv;
    unsigned int ucp_fastinit;
    int sigquit;
    int sigsuspend;
    int sigsegv;
    unsigned int readahead;
    unsigned int retry;
    unsigned int connect_timeout;
    unsigned int shutdown_timeout;
    int deadlock_warnings;
    unsigned int guard;
    unsigned int skipblocksize;
    unsigned int iprobe_count;
    unsigned int rma_get_acc_direct_mem_copy;

    char *network;
    char *info;
    char *plugindir;

    char *debug_timing;
    int debug_version;
    int debug_stats;
    int debug_contype;
    int debug_bye_msg;
    int debug_suspend;
    int debug_param;
    int debug_precon;
    char *precon_type;
    int rrc_resend_times;
    int rrc_resend_delay;
    unsigned int user_prio[PSCOM_ENV_ARCH_COUNT];
#ifdef PSCOM_CUDA_AWARENESS
    int cuda;
    unsigned int cuda_sync_memops;
    unsigned int cuda_enforce_staging;
    unsigned int cuda_aware_shm;
    unsigned int cuda_aware_openib;
    unsigned int cuda_aware_ucp;
    unsigned int cuda_aware_velo;
    unsigned int cuda_aware_extoll;
#endif
};

void pscom_env_init(void);
void pscom_env_table_list_clear(void);


void pscom_env_cleanup(void);

pscom_err_t pscom_env_parser_set_config_uint(void *buf, const char *config_val);
pscom_err_t pscom_env_parser_set_config_int(void *env_entry,
                                            const char *config_val);
pscom_err_t pscom_env_parser_set_config_str(void *env_entry,
                                            const char *config_val);
pscom_err_t pscom_env_parser_set_config_dir(void *env_entry,
                                            const char *config_val);
pscom_err_t pscom_env_parser_set_config_size_t(void *env_entry,
                                               const char *config_val);

pscom_err_t pscom_env_parser_get_config_uint(void *env_entry, char *val,
                                             size_t max_len);
pscom_err_t pscom_env_parser_get_config_int(void *env_entry, char *val,
                                            size_t max_len);
pscom_err_t pscom_env_parser_get_config_str(void *env_entry, char *val,
                                            size_t max_len);
pscom_err_t pscom_env_parser_get_config_dir(void *env_entry, char *val,
                                            size_t max_len);
pscom_err_t pscom_env_parser_get_config_size_t(void *env_entry, char *val,
                                               size_t max_len);


#define PSCOM_ENV_PARSER_UINT                                                  \
    {                                                                          \
        pscom_env_parser_set_config_uint, pscom_env_parser_get_config_uint     \
    }

#define PSCOM_ENV_PARSER_INT                                                   \
    {                                                                          \
        pscom_env_parser_set_config_int, pscom_env_parser_get_config_int       \
    }

#define PSCOM_ENV_PARSER_STR                                                   \
    {                                                                          \
        pscom_env_parser_set_config_str, pscom_env_parser_get_config_str       \
    }

#define PSCOM_ENV_PARSER_DIR                                                   \
    {                                                                          \
        pscom_env_parser_set_config_dir, pscom_env_parser_get_config_dir       \
    }

#define PSCOM_ENV_PARSER_SIZE_T                                                \
    {                                                                          \
        pscom_env_parser_set_config_size_t, pscom_env_parser_get_config_size_t \
    }

void pscom_env_psm_fastinit_set(unsigned int psm_fastinit);
void pscom_env_ucp_fastinit_set(unsigned int ucp_fastinit);

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
                                  const char *prefix, const char *sub_prefix,
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
