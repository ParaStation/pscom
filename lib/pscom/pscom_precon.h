/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
#ifndef _PSCOM_PRECON_H_
#define _PSCOM_PRECON_H_

#include <stdint.h>

#include "list.h"
#include "pscom_plugin.h"
#include "pscom_types.h"
#include "pscom.h"
#include "pscom_ufd.h"

#define PSCOM_INFO_FD_ERROR                                                    \
    0x0ffffe /* int errno; Pseudo message. Error in read(). */
#define PSCOM_INFO_FD_EOF 0x0fffff /* Pseudo message fd got EOF */

#define PSCOM_INFO_EOF 0x100000 /* Last info message */
// #define PSCOM_INFO_ANSWER	0x100001	/* request remote side, to send
// answers */
#define PSCOM_INFO_CON_INFO 0x100002 /* pscom_info_con_info_t; */
#define PSCOM_INFO_VERSION                                                     \
    0x100003 /* pscom_info_version_t;	Supported version range */
#define PSCOM_INFO_CON_INFO_DEMAND                                             \
    0x100004 /* pscom_info_con_info_t; On demand connect request. */
#define PSCOM_INFO_BACK_CONNECT                                                \
    0x100005 /* pscom_info_con_info_t; Request a back connect */
#define PSCOM_INFO_BACK_ACK 0x100006 /* null; Ack a back_connect */
#define PSCOM_INFO_ARCH_REQ                                                    \
    0x100010 /* pscom_info_arch_req_t;	Request to connect with .arch_id */
#define PSCOM_INFO_ARCH_OK    0x100011 /* Use last requested arch */
#define PSCOM_INFO_ARCH_NEXT  0x100012 /* Try next arch */
#define PSCOM_INFO_ARCH_STEP1 0x100013
#define PSCOM_INFO_ARCH_STEP2 0x100014
#define PSCOM_INFO_ARCH_STEP3 0x100015
#define PSCOM_INFO_ARCH_STEP4 0x100016

#define MAGIC_PRECON 0x4a656e73


struct pscom_listener {
    ufd_info_t ufd_info; // TCP listen for new connections
    unsigned usercnt;    // Count the users of the listening fd. (keep fd open,
                         // if > 0) (pscom_listen and "on demand" connections)
    unsigned activecnt;  // Count active listeners. (poll on fd, if > 0)
    unsigned suspend;    // Suspend listening and remove ufd info
};


typedef enum {
    PSCOM_PRECON_TYPE_TCP    = 0,
    PSCOM_PRECON_TYPE_RRCOMM = 1,
    PSCOM_PRECON_TYPE_COUNT
} pscom_precon_type_t;


/* common part of tcp and rrcomm plugin, used for general precon functions */
typedef struct PSCOM_precon {
    unsigned long magic;

    /* state information */
    pscom_plugin_t *plugin;      // The plugin handling the handshake messages
                                 // (==plugin_cur or NULL)
    pscom_plugin_t *_plugin_cur; // Current plugin iterator (used to loop
                                 // through all plugins)

    struct list_head next; // add to precon plugin list
    char precon_data[0];
} pscom_precon_t;

/**
 * @brief Initialize a precon provider
 *
 * This provider routine initializes the precon object to be used.
 *
 */
typedef void (*pscom_precon_provider_init_t)(void);


/**
 * @brief Finalize a precon provider
 *
 * This finalizes RRcomm in `pscom_precon_rrc.c` and is empty if TCP is used.
 */
typedef void (*pscom_precon_provider_destroy_t)(void);


/**
 * @brief Send a message via a precon provider
 *
 * This provider routine sends a message with given type and size. Actual data
 * transmission is done in the progress engine via the ufd module.
 *
 * @param [in] precon  The precon to be used for sending the message.
 * @param [in] type    The message type (i.e., PSCOM_INFO_*).
 * @param [in] data    The data to be sent.
 * @param [in] size    The number of bytes to be sent.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
typedef pscom_err_t (*pscom_precon_provider_send_t)(pscom_precon_t *precon,
                                                    unsigned type, void *data,
                                                    unsigned size);


/**
 * @brief Create a precon object for a given connection
 *
 * This provider routine creates a precon object for a given connection.
 *
 * @param [in] con  The pscom connection for which the precon shall be created.
 *
 * @return The created @ref pscom_precon_t object.
 */
typedef pscom_precon_t *(*pscom_precon_provider_create_t)(pscom_con_t *con);


/**
 * @brief Cleanup a the provider-specific part of a precon object
 *
 * This provider routine cleans up the provider-specific part of a precon object
 * by freeing all resources that have been allocated for the precon object.
 *
 * @param [in] precon The precon object to be cleaned up.
 */
typedef void (*pscom_precon_provider_cleanup_t)(pscom_precon_t *precon);


/**
 * @brief Set a precon object into receiving mode.
 *
 * This provider routine sets the given @ref pscom_precon_t object into
 * receiving mode.
 *
 * @param [in] precon The precon object to be set to receiving mode.
 */
typedef void (*pscom_precon_provider_recv_start_t)(pscom_precon_t *precon);


/**
 * @brief Unset a precon object from receiving mode.
 *
 * This provider routine unsets the given @ref pscom_precon_t object from
 * receiving mode.
 *
 * @param [in] precon The precon object to be unset from receiving mode.
 */
typedef void (*pscom_precon_provider_recv_stop_t)(pscom_precon_t *precon);


/**
 * @brief Establish a pscom connection via a precon provider
 *
 * This provider routine establishes the actual pscom payload connection by
 * implementing the precon handshake. This call is non-blocking and the
 * connection state has to be polled to ensure that the payload connection has
 * been actually established.
 *
 * @param [in] con The pscom connection to be established.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
typedef int (*pscom_precon_provider_connect_t)(pscom_con_t *con);


/**
 * @brief Setup connection guards for a given connection
 *
 * This provider routine can be used to enable connection guards for a pscom
 * payload connection. If supported by the precon provider (e.g., as done by the
 * TCP provider), these guards can be used for out-of-band checking for
 * connection errors.
 *
 * @param [in] precon The precon used for out-of-band error detection.
 *
 * @return A file descriptor that can be observed.
 */
typedef int (*pscom_precon_guard_setup_t)(pscom_precon_t *precon);


/**
 * @brief Get the endpoint string of a socket.
 *
 * This is the provider routine implementing the semantics of @ref
 * pscom_socket_get_ep_str.
 *
 * @param [in]  socket The communication socket for which the endpoint string
 *                     shall be generated.
 * @param [out] ep_str A pointer to the resulting endpoint string; the memory is
 *                     allocated by pscom and has to be released by calling @ref
 *                     pscom_socket_free_ep_str; can be NULL if the rank is
 *                     sufficient to connect to this process.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
typedef pscom_err_t (*pscom_precon_get_ep_info_from_socket_t)(
    pscom_socket_t *socket, char **ep_str);


/**
 * @brief Parse a given endpoint string obtained from a remote process.
 *
 * This provider routine parses an endpoint string generated by a remote
 * process using @ref pscom_precon_get_ep_info_from_socket_t.
 *
 * @param [in]     ep_str   The endpoint string to be parsed.
 * @param [in/out] con_info The @ref pscom_con_info_t object to be filled with
 *                          the parsed endpoint information.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
typedef pscom_err_t (*pscom_precon_parse_ep_info_t)(const char *ep_str,
                                                    pscom_con_info_t *con_info);


/**
 * @brief Detect whether the remote can be reached via a loopback connection
 *
 * This provider routine detects whether the provided connection can be
 * established in a loopback fashion to a given socket. Therefore, the provider
 * analyses provider-specific remote and local connection information.
 *
 * @param [in] socket     The local socket used for connecting.
 * @param [in] connection The connection with valid remote connection
 *                        information.
 *
 * @return boolean
 */
typedef int (*pscom_precon_is_connect_loopback_t)(
    pscom_socket_t *socket, pscom_connection_t *connection);


/**
 * @brief Wrapper type for the `start_listen` functions of the precon
 * providers
 */
typedef pscom_err_t (*pscom_precon_provider_start_listen_t)(pscom_sock_t *sock,
                                                            int portno);


/**
 * @brief Wrapper type for the `stop_listen` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_stop_listen_t)(pscom_sock_t *sock);


/**
 * @brief Wrapper type for the `ondemand_backconnect` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_ondemand_backconnect_t)(pscom_con_t *con);


/**
 * @brief Wrapper type for the `listener_suspend` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_listener_suspend_t)(
    struct pscom_listener *listener);


/**
 * @brief Wrapper type for the `listener_resume` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_listener_resume_t)(
    struct pscom_listener *listener);


/**
 * @brief Wrapper type for the `listener_active_inc` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_listener_active_inc_t)(
    struct pscom_listener *listener);


/**
 * @brief Wrapper type for the `listener_active_dec` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_listener_active_dec_t)(
    struct pscom_listener *listener);


/**
 * @brief Wrapper type for the `listener_user_inc` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_listener_user_inc_t)(
    struct pscom_listener *listener);


/**
 * @brief Wrapper type for the `listener_user_dec` functions of the precon
 * providers
 */
typedef void (*pscom_precon_provider_listener_user_dec_t)(
    struct pscom_listener *listener);


/* Global pre-connection struct containing shared functions and variables. Used
 * for the initial TCP or RRcomm handshaking. Global RRcomm variables will be
 * added here.
 */
typedef struct PSCOM_precon_provider {
    struct list_head precon_list; // List of precon objests, either tcp or rrcom
    int precon_count;
    pscom_precon_type_t precon_type;
    pscom_precon_provider_init_t init;
    pscom_precon_provider_destroy_t destroy;
    pscom_precon_provider_send_t send;
    pscom_precon_provider_create_t create;
    pscom_precon_provider_cleanup_t cleanup;
    pscom_precon_provider_recv_start_t recv_start;
    pscom_precon_provider_recv_stop_t recv_stop;
    pscom_precon_provider_connect_t connect;
    pscom_precon_guard_setup_t guard_setup;
    pscom_precon_get_ep_info_from_socket_t get_ep_info_from_socket;
    pscom_precon_parse_ep_info_t parse_ep_info;
    pscom_precon_is_connect_loopback_t is_connect_loopback;
    pscom_precon_provider_start_listen_t start_listen;
    pscom_precon_provider_stop_listen_t stop_listen;
    pscom_precon_provider_ondemand_backconnect_t ondemand_backconnect;
    pscom_precon_provider_listener_suspend_t listener_suspend;
    pscom_precon_provider_listener_resume_t listener_resume;
    pscom_precon_provider_listener_active_inc_t listener_active_inc;
    pscom_precon_provider_listener_active_dec_t listener_active_dec;
    pscom_precon_provider_listener_user_inc_t listener_user_inc;
    pscom_precon_provider_listener_user_dec_t listener_user_dec;
    void *precon_provider_data;
} pscom_precon_provider_t;

extern pscom_precon_provider_t pscom_precon_provider;


#define VER_FROM 0x0200
#define VER_TO   0x0200

typedef struct {
    /* supported version range from sender,
       overlap must be non empty. */
    uint32_t ver_from;
    uint32_t ver_to;
} pscom_info_version_t;


typedef struct {
    unsigned int arch_id;
} pscom_info_arch_req_t;


typedef struct {
    pscom_con_info_t con_info;
} pscom_info_con_info_t;

/* initialize the precon module */
void pscom_precon_init(void);
void pscom_precon_provider_init(void);

/* destroy the precon module */
void pscom_precon_provider_destroy(void);

/* Send a message of type type */
pscom_err_t pscom_precon_send(pscom_precon_t *precon, unsigned type, void *data,
                              unsigned size);

/* Send a PSCOM_INFO_ARCH_NEXT message and disable current plugin */
void pscom_precon_send_PSCOM_INFO_ARCH_NEXT(pscom_precon_t *precon);

/* Print handshake information */
const char *pscom_info_type_str(int type);

void pscom_precon_info_dump(pscom_precon_t *precon, const char *op, int type,
                            void *data, unsigned size);

/* select and try plugin for connection */
void plugin_connect_next(pscom_con_t *con);

void plugin_connect_first(pscom_con_t *con);

pscom_precon_t *pscom_precon_create(pscom_con_t *con);

void pscom_precon_destroy(pscom_precon_t *precon);

static inline void pscom_precon_recv_start(pscom_precon_t *precon)
{
    pscom_precon_provider.recv_start(precon);
}

static inline void pscom_precon_recv_stop(pscom_precon_t *precon)
{
    pscom_precon_provider.recv_stop(precon);
}

static inline int pscom_precon_connect(pscom_con_t *con)
{
    return pscom_precon_provider.connect(con);
}

static inline int pscom_precon_guard_setup(pscom_precon_t *precon)
{
    return pscom_precon_provider.guard_setup(precon);
}

static inline int pscom_precon_is_connect_loopback(
    pscom_socket_t *socket, pscom_connection_t *connection)
{
    return pscom_precon_provider.is_connect_loopback(socket, connection);
}

static inline pscom_err_t pscom_precon_parse_ep_info(const char *ep_str,
                                                     pscom_con_info_t *con_info)
{
    return pscom_precon_provider.parse_ep_info(ep_str, con_info);
}


static inline pscom_err_t
pscom_precon_get_ep_info_from_socket(pscom_socket_t *socket, char **ep_str)
{
    return pscom_precon_provider.get_ep_info_from_socket(socket, ep_str);
}

#endif /* _PSCOM_PRECON_H_ */
