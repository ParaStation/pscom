/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * ParaStation Communication Library
 */

#ifndef _PSCOM_H_
#define _PSCOM_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

struct in_addr;
struct sockaddr_in;


#ifndef PSCOM_CUDA_AWARENESS
#define PSCOM_VERSION 0x0300
#else
#define PSCOM_VERSION 0x8300
/* allow user applications to determine whether CUDA-awareness is supported */
#define PSCOM_CUDA_AWARENESS_SUPPORT
#endif


/**
 * @brief Status codes.
 *
 * @note These are status codes that are returned by some calls of the pscom
 * API. In case @ref PSCOM_ERR_STDERROR is returned, `errno` has to be checked
 * additionally.
 */
typedef enum PSCOM_err {
    PSCOM_SUCCESS                 = 0,  /**< Success */
    PSCOM_ERR_STDERROR            = -1, /**< Standard error, see errno */
    PSCOM_ERR_INVALID             = -2, /**< Invalid argument */
    PSCOM_ERR_ALREADY             = -3, /**< Operation already in progress */
    PSCOM_NOT_IMPLEMENTED         = -4, /**< Function not implemented */
    PSCOM_ERR_EOF                 = -5, /**< End of file */
    PSCOM_ERR_IOERROR             = -6, /**< IO Error */
    PSCOM_ERR_UNSUPPORTED_VERSION = -7, /**< Unsupported version */
    PSCOM_ERR_CONNECTION_REFUSED  = -8, /**< Connection refused */
} pscom_err_t;


/**
 * @brief Connection states.
 */
typedef enum PSCOM_con_state {
    PSCOM_CON_STATE_NO_RW  = 0x0, /**< Neither open for reading or writing */
    PSCOM_CON_STATE_R      = 0x1, /**< Open for reading */
    PSCOM_CON_STATE_W      = 0x2, /**< Open for writing */
    PSCOM_CON_STATE_RW     = 0x3, /**< Open for reading and writing */
    PSCOM_CON_STATE_CLOSED = 0x4, /**< Closed */
    PSCOM_CON_STATE_CONNECTING = 0x8,   /**< Connection setup in progress via
                                           precon (active) */
    PSCOM_CON_STATE_ACCEPTING  = 0x10,  /**< Connection setup in progress via
                                           precon (passive) */
    PSCOM_CON_STATE_CLOSE_WAIT = 0x400, /**< EOF sent; wait for EOF from peer */
    PSCOM_CON_STATE_CLOSING    = 0x20,  /**< Send EOF */
    PSCOM_CON_STATE_SUSPENDING = 0x40,  /**< Send PSCOM_MSGTYPE_SUSPEND */
    /**< PSCOM_MSGTYPE_SUSPEND sent; wait for PSCOM_MSGTYPE_SUSPEND from peer */
    PSCOM_CON_STATE_SUSPEND_SENT     = PSCOM_CON_STATE_SUSPENDING | 0x080,
    /**< Received a PSCOM_MSGTYPE_SUSPEND from peer*/
    PSCOM_CON_STATE_SUSPEND_RECEIVED = PSCOM_CON_STATE_SUSPENDING | 0x100,
    /**< Suspend complete */
    PSCOM_CON_STATE_SUSPENDED        = PSCOM_CON_STATE_SUSPENDING |
                                PSCOM_CON_STATE_SUSPEND_SENT |
                                PSCOM_CON_STATE_SUSPEND_RECEIVED,
    /**< Connection setup in progress via precon/ondemand (active) */
    PSCOM_CON_STATE_CONNECTING_ONDEMAND = 0x200 | PSCOM_CON_STATE_CONNECTING,
    /**< Connection setup in progress via precon/ondemand (passive) */
    PSCOM_CON_STATE_ACCEPTING_ONDEMAND  = 0x200 | PSCOM_CON_STATE_ACCEPTING,
} pscom_con_state_t;


/**
 * @brief Connection types.
 */
typedef enum PSCOM_con_type {
    PSCOM_CON_TYPE_NONE = 0x00, /**< Initial generic connection */
    PSCOM_CON_TYPE_LOOP = 0x01, /**< Loopback connection */
    PSCOM_CON_TYPE_TCP  = 0x02, /**< TCP communication */
    PSCOM_CON_TYPE_SHM  = 0x03, /**< Shared memory communication */
    PSCOM_CON_TYPE_P4S __attribute__((deprecated)) = 0x04,
    PSCOM_CON_TYPE_GM       = 0x05, /**< Myrinet communication */
    PSCOM_CON_TYPE_MVAPI    = 0x06, /**< @deprecated */
    PSCOM_CON_TYPE_OPENIB   = 0x07, /**< InfiniBand communication via verbs */
    PSCOM_CON_TYPE_ELAN     = 0x08, /**< ELAN communication */
    PSCOM_CON_TYPE_DAPL     = 0x09, /**< DAPL communication (e.g., via IB) */
    PSCOM_CON_TYPE_ONDEMAND = 0x0a, /**< Pseudo connection for on-demand
                                         connection establishment */
    PSCOM_CON_TYPE_OFED   = 0x0b, /**< Alternative IB communication via verbs */
    PSCOM_CON_TYPE_EXTOLL = 0x0c, /**< EXTOLL communication */
    PSCOM_CON_TYPE_PSM    = 0x0d, /**< PSM communication (e.g., for OmniPath) */
    PSCOM_CON_TYPE_VELO   = 0x0e, /**< Alternative EXTOLL communication */
    PSCOM_CON_TYPE_CBC    = 0x0f, /**< @deprecated */
    PSCOM_CON_TYPE_MXM = 0x10, /**< MXM communication (Mellanox InfiniBand) */
    PSCOM_CON_TYPE_SUSPENDED = 0x11, /**< A suspended connection */
    PSCOM_CON_TYPE_UCP = 0x12, /**< UCP communication (e.g., for InfiniBand) */
    PSCOM_CON_TYPE_GW  = 0x13, /**< Communication via a gateway node */
    PSCOM_CON_TYPE_PORTALS = 0x14, /**< Portals4 communication (e.g., BXI) */
    PSCOM_CON_TYPE_COUNT,          /**< Number of connection types*/
} pscom_con_type_t;

/**
 * @brief Basic operations that can be performed on a connection.
 *
 * These operations are used for proper error handling in case of connection
 * errors, i.e., to provide detailed information on the error type.
 */
typedef enum PSCOM_op {
    PSCOM_OP_READ    = 1, /**< Read */
    PSCOM_OP_WRITE   = 2, /**< Write */
    PSCOM_OP_CONNECT = 3, /**< Connection setup */
    PSCOM_OP_RW      = 4, /**< Read or write */
} pscom_op_t;

/**< The request refers to a send operation */
#define PSCOM_REQ_STATE_SEND_REQUEST 0x00000001
/**< The request refers to a receive operation */
#define PSCOM_REQ_STATE_RECV_REQUEST 0x00000002
/**< Generated request; matching user-level receive is missing */
#define PSCOM_REQ_STATE_GRECV_REQUEST 0x00000004
/**< The request has been appended to the send or receive queue */
#define PSCOM_REQ_STATE_POSTED 0x00000008
/**< Reading/writing from/to the buffer is ongoing;
     the request cannot be
     cancelled */
#define PSCOM_REQ_STATE_IO_STARTED 0x00000010
/**< Reading/writing from/to the buffer completed */
#define PSCOM_REQ_STATE_IO_DONE 0x00000020
/**< An error occurred while processing this request */
#define PSCOM_REQ_STATE_ERROR 0x00000040
/**< The request has been cancelled by the application */
#define PSCOM_REQ_STATE_CANCELED 0x00000080
/**< The receive buffer is too small for the incoming data */
#define PSCOM_REQ_STATE_TRUNCATED 0x00000100
/**< The request is completed and the io_done()-callback will be called */
#define PSCOM_REQ_STATE_DONE 0x00000200
/**< The request refers to an RMA read operation */
#define PSCOM_REQ_STATE_RMA_READ_REQUEST 0x00000400
/**< The request refers to an RMA write operation */
#define PSCOM_REQ_STATE_RMA_WRITE_REQUEST 0x00000800
/**< The passive side of an RMA write operation */
#define PSCOM_REQ_STATE_PASSIVE_SIDE 0x00001000
/**< The data will be sent/received by using the rendezvous protocol */
#define PSCOM_REQ_STATE_RENDEZVOUS_REQUEST 0x00002000
/**< A generated request that was merged with the matching user request */
#define PSCOM_REQ_STATE_GRECV_MERGED 0x00004000

#define PSCOM_V_NONSTRING
#ifdef __has_attribute
#if __has_attribute(__nonstring__)
#undef PSCOM_V_NONSTRING
#define PSCOM_V_NONSTRING __attribute__((__nonstring__))
#endif
#endif

typedef unsigned int pscom_req_state_t;


typedef struct PSCOM_socket pscom_socket_t;
typedef struct PSCOM_connection pscom_connection_t;
typedef struct PSCOM_request pscom_request_t;
typedef struct PSCOM_header_net pscom_header_net_t;
typedef struct PSCOM_con_info pscom_con_info_t;


/**
 * @brief RMA memory region handle
 */
typedef struct PSCOM_memh *pscom_memh_t;


/**
 * @brief RMA remote key handle
 */
typedef struct PSCOM_rkey *pscom_rkey_t;


/**
 * @brief Extended header used for RMA write operations.
 */
typedef struct PSCOM_xheader_rma_write {
    void *dest; /**< Destination address on the target node */
} pscom_xheader_rma_write_t;


/**
 * @brief Extended header used for RMA read operations.
 */
typedef struct PSCOM_xheader_rma_read {
    void *id;         /**< Unique ID to match read requests at the
                           requester */
    void *src;        /**< Source address on the target node */
    uint64_t src_len; /**< The number of bytes to read from src */
} pscom_xheader_rma_read_t;


/**
 * @brief Extended header used for rendezvous requests based on RMA read.
 */
typedef struct PSCOM_xheader_rma_read_answer {
    void *id;
} pscom_xheader_rma_read_answer_t;


/**
 * @brief Extended header used for finalizing rendezvous requests.
 */
typedef struct PSCOM_xheader_rendezvous_fin {
    void *id;
} pscom_xheader_rendezvous_fin_t;


/**
 * @brief Extended header used for broadcast messages.
 */
typedef struct PSCOM_xheader_bcast {
    uint32_t group_id;
    uint32_t bcast_root;
    uint32_t bcast_arg1; /* internal usage */
    uint32_t bcast_arg2; /* internal usage */
    char user[0];
} pscom_xheader_bcast_t;


/**
 * @brief The generic extended header.
 *
 * @note @ref PSCOM_XHEADER_USER_TYPE can be defined to provide custom xheader
 * types.
 */
typedef union PSCOM_xheader {
    pscom_xheader_rma_read_t rma_read;
    pscom_xheader_rma_read_answer_t rma_read_answer;
    pscom_xheader_rma_write_t rma_write;
    pscom_xheader_rendezvous_fin_t ren_fin;
    pscom_xheader_bcast_t bcast;
#ifdef PSCOM_XHEADER_USER_TYPE
    PSCOM_XHEADER_USER_TYPE user;
#else
    char user[0];
#endif
} pscom_xheader_t;


#define PSCOM_DATA_LEN_MASK 0xffffffffff


/**
 * @brief The network header preceding every pscom message.
 */
struct PSCOM_header_net {
    uint16_t xheader_len;       /**< Length of the extended header */
    uint8_t msg_type;           /**< Message type
                                     (cf. @ref pscom_msgtype_t) */
    uint64_t data_len : 40;     /**< Message length */
    pscom_xheader_t xheader[0]; /**< Zero length xheader */
};


/**
 * @brief Local handle for referencing any type of message request.
 */
struct PSCOM_request {
    pscom_req_state_t state;

    size_t xheader_len; /**< Length of the extended header */
    size_t data_len;    /**< Number of bytes to be
                             sent/received */
    void *data;         /**< Destination/source address */

    pscom_connection_t *connection; /**< The communication channel to be
                                         used (may be NULL in case of
                                         "any source" receive request) */
    pscom_socket_t *socket;         /**< The @ref pscom_socket_t to be used
                                         (relevant for receive requests
                                         only, and may be NULL for the "any
                                         source on any socket" case) */

    struct PSCOM_request_ops {
        /**
         * @brief Callback for matching incoming messages.
         *
         * @param [in] request    The @ref pscom_request_t to be
         *                                 matched.
         * @param [in] connection The @ref pscom_connect_t on which the
         *                                 header arrived.
         * @param [in] header_net The @ref pscom_header_net_t to be
         *                                 matched with the request.
         *
         * @note The recv_accept callback shall return 1 to accept a
         *       message.
         */
        int (*recv_accept)(pscom_request_t *request,
                           pscom_connection_t *connection,
                           pscom_header_net_t *header_net);
        /**
         * @brief Completion callback for pscom requests.
         *
         * This callback routine is invoked when a @ref pscom_request_t
         * is marked as done (i.e., PSCOM_REQ_STATE_IO_DONE).
         *
         * @param [in] request The completed pscom request.
         */
        void (*io_done)(pscom_request_t *request);
    } ops;

    size_t user_size;            /**< User storage size */
    struct PSCOM_req_user *user; /**< User-defined storage in
                                      the request structure */

    size_t max_xheader_len; /**< Maximum length of the
                                 extended header */

    pscom_header_net_t header; /**< The network header */

    /**
     * @brief The extended message header.
     *
     * @note Storage size of xheader depends on
     * sizeof(PSCOM_XHEADER_USER_TYPE)
     */
    pscom_xheader_t xheader;
};


/**
 * @brief Connection information.
 */
struct PSCOM_con_info {
    int node_id; /**< A unique node identifier */
    int pid;     /**< Process ID of the connection owning process */
    void *id;    /**< A unique 32bit identifier for the connection */
    /**
     * @brief Name of the corresponding socket.
     *
     * @note Be aware: name is not null-terminated! A printf format that
     *       fits is: printf("%.8s", con_info->name);
     */
    char name[8] PSCOM_V_NONSTRING;
};


/**
 * @brief Communication socket.
 */
struct PSCOM_socket {
    struct PSCOM_socket_ops {
        /**
         * @brief Callback for accepting a connection request.
         *
         * @param [in] new_connection The connection handle
         */
        void (*con_accept)(pscom_connection_t *new_connection);

        /**
         * @brief Callback that is invoked upon any connection error.
         *
         * @param [in] connection The erroneous connection.
         * @param [in] operation  The @ref pscom_op_t causing the error.
         * @param [in] error      An error code precising the cause.
         */
        void (*con_error)(pscom_connection_t *connection, pscom_op_t operation,
                          pscom_err_t error);

        /**
         * @brief Default callback for message matching.
         *
         * This callback is invoked whenever a user message (i.e.,
         * PSCOM_MSGTYPE_USER) arrives on any connection of this socket.
         *
         * @param [in] connection The connection where the msg arrived.
         * @param [in] header_net The header of the message.
         */
        pscom_request_t *(*default_recv)(pscom_connection_t *connection,
                                         pscom_header_net_t *header_net);
    } ops;
    int listen_portno; /* portno or -1 */

    pscom_con_info_t local_con_info; /**< Node-local connection
                                          information */
    size_t connection_userdata_size; /**< Size of the user-defined
                                          local storage within the
                                          connection structure. */
    size_t userdata_size;            /**< Size of the user-defined
                                          local storage within the
                                          socket structure. */
                                     /**
                                      * @brief User-defined storage.
                                      */
#ifdef PSCOM_SOCKET_USERDATA_TYPE
    PSCOM_SOCKET_USERDATA_TYPE userdata;
#else
    char userdata[0];
#endif
};


/**
 * @brief A bi-directional point-to-point connection.
 */
struct PSCOM_connection {
    pscom_socket_t *socket;  /**< The socket this connection belongs to. */
    pscom_con_state_t state; /**< The connection state. */
    pscom_con_type_t type;   /**< The connection type (i.e., corresponding
                                  to the respective plugin, an on-demand
                                  connection, or a precon) */

    pscom_con_info_t remote_con_info; /**< Connection information of the
                                           connected peer process. */

    size_t userdata_size; /**< Size of the user-defined storage
                               within the connection
                               structure. */

    /**
     * @brief User-defined storage.
     */
#ifdef PSCOM_CONNECTION_USERDATA_TYPE
    PSCOM_CONNECTION_USERDATA_TYPE userdata;
#else
    char userdata[0];
#endif
};


/**
 * @brief Initialize the library.
 *
 * This function must be called before any other call to the library.
 *
 * @param [in] pscom_version A version number for checking ABI compatibility.
 *                           Has to be called with PSCOM_VERSION.
 *
 * return PSCOM_SUCCESS or PSCOM_ERR_UNSUPPORTED_VERSION
 */
pscom_err_t pscom_init(int pscom_version);


/**
 * @brief Initialize the library for multithreaded usage.
 *
 * This function must be called before any other call to the library.
 *
 * @param [in] pscom_version A version number for checking ABI compatibility.
 *                           Has to be called with PSCOM_VERSION.
 *
 *
 * return PSCOM_SUCCESS or PSCOM_ERR_UNSUPPORTED_VERSION
 */
pscom_err_t pscom_init_thread(int pscom_version);


/**
 * @brief Get the ID of this node.
 *
 * Get the ParaStation ID of this node.
 *
 * @return NodeID on success or -1 on error.
 */
int pscom_get_nodeid(void);


/**
 * @brief Returns the listening port of a pscom socket.
 *
 * @return The listening port number or -1 on error (i.e., no listen on socket).
 */
int pscom_get_portno(pscom_socket_t *socket);


/**
 * @brief Opens a new socket for communication.
 *
 * @param [in] socket_userdata_size     Size of the user-defined storage within
 *                                      the socket structure.
 * @param [in] connection_userdata_size Size of the user-defined storage within
 *                                      connection structure of the associated
 *                                      connections.
 *
 * @return A pointer to the socket or NULL on error.
 */
pscom_socket_t *pscom_open_socket(size_t socket_userdata_size,
                                  size_t connection_userdata_size);


#define PSCOM_OPEN_SOCKET()                                                    \
    pscom_open_socket(sizeof(PSCOM_SOCKET_USERDATA_TYPE),                      \
                      sizeof(PSCOM_CONNECTION_USERDATA_TYPE))


/**
 * @brief Sets the socket name.
 *
 * @param [in] socket The pscom socket.
 * @param [in] name   The socket name
 *                    (i.e., stored in socket->local_con_info.name)
 */
void pscom_socket_set_name(pscom_socket_t *socket, const char *name);


/**
 * @brief Start to listen on a socket for incoming connection requests.
 *
 * @param [in] socket The socket to listen.
 * @param [in] portno The port number to listen on (may be PSCOM_ANYPORT).
 *
 * @return ::PSCOM_SUCCESS      The socket successfully listens on portno.
 *
 * @return ::PSCOM_ERR_ALREADY  The socket is already in listening state.
 *
 * @return ::PSCOM_ERR_STDERROR Another error occurred and an according error
 *                              message is provided in the log if this is
 *                              enabled (i.e, PSCOM_DEBUG >= 1). Errno
 *                              additionally indicates the type of error.
 */
pscom_err_t pscom_listen(pscom_socket_t *socket, int portno);
#define PSCOM_ANYPORT                                                          \
    -1 /**< When used as a port-number, stands for any                         \
            port (wildcard). */
#define PSCOM_LISTEN_FD0                                                       \
    0 /**< When used as a port-number, listen on socket at                     \
           fd=0. */


/**
 * @brief Stop listening for new connections on port.
 *
 * @param [in] socket The listening socket.
 */
void pscom_stop_listen(pscom_socket_t *socket);


/**
 * @brief Flush the send queue of a connection.
 *
 * This empties the send queue of a given connection and ensures that IO has
 * been started on the complete send buffer of each outstanding send request.
 *
 * @note This does *not* imply that all send requests are marked as done after
 *       calling this function.
 *
 * @param [in] connection The connection to flush.
 */
void pscom_flush(pscom_connection_t *connection);


/**
 * @brief Close a connection for sending and receiving.
 *
 * This call cancels all active send/recv requests and gracefully closes the
 * connection by sending EOFs.
 *
 * @param [in] connection The connection to close.
 */
void pscom_close_connection(pscom_connection_t *connection);


/**
 * @brief Stop listening and close all connections.
 *
 * This call stops listening on the given socket and closes all associated
 * connections on that socket (cf. @ref pscom_close_connection()). Afterwards,
 * the socket handle must not be used with any pscom API call.
 * If no specific socket is given but NULL as the passed argument, then all
 * sockets known to pscom as maintained within an internal list are closed.
 *
 * @param [in] socket The socket to close.
 */
void pscom_close_socket(pscom_socket_t *socket);


/**
 * @brief Create a new connection.
 *
 * Creates and initializes a connection handle on a given socket. This will
 * provide room for user-defined data associated with the connection
 * corresponding to what was provided to @ref pscom_socket_open().
 *
 * @param [in] socket The socket on which the connection shall be created.
 *
 * @return A handle to the created connection or NULL on error.
 */
pscom_connection_t *pscom_open_connection(pscom_socket_t *socket);


/**
 * @brief Establish a connection to a remote process.
 *
 * This routine establishes a connection to a remote process and blocks until
 * the connection has been established successfully or an error occurred.
 *
 * @param [in] connection The local connection to be used.
 * @param [in] nodeid     The pscom ID of the remote node.
 * @param [in] portno     The listening port of the remote process.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
pscom_err_t pscom_connect(pscom_connection_t *connection, int nodeid,
                          int portno);


/* connect to nodeid:port or accept a connection from a socket with the name
   (see pscom_socket_set_name()) */
#define PSCOM_HAS_ON_DEMAND_CONNECTIONS 1


/**
 * @brief Create an on-demand connection to a remote process.
 *
 * This routine creates an on-demand connection to a remote process. In contrast
 * to @ref pscom_connect(), it does not block until this has been established
 * but rather sets up everything to connect upon the first write attempt on that
 * connection.
 *
 * @param [in] connection The local connection to be used.
 * @param [in] nodeid     The pscom ID of the remote node.
 * @param [in] portno     The listening port of the remote process.
 * @param [in] name       The socket name of the remote process
 *                        (cf. @ref pscom_con_info_t).
 *
 * @return Always returns PSCOM_SUCCESS.
 */
pscom_err_t pscom_connect_ondemand(pscom_connection_t *connection, int nodeid,
                                   int portno, const char name[8]);


/**
 * @brief Creates a pscom request object for communication.
 *
 * This routine creates a request object to be with any communication routine,
 * i.e., be it two-sided send/recv operations or one-sided RMA operations. It
 * allocates memory which has to be released by the user application via the
 * @ref pscom_request_free routine.
 *
 * @param [in] max_xheader_len The maximum length of the extended header.
 * @param [in] user_size       The size of the user-defined data to be stored
 *                             in this request object.
 *
 * @return A pointer to the request handle or NULL on error.
 */
pscom_request_t *pscom_request_create(size_t max_xheader_len, size_t user_size);


#define PSCOM_REQUEST_CREATE()                                                 \
    pscom_request_create(sizeof(PSCOM_XHEADER_USER_TYPE),                      \
                         sizeof(struct PSCOM_req_user))


/**
 * @brief Free a pscom request object.
 *
 * Release resources associated with a pscom request handle. Afterwards, this
 * handle must not be used by any pscom API call.
 *
 * @param [in] request The request handle to be released.
 */
void pscom_request_free(pscom_request_t *request);


/**
 * @brief Post a non-blocking receive request.
 *
 * Receiving up to req->xheader_len bytes to req->xheader and up to
 * req->data_len bytes to req->data from connection req->connection, or from ANY
 * connection from req->socket in the case of req->connection==NULL, or from ANY
 * connection of ANY socket in the case of req->connection==req->socket==NULL.
 *
 * Progress of this request can be checked by calling any of the test or wait
 * routines.
 *
 * Mandatory fields in the @a request:
 * - xheader_len
 * - xheader
 * - data_len
 * - data
 * - connection (specific source) OR
 *   connection == NULL and socket (any connection on socket) OR
 *   connection == NULL and socket == NULL (any connection on any socket)
 *
 * Optional fields in the @ref pscom_request_t handle:
 * - ops.recv_accept
 * - ops.io_done
 *
 *  @param [in] request The request handle of the message to be received.
 */
void pscom_post_recv(pscom_request_t *request);


/**
 * @brief Post a non-blocking send request.
 *
 * Post a non-blocking send (of even 0 bytes). Progress of this request can be
 * checked by calling any of the test or wait routines.
 *
 * Mandatory fields in the @ref pscom_request_t handle:
 * - connection
 *
 * @param [in] request The request handle of the message to be sent.
 */
void pscom_post_send(pscom_request_t *request);


static inline pscom_request_t *pscom_req_prepare(pscom_request_t *req,
                                                 pscom_connection_t *connection,
                                                 void *data, size_t data_len,
                                                 void *xheader,
                                                 size_t xheader_len)
{
    req->connection  = connection;
    req->data        = data;
    req->data_len    = data_len;
    req->xheader_len = xheader_len;
    if (xheader) {
        assert(xheader_len <= req->max_xheader_len);
        memcpy(&req->xheader.user, xheader, xheader_len);
    }
    return req;
}


/**
 * @brief Send a copy of data to a remote process.
 *
 * This routine sends a copy of data to a remote process in a non-blocking
 * manner. This does not return a request handle and therefore progress has to
 * be made by calling @ref pscom_test_any or @ref pscom_wait_any. The data
 * buffer may be immediately reused by the user application.
 *
 * @param [in] connection  The connection to the remote process.
 * @param [in] xheader     A pointer to the extended header to be used.
 * @param [in] xheader_len The size of the extended header.
 * @param [in] data        A pointer to the data to be sent.
 * @param [in] data_len    The amount of data to be sent in byte.
 */
void pscom_send(pscom_connection_t *connection, void *xheader,
                size_t xheader_len, void *data, size_t data_len);


/**
 * @brief Send data to a remote process.
 *
 * This routine sends data to a remote process in a non-blocking manner. This
 * does not return a request handle and therefore progress has to be made by
 * calling @ref pscom_test_any or @ref pscom_wait_any. The data buffer must not
 * be reused until io_done is called.
 *
 * @param [in] connection  The connection to the remote process.
 * @param [in] xheader     A pointer to the extended header to be used.
 * @param [in] xheader_len The size of the extended header.
 * @param [in] data        A pointer to the data to be sent.
 * @param [in] io_done     A callback that is invoked once it is safe to reuse
 *                         the data buffer.
 */
void pscom_send_inplace(pscom_connection_t *connection, void *xheader,
                        size_t xheader_len, void *data, size_t data_len,
                        void (*io_done)(pscom_req_state_t state, void *priv),
                        void *priv);


/**
 * @brief Blocking receive data from a remote process.
 *
 * This routine receives data from a remote process and blocks until the data
 * could be received.
 *
 * @param [in] connection   The connection to the remote process. This may be
 *                          NULL in the "any source" case.
 * @param [in] socket       The socket related to the connection. This may be
 *                          NULL in the "any source on any socket" case.
 * @param [in] xheader      A buffer to store the extended header.
 * @param [in] xheader_len  Size of the buffer pointed to by `xheader`.
 * @param [in] data         A buffer where the data shall be received.
 * @param [in] data_len     The size of the buffer pointed to by `data`.
 *
 * @return PSCOM_SUCCESS      If the data could be received successfully. This
 *                            may be less compared to the length of the data
 *                            buffer.
 * @return PSCOM_ERR_IOERROR  If any error occurred while receiving the data.
 * @return PSCOM_ERR_STDERROR Otherwise and `errno` additionally indicates the
 *                            type of error.
 */
pscom_err_t pscom_recv(pscom_connection_t *connection, pscom_socket_t *socket,
                       void *xheader, size_t xheader_len, void *data,
                       size_t data_len);


/**
 * @brief Blocking receive data from a remote process.
 *
 * This routine receives data from a remote process and blocks until the data
 * could be received.
 *
 * @param [in] connection   The connection to the remote process. This must not
 *                          be NULL.
 * @param [in] xheader      A buffer to store the extended header.
 * @param [in] xheader_len  Size of the buffer pointed to by `xheader`.
 * @param [in] data         A buffer where the data shall be received.
 * @param [in] data_len     The size of the buffer pointed to by `data`.
 *
 * @return PSCOM_SUCCESS      If the data could be received successfully. This
 *                            may be less compared to the length of the data
 *                            buffer.
 * @return PSCOM_ERR_IOERROR  If any error occurred while receiving the data.
 * @return PSCOM_ERR_STDERROR Otherwise and `errno` additionally indicates the
 *                            type of error.
 */
static inline pscom_err_t pscom_recv_from(pscom_connection_t *connection,
                                          void *xheader, size_t xheader_len,
                                          void *data, size_t data_len)
{
    return pscom_recv(connection, connection->socket, xheader, xheader_len,
                      data, data_len);
}


/**
 * @brief Blocking receive data from any process.
 *
 * This routine receives data from any process reachable via a certain socket
 * and blocks until the requested amount of data could be received.
 *
 * @param [in] socket       The socket whose connections should be used for
 *                          receiving data. May be NULL in the "any source on
 *                          any socket" case.
 * @param [in] xheader      A buffer to store the extended header.
 * @param [in] xheader_len  Size of the buffer pointed to by `xheader`.
 * @param [in] data         A buffer where the data shall be received.
 * @param [in] data_len     The size of the buffer pointed to by `data`.
 *
 * @return PSCOM_SUCCESS      If the data could be received successfully. This
 *                            may be less compared to the length of the data
 *                            buffer.
 * @return PSCOM_ERR_IOERROR  If any error occurred while receiving the data.
 * @return PSCOM_ERR_STDERROR Otherwise and `errno` additionally indicates the
 *                            type of error.
 */
static inline pscom_err_t pscom_recv_any(pscom_socket_t *socket, void *xheader,
                                         size_t xheader_len, void *data,
                                         size_t data_len)
{
    return pscom_recv(NULL, socket, xheader, xheader_len, data, data_len);
}


/* post the rma_write request.
   Write req->data_len bytes from req->data to remote mem
   at req->xheader.rma_write.dest at connection req->connection.

   req->data_len
   req->data
   req->connection
   req->xheader.rma_write.dest

   optional:
   req->ops.io_done
*/

/**
 * @brief Non-blocking RMA write operation.
 *
 * This routine triggers a write operation of a contiguous block of data to the
 * memory of a remote process. The call returns immediately and the source data
 * region specified in the @a request must not be used before the operation is
 * completed, i.e., the io_cone callback is invoked.
 *
 * Mandatory fields in the @a request:
 * - req->data_len (number of bytes to be written)
 * - req->data (source address in the VA of the local process)
 * - req->connection (associated connection)
 * - req->xheader.rma_write.dest (destination address within the VA of the
 *   target process)
 *
 * Optional fields in the @a request:
 * - req->ops.io_done
 *
 * @param [in] request The request handle for tracking the progress.
 */
void pscom_post_rma_write(pscom_request_t *request);


/**
 * @brief Non-blocking RMA read operation.
 *
 * This routine triggers a write operation of a contiguous block of data to the
 * memory of a remote process. The call returns immediately and the source data
 * region specified in the @a request must not be used before the operation is
 * completed, i.e., the io_cone callback is invoked.
 *
 * Mandatory fields in the @a request:
 * - req->data_len (number of bytes to be written)
 * - req->data (target address in the VA of the local process)
 * - req->connection (associated connection)
 * - req->xheader.rma_read.src (source address within the VA of the target
 *   process)
 *
 * Optional fields in the @a request:
 * - req->ops.io_done
 *
 * @param [in] request The request handle for tracking the progress.
 */
void pscom_post_rma_read(pscom_request_t *request);


/**
 * @brief Wait for the completion of a request.
 *
 * This routine blocks until the @a request is completed and likewise fosters
 * progress of all communication within the pscom.
 *
 * @param [in] request The request to wait for.
 */
void pscom_wait(pscom_request_t *request);


/**
 * @brief Wait for the completion of multiple request.
 *
 * This routine blocks until all @a requests are completed and likewise fosters
 * progress of all communication within the pscom.
 *
 * @param [in] requests NULL-terminated array of @ref pscom_request_t.
 */
void pscom_wait_all(pscom_request_t **requests);


/**
 * @brief Make progress within the pscom.
 *
 * This routine fosters progress of all communication within the pscom.
 *
 * @return 1 if progress was made on any communication channel; 0 otherwise.
 */
int pscom_test_any(void);


/**
 * @brief Wait for progress on any communication channel.
 *
 * This routine fosters progress of all communication within the pscom and waits
 * until progress was made on any communication channel.
 */
void pscom_wait_any(void);


/**
 * @brief Cancel a pscom request.
 *
 * This routine tries to cancel any kind of pscom request.
 *
 * @note See description of @ref pscom_cancel_send and @ref pscom_cancel_recv
 *       concerning details on the conditions when a cancel may fail.
 *
 * @param [in] request The request to be cancelled.
 *
 * @return 1  The request could be cancelled successfully.
 * @return 0  The request is already done or cancel failed.
 */
int pscom_cancel(pscom_request_t *request);


/**
 * @brief Cancel a send request.
 *
 * This routine attempts to cancel a send request (i.e.,
 * PSCOM_REQ_STATE_SEND_REQUEST). This fails if any IO of the request already
 * started or if the request is already marked as done (i.e.,
 * PSCOM_REQ_STATE_DONE).
 *
 * @param [in] request The send request to cancel.
 *
 * @return 1  The request could be cancelled successfully.
 * @return 0  The request is already done or cancel failed.
 */
int pscom_cancel_send(pscom_request_t *request);


/**
 * @brief Cancel a recv request.
 *
 * This routine attempts to cancel a send request (i.e.,
 * PSCOM_REQ_STATE_RECV_REQUEST). This fails if any IO of the request already
 * started or if the request is already marked as done (i.e.,
 * PSCOM_REQ_STATE_DONE).
 *
 * @param [in] request The recv request to cancel.
 *
 * @return 1  The request could be cancelled successfully.
 * @return 0  The request is already done or cancel failed.
 */
int pscom_cancel_recv(pscom_request_t *request);


/* return 1, if there is a matching receive. 0 otherwise. */
/* in case 1: copy also the message header */

/**
 * @brief Non-blocking probe for a matching message.
 *
 * This routine checks if any message (header) arrived that matches the provided
 * request, i.e., according to req->pub.ops.recv_accept. It does not block until
 * a matching message could be found but returns immediately. If a matching
 * message could be found, the message header is copied into the request
 * structure.
 *
 * @param [in] request The request to be matched.
 *
 * @return 1 If there is a matching message header; 0 otherwise.
 */
int pscom_iprobe(pscom_request_t *request);


/**
 * @brief Blocking probe for a matching message.
 *
 * This is the blocking version of @ref pscom_iprobe, i.e., it blocks until the
 * request could be matched successfully.
 *
 * @param [in] request The request to be matched.
 */
void pscom_probe(pscom_request_t *request);


static inline int pscom_req_state_successful(pscom_req_state_t state)
{
    return (state & (PSCOM_REQ_STATE_ERROR | PSCOM_REQ_STATE_CANCELED |
                     PSCOM_REQ_STATE_TRUNCATED | PSCOM_REQ_STATE_DONE)) ==
           (PSCOM_REQ_STATE_DONE);
}


static inline int pscom_req_successful(pscom_request_t *req)
{
    return pscom_req_state_successful(req->state);
}


static inline int pscom_req_state_is_done(pscom_req_state_t state)
{
    return state & PSCOM_REQ_STATE_DONE;
}


static inline int pscom_req_is_done(pscom_request_t *req)
{
    return pscom_req_state_is_done(req->state);
}


/*
 * Memory handling and CUDA support
 */
#ifdef PSCOM_CUDA_AWARENESS
/**
 * @brief A CUDA-aware memory copy.
 *
 * This routine implements a CUDA-aware memory copy operation that transparently
 * copies data to/from and between accelerators.
 *
 * @param [in] dst The destination address.
 * @param [in] src The source address.
 * @param [in] len The number of bytes to copy.
 */
void pscom_memcpy(void *dst, const void *src, size_t len);


/**
 * @brief Test whether a given address points to CUDA GPU memory.
 *
 * @param [in] ptr The pointer to test.
 *
 * @return 1 if @a ptr resides within GPU device memory; 0 otherwise.
 */
int pscom_is_gpu_mem(const void *ptr);
#else
static inline void pscom_memcpy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
}
#endif


/**
 * @brief Query if CUDA-support is enabled.
 *
 * @return boolean
 */
int pscom_is_cuda_enabled(void);


/*
 * Collective Operations/ Group handling
 */

typedef struct PSCOM_group pscom_group_t;


pscom_group_t *pscom_group_open(pscom_socket_t *socket, uint32_t group_id,
                                uint32_t my_grank, uint32_t group_size,
                                pscom_connection_t **connections);


void pscom_group_close(pscom_group_t *group);


/* post the broadcast request request.
   Send/Receive up to req->xheader_len bytes from/to req->xheader and
   up to req->data_len bytes from/to req->data from/to group with id
   req->xheader.bcast.group_id of socket req->socket.
   receive if req->xheader.bcast.group_src != group->my_rank, else send.

   req->xheader_len		: user len + sizeof(xheader.bcast)!
   req->xheader.bcast.group_id
   req->xheader.bcast.bcast_root
   req->xheader.bcast.user	: user data behind req->xheader.bcast
   req->data_len
   req->data
   req->socket

   optional:
   req->ops.recv_accept
   req->ops.io_done
*/
void pscom_post_bcast(pscom_request_t *request);


/* Blocking version of bcast */
void pscom_bcast(pscom_group_t *group, unsigned bcast_root, void *xheader,
                 size_t xheader_len, void *data, size_t data_len);


/* communication barrier in group group. */
void pscom_barrier(pscom_group_t *group);


/* find group by id */
pscom_group_t *pscom_group_find(pscom_socket_t *socket, uint32_t group_id);


/* get id from group */
uint32_t pscom_group_get_id(pscom_group_t *group);


/*
 * Connection type's
 */

/**
 * @brief Enable all connection types on a socket.
 *
 * This routine enables all connection types on a socket to be used for
 * communication.
 *
 * @note This is the default for a newly created socket.
 *
 * @note This does not prevent connection types from being disabled via the
 *       environment (i.e., env PSP_{arch}=0).
 *
 * @param [in] socket The communication socket.
 */
void pscom_con_type_mask_all(pscom_socket_t *socket);


/**
 * @brief Only enable one specific connection type on a socket.
 *
 * This routine disables all connection types on a socket except one specific.
 *
 * @param [in] socket   The communication socket.
 * @param [in] con_type The connection type to be enabled.
 */
void pscom_con_type_mask_only(pscom_socket_t *socket, pscom_con_type_t con_type);


/**
 * @brief Enable an additional connection type on a socket.
 *
 * This routine adds an additional connection type to the list of enabled
 * connection types of a socket.
 *
 * @param [in] socket   The communication socket.
 * @param [in] con_type The connection type to be added.
 */
void pscom_con_type_mask_add(pscom_socket_t *socket, pscom_con_type_t con_type);


/**
 * @brief Disable a connection type on a socket.
 *
 * This routine removes a connection type from the list of enabled connection
 * types of a socket.
 *
 * @param [in] socket   The communication socket.
 * @param [in] con_type The connection type to be removed.
 */
void pscom_con_type_mask_del(pscom_socket_t *socket, pscom_con_type_t con_type);


/**
 * @brief Test if a certain connection type is enabled on a given socket.
 *
 * This routine checks whether a given connection type belongs to the list of
 * enabled connection types of a socket.
 *
 * @param [in] socket   The communication socket.
 * @param [in] con_type The connection type to be tested.
 *
 * @return 1 if @a con_type is enabled; 0 otherwise.
 */
int pscom_con_type_mask_is_set(pscom_socket_t *socket,
                               pscom_con_type_t con_type);


/**
 * @brief Backup the list of enabled connection types of a socket.
 *
 * This routine creates a backup of the list of enabled connection types of a
 * given socket. The allocated memory gets either freed when restoring the mask
 * via @ref pscom_con_type_mask_restore or has to be freed manually.
 *
 * @param [in] socket The communication socket.
 *
 * @return An opaque pointer to the backup.
 *
 * @return NULL if any error occurred.
 */
void *pscom_con_type_mask_backup(pscom_socket_t *socket);


/**
 * @brief Restore a list of enabled connection types of a socket.
 *
 * This routine restores the connection type mask that has been previously
 * backed up via @ref pscom_con_type_mask_backup. It likewise releases the
 * memory storing this list, i.e., @a con_type_mask_backup must not be used
 * after this call.
 *
 * @param [in] socket               The communication socket.
 * @param [in] con_type_mask_backup The list to be restored.
 */
void pscom_con_type_mask_restore(pscom_socket_t *socket,
                                 void *con_type_mask_backup);


/**
 * @brief Get a reference to a connection of a given socket.
 *
 * This routine returns a reference to the next open connection of a given
 * socket. If @a con is provided (i.e., not NULL), it starts searching the list
 * from this connection. This may be useful when calling this routine multiple
 * times to not always retrieve the same open connection. Starts from the
 * beginning if con == NULL.
 *
 * @param [in] socket The communication socket to be queried.
 * @param [in] con    The connection where to start the search
 *
 * @return A pointer to the first open connection that could be found; NULL
 *         otherwise.
 */
pscom_connection_t *pscom_get_next_connection(pscom_socket_t *socket,
                                              pscom_connection_t *con);


/**
 * @brief Connect to a remote process using a string.
 *
 * This routine establishes a connection to a remote process using a socket
 * string that is returned by the @ref pscom_listen_socket_str call (or
 * @ref pscom_listen_socket_ondemand_str for on-demand connections) on the
 * remote side.
 *
 * @param connection The local connection to be used.
 * @param socket_str The connection string obtained at the remote process.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
pscom_err_t pscom_connect_socket_str(pscom_connection_t *connection,
                                     const char *socket_str);


/**
 * @brief Get the listening address of a socket.
 *
 * This routine returns a string that can be used to connect to this process
 * by calling @ref pscom_connect_socket_str. It does not set the socket to
 * listening state; this has to be done by calling @ref pscom_listen.
 *
 * @param [in] socket The communication socket to connect to.
 *
 * @return The string address of the listening socket; NULL if the socket is not
 *         in listening state.
 */
const char *pscom_listen_socket_str(pscom_socket_t *socket);


/**
 * @brief Get the listening address of a socket for on-demand connections.
 *
 * This routine returns a string that can be used to connect to this process
 * by calling @ref pscom_connect_socket_str. It does not set the socket to
 * listening state; this has to be done by calling @ref pscom_listen. The
 * returned address will be used for creating an on-demand connection (cf.
 * @ref pscom_connect_ondemand for details).
 *
 * @param [in] socket The communication socket to connect to.
 *
 * @return The string address of the listening socket; NULL if the socket is not
 *         in listening state.
 */
const char *pscom_listen_socket_ondemand_str(pscom_socket_t *socket);


/**
 * @brief Create a human-readable string describing the connection state.
 *
 * This routine translates a @ref pscom_con_state_t into a human-readable
 * string. The memory buffer is maintained internally and the string has to be
 * copied out for later use.
 *
 * @param [in] state The connection state to be translated into a string.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_con_state_str(pscom_con_state_t state);


/**
 * @brief Create a human-readable string describing the connection type.
 *
 * This routine translates a @ref pscom_con_type_t into a human-readable
 * string. The memory buffer is maintained internally and the string has to be
 * copied out for later use.
 *
 * @param [in] type The connection type to be translated into a string.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_con_type_str(pscom_con_type_t type);


/**
 * @brief Create a human-readable representation of the connection information.
 *
 * This routine translates a @ref pscom_con_info_t into a human-readable
 * string. The memory buffer is maintained internally and the string has to be
 * copied out for later use.
 *
 * @param [in] info The connection information to be translated into a string.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_con_info_str(pscom_con_info_t *con_info);

/**
 * @brief Create a human-readable representation of two connection information.
 *        objects
 *
 * This routine translates two @ref pscom_con_info_t objects into a
 * human-readable string of the form
 *
 *    (<con_info1>) to (<con_info2>)
 *
 * The memory buffer is maintained internally and the string has to be copied
 * out for later use.
 *
 * @param [in] con_info1 The first connection information to be translated.
 * @param [in] con_info2 The first connection information to be translated.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_con_info_str2(pscom_con_info_t *con_info1,
                                pscom_con_info_t *con_info2);


/**
 * @brief Create a human-readable representation of a pscom connection.
 *
 * This routine calls @ref pscom_con_str2 for a pscom connection.
 *
 * @param connection  The connection to be translated into a string.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_con_str(pscom_connection_t *connection);


/**
 * @brief Create a human-readable string describing the connection state.
 *
 * This routine translates a @ref pscom_con_state_t into a human-readable
 * string. The memory buffer is maintained internally and the string has to be
 * copied out for later use.
 *
 * @param [in] state The connection state to be translated into a string.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_req_state_str(pscom_req_state_t state);


/**
 * @brief Translate an error code to a verbose status message.
 *
 * @param [in] error The @ref pscom_err_t to be translated.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_err_str(pscom_err_t error);


/**
 * @brief Translate an operation type to a verbose string.
 *
 * @param [in] op The @ref pscom_op_t to be translated.
 *
 * @return Pointer to a buffer containing the NULL-terminated string.
 */
const char *pscom_op_str(pscom_op_t operation);


/**
 * @brief Memory region registration
 *
 * This routine registers a user-specified memory segment with pscom socket
 * and the plugins associated with it.
 *
 * @param [in]  socket   The pscom socket handle.
 * @param [in]  addr     The memory segment start address.
 * @param [in]  length   The length of the memory segment.
 * @param [out] memh     The memory region handle.
 *
 * @return  PSCOM_SUCCESS       success
 * @return  PSCOM_ERR_STDERROR  memory registration error in plugin layer
 * @return  PSCOM_ERR_INVALID   no valid socket or wrong address input
 */
pscom_err_t pscom_mem_register(pscom_socket_t *socket, void *addr,
                               size_t length, pscom_memh_t *memh);


/**
 * @brief Remote key generation
 *
 * This routine generates a remote key associated with the pscom connection and
 * plugin. The opaque key object in the remote key buffer is used to generate
 * the remote key. And the generated remote key object can be used by pscom RMA
 * routines.
 *
 * @param [in]  connection    The pscom connection handle.
 * @param [in]  rkeybuf       The remote key buffer returned by memory
 *                            registration from other processes.
 * @param [in]  bufsize       The buffer size.
 * @param [out] rkey          The remote key object used for RMA routines.
 *
 * @return  PSCOM_SUCCESS       success
 * @return  PSCOM_ERR_STDERROR  remote key generation error in plugin layer or
 *                              error in remote key buffer
 */
pscom_err_t pscom_rkey_generate(pscom_connection_t *connection, void *rkeybuf,
                                size_t bufsize, pscom_rkey_t *rkey);


/**
 * @brief Memory region deregistration
 *
 * This routine deregisters the memory region and frees the related memory
 * handle
 *
 * @param [in] memh    The memory region handle.
 *
 * @return  PSCOM_SUCCESS       success
 * @return  PSCOM_ERR_STDERROR  deregistration error in plugin layer
 */
pscom_err_t pscom_mem_deregister(pscom_memh_t memh);


/**
 * @brief Remote key destroy
 *
 * This routine destroys the remote key and frees its space
 *
 * @param [in] rkey    The remote key handle.
 *
 * @return  PSCOM_SUCCESS       success
 * @return  PSCOM_ERR_STDERROR  error in plugin layer
 */
pscom_err_t pscom_rkey_destroy(pscom_rkey_t rkey);


/**
 * @brief Pack remote key buffer
 *
 * This routine should be called after the registration of a memory region.
 * It allocates an opaque buffer and packs the information of the memory
 * region referenced by the region handle into it.
 * This opaque rkey buffer should then be sent to the remote process, which
 * can use it to generate a remote key for accessing the memory region.
 *
 * @param [out] rkeybuf   The remote key buffer returned from this routine.
 * @param [out] bufsize   The size of this opaque rkey buffer.
 * @param [in]  memh      The memory region handle.
 *
 * @return  PSCOM_SUCCESS       success
 * @return  PSCOM_ERR_INVALID   no valid memory region handle
 */
pscom_err_t pscom_rkey_buffer_pack(void **rkeybuf, size_t *bufsize,
                                   pscom_memh_t memh);


/**
 * @brief Remote key buffer release
 *
 * This routine frees the rkey buffer space which is allocated during the
 * registration of a memory region.
 * This should be called after the local completion of sending rkey_buffer to
 * those porcesses, which need it to generate a remote key.
 *
 * @param [in] rkey buffer    the buffer to be released.
 */
void pscom_rkey_buffer_release(void *rkey_buffer);


/**
 * @brief Non-blocking RMA put operation.
 *
 * This routine triggers a put operation of a contiguous block of data to the
 * memory of a remote process. The call returns immediately and the source data
 * region specified in the @a request must not be used before the operation is
 * completed, i.e., the io_done callback including the globally registered
 * RMA callback is invoked. The execution of pscom_wait() or other
 * similar functions, e.g., pscom_test_any(), will ensure progress.
 *
 * Mandatory fields in the @a request:
 * - req->data_len (number of bytes to be written)
 * - req->data (source address in the VA of the local process)
 * - req->connection (associated connection)
 * - req->ops.io_done
 *
 * @param [in] request         The request handle for tracking the progress.
 * @param [in] remote_address  The destination address within the VA of the
 *                             remote process.
 * @param [in] rkey            The remote key handle.
 *
 */
void pscom_post_rma_put(pscom_request_t *request, void *remote_address,
                        pscom_rkey_t rkey);


/**
 * @brief Non-blocking RMA get operation.
 *
 * This routine triggers a get operation of a contiguous block of data from the
 * memory of a remote process. The call returns immediately and the source data
 * region specified in the @a request must not be used before the operation is
 * completed, i.e., the io_done callback including the globally registered
 * RMA callback is invoked. The execution of pscom_wait() or other
 * similar functions, e.g., pscom_test_any(), will ensure progress.
 *
 * Mandatory fields in the @a request:
 * - req->data_len (number of bytes to be gotten)
 * - req->data (target address in the VA of the local process)
 * - req->connection (associated connection)
 * - req->ops.io_done
 *
 * @param [in] request        The request handle for tracking the progress.
 * @param [in] remote_address The source address within the VA of the remote
 *                            process.
 * @param [in] rkey           The remote key handle.
 *
 */
void pscom_post_rma_get(pscom_request_t *request, void *remote_address,
                        pscom_rkey_t rkey);


const char *pscom_socket_str(int nodeid, int portno);
const char *pscom_socket_ondemand_str(int nodeid, int portno,
                                      const char name[8]);
int pscom_parse_socket_str(const char *socket_str, int *nodeid, int *portno);
int pscom_parse_socket_ondemand_str(const char *socket_str, int *nodeid,
                                    int *portno, char (*name)[8]);


void pscom_set_debug(int level);

ssize_t pscom_readall(int fd, void *buf, size_t count);
ssize_t pscom_writeall(int fd, const void *buf, size_t count);
int pscom_atoport(const char *service, const char *proto);
int pscom_atoaddr(const char *address, struct in_addr *addr);
int pscom_ascii_to_sockaddr_in(const char *host, const char *port,
                               const char *protocol, struct sockaddr_in *addr);

const char *pscom_dumpstr(const void *buf, size_t size);


#define pscom_min(a, b) (((a) < (b)) ? (a) : (b))
#define pscom_max(a, b) (((a) > (b)) ? (a) : (b))

void pscom_dump_connection(FILE *out, pscom_connection_t *connection);
void pscom_dump_reqstat(FILE *out);
void pscom_dump_info(FILE *out);

/* Get value name from environment */
void pscom_env_get_int(int *val, const char *name);
void pscom_env_get_uint(unsigned int *val, const char *name);
void pscom_env_get_size_t(size_t *val, const char *name);
void pscom_env_get_str(char **val, const char *name);
void pscom_env_get_dir(char **val, const char *name);

extern char *(*pscom_env_get)(const char *name);
extern int (*pscom_env_set)(const char *name, const char *value, int overwrite);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _PSCOM_H_ */

/*
 * Local Variables:
 *   mode: c
 *   c-basic-offset: 8
 * End:
 */
