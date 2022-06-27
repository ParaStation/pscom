/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSPORTALS_H_
#define _PSPORTALS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

/* some forward declarations */
typedef struct psptl_con_info psptl_con_info_t;
typedef struct psptl_ep psptl_ep_t;


/**
 * @brief The initialization state of the psptl layer.
 */
typedef enum psptl_init_state {
    PSPORTALS_NOT_INITIALIZED = 1, /**< psptl_init() has not been called */
    PSPORTALS_INIT_DONE       = 0, /**< The psptl layer is initialized */
    PSPORTALS_INIT_FAILED     = -1 /**< The initialization of the psptl layer
                                        failed */
} psptl_init_state_t;


/**
 * @brief The different protocols implemented by the psptl layer.
 */
typedef enum psptl_prot_type {
    PSPTL_PROT_EAGER, /**< Eager communication */
    PSPTL_PROT_RNDV,  /**< Rendezvous (write) communication */
    PSPTL_PROT_COUNT, /**< The number of implemented communication protocols */
} psptl_prot_type_t;


/**
 * @brief Information exchanged during the pscom4portals handshake.
 */
typedef struct psptl_info_msg {
    uint64_t pid;                   /**< The Portals4 PID */
    uint32_t pti[PSPTL_PROT_COUNT]; /**< The PTIs for the different protocols */
} psptl_info_msg_t;


/**
 * @brief Callback triggered on the termination of an eager send request.
 *
 * This callback is triggered by the psptl layer once an eager send request has
 * been completed (be it successfully or not).
 *
 * @param [in] con_priv An opaque handle set in con_info->con_priv.
 */
typedef void (*psptl_sendv_done_t)(void *con_priv);


/**
 * @brief Callback triggered on the arrival of an eager packet.
 *
 * This callback is triggered once a new eager packet arrived on the psptl
 * layer.
 *
 * @param [in] priv An opaque handle set in con_info->con_priv.
 * @param [in] buf  A pointer to the memory location where the packet is stored.
 * @param [in] len  Length of the received data.
 */
typedef void (*psptl_recv_done_t)(void *priv, void *buf, size_t len);


/**
 * @brief Configuration structure of the psptl layer.
 */
typedef struct psptl {
    struct {
        int level;    /**< The debug level */
        FILE *stream; /**< The debug stream */
    } debug;
    uint32_t eq_size; /**< Size of the event queues */
    struct {
        size_t bufsize;            /**< Size of the pre-allocate comm buffers */
        size_t rndv_fragment_size; /**< Max. size of the rendezvous fragments */
        uint32_t sendq_size;       /**< Number of pre-allocated send buffers */
        uint32_t recvq_size;       /**< Number of pre-allocated recv buffers */
        uint32_t max_rndv_reqs;    /**< Max. number of rendezvous requests */
    } con_params;                  /**< Per-connection parameters */
    struct {
        uint64_t retry_cnt;           /**< Number of eager retries */
        uint64_t outstanding_put_ops; /**< Outstanding (eager) put operations */
        uint64_t rndv_write;          /**< Number of rndv write operations */
    } stats;                          /**< Plugin-wide statistics */
    struct {
        psptl_sendv_done_t sendv_done; /**< cf. @ref psptl_sendv_done_t */
        psptl_recv_done_t recv_done;   /**< cf. @ref psptl_recv_done_t */
    } callbacks;                       /**< Callbacks set by the upper
                                            pscom4portals layer */

    psptl_init_state_t init_state; /**< Initialization state of psptl */
    struct list_head cleanup_cons; /**< Connection to be cleanup within
                                        @ref psptl_cleanup_ep */
} psptl_t;


/**
 * @brief Memory region for receiving RMA puts (i.e., PtlPut()).
 */
typedef struct psptl_rma_mreg {
    void *priv;          /**< An internal handle to a memory region */
    uint64_t match_bits; /**< Match bits to be exchanged with the peer */
} psptl_rma_mreg_t;

/**
 * @brief A structure holding relevant information describing an RMA request
 */
typedef struct psptl_rma_req {
    void (*io_done)(void *priv, int err); /**< CB triggered once the request has
                                               been processed */
    void *priv;                           /**< Handle to be passe to io_done */
    psptl_con_info_t *con_info;           /**< Handle to the corresponding
                                               @ref psptl_con_info_t */
    void *data;                           /**< User buffer to be sent */
    size_t data_len;                      /**< Amount of bytes to be sent */
    uint64_t match_bits;                  /**< Match bits defined by the peer */
    size_t remaining_fragments;           /**< Remaining fragments of this RMA
                                               request */
} psptl_rma_req_t;


/**
 * @brief Provides the upper pscom4portals layer access to the psptl config.
 */
extern psptl_t psptl;


/**
 * @brief Plugin-wide initialization of the psptl layer.
 *
 * @return 0 on success; -1 otherwise.
 */
int psptl_init(void);


/**
 * @brief Plugin-wide finalize of the psptl layer.
 */
void psptl_finalize(void);


/**
 * @brief Initialize a psptl endpoint.
 *
 * This function initializes a psptl endpoint that can be used by multiple
 * connections belonging to the same socket. It sets up the required event
 * queues and allocates the portals indices necessary for message matching.
 *
 * @param [out] ep_priv An opaque handle to the endpoint.
 *
 * @return 0 on success; -1 otherwise.
 */
int psptl_init_ep(void **ep_priv);


/**
 * @brief Cleanup of endpoint-related resources.
 *
 * This function cleans up all resources that have been allocated and configured
 * in a previous call to @ref psptl_init_ep.
 *
 * @param [in] ep_priv  An opaque handle to the endpoint information.
 */
void psptl_cleanup_ep(void *ep_priv);


/**
 * @brief Create a @ref psptl_con_info_t object.
 *
 * This function allocates a psptl_con_info_t object used for bookkeeping and
 * the configuration of a pscom4portals connection.
 *
 * @return A handle to a pre-initialized and opaque psptl_con_info_t object.
 */
psptl_con_info_t *psptl_con_create(void);


/**
 * @brief Initialize a @ref psptl_con_info_t object.
 *
 * This function initializes a previously allocated psptl_con_info_t object with
 * local endpoint information required for latter connection setup among others.
 *
 * @param [in] con_info The psptl_con_info_t object to be initialized.
 * @param [in] con_priv The corresponding pscom_con_t from the pscom layer.
 * @param [in] ep_priv  The corresponding psptl endpoint object.
 *
 * @return 0
 */
int psptl_con_init(psptl_con_info_t *con_info, void *con_priv, void *ep_priv);


/**
 * @brief Create and initialize the eager communication buffers.
 *
 * This function denotes the final step during the creation and initialization
 * of a pscom4portals connection. It creates and initializes the pre-allocated
 * eager buffers based on the endpoint information obtained from the peer
 * process.
 *
 * @param [in] con_info The local psptl_con_info_t object of this connection.
 * @param [in] info_msg The remote endpoint information.
 *
 * @return 0 on success; -1 otherwise.
 */
int psptl_con_connect(psptl_con_info_t *con_info, psptl_info_msg_t *info_msg);


/**
 * @brief Cleanup the eager communication buffers.
 *
 * This function cleanups all eager-related resources of the corresponding
 * connection. If there are outstanding put operations, the release of resources
 * is deferred until @ref psptl_cleanup_ep is called to avoid the receiving of
 * unexpected events.
 *
 * @param [in] con_info The psptl_con_info_t object whose resources should be
 *                      released.
 */
void psptl_con_cleanup(psptl_con_info_t *con_info);


/**
 * @brief Release the psptl_con_info_t object.
 *
 * This function releases the psptl_con_info_t object and should be called after
 * the cleanup (@ref psptl_con_cleanup) of this connection. If it is not
 * possible to release the resources (e.g., since there are outstanding send
 * requests), it adds the psptl_con_info_t object to a list to be processed
 * during @ref psptl_cleanup_ep.
 *
 * @note The psptl_con_info_t object should *not* be used after a call to
 *       psptl_con_free!
 *
 * @param [in] con_info The psptl_con_info_t to be released.
 */
void psptl_con_free(psptl_con_info_t *con_info);


/**
 * @brief Obtain the local endpoint information for connection establishment.
 *
 * This routine extracts information from a @ref psptl_con_info_t object to be
 * sent to a peer process for the connection establishment.
 *
 * @param [in]  con_info The local pscom_con_info_t object
 * @param [out] info_msg A pre-allocated psptl_info_msg_t object to be filled
 *                       with the relevant endpoint information.
 */
void psptl_con_get_info_msg(psptl_con_info_t *con_info,
                            psptl_info_msg_t *info_msg);


/**
 * @brief Make progress on a psptl endpoint.
 *
 * This function check the endpoint-related event queues for incoming events (be
 * it eager-related or rendezvous-related) and processes them accordingly.
 *
 * @param [in] ep_priv The endpoint to make progress on.
 *
 * @return 1 if there was progress on any of the endpoint's connections;
 *         0 otherwise.
 */
int psptl_progress(void *ep_priv);


/**
 * @brief Request the (eager) transmission of an iov on a connection.
 *
 * @param [in] con_info The connection to be used for sending the iov.
 * @param [in] iov      The iov to be sent.
 * @param [in] len      The total amount of bytes to be sent.
 *
 * @return The actual amount of bytes being sent. In case of an error, a
 *         negative errno is returned indicating the failure:
 *
 *         EAGAIN There are no free send buffers left
 *         EPIPE  An error happened on the lower Portals4 layer
 */
ssize_t
psptl_sendv(psptl_con_info_t *con_info, struct iovec iov[2], size_t len);


/**
 * @brief Configure the debug output of the psptl layer.
 *
 * @param [in] stream The debug stream that shall be used
 * @param [in] level  The debug level
 */
void psptl_configure_debug(FILE *stream, int level);


/**
 * @brief Print plugin-wide communication-related statistics.
 */
void psptl_print_stats(void);


/**
 * @brief Register a communication buffer for later RMA transfers.
 *
 * This function registers a memory buffer to be used for RMA transfers by
 * remote processes with the Portals4 layer. Additionally, it initializes a
 * pre-allocated @ref psptl_rma_mreg_t object identifying this RMA regions
 * during later RMA transfers.
 *
 * @param [in]  con_info The connection to be used for the RMA transfers
 * @param [in]  buf      The memory buffer to be registered
 * @param [in]  len      The length of the memory buffer
 * @param [out] rma_mreg A pre-allocated psptl_rma_mreg_t object describing the
 *                       RMA region.
 *
 * @return 0 on success; -1 otherwise.
 */
int psptl_rma_mem_register(psptl_con_info_t *con_info, void *buf, size_t len,
                           psptl_rma_mreg_t *rma_mreg);


/**
 * @brief Deregister a RMA region From the psptl layer.
 *
 * This function deregisters a previously registered RMA region from the psptl
 * layer (e.g., at the end of a rendezvous transfer). It releases all
 * resources that have been allocated in @ref psptl_rma_mem_register.
 *
 * @param [in] rma_mreg The RMA region to be deregistered.
 */
void psptl_rma_mem_deregister(psptl_rma_mreg_t *rma_mreg);


/**
 * @brief Process an RMA put request.
 *
 * This function processes an RMA put (i.e, write) request to a remote
 * @ref psptl_rma_mreg_t. This is an asynchronous operations whose termination
 * is indicated by a call to rma_req->io_done.
 *
 * @param [in] rma_req The RMA region to write to.
 *
 * @return 0 on success; -1 otherwise.
 */
int psptl_post_rma_put(psptl_rma_req_t *rma_req);

#endif /* _PSPORTALS_H_ */
