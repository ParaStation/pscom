/*
 * ParaStation
 *
 * Copyright (C) 2022-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_portals.h"
#include "pscom_async.h"
#include "pscom_con.h"
#include "pscom_precon.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "psptl.h"

uint8_t foster_progress = 0;

/**
 * @brief Initialization state of the pscom4portals socket.
 */
typedef enum pscom_portals_sock_init_state {
    PSCOM_PORTALS_SOCK_NOT_INITIALIZED = 1, /**< The psptl layer has not been
                                                 initialized */
    PSCOM_PORTALS_SOCK_INIT_DONE       = 0, /**< The psptl has been initialized
                                                 successfully */
    PSCOM_PORTALS_SOCK_INIT_FAILED     = -1 /**< The initialization of the psptl
                                                 layer failed */
} pscom_portals_sock_init_state_t;


/**
 * @brief The pscom4portals environment configuration table.
 */
pscom_env_table_entry_t pscom_env_table_portals[] = {
    {"BUFFER_SIZE", "8192", "The size of the buffers in the send/recv queues.",
     &psptl.con_params.bufsize, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"RECVQ_SIZE", "16", "Number of receive buffers per connection.",
     &psptl.con_params.recvq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"SENDQ_SIZE", "16", "Number of send buffers per connection.",
     &psptl.con_params.sendq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"EQ_SIZE", "65536", "Size of the event queue.", &psptl.eq_size,
     PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_UINT},

    {"FOSTER_PROGRESS", "0",
     "Make additional progress on the completion of send operations "
     "(when relying on SWPTL this may be required).",
     &foster_progress, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_UINT},

    {"MAX_RNDV_REQS", "4096",
     "Maximum number of outstanding rendezvous requests per connection.",
     &psptl.con_params.max_rndv_reqs, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"RNDV_FRAGMENT_SIZE", "inf",
     "Maximum size of the fragments being sent during rendezvous "
     "communication. "
     "This is limited by the maximum message size supported by the NI.",
     &psptl.con_params.rndv_fragment_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"RENDEZVOUS", "40000", "The rendezvous threshold for pscom4portals.",
     &pscom.env.rendezvous_size_portals, PSCOM_ENV_ENTRY_HAS_PARENT,
     PSCOM_ENV_PARSER_UINT},

    {0},
};

/**
 * @brief Structure holding rendezvous data.
 *
 * This structure is used to store and exchange information between the
 * different steps taken on the rendezvous path.
 */
typedef union pscom_rendezvous_data_portals {
    /* RMA write: receiver side */
    struct {
        psptl_rma_mreg_t rma_mreg; /**< descriptor for the RMA region */
    } rma_write_rx;
    /* RMA write: sender side */
    struct {
        psptl_rma_req_t rma_req;              /**< RMA request object */
        void (*io_done)(void *priv, int err); /**< upper layer io_done cb */
        void *priv;                           /**< argument to io_done cb */
    } rma_write_tx;
} pscom_rendezvous_data_portals_t;

static int pscom_portals_make_progress(pscom_poll_t *poll);

/**
 * @brief Increase the number of connections in reading state on a socket.
 *
 * Increases an internal counter in the psptl_sock_t structure to keep track of
 * its connections in reading state. If this is the first connection, it
 * actually appends the polling object to the pscom's global reading queue,
 * i.e., there is only _one_ polling object for all connections of a socket.
 *
 * @param [in] sock The socket corresponding to the connection in reading state.
 */
static void poll_reader_inc(psptl_sock_t *sock)
{
    /* enqueue to polling reader if not enqueued yet */
    if (!sock->reader_user) {
        pscom_poll_start(&sock->poll_read, pscom_portals_make_progress,
                         &pscom.poll_read);
    }

    /* increase the reader counter */
    sock->reader_user++;
}


/**
 * @brief Decrease the number of connections in reading state on a socket.
 *
 * Decreases an internal counter in the psptl_sock_t structure to keep track of
 * its connections in reading state. (see also: poll_reader_inc()).
 *
 * @param [in] sock The socket corresponding to the connection in reading state.
 */
static void poll_reader_dec(psptl_sock_t *sock)
{
    /* decrease the reader counter */
    sock->reader_user--;

    /* dequeue from polling reader if there are no readers left */
    if (!sock->reader_user) { pscom_poll_stop(&sock->poll_read); }
}

/**
 * @brief Set a pscom4portals connection to reading state.
 *
 * Sets a  connection to reading state. This can be called multiple times on the
 * same connection.
 *
 * @param [in] con The connection to be set to reading state.
 */
static void pscom_portals_read_start(pscom_con_t *con)
{
    /* set to reading state if not yet reading */
    if (!con->arch.portals.reading) {
        psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

        con->arch.portals.reading = 1;
        poll_reader_inc(sock);
    }
}


/**
 * @brief Unset a pscom4portals connection's reading state.
 *
 * Stop reading on a connection. This can be called multiple times on the same
 * connection regardless of the number of previous calls to
 * pscom_portals_read_start().
 *
 * @param [in] con The connection to stop reading.
 */
static void pscom_portals_read_stop(pscom_con_t *con)
{
    /* unset reading state if this connection is still reading */
    if (con->arch.portals.reading) {
        psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

        con->arch.portals.reading = 0;
        poll_reader_dec(sock);
    }
}


/**
 * @brief Make progress on all connections of a socket.
 *
 * @param [in] poll The polling object corresponding to the portals socket.
 *
 * @return 1 if progress was made on any connection; 0 otherwise.
 */
static int pscom_portals_make_progress(pscom_poll_t *poll)
{
    /* retrieve the socket corresponding to the polling object */
    psptl_sock_t *sock = list_entry(poll, psptl_sock_t, poll_read);

    /* trigger the progress engine of the lower psptl layer */
    return psptl_progress(sock->priv);
}


/**
 * @brief Callback to be triggered upon successful data transmission.
 *
 * This callback is triggered by the psptl layer, once an (eager) send request
 * has been completed locally. This decrements the reader counter that has been
 * incremented in a previous call to pscom_portals_do_write() after posting the
 * send request.
 *
 * @param [in] sock_priv The socket corresponding to the connection on which the
 *                       send request terminated.
 */
static inline void pscom_portals_sendv_done(void *sock_priv)
{
    psptl_sock_t *sock = (psptl_sock_t *)sock_priv;

    poll_reader_dec(sock);
}


/**
 * @brief Alternative CB to be triggered upon successful data transmission.
 *
 * This is an alternative callback to pscom_portals_sendv_done() that
 * additionally triggers the progress engine if there are not more readers on
 * the corresponding socket.
 *
 * @remark This might be required when using the SWPTL implementation and can be
 *         enabled by setting the `PSP_PORTALS4_FOSTER_PROGRESS` environment
 *         variable.
 *
 * @param [in] sock_priv The socket corresponding to the connection on which the
 *                       send request terminated.
 */
static void pscom_portals_sendv_done_with_progress(void *sock_priv)
{
    psptl_sock_t *sock = (psptl_sock_t *)sock_priv;

    pscom_portals_sendv_done(sock);

    /* trigger the progress engine once again */
    if (!sock->reader_user) { psptl_progress(sock->priv); }
}


/**
 * @brief Callback to be triggered once incoming data arrived.
 *
 * This callback is triggered by the psptl layer once (eager) data has been
 * stored into an intermediate buffer and can be copied to the target user
 * buffer.
 *
 * @param [in] priv The connection on which the data arrived.
 * @param [in] buf  The intermediate buffer where the new data is located.
 * @param [in] len  Number of bytes to be copied to the user buffer.
 */
static void pscom_portals_recv_done(void *priv, void *buf, size_t len)
{
    pscom_con_t *con = (pscom_con_t *)priv;
    assert(con->magic == MAGIC_CONNECTION);

    pscom_read_done(con, buf, len);
}


/**
 * @brief Send eager data on a connection.
 *
 * This function is triggered by the pscom's progress engine and grabs the next
 * send request of the connection's send queue. As the lower psptl layer relies
 * on pre-allocated send buffers, the corresponding user buffers may be modified
 * directly afterwards.
 *
 * The reader counter is increased (decrease in pscom_portals_sendv_done()) to
 * ensure the progress engine is triggered regularly until the send request has
 * been processed by the lower psptl layer.
 *
 * @param [in] poll The polling object corresponding to the connection.
 *
 * @return 0 always (i.e., do not leave the progress engine upon successful
 *         write)
 */
static int pscom_portals_do_write(pscom_poll_t *poll)
{
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;
    pscom_con_t *con   = list_entry(poll, pscom_con_t, poll_write);
    psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

    /* get the next req/iov from the connection's send queue */
    req = pscom_write_get_iov(con, iov);

    if (req) {
        psptl_con_info_t *ci = con->arch.portals.ci;
        len                  = iov[0].iov_len + iov[1].iov_len;

        /* post the send request to the lower psptl layer */
        ssize_t slen = psptl_sendv(ci, iov, len);

        if (slen >= 0) {
            /* ensure execution of the psptl progress engine */
            poll_reader_inc(sock);

            /* tell the upper layers that the user buffers can be modified */
            pscom_write_done(con, req, slen);
        } else if (slen != -EAGAIN) {
            /* set the connection into error state */
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }

    return 0;
}


/**
 * @brief Retrieve the portals-specific rendezvous data.
 *
 * @param [in] rd The generic rendezvous data object of the pscom.
 *
 * @return A handle to the portals-specific rendezvous data.
 */
static inline pscom_rendezvous_data_portals_t *
get_req_data(pscom_rendezvous_data_t *rd)
{
    _pscom_rendezvous_data_portals_t *data = &rd->arch.portals;
    pscom_rendezvous_data_portals_t *res   = (pscom_rendezvous_data_portals_t *)
        data;
    assert(sizeof(*res) <= sizeof(*data));
    return res;
}


/**
 * @brief Register a memory region used for RMA (i.e., rendezvous) transfers.
 *
 * This function registers a memory region to be used by later rendezvous
 * transfers and prepares the control message to be sent to the peer process.
 *
 * @param [in] con The connection to be used for the RMA transfers.
 * @param [in] rd  A handle to a rendezvous data object.
 *
 * @return The size of the rendezvous control message; 0 in case of an error.
 */
static unsigned int
pscom_portals_rma_mem_register(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
    int err = 0;

    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(rd);
    psptl_rma_mreg_t *psptl_rma_mreg = &rd_portals->rma_write_rx.rma_mreg;

    /* register the RMA region */
    err = psptl_rma_mem_register(con->arch.portals.ci, rd->msg.data,
                                 rd->msg.data_len, psptl_rma_mreg);
    if (err < 0) goto err_out;

    /* provide match bits to the peer */
    rd->msg.arch.portals.match_bits = psptl_rma_mreg->match_bits;

    return sizeof(rd->msg.arch.portals);
    /* --- */
err_out:
    return 0;
}


/**
 * @brief Deregister a memory region used for RMA (i.e., rendezvous) transfers.
 *
 * This function deregisters a memory region that was used for previous
 * rendezvous transfers.
 *
 * @param [in] con The connection to be used for the RMA transfers.
 * @param [in] rd  A handle to a rendezvous data object.
 */
static void
pscom_portals_rma_mem_deregister(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(rd);
    psptl_rma_mreg_t *psptl_rma_mreg = &rd_portals->rma_write_rx.rma_mreg;

    /* deregister the RMA region */
    psptl_rma_mem_deregister(psptl_rma_mreg);
}


/**
 * @brief Callback triggered upon successful transmission of RMA data.
 *
 * This callback is triggered by the psptl layer once the corresponding RMA
 * operation completed on the remote side. The callback then informs the upper
 * pscom layer triggering the next step of the rendezvous protocol.
 *
 * @note Additionally, it frees resources that have been allocated previously in
 *       @ref pscom_portals_rma_write().
 *
 * @param [in] priv Handle to the rendezvous data object.
 * @param [in] err  Error flag (0: success; 1: error)
 */
static void pscom_portals_rma_write_io_done(void *priv, int err)
{
    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)priv;
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(rd);

    /* trigger the upper layer io_cone callback */
    rd_portals->rma_write_tx.io_done(rd_portals->rma_write_tx.priv, err);

    /* free the rendezvous data (allocated in pscom_portals_rma_write()) */
    free(rd);
}


/**
 * @brief Trigger an RMA operation on a connection.
 *
 * This function triggers an RMA operation on a connection by preparing an
 * according rendezvous data object and requesting the lower psptl layer to
 * perform the actual data transfer.
 *
 * @note Allocated resources are freed by
 *       @ref pscom_portals_rma_write_io_done().
 *
 * @param [in] con       The connection to be used for the RMA operation.
 * @param [in] src       The source buffer to the data to be written.
 * @param [in] rndv_msg  Information on the target buffer.
 * @param [in] io_done   A callback to be triggered on successful transmission.
 * @param [in] priv      An opaque handle to be passed to the io_done callback.
 *
 * @return 0 in case of success; -1 otherwise.
 */
static int pscom_portals_rma_write(pscom_con_t *con, void *src,
                                   pscom_rendezvous_msg_t *rndv_msg,
                                   void (*io_done)(void *priv, int err),
                                   void *priv)
{
    int err;
    psptl_con_info_t *con_info  = con->arch.portals.ci;
    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)malloc(
        sizeof(*rd));
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(rd);
    psptl_rma_req_t *psptl_rma_req = &rd_portals->rma_write_tx.rma_req;

    /* prepare the internal RMA request */
    psptl_rma_req->io_done    = pscom_portals_rma_write_io_done;
    psptl_rma_req->priv       = rd;
    psptl_rma_req->match_bits = rndv_msg->arch.portals.match_bits;
    psptl_rma_req->data       = rndv_msg->data;
    psptl_rma_req->data_len   = rndv_msg->data_len;
    psptl_rma_req->con_info   = con_info;

    /* store the io_done callback information */
    rd_portals->rma_write_tx.io_done = io_done;
    rd_portals->rma_write_tx.priv    = priv;

    /* write to the RMA region */
    err = psptl_post_rma_put(psptl_rma_req);
    if (err < 0) goto err_out;

    return 0;
    /* --- */
err_out:
    return -1;
}


/**
 * @brief Cleanup routine.
 *
 * This function cleans up the eager-related resources of a pscom4portals
 * connection. This can be called multiple times.
 *
 * @param [in] con The connection to be cleaned up.
 */
static void pscom_portals_con_cleanup(pscom_con_t *con)
{
    psptl_con_info_t *ci = con->arch.portals.ci;
    if (!ci) return;

    psptl_con_cleanup(ci);
    psptl_con_free(ci);

    con->arch.portals.ci = NULL;
}


/**
 * @brief Close a pscom4portals connection.
 *
 * This implements the con->close() callback of the pscom4portals plugin. It
 * wraps around pscom_portals_con_cleanup() adding a sanity check whether this
 * already has been called before.
 *
 * @param [in] con The connection to be closed.
 */
static void pscom_portals_con_close(pscom_con_t *con)
{
    psptl_con_info_t *ci = con->arch.portals.ci;
    if (!ci) return;

    pscom_portals_con_cleanup(con);
}


/**
 * @brief Start writing on a connection.
 *
 * This implements the con->write_start() callback of the pscom4portals plugin
 * by leveraging the pscom's polling interface.
 *
 * @param [in] con The connection that shall start writing.
 */
static void pscom_poll_write_start_portals(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_portals_do_write);
}


/**
 * @brief Configure eager-related callbacks.
 *
 * This function sets the callbacks related to the eager protocol of the
 * pscom4portals plugin.
 *
 * @param [in] con The connection to be configured.
 */
static void pscom_portals_configure_eager(pscom_con_t *con)
{
    con->write_start = pscom_poll_write_start_portals;
    con->write_stop  = pscom_poll_write_stop;

    con->read_start = pscom_portals_read_start;
    con->read_stop  = pscom_portals_read_stop;
}


/**
 * @brief Configure rendezvous(-write)-related callbacks.
 *
 * This function sets the callbacks related to the rendezvous write  protocol of
 * the pscom4portals plugin.
 *
 * @param [in] con The connection to be configured.
 */
static void pscom_portals_configure_rndv_write(pscom_con_t *con)
{
    /* memory (de-)registration */
    con->rma_mem_register       = pscom_portals_rma_mem_register;
    con->rma_mem_deregister     = pscom_portals_rma_mem_deregister;
    con->rma_mem_register_check = NULL;

    /* communication */
    con->rma_write = pscom_portals_rma_write;

    /* the rendezvous threshold */
    con->rendezvous_size = pscom.env.rendezvous_size_portals;
}


/**
 * @brief Initialize a pscom4portals connection.
 *
 * This function initializes a pscom4portals connection after a successful
 * handshake. It sets the connection's type and the according callback routines.
 *
 * @param [in] con The connection to be initialized.
 */
static void pscom_portals_init_con(pscom_con_t *con)
{
    con->pub.type = PSCOM_CON_TYPE_PORTALS;

    /* eager communication */
    pscom_portals_configure_eager(con);

    /* rendezvous RMA write interface */
    pscom_portals_configure_rndv_write(con);

    con->close = pscom_portals_con_close;

    pscom_con_setup_ok(con);
}


/**
 * @brief Initialize the pscom4portals plugin.
 *
 * This function implements the plugin->init() callback of the pscom4portals
 * plugin. It only prepares the plugin to be initialized on the first call
 * to plugin->con_init(). This way, the underlying psptl layer is not
 * initialized before the first connection is created within this plugin.
 *
 */
static void pscom_portals_init(void)
{
    psptl_configure_debug(pscom_debug_stream(), pscom.env.debug);

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom PORTALS", "PORTALS_",
                                       pscom_env_table_portals);

    /* set the callbacks to be called by the lowe layer */
    if (foster_progress) {
        psptl.callbacks.sendv_done = pscom_portals_sendv_done_with_progress;
    } else {
        psptl.callbacks.sendv_done = pscom_portals_sendv_done;
    }
    psptl.callbacks.recv_done = pscom_portals_recv_done;
}


/**
 * @brief Initialize a pscom4portals socket.
 *
 * This function implements the plugin->sock_init() callback of the
 * pscom4portals plugin. It only prepares the the socket but the actual
 * initialization does not take place before plugin->con_init() is called for
 * the first time. This way, the underlying psptl layer is only initialized if
 * there is actually a connection created within this plugin.
 *
 * @param [in] sock The socket to be initialized.
 */
static void pscom_portals_sock_init(pscom_sock_t *sock)
{
    psptl_sock_t *portals_sock = &sock->portals;

    /* initialize the poll reader */
    pscom_poll_init(&portals_sock->poll_read);
    portals_sock->reader_user = 0;

    /* set the initialization state */
    portals_sock->init_state = PSCOM_PORTALS_SOCK_NOT_INITIALIZED;
}


/**
 * @brief Destroy a pscom4portals socket.
 *
 * This function implements the plugin->sock_destroy() callback of the
 * pscom4portals plugin.
 *
 * @param [in] sock The socket to be destroyed.
 */
static void pscom_portals_sock_destroy(pscom_sock_t *sock)
{
    psptl_sock_t *portals_sock = &sock->portals;

    /* only cleanup the ep if the socket has been (successfully) initialized */
    if (portals_sock->init_state == PSCOM_PORTALS_SOCK_INIT_DONE) {
        psptl_cleanup_ep(portals_sock->priv);
        portals_sock->priv = NULL;
    }

    /* are there still any connections in reading state */
    if (portals_sock->reader_user) {
        DPRINT(D_WARN,
               "Closing the reader of sock %p but there are still %u "
               "connections in reading state!",
               sock, portals_sock->reader_user);
    }

    /* we do not want to make further progress on the Portals4 layer */
    pscom_poll_stop(&portals_sock->poll_read);

    /* set the initialization state */
    portals_sock->init_state = PSCOM_PORTALS_SOCK_NOT_INITIALIZED;
}


/**
 * @brief Pre-initialization of a pscom4portals connection.
 *
 * This function implements the plugin->con_init() callback of the pscom4portals
 * plugin. It ensures the proper initialization of the underlying psptl layer
 * on the creation of the first pscom4portals connection. Likewise, it ensures
 * the initialization of the psptl endpoint on the first connection created on
 * this socket.
 *
 * @param [in] con The connection to be initialized.
 *
 * @return 0 on success; -1 on failure
 */
static int pscom_portals_con_init(pscom_con_t *con)
{
    int ret;
    psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

    /* initialize the psptl layer (once for all sockets) */
    ret = psptl_init();
    if (ret != PSPORTALS_INIT_DONE) goto err_out;

    /*
     * initialize one endpoint per sock
     * (cleanup in pscom_portals_sock_destroy()!)
     */
    if (sock->init_state == PSCOM_PORTALS_SOCK_NOT_INITIALIZED) {
        ret = psptl_init_ep(&sock->priv);
        if (ret < 0) goto err_out;

        sock->init_state = PSCOM_PORTALS_SOCK_INIT_DONE;
    }

    return sock->init_state;
    /* --- */
err_out:
    sock->init_state = PSCOM_PORTALS_SOCK_INIT_FAILED;
    return ret;
}

#define PSCOM_INFO_PORTALS_ID PSCOM_INFO_ARCH_STEP1


/**
 * @brief The handshake procedure of the pscom4portals plugin.
 *
 * This function implements the handshake procedure of the pscom4portals plugin.
 *
 * @param [in] con  The connection to be initialized.
 * @param [in] type The handshake message type.
 * @param [in] data The psptl_info_msg_t in the PSCOM_INFO_PORTALS_ID step.
 * @param [in] size Size of @ref data.
 */
static void
pscom_portals_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
    switch (type) {
    case PSCOM_INFO_ARCH_REQ: {
        psptl_info_msg_t msg = {0};
        psptl_con_info_t *ci = psptl_con_create();
        psptl_sock_t *sock   = &get_sock(con->pub.socket)->portals;

        con->arch.portals.ci      = ci;
        con->arch.portals.reading = 0;

        if (psptl_con_init(ci, con, sock, sock->priv)) goto error_con_init;

        /* send my connection id's */
        psptl_con_get_info_msg(ci, &msg);

        pscom_precon_send(con->precon, PSCOM_INFO_PORTALS_ID, &msg,
                          sizeof(msg));
        break; /* Next: PSCOM_INFO_PORTALS_ID or PSCOM_INFO_ARCH_NEXT */
    }
    case PSCOM_INFO_PORTALS_ID: {
        psptl_info_msg_t *msg = data;
        assert(sizeof(*msg) == size);

        if (psptl_con_connect(con->arch.portals.ci, msg)) {
            goto error_con_connect;
        }

        pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
        break; /* Next: EOF or ARCH_NEXT */
    }
    case PSCOM_INFO_ARCH_NEXT: {
        /* Something failed. Cleanup. */
        pscom_portals_con_cleanup(con);
        break; /* Done. Portals failed */
    }
    case PSCOM_INFO_ARCH_OK: {
        pscom_con_guard_start(con);
        break;
    }
    case PSCOM_INFO_EOF:
        pscom_portals_init_con(con);
        break; /* Done. Use Portals */
    }
    return;
/* --- */
error_con_connect:
error_con_init:
    pscom_portals_con_cleanup(con);
    pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


/**
 * @brief Destroy the pscom4portals plugin.
 *
 * This function implements the plugin->destroy() callback and calls the
 * finalize routine of the underlying psptl layer.
 */
static void pscom_portals_destroy(void)
{
    psptl_finalize();
}


/**
 * @brief The pscom4portals plugin.
 */
PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin_portals = {
    .name     = "portals",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_PORTALS,
    .priority = PSCOM_PORTALS_PRIO,

    .init          = pscom_portals_init,
    .destroy       = pscom_portals_destroy,
    .sock_init     = pscom_portals_sock_init,
    .sock_destroy  = pscom_portals_sock_destroy,
    .con_init      = pscom_portals_con_init,
    .con_handshake = pscom_portals_handshake,
};
