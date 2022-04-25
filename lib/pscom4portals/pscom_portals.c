/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
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

typedef enum pscom_portals_sock_init_state {
    PSCOM_PORTALS_SOCK_NOT_INITIALIZED = 1,
    PSCOM_PORTALS_SOCK_INIT_DONE       = 0,
    PSCOM_PORTALS_SOCK_INIT_FAILED     = -1
} pscom_portals_sock_init_state_t;

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

    {"RENDEZVOUS", "40000", "The rendezvous threshold for pscom4portals.",
     &pscom.env.rendezvous_size_portals, PSCOM_ENV_ENTRY_HAS_PARENT,
     PSCOM_ENV_PARSER_UINT},

    {0},
};


typedef union pscom_rendezvous_data_portals {
    /* RMA write: receiver side */
    struct {
        psptl_rma_mreg_t rma_mreg; /* descriptor for the RMA region */
    } rma_write_rx;
    /* RMA write: sender side */
    struct {
        psptl_rma_req_t rma_req;              /* RMA request object */
        void (*io_done)(void *priv, int err); /* upper layer io_done cb */
        void *priv;                           /* argument to io_done cb */

    } rma_write_tx;
} pscom_rendezvous_data_portals_t;

static int pscom_portals_make_progress(pscom_poll_t *poll);

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

static void poll_reader_dec(psptl_sock_t *sock)
{
    /* decrease the reader counter */
    sock->reader_user--;

    /* dequeue from polling reader if there are no readers left */
    if (!sock->reader_user) { pscom_poll_stop(&sock->poll_read); }
}

static void pscom_portals_read_start(pscom_con_t *con)
{
    /* increment the reader counter if not yet reading */
    if (!con->arch.portals.reading) {
        psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

        con->arch.portals.reading = 1;
        poll_reader_inc(sock);
    }
}

static void pscom_portals_read_stop(pscom_con_t *con)
{
    /* decrement the reader counter if this connection is still reading */
    if (con->arch.portals.reading) {
        psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

        con->arch.portals.reading = 0;
        poll_reader_dec(sock);
    }
}

static int pscom_portals_make_progress(pscom_poll_t *poll)
{
    psptl_sock_t *sock = list_entry(poll, psptl_sock_t, poll_read);

    return psptl_progress(sock->priv);
}

static inline void pscom_portals_sendv_done(void *con_priv)
{
    pscom_con_t *con   = (pscom_con_t *)con_priv;
    psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

    assert(con->magic == MAGIC_CONNECTION);

    poll_reader_dec(sock);
}

static void pscom_portals_sendv_done_with_progress(void *con_priv)
{
    pscom_con_t *con   = (pscom_con_t *)con_priv;
    psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

    pscom_portals_sendv_done(con_priv);

    /* trigger the progress engine once again */
    if (!sock->reader_user) { psptl_progress(sock->priv); }
}


static void pscom_portals_recv_done(void *priv, void *buf, size_t len)
{
    pscom_con_t *con = (pscom_con_t *)priv;
    assert(con->magic == MAGIC_CONNECTION);

    pscom_read_done(con, buf, len);
}

static int pscom_portals_do_write(pscom_poll_t *poll)
{
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;
    pscom_con_t *con   = list_entry(poll, pscom_con_t, poll_write);
    psptl_sock_t *sock = &get_sock(con->pub.socket)->portals;

    /* get a new iov for sending */
    req = pscom_write_get_iov(con, iov);

    if (req) {
        psptl_con_info_t *ci = con->arch.portals.ci;
        len                  = iov[0].iov_len + iov[1].iov_len;

        ssize_t slen = psptl_sendv(ci, iov, len);

        if (slen >= 0) {
            /* ensure execution of the psptl progress engine */
            poll_reader_inc(sock);

            pscom_write_done(con, req, slen);
        } else if (slen != -EAGAIN) {
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }

    return 0;
}

static inline pscom_rendezvous_data_portals_t *
get_req_data(pscom_rendezvous_data_t *rd)
{
    _pscom_rendezvous_data_portals_t *data = &rd->arch.portals;
    pscom_rendezvous_data_portals_t *res   = (pscom_rendezvous_data_portals_t *)
        data;
    assert(sizeof(*res) <= sizeof(*data));
    return res;
}


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


static void
pscom_portals_rma_mem_deregister(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(rd);
    psptl_rma_mreg_t *psptl_rma_mreg = &rd_portals->rma_write_rx.rma_mreg;

    /* deregister the RMA region */
    psptl_rma_mem_deregister(psptl_rma_mreg);
}


static void pscom_portals_rma_write_io_done(void *priv, int err)
{
    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)priv;
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(rd);

    /* trigger the upper layer io_cone callback */
    rd_portals->rma_write_tx.io_done(rd_portals->rma_write_tx.priv, err);

    /* free the rendezvous data (allocated in pscom_portals_rma_write()) */
    free(rd);
}


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


static void pscom_portals_con_cleanup(pscom_con_t *con)
{
    psptl_con_info_t *ci = con->arch.portals.ci;
    if (!ci) return;

    psptl_con_cleanup(ci);
    psptl_con_free(ci);

    con->arch.portals.ci = NULL;
}

static void pscom_portals_con_close(pscom_con_t *con)
{
    psptl_con_info_t *ci = con->arch.portals.ci;
    if (!ci) return;

    pscom_portals_con_cleanup(con);
}

static void pscom_poll_write_start_portals(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_portals_do_write);
}


static void pscom_portals_configure_eager(pscom_con_t *con)
{
    con->write_start = pscom_poll_write_start_portals;
    con->write_stop  = pscom_poll_write_stop;

    con->read_start = pscom_portals_read_start;
    con->read_stop  = pscom_portals_read_stop;
}


static void pscom_portals_configure_rndv_write(pscom_con_t *con)
{
    /* memor (de-)registration */
    con->rma_mem_register       = pscom_portals_rma_mem_register;
    con->rma_mem_deregister     = pscom_portals_rma_mem_deregister;
    con->rma_mem_register_check = NULL;

    /* communication */
    con->rma_write = pscom_portals_rma_write;

    /* the rendezvous threshold */
    con->rendezvous_size = pscom.env.rendezvous_size_portals;
}


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


static void pscom_portals_sock_init(pscom_sock_t *sock)
{
    psptl_sock_t *portals_sock = &sock->portals;

    /* initialize the poll reader */
    pscom_poll_init(&portals_sock->poll_read);
    portals_sock->reader_user = 0;

    /* set the initialization state */
    portals_sock->init_state = PSCOM_PORTALS_SOCK_NOT_INITIALIZED;
}


static void pscom_portals_sock_destroy(pscom_sock_t *sock)
{
    psptl_sock_t *portals_sock = &sock->portals;

    if (portals_sock->init_state == PSCOM_PORTALS_SOCK_INIT_DONE) {
        psptl_cleanup_ep(portals_sock->priv);
        portals_sock->priv = NULL;
    }

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

        if (psptl_con_init(ci, con, sock->priv)) goto error_con_init;

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

static void pscom_portals_destroy(void)
{
    psptl_finalize();
}

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
