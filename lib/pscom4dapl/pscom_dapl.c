/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_dapl.c: DAPL communication
 */

#include "psdapl.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_priv.h"
#include "pscom_io.h"
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_dapl.h"


pscom_env_table_entry_t pscom_env_table_dapl[] = {
    {"RENDEZVOUS", PSCOM_ENV_UINT_INF_STR,
     "The rendezvous threshold for pscom4dapl.", &pscom.env.rendezvous_size_dapl,
     PSCOM_ENV_ENTRY_HAS_PARENT, PSCOM_ENV_PARSER_UINT},

    {"PROVIDER", "<query>", "The rendezvous threshold for pscom4dapl.",
     &psdapl_provider, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_STR},

    {0},
};

static int _pscom_dapl_do_read(pscom_con_t *con, psdapl_con_info_t *ci)
{
    void *buf;
    int size;

    size = psdapl_recvlook(ci, &buf);

    if (size >= 0) {
        pscom_read_done(con, buf, size);

        psdapl_recvdone(ci);
        return 1;
    } else if ((size == -EINTR) || (size == -EAGAIN)) {
        // Nothing received
        return 0;
    } else {
        // Error
        errno = -size;
        pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
        return 1;
    }
}


static int pscom_dapl_do_read(pscom_poll_t *poll)
{
    pscom_con_t *con      = list_entry(poll, pscom_con_t, poll_read);
    psdapl_con_info_t *ci = con->arch.dapl.ci;

    return _pscom_dapl_do_read(con, ci);
}


static void pscom_dapl_do_write(pscom_con_t *con)
{
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;

    req = pscom_write_get_iov(con, iov);

    if (req) {
        psdapl_con_info_t *ci = con->arch.dapl.ci;
        len                   = iov[0].iov_len + iov[1].iov_len;

        ssize_t rlen = psdapl_sendv(ci, iov, len);

        if (rlen >= 0) {
            pscom_write_done(con, req, rlen);
        } else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
            // Busy: Maybe out of tokens? try to read more tokens:
            _pscom_dapl_do_read(con, ci);
        } else {
            // Error
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }
}


/*
 * RMA
 */

typedef struct pscom_rendezvous_data_dapl {
    struct psdapl_rdma_req rma_req;
    pscom_req_t *rendezvous_req;
} pscom_rendezvous_data_dapl_t;


static inline pscom_rendezvous_data_dapl_t *
get_req_data(pscom_rendezvous_data_t *rd)
{
    _pscom_rendezvous_data_dapl_t *data = &rd->arch.dapl;
    pscom_rendezvous_data_dapl_t *res   = (pscom_rendezvous_data_dapl_t *)data;
    assert(sizeof(*res) <= sizeof(*data));
    return res;
}


static unsigned int pscom_dapl_rma_mem_register(pscom_con_t *con,
                                                pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_dapl_t *dapl_rd = get_req_data(rd);
    psdapl_con_info_t *ci                 = con->arch.dapl.ci;

    /* get mem region */
    psdapl_mregion_cache_t *mreg = psdapl_get_mregion(rd->msg.data,
                                                      rd->msg.data_len, ci);
    if (!mreg) { goto err_get_region; }

    dapl_rd->rma_req.mreg = mreg;

    rd->msg.arch.dapl.rmr_context = psdapl_get_rmr_context(mreg);
    rd->msg.arch.dapl.rmr_vaddr   = psdapl_get_rmr_vaddr(rd->msg.data);

    return sizeof(rd->msg.arch.dapl);
err_get_region:
    // ToDo: Count get_mregion errors!
    dapl_rd->rma_req.mreg = NULL;
    return 0;
}


static void pscom_dapl_rma_mem_deregister(pscom_con_t *con,
                                          pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_dapl_t *dapl_rd = get_req_data(rd);

    if (dapl_rd->rma_req.mreg) {
        psdapl_put_mregion(dapl_rd->rma_req.mreg);
        dapl_rd->rma_req.mreg = NULL;
    }
}


static void pscom_dapl_rma_read_io_done(psdapl_rdma_req_t *dreq)
{
    pscom_rendezvous_data_dapl_t *dapl_rd = (pscom_rendezvous_data_dapl_t *)
                                                dreq->priv;

    pscom_req_t *rendezvous_req = dapl_rd->rendezvous_req;

    /* called via
       _psdapl_sendv() -> psdapl_flush_evd() ->
       do_DTO_COMPLETION_EVENT() -> io_done.

       we have the global lock!
       Use locked version of req_done: */

    _pscom_recv_req_done(rendezvous_req);
}


static int pscom_dapl_rma_read(pscom_req_t *rendezvous_req,
                               pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_dapl_t *dapl_rd = get_req_data(rd);
    psdapl_rdma_req_t *dreq               = &dapl_rd->rma_req;
    pscom_con_t *con      = get_con(rendezvous_req->pub.connection);
    psdapl_con_info_t *ci = con->arch.dapl.ci;


    dreq->ci          = ci;
    dreq->rmr_context = rd->msg.arch.dapl.rmr_context;
    dreq->rmr_vaddr   = rd->msg.arch.dapl.rmr_vaddr;
    dreq->lmr_buf     = rendezvous_req->pub.data;
    dreq->size        = rendezvous_req->pub.data_len;

    dreq->io_done = pscom_dapl_rma_read_io_done;
    dreq->priv    = dapl_rd;

    dapl_rd->rendezvous_req = rendezvous_req;

    return psdapl_post_rdma_get(dreq);
}


/* RMA end */

static void pscom_dapl_con_cleanup(pscom_con_t *con)
{
    psdapl_con_info_t *ci = con->arch.dapl.ci;
    if (!ci) { return; }

    psdapl_con_destroy(ci);

    con->arch.dapl.ci = NULL;
}


static void pscom_dapl_con_close(pscom_con_t *con)
{
    psdapl_con_info_t *ci = con->arch.dapl.ci;
    if (!ci) { return; }

    pscom_dapl_con_cleanup(con);
}


static void pscom_poll_read_start_dapl(pscom_con_t *con)
{
    pscom_poll_read_start(con, pscom_dapl_do_read);
}


static void pscom_poll_write_start_dapl(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_dapl_do_write);
}


static void pscom_dapl_init_con(pscom_con_t *con)
{
    con->pub.type = PSCOM_CON_TYPE_DAPL;

    // Only Polling:
    con->read_start = pscom_poll_read_start_dapl;
    con->read_stop  = pscom_poll_read_stop;

    con->write_start = pscom_poll_write_start_dapl;
    con->write_stop  = pscom_poll_write_stop;

    con->close = pscom_dapl_con_close;

    con->rndv.mem_register   = pscom_dapl_rma_mem_register;
    con->rndv.mem_deregister = pscom_dapl_rma_mem_deregister;
    con->rndv.rma_read       = pscom_dapl_rma_read;

    con->rendezvous_size = pscom.env.rendezvous_size_dapl;

    pscom_con_setup_ok(con);
}

/*********************************************************************/
static void pscom_dapl_init(void)
{
    psdapl_debug        = pscom.env.debug;
    psdapl_debug_stream = pscom_debug_stream();

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom DAPL", "DAPL_",
                                       pscom_env_table_dapl);
}


static psdapl_socket_t *glob_sock = NULL;


static void pscom_dapl_destroy(void)
{
    if (!glob_sock) { return; }

    psdapl_socket_put(glob_sock);
    glob_sock = NULL;
}


static psdapl_socket_t *pscom_dapl_get_sock(void)
{
    if (glob_sock) { return glob_sock; }

    glob_sock = psdapl_socket_create();
    if (glob_sock) { psdapl_socket_hold(glob_sock); }

    return glob_sock;
}


#define PSCOM_INFO_DAPL_ID PSCOM_INFO_ARCH_STEP1


static int pscom_dapl_con_init(pscom_con_t *con)
{
    return 0; // psdapl_init();
}


static void pscom_dapl_handshake(pscom_con_t *con, int type, void *data,
                                 unsigned size)
{
    switch (type) {
    case PSCOM_INFO_ARCH_REQ: {
        psdapl_info_msg_t msg;
        psdapl_socket_t *sock = pscom_dapl_get_sock();
        psdapl_con_info_t *ci = psdapl_con_create(sock);

        con->arch.dapl.ci = ci;
        // con->arch.dapl.reading = 0;

        // if (psdapl_con_init(ci, NULL, con)) goto error_con_init;

        if (con->pub.state & PSCOM_CON_STATE_CONNECTING) {
            if (psdapl_listen(sock)) { goto error_listen; }

            /* send my connection id's */
            psdapl_con_get_info_msg(ci, &msg);

            pscom_err_t ret = pscom_precon_send(con->precon, PSCOM_INFO_DAPL_ID,
                                                &msg, sizeof(msg));
            assert(ret == PSCOM_SUCCESS);
            /* Next is PSCOM_INFO_DAPL_ACCEPT or PSCOM_INFO_ARCH_NEXT */
        } else {
            // ToDo: FixMe: "ok" should be send after a non blocking
            // psdapl_connect().
            pscom_err_t ret = pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK,
                                                NULL, 0);
            assert(ret == PSCOM_SUCCESS);
        }
        break;
    }
    case PSCOM_INFO_DAPL_ID: {
        psdapl_info_msg_t *msg = data;
        assert(sizeof(*msg) == size);

        // ToDo: FixMe: psdapl_connect() is blocking!
        if (psdapl_connect(con->arch.dapl.ci, msg)) { goto error_connect; }

        break; /* Next is EOF or ARCH_NEXT */
    }
    case PSCOM_INFO_ARCH_OK: {
        // ToDo: psdapl_accept_wait() is blocking, but handshake should not
        // block!
        if (con->pub.state & PSCOM_CON_STATE_CONNECTING) {

            // ToDo: FixMe: psdapl_accept_wait() is blocking!
            if (psdapl_accept_wait(con->arch.dapl.ci)) { goto error_accept; }

            pscom_err_t ret = pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK,
                                                NULL, 0);
            assert(ret == PSCOM_SUCCESS);
        }
        break; /* Next is PSCOM_INFO_EOF */
    }
    case PSCOM_INFO_ARCH_NEXT:
        /* Something failed. Cleanup. */
        pscom_dapl_con_cleanup(con);
        break; /* Done. Dapl failed */
    case PSCOM_INFO_EOF: pscom_dapl_init_con(con); break; /* Done. Use Dapl */
    }
    return;
    /* --- */
error_listen:
error_connect:
error_accept:
    // error_con_init:
    pscom_dapl_con_cleanup(con);
    pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin_dapl = {
    .name     = "dapl",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_DAPL,
    .priority = PSCOM_DAPL_PRIO,

    .init          = pscom_dapl_init,
    .destroy       = pscom_dapl_destroy,
    .sock_init     = NULL,
    .sock_destroy  = NULL,
    .con_init      = pscom_dapl_con_init,
    .con_handshake = pscom_dapl_handshake,
};
