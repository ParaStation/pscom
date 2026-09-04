/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_ucp.c: UCP communication
 */

#include "pscom_ucp.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <ucp/api/ucp_def.h>

#include "list.h"
#include "pscom.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_plugin.h"
#include "pscom_poll.h"
#include "pscom_precon.h"
#include "pscom_io.h"
#include "pscom_priv.h"
#include "psucp.h"
#include "ucp/api/ucp.h"


pscom_env_table_entry_t pscom_env_table_ucp[] = {
    {"MAX_RECV", PSCOM_ENV_UINT_INF_STR,
     "Limit the number of outstanding receive requests that are handled by "
     "the pscom4ucp plugin concurrently.",
     &psucp_max_recv, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_UINT},

    {"FASTINIT", "1",
     "If enabled, ucp_init() is called from within pscom4ucp plugin init, "
     "otherwise on first usage of a pscom4ucp connection.",
     &pscom.env.ucp_fastinit, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"RENDEZVOUS", PSCOM_ENV_UINT_INF_STR,
     "The rendezvous threshold for pscom4ucp.", &pscom.env.rendezvous_size_ucp,
     (PSCOM_ENV_ENTRY_HAS_PARENT | PSCOM_ENV_ENTRY_HIDDEN),
     PSCOM_ENV_PARSER_UINT},

    {"SMALL_MSG_LEN", "350",
     "The threshold for buffered sending of small messages.",
     &psucp_small_msg_len, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_UINT},

    {0},
};


static struct {
    pscom_poll_t poll_read; // pscom_ucp_do_read
    unsigned reader_user;
} pscom_ucp;


static int pscom_ucp_do_read(pscom_poll_t *poll);


static void reader_inc(void)
{
    if (!pscom_ucp.reader_user) {
        // enqueue to polling reader
        pscom_poll_start(&pscom_ucp.poll_read, pscom_ucp_do_read,
                         &pscom.poll_read);
    }
    pscom_ucp.reader_user++;
}


static void reader_dec(void)
{
    pscom_ucp.reader_user--;
    if (!pscom_ucp.reader_user) {
        // dequeue from polling reader
        pscom_poll_stop(&pscom_ucp.poll_read);
    }
}


static void pscom_ucp_read_start(pscom_con_t *con)
{
    if (!con->arch.ucp.reading) {
        con->arch.ucp.reading = 1;
        reader_inc();
    }
}


static void pscom_ucp_read_stop(pscom_con_t *con)
{
    if (con->arch.ucp.reading) {
        con->arch.ucp.reading = 0;
        reader_dec();
    }
}

static int pscom_ucp_do_read(pscom_poll_t *poll)
{
    psucp_msg_t msg;
    ssize_t rc;

    rc = psucp_probe(&msg);

    if (rc > 0) {
        pscom_con_t *con     = (pscom_con_t *)msg.info_tag.sender_tag;
        psucp_con_info_t *ci = con->arch.ucp.ci;
        char *buf;
        size_t len;
        ssize_t rlen;

        assert(con->magic == MAGIC_CONNECTION);

        pscom_read_get_buf(con, &buf, &len);

        rlen = psucp_irecv(ci, &msg, buf, len);

        if (rlen < 0) {
            // error receive
            errno = -(int)rlen;
            pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
            return 1;
        }

        //		printf("%s:%u:%s  recv len:%u rlen:%u buf:%s\n",
        //__FILE__,
        //__LINE__, __func__, 		       (unsigned)len, (unsigned)rlen,
        // pscom_dumpstr(buf, rlen)); 		pscom_read_done(con, buf, rlen);
    }

    return rc > 0;
}


void pscom_psucp_sendv_done(void *req_priv)
{
    pscom_req_t *req = (pscom_req_t *)req_priv;
    assert(req != NULL);
    assert(req->magic == MAGIC_REQUEST);

    pscom_write_pending_done(get_con(req->pub.connection), req);
}


static int pscom_ucp_do_write(pscom_poll_t *poll)
{
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;
    pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);

    req = pscom_write_get_iov(con, iov);

    if (req) {
        psucp_con_info_t *ci = con->arch.ucp.ci;
        len                  = iov[0].iov_len + iov[1].iov_len;

        pscom_write_pending(con, req, len);

        ssize_t rlen = psucp_sendv(ci, iov, req);

        if (rlen >= 0) {
            assert((size_t)rlen == len);
            // pscom_write_done(con, req, rlen);
        } else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
            // Busy: Retry later.
            // ToDo: revert the call to pscom_write_pending. For now, fail:
            assert(0);
        } else {
            // Error
            pscom_write_pending_error(con, req);
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }

    /* make progress if the connection is closed for reading */
    if (!pscom_ucp.reader_user) { psucp_progress(); }

    return 0;
}


static void pscom_ucp_con_cleanup(pscom_con_t *con)
{
    psucp_con_info_t *ci = con->arch.ucp.ci;
    if (!ci) { return; }

    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    free(con_rma_stat);
    psucp_con_cleanup(ci);
    psucp_con_free(ci);


    con->arch.ucp.ci = NULL;
}


static void pscom_ucp_con_close(pscom_con_t *con)
{
    psucp_con_info_t *ci = con->arch.ucp.ci;
    if (!ci) { return; }

    pscom_ucp_con_cleanup(con);
}


static void pscom_poll_write_start_ucp(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_ucp_do_write);
}


static int pscom_ucp_rma_mem_register(void *addr, size_t length, void **rkeybuf,
                                      uint16_t *bufsize,
                                      pscom_arch_sock_t *arch_sock,
                                      void **plugin_memh)
{
    ucp_mem_h ucp_memh = NULL;
    int status         = psucp_rma_mem_register(addr, length, rkeybuf, bufsize,
                                                &ucp_memh);

    *plugin_memh = (void *)ucp_memh;
    return status;
}

static int pscom_ucp_rma_mem_deregister(void *plugin_memh)
{
    int status = psucp_rma_mem_deregister((ucp_mem_h)plugin_memh);
    return status;
}

static int pscom_ucp_rma_rkey_generate(pscom_con_t *con, void *rkeybuf,
                                       void **plugin_rkey)
{
    psucp_con_info_t *ci = con->arch.ucp.ci;
    ucp_rkey_h ucp_rkey  = NULL;

    int status = psucp_rma_rkey_generate(ci, rkeybuf, &ucp_rkey);

    if (status == 0) {
        *plugin_rkey = (void *)ucp_rkey;
    } else {
        *plugin_rkey = NULL;
    }

    return status;
}

static int pscom_ucp_rma_rkey_destroy(void *plugin_rkey)
{
    int status = psucp_rma_rkey_destroy((ucp_rkey_h)plugin_rkey);
    return status;
}

static void pscom_ucp_rma_rkey_buf_free(void *rkey_buf)
{
    psucp_rma_rkey_buf_free(rkey_buf);

    return;
}

static int pscom_ucp_rma_put(pscom_con_t *con, void *buffer, size_t length,
                             void *remote_addr, void *plugin_rkey,
                             pscom_req_t *req)
{
    ucp_rkey_h ucp_rkey;
    psucp_con_info_t *ci = con->arch.ucp.ci;

    ucp_rkey = (ucp_rkey_h)plugin_rkey;
    return psucp_rma_put(ci, buffer, length, remote_addr, ucp_rkey, (void *)req);
}

void pscom_psucp_rma_put_done(void *req_priv)
{
    pscom_req_t *req = (pscom_req_t *)req_priv;
    assert(req != NULL);
    assert(req->magic == MAGIC_REQUEST);

    /* Note: Which version should be used here? locked or unlocked? */
    pscom_req_done(req);
}

void pscom_psucp_rma_cs_done(void *req_priv)
{
    pscom_req_t *req = (pscom_req_t *)req_priv;
    assert(req != NULL);
    assert(req->magic == MAGIC_REQUEST);

    /* copy the result data to result buffer */
    memcpy(req->pub.rma.result_addr, req->pub.data, req->pub.data_len);

    /* free the temp buffer: IMPORTANT */
    free(req->pub.data);

    /* Note: Which version should be used here? locked or unlocked? */
    pscom_req_done(req);
}

static int pscom_ucp_rma_get(pscom_con_t *con, void *buffer, size_t length,
                             void *remote_addr, void *plugin_rkey,
                             pscom_req_t *req)
{
    ucp_rkey_h ucp_rkey;
    psucp_con_info_t *ci = con->arch.ucp.ci;

    ucp_rkey = (ucp_rkey_h)plugin_rkey;

    return psucp_rma_get(ci, buffer, length, remote_addr, ucp_rkey, (void *)req);
}

static int pscom_ucp_rma_atomic(pscom_con_t *con, void *buffer, size_t length,
                                void *remote_addr, void *result_addr,
                                pscom_rma_atomic_op_t rma_atomic_op,
                                pscom_datatype_t data_type, void *plugin_rkey,
                                pscom_req_t *req)
{
    ucp_rkey_h ucp_rkey;
    psucp_con_info_t *ci = con->arch.ucp.ci;

    ucp_rkey                   = (ucp_rkey_h)plugin_rkey;
    ucp_atomic_op_t ucp_opcode = psucp_rma_opcode_convert(rma_atomic_op);

    return psucp_rma_atomic_op(ci, buffer, length, remote_addr, result_addr,
                               ucp_opcode, ucp_rkey, (void *)req);
}


static int pscom_ucp_rma_atomic_segment(pscom_con_t *con, void *buffer,
                                        size_t length, void *remote_addr,
                                        void *result_addr,
                                        pscom_rma_atomic_op_t rma_atomic_op,
                                        pscom_datatype_t data_type,
                                        void *plugin_rkey, pscom_req_t *req)
{
    ucp_rkey_h ucp_rkey;
    psucp_con_info_t *ci = con->arch.ucp.ci;

    ucp_rkey                   = (ucp_rkey_h)plugin_rkey;
    ucp_atomic_op_t ucp_opcode = psucp_rma_opcode_convert(rma_atomic_op);

    return psucp_rma_atomic_op_segment(ci, buffer, length, data_type,
                                       remote_addr, result_addr, ucp_opcode,
                                       ucp_rkey, (void *)req);
}


static int pscom_ucp_rma_compare_swap(pscom_con_t *con, void *buffer,
                                      size_t length, void *remote_addr,
                                      void *origin_addr, void *result_addr,
                                      pscom_datatype_t data_type,
                                      void *plugin_rkey, pscom_req_t *req)
{
    /*
    Comments:
    In MPI standard, the origin and result buffers (origin_addr and result_addr)
    must be disjoint. However, in ucx implementation those buffers are identical
    in psucp_rma_atomic_op. result_addr = origin_addr in ucx. Here, a new buffer
    will be allocated and data will be copied from origin_addr to this new
    buffer, this new buffer will be passed to ucp_atomic_op_nbx as the origin
    and result buffer. When the compare&swap is finished, the data in this new
    buffer has to be copied to result_addr. This avoids overwriting origin_addr
    and gets the data from target into result_addr, but increases the overheads
    of the communication slightly due to the data copy.

    Result=Y; if (X==Y) then Y=Z
              X              Y                 Z                     R
    ucx    buffer       remote_addr    param.reply_buffer   param.reply_buffer
    mpi  compare_addr   target_addr       origin_addr           result_addr
     */
    ucp_rkey_h ucp_rkey;
    psucp_con_info_t *ci = con->arch.ucp.ci;

    ucp_rkey = (ucp_rkey_h)plugin_rkey;

    void *reply_addr  = malloc(length);
    req->pub.data     = reply_addr;
    req->pub.data_len = length;
    memcpy(reply_addr, origin_addr, length);

    return psucp_rma_atomic_op(ci, buffer, length, remote_addr, reply_addr,
                               UCP_ATOMIC_OP_CSWAP, ucp_rkey, (void *)req);
}

/* check if RMA communication is supported or not */
static int pscom_ucp_rma_native_check(pscom_rma_op_t rma_op)
{
    return psucp_rma_native_check(rma_op);
}

/* check if accumulate operation and max data length is supported or not */
static int pscom_ucp_rma_atomics_check(pscom_rma_atomic_op_t atomic_op,
                                       pscom_datatype_t data_type,
                                       size_t length, pscom_rma_op_t rma_op)
{
    /* ucx does not support different data_type*/
    return psucp_rma_atomics_check(atomic_op, data_type, length, rma_op);
}


static int pscom_ucp_rma_worker_flush(pscom_sock_t *sock)
{
    pscom_arch_sock_t *arch_sock = get_arch_sock(sock, PSCOM_CON_TYPE_UCP);
    assert(arch_sock);
    pscom_ucp_sock_t *ucp_sock = arch_sock->arch.ucp;
    int status                 = 0;
    if (ucp_sock->flush_required) {
        status                   = psucp_rma_worker_flush();
        ucp_sock->flush_required = 0;
    }
    /* commemnts: Flush socket will also flush all the connections but flush
    flag is not set in connection, this may cause problems. */
    return status;
}


static int pscom_ucp_rma_ep_flush(pscom_con_t *con)
{
    psucp_con_info_t *ci               = con->arch.ucp.ci;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    int status = 0;
    if (con_rma_stat->flush_remote) {
        status                     = psucp_rma_ep_flush(ci);
        con_rma_stat->flush_remote = 0;
        con_rma_stat->flush_local  = 0;
    }
    return status;
}

static int pscom_ucp_rma_ep_flush_local(pscom_con_t *con)
{
    psucp_con_info_t *ci               = con->arch.ucp.ci;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    int status = 0;

    if (con_rma_stat->flush_local) {
        assert(con_rma_stat->local_complete < con_rma_stat->issued_op_count);
        status = psucp_rma_ep_flush_local(ci);
        assert(con_rma_stat->local_complete == con_rma_stat->issued_op_count);
        con_rma_stat->flush_local = 0;
    }

    return status;
}


static void pscom_ucp_init_con(pscom_con_t *con)
{
    con->pub.type = PSCOM_CON_TYPE_UCP;

#ifdef PSCOM_CUDA_AWARENESS
    con->is_gpu_aware = pscom.env.cuda && pscom.env.cuda_aware_ucp;
#endif

    // Only Polling:
    con->read_start = pscom_ucp_read_start;
    con->read_stop  = pscom_ucp_read_stop;

    con->write_start = pscom_poll_write_start_ucp;
    con->write_stop  = pscom_poll_write_stop;

    // rma
    con->rma.rkey_generate = pscom_ucp_rma_rkey_generate;
    con->rma.rkey_destroy  = pscom_ucp_rma_rkey_destroy;
    con->rma.put           = pscom_ucp_rma_put;
    con->rma.get           = pscom_ucp_rma_get;
    con->rma.acc           = pscom_ucp_rma_atomic_segment;
    con->rma.get_acc       = pscom_ucp_rma_atomic_segment;
    con->rma.fop           = pscom_ucp_rma_atomic;
    con->rma.cas           = pscom_ucp_rma_compare_swap;
    con->rma.native_check  = pscom_ucp_rma_native_check;
    con->rma.atomics_check = pscom_ucp_rma_atomics_check;
    con->rma.flush         = pscom_ucp_rma_ep_flush;
    con->rma.flush_local   = pscom_ucp_rma_ep_flush_local;

    con->close = pscom_ucp_con_close;

    con->rendezvous_size = pscom.env.rendezvous_size_ucp;

    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)malloc(
        sizeof(psucp_con_rma_stat_t));

    con->arch.ucp.rma_stat        = (void *)con_rma_stat;
    con_rma_stat->issued_op_count = 0;
    con_rma_stat->local_complete  = 0;
    con_rma_stat->flush_local     = 0;
    con_rma_stat->flush_remote    = 0;

    pscom_con_setup_ok(con);
}


/*********************************************************************/
static void pscom_ucp_init(void)
{
    psucp_debug        = pscom.env.debug;
    psucp_debug_stream = pscom_debug_stream();

    /* set the rendezvous threshold based on the global configuration */
    if (pscom.env.rendezvous_size != (unsigned)~0) {
        pscom.env.rendezvous_size_ucp = pscom.env.rendezvous_size;
    }

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom UCP", "UCP_", pscom_env_table_ucp);

    pscom_poll_init(&pscom_ucp.poll_read);
    pscom_ucp.reader_user = 0;

    /* ensure the initialization of the UCP memory cache */
    if (pscom.env.ucp_fastinit) { psucp_init(); }

    psucp_init_rma_masks();
}


static void pscom_ucp_destroy(void)
{
    psucp_finalize();
}


static void pscom_ucp_sock_init(pscom_sock_t *sock)
{
    /* init ucp and prepare for memory region registration */
    int ret = psucp_init();

    if (ret != 0) {
        DPRINT(D_ERR, "ucp plugin init failed!\n");
        /* UCP init failed and we return directly here, so no ucp arch sock is
         * added. */
        return;
    }

    /* allocate space for a new arch sock */
    pscom_arch_sock_t *arch_sock = malloc(sizeof(pscom_arch_sock_t) +
                                          sizeof(pscom_ucp_sock_t));
    /* set up the arch_sock structure */
    arch_sock->plugin_con_type   = PSCOM_CON_TYPE_UCP;
    arch_sock->arch.ucp = (pscom_ucp_sock_t *)&arch_sock->arch_sock_data;

    arch_sock->rma.mem_register   = pscom_ucp_rma_mem_register;
    arch_sock->rma.mem_deregister = pscom_ucp_rma_mem_deregister;
    arch_sock->rma.rkey_buf_free  = pscom_ucp_rma_rkey_buf_free;
    arch_sock->rma.fence          = pscom_ucp_rma_worker_flush;

    /* add the new arch sock to the socket archs list */
    assert(get_arch_sock(sock, PSCOM_CON_TYPE_UCP) == NULL);
    list_add_tail(&arch_sock->next, &sock->archs);

    pscom_ucp_sock_t *ucp_sock = arch_sock->arch.ucp;
    ucp_sock->flush_required   = 0;

    return;
}


static void pscom_ucp_sock_destroy(pscom_sock_t *sock)
{
    pscom_arch_sock_t *arch_sock = get_arch_sock(sock, PSCOM_CON_TYPE_UCP);
    assert(arch_sock);

    /* release resources associated with the arch_sock structure */
    list_del_init(&arch_sock->next);
    free(arch_sock);
}


#define PSCOM_INFO_UCP_ID PSCOM_INFO_ARCH_STEP1


static int pscom_ucp_con_init(pscom_con_t *con)
{
    return psucp_init();
}


static void pscom_ucp_handshake(pscom_con_t *con, int type, void *data,
                                unsigned size)
{
    pscom_err_t ret = PSCOM_SUCCESS;

    switch (type) {
    case PSCOM_INFO_ARCH_REQ: {
        psucp_info_msg_t *msg;
        psucp_con_info_t *ci = psucp_con_create();

        con->arch.ucp.ci      = ci;
        con->arch.ucp.reading = 0;

        if (psucp_con_init(ci, NULL, con)) { goto error_con_init; }

        /* send my connection id's */
        msg = psucp_con_get_info_msg(ci, (unsigned long)con);

        ret = pscom_precon_send(con->precon, PSCOM_INFO_UCP_ID, msg,
                                psucp_info_msg_length(msg));
        assert(ret == PSCOM_SUCCESS);

        free(msg);

        break; /* Next is PSCOM_INFO_UCP_ID or PSCOM_INFO_ARCH_NEXT */
    }
    case PSCOM_INFO_UCP_ID: {
        psucp_info_msg_t *msg = data;
        assert(sizeof(*msg) <= size);
        assert(psucp_info_msg_length(msg) <= size);

        if (psucp_con_connect(con->arch.ucp.ci, msg)) {
            goto error_con_connect;
        }

        ret = pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
        assert(ret == PSCOM_SUCCESS);

        break; /* Next is EOF or ARCH_NEXT */
    }
    case PSCOM_INFO_ARCH_NEXT:
        /* Something failed. Cleanup. */
        pscom_ucp_con_cleanup(con);
        break; /* Done. Ucp failed */
    case PSCOM_INFO_ARCH_OK: pscom_con_guard_start(con); break;
    case PSCOM_INFO_EOF: pscom_ucp_init_con(con); break; /* Done. Use Ucp */
    }
    return;
    /* --- */
error_con_connect:
error_con_init:
    pscom_ucp_con_cleanup(con);
    pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


#ifndef PSCOM_ALLIN_UCP
PSCOM_PLUGIN_API_EXPORT
#endif
pscom_plugin_t pscom_plugin_ucp = {
    .name     = "ucp",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_UCP,
    .priority = PSCOM_UCP_PRIO,

    .init          = pscom_ucp_init,
    .destroy       = pscom_ucp_destroy,
    .sock_init     = pscom_ucp_sock_init,
    .sock_destroy  = pscom_ucp_sock_destroy,
    .con_init      = pscom_ucp_con_init,
    .con_handshake = pscom_ucp_handshake,
};
