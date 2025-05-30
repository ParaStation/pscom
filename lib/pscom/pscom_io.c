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

#include "pscom_io.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "perf.h"
#include "pscom_con.h"
#include "pscom_cuda.h"
#include "pscom_env.h"
#include "pscom_priv.h"
#include "pscom_queues.h"
#include "pscom_req.h"
#include "pscom_util.h"


static inline size_t header_length(pscom_header_net_t *header);
static inline int header_complete(void *buf, size_t size);
static inline int is_recv_req_done(pscom_req_t *req);
static void _pscom_rendezvous_read_data(pscom_req_t *user_recv_req,
                                        pscom_req_t *rendezvous_req);
static void _pscom_rendezvous_read_data_abort_arch(pscom_req_t *rendezvous_req);
static void pscom_req_prepare_send(pscom_req_t *req, pscom_msgtype_t msg_type);
static void pscom_req_prepare_rma_write(pscom_req_t *req);
static void _check_readahead(pscom_con_t *con, size_t len);
static void _genreq_merge(pscom_req_t *newreq, pscom_req_t *genreq);
static pscom_req_t *pscom_get_default_recv_req(pscom_con_t *con,
                                               pscom_header_net_t *nh);
static inline pscom_req_t *_pscom_get_user_receiver(pscom_con_t *con,
                                                    pscom_header_net_t *nh);
static pscom_req_t *pscom_get_rma_write_receiver(pscom_con_t *con,
                                                 pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_read_receiver(pscom_con_t *con,
                                                 pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_read_answer_receiver(pscom_con_t *con,
                                                        pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_eof_receiver(pscom_con_t *con,
                                            pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_suspend_receiver(pscom_con_t *con,
                                                pscom_header_net_t *nh);
static void pscom_rendezvous_read_data_io_done(pscom_request_t *request);
static pscom_req_t *pscom_get_rendezvous_receiver(pscom_con_t *con,
                                                  pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rendezvous_fin_receiver(pscom_con_t *con,
                                                       pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_recv_req(pscom_con_t *con,
                                        pscom_header_net_t *nh);
// return true at the end of each message
static void _pscom_send(pscom_con_t *con, pscom_msgtype_t msg_type,
                        void *xheader, size_t xheader_len, void *data,
                        size_t data_len);
static void pscom_send_inplace_io_done(pscom_request_t *req);
static int _pscom_cancel_send(pscom_req_t *req);
static int _pscom_cancel_recv(pscom_req_t *req);
static inline void pscom_post_send_direct_inline(pscom_req_t *req,
                                                 pscom_msgtype_t msg_type);
static inline void _pscom_post_send_direct_inline(pscom_con_t *con,
                                                  pscom_req_t *req,
                                                  pscom_msgtype_t msg_type);
static inline void _pscom_post_rma_read_inline(pscom_req_t *rma_read_req);

int pscom_read_is_at_message_start(pscom_con_t *con);
void pscom_read_get_buf(pscom_con_t *con, char **buf, size_t *len);
void pscom_read_done(pscom_con_t *con, char *buf, size_t len);

static void pscom_rma_put_recv_io_done(pscom_request_t *request);
static void pscom_rma_accumulate_recv_io_done(pscom_request_t *request);
static void pscom_rma_get_accumulate_recv_io_done(pscom_request_t *request);
static void pscom_rma_fetch_op_recv_io_done(pscom_request_t *request);
static void pscom_rma_compare_swap_recv_io_done(pscom_request_t *request);

static pscom_req_t *pscom_get_rma_put_receiver(pscom_con_t *con,
                                               pscom_header_net_t *nh);
static pscom_req_t *pscom_get_rma_accumulate_receiver(pscom_con_t *con,
                                                      pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_get_receiver(pscom_con_t *con,
                                                pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_get_answer_receiver(pscom_con_t *con,
                                                       pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_get_acc_receiver(pscom_con_t *con,
                                                    pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_get_acc_answer_receiver(
    pscom_con_t *con, pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_fetch_op_receiver(pscom_con_t *con,
                                                     pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_compare_swap_receiver(pscom_con_t *con,
                                                         pscom_header_net_t *nh);
static pscom_req_t *_pscom_get_rma_compare_swap_answer_receiver(
    pscom_con_t *con, pscom_header_net_t *nh);

PSCOM_PLUGIN_API_EXPORT
pscom_req_t *(*_pscom_get_gw_envelope_receiver)(pscom_con_t *con,
                                                pscom_header_net_t *nh);

void pscom_req_prepare_recv(pscom_req_t *req, const pscom_header_net_t *nh,
                            pscom_connection_t *connection)
{
    size_t copy_header = sizeof(req->pub.header) +
                         pscom_min(req->pub.xheader_len, nh->xheader_len);

    memcpy(&req->pub.header, nh, copy_header);

    req->cur_data.iov_base = req->pub.data;

    if (nh->data_len <= req->pub.data_len) {
        req->cur_data.iov_len = nh->data_len;
        req->skip             = 0;
    } else {
        assert(req->magic == MAGIC_REQUEST);
        req->cur_data.iov_len = req->pub.data_len;
        req->skip             = nh->data_len - req->pub.data_len;
        req->pub.state |= PSCOM_REQ_STATE_TRUNCATED;
    }

    D_TR(printf("%s:%u:%s(%s) hlen=%zu dlen=%zu dlen_req=%zu dlen_net=%zu "
                "skip=%zu\n",
                __FILE__, __LINE__, __func__, pscom_debug_req_str(req),
                copy_header, req->cur_data.iov_len, req->pub.data_len,
                (size_t)nh->data_len, req->skip));

    assert(connection);
    req->pub.connection = connection;
}


static inline size_t header_length(pscom_header_net_t *header)
{
    return sizeof(pscom_header_net_t) + header->xheader_len;
}


static inline int header_complete(void *buf, size_t size)
{
    pscom_header_net_t *nhead = (pscom_header_net_t *)buf;

    return (size >= sizeof(pscom_header_net_t)) &&
           (size >= header_length(nhead));
}


static inline int is_recv_req_done(pscom_req_t *req)
{
    return (req->cur_data.iov_len == 0);
}


static inline void pscom_header_net_prepare(pscom_header_net_t *header,
                                            pscom_msgtype_t msg_type,
                                            size_t xheader_len, size_t data_len)
{
    header->msg_type    = msg_type;
    header->xheader_len = (uint16_t)xheader_len;
    header->data_len    = PSCOM_DATA_LEN_MASK & data_len;
}


static inline void pscom_req_prepare_send_pending_inline(
    pscom_req_t *req, pscom_msgtype_t msg_type, unsigned data_pending)
{
    pscom_header_net_prepare(&req->pub.header, msg_type, req->pub.xheader_len,
                             req->pub.data_len);

    req->cur_header.iov_base = &req->pub.header;
    req->cur_header.iov_len  = sizeof(pscom_header_net_t) +
                              req->pub.header.xheader_len;
    req->cur_data.iov_base = req->pub.data;
    req->cur_data.iov_len  = req->pub.data_len - data_pending;

    req->skip       = data_pending;
    req->pending_io = 0;
}


void pscom_req_prepare_send_pending(pscom_req_t *req, pscom_msgtype_t msg_type,
                                    unsigned data_pending)
{
    pscom_req_prepare_send_pending_inline(req, msg_type, data_pending);
}


static void pscom_req_prepare_send(pscom_req_t *req, pscom_msgtype_t msg_type)
{
    pscom_req_prepare_send_pending_inline(req, msg_type, 0);
}


static void pscom_req_prepare_rma_write(pscom_req_t *req)
{
    req->pub.xheader_len = sizeof(req->pub.xheader.rma_write);
}


/*
 * Request queueing network side
 */

static void _check_readahead(pscom_con_t *con, size_t len)
{
    if (con->in.readahead_size < len) {
        con->in.readahead.iov_base = realloc(con->in.readahead.iov_base, len);
        con->in.readahead_size     = len;
        if (!con->in.readahead.iov_base) {
            perror("allocate mem");
            exit(1);
        }
    }
}


int _pscom_update_recv_req(pscom_req_t *req)
{
    if (is_recv_req_done(req)) {
        if (!req->pending_io) { _pscom_recv_req_done(req); }
        return 1;
    }
    return 0;
}


static void _pscom_update_in_recv_req(pscom_con_t *con, pscom_req_t *req)
{
    if (req && is_recv_req_done(req)) {
        con->in.skip = req->skip;
        con->in.req  = NULL;

        if (!req->pending_io) { _pscom_recv_req_done(req); }
        pscom_con_check_read_stop(con);
    }
}


pscom_req_t *_pscom_generate_recv_req(pscom_con_t *con, pscom_header_net_t *nh)
{
    pscom_req_t *req;

    pscom.stat.gen_reqs++;

    req            = pscom_req_create(nh->xheader_len, nh->data_len);
    req->pub.state = PSCOM_REQ_STATE_GRECV_REQUEST;
    /* freed inside genreq_merge() */

    req->pub.data        = req->pub.user;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = nh->xheader_len;
    req->partner_req     = NULL;
    req->pending_io_req  = NULL;

    D_TR(printf("%s:%u:%s(). %s xheaderlen=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.xheader_len));

    return req;
}


/* return number of data bytes already received or prepared to be received
 * (pending_io > 0). */
static size_t get_req_received_len(pscom_req_t *req)
{
    return (char *)req->cur_data.iov_base - (char *)req->pub.data;
}


static void genreq_copy_header(pscom_req_t *ureq, pscom_req_t *greq)
{
    pscom_req_prepare_recv(ureq, &greq->pub.header, greq->pub.connection);
}


static void genreq_copy_data_prepare(pscom_req_t *ureq, pscom_req_t *greq)
{
    pscom_req_forward(ureq, get_req_received_len(greq));
}


static void genreq_copy_data_done(pscom_req_t *ureq, pscom_req_t *greq)
{
    size_t len    = get_req_received_len(greq);
    size_t maxlen = get_req_received_len(ureq);
    if (len > maxlen) {
        len = maxlen; // Do not copy more than maxlen (truncate message?)
    }

    _pscom_memcpy_to_user(ureq->pub.data, greq->pub.data, len);
}


static void genreq_copy_data(pscom_req_t *ureq, pscom_req_t *greq)
{
    pscom_req_write(ureq, greq->pub.data, get_req_received_len(greq));
}


void pscom_greq_check_free(pscom_con_t *con, pscom_req_t *greq)
{
    assert(greq->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST);
    if (greq == con->in.req_locked) {
        return; // greq locked by plugin
    }
    if (!(greq->pub.state & PSCOM_REQ_STATE_GRECV_MERGED)) {
        return; // greq not merged yet
    }

    pscom_req_free(greq);
}


static void genreq_pending_io_done(pscom_req_t *greq)
{
    pscom_con_t *con = get_con(greq->pub.connection);

    assert(greq->pending_io == 0);

    if (greq->pending_io_req) {
        pscom_req_t *ureq = greq->pending_io_req;

        genreq_copy_data_done(ureq, greq);

        greq->pending_io_req = NULL;
        _pscom_read_pendingio_cnt_dec(con, ureq);

        _pscom_update_recv_req(ureq);
        _pscom_grecv_req_done(greq);
    }
    pscom_greq_check_free(con, greq);
}


static void _genreq_merge(pscom_req_t *newreq, pscom_req_t *genreq)
{
    pscom_con_t *con = get_con(genreq->pub.connection);

    //	printf("GHeader: " RED "%s" NORM "\n",
    // pscom_dumpstr(&genreq->pub.header, genreq->pub.xheader_len +
    // sizeof(genreq->pub.header)));
    D_TR(printf("%s:%u:%s(gen: %s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(genreq)));
    assert(genreq->magic == MAGIC_REQUEST);

    pscom.stat.gen_reqs_used++;

    genreq_copy_header(newreq, genreq);

    newreq->pub.state |= (genreq->pub.state & ~PSCOM_REQ_STATE_GRECV_REQUEST);

    if (con->in.req == genreq) {
        // replace existing genreq with newreq;
        // Receiving should be started (PSCOM_REQ_STATE_IO_STARTED),
        // but not done (!PSCOM_REQ_STATE_IO_DONE, because (con->in.req ==
        // genreq))
        assert((genreq->pub.state &
                (PSCOM_REQ_STATE_IO_STARTED | PSCOM_REQ_STATE_IO_DONE)) ==
               PSCOM_REQ_STATE_IO_STARTED);

        // from now receive into newreq
        con->in.req = newreq;

        /* ensure that we further read on that connection */
        pscom_con_check_read_start(con);
    }

    if (genreq->pending_io) {
        genreq_copy_data_prepare(newreq, genreq);
        /* genreq_copy_data_done() in genreq_pending_io_done() */
        genreq->pending_io_req = newreq;
        _pscom_read_pendingio_cnt_inc(con, newreq);
    } else {
        /* copy already received data: */
        genreq_copy_data(newreq, genreq);
        _pscom_update_recv_req(newreq);
        _pscom_grecv_req_done(genreq);
    }

    if (genreq->partner_req) {
        /* genreq from rendezvous. Now request the data: */
        assert(genreq->partner_req->magic == MAGIC_REQUEST);

        _pscom_rendezvous_read_data(newreq, genreq->partner_req);
        genreq->partner_req = NULL;
    }

    pscom_greq_check_free(con, genreq);
}


void _pscom_genreq_abort_rendezvous_rma_reads(pscom_con_t *con)
{
    struct list_head *pos;

    list_for_each (pos, &con->net_recvq_user) {
        pscom_req_t *genreq = list_entry(pos, pscom_req_t, next);
        if (genreq->partner_req) {
            assert(genreq->partner_req->magic == MAGIC_REQUEST);
            _pscom_rendezvous_read_data_abort_arch(genreq->partner_req);
        }
    }
}


static pscom_req_t *pscom_get_default_recv_req(pscom_con_t *con,
                                               pscom_header_net_t *nh)
{
    pscom_request_t *(*default_recv)(pscom_connection_t *connection,
                                     pscom_header_net_t *header_net) =
        get_sock(con->pub.socket)->pub.ops.default_recv;
    if (default_recv) {
        pscom_request_t *ureq;
        pscom_req_t *req;

        ureq = default_recv(&con->pub, nh);
        if (ureq) {
            assert(ureq->state & PSCOM_REQ_STATE_DONE);
            ureq->state      = PSCOM_REQ_STATE_RECV_REQUEST;
            ureq->connection = &con->pub;
            ureq->socket     = con->pub.socket;
            req              = get_req(ureq);
            assert(req->magic == MAGIC_REQUEST);
        } else {
            req = NULL;
        }

        return req;
    } else {
        return NULL;
    }
}


static inline pscom_req_t *_pscom_get_user_receiver(pscom_con_t *con,
                                                    pscom_header_net_t *nh)
{
    pscom_req_t *req;
    req = pscom_get_default_recv_req(con, nh);
    if (!req) {
        req = _pscom_recvq_user_find_and_deq(con, nh);

        if (!req) {
            /* generate a request */
            req = _pscom_generate_recv_req(con, nh);

            assert(req);
            _pscom_net_recvq_user_enq(con, req);
        }
    }

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));
    return req;
}


pscom_req_t *_pscom_get_ctrl_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
    pscom_req_t *req;

    req = _pscom_recvq_ctrl_find_and_deq(con, nh);
    if (!req) {
        /* generate a request */
        req = _pscom_generate_recv_req(con, nh);

        assert(req);
        _pscom_net_recvq_ctrl_enq(con, req);
    }

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));
    return req;
}


static pscom_req_t *pscom_get_rma_write_receiver(pscom_con_t *con,
                                                 pscom_header_net_t *nh)
{
    pscom_req_t *req;
    pscom_xheader_rma_write_t *rma_header = &nh->xheader->rma_write;

    req            = pscom_req_create(0, 0);
    req->pub.state = PSCOM_REQ_STATE_RMA_WRITE_REQUEST |
                     PSCOM_REQ_STATE_PASSIVE_SIDE;

    /* freed in io_done() */
    req->pub.data        = rma_header->dest;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = 0;
    req->pub.ops.io_done = pscom_request_free;

    D_TR(printf("%s:%u:%s() %s dest=%p, len=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.data, req->pub.data_len));

    return req;
}


static void _send_rma_read_answer(pscom_req_t *req_answer)
{
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));
    assert(req_answer->magic == MAGIC_REQUEST);
    pscom_mverify(req_answer);

    req_answer->pub.ops.io_done = pscom_request_free;

    _pscom_post_send_direct_inline(get_con(req_answer->pub.connection),
                                   req_answer, PSCOM_MSGTYPE_RMA_READ_ANSWER);
}


static void send_rma_read_answer_error(pscom_request_t *request_answer)
{
    pscom_con_error(get_con(request_answer->connection), PSCOM_OP_WRITE,
                    PSCOM_ERR_IOERROR);
    pscom_request_free(request_answer);
}


static void send_rma_read_answer(pscom_request_t *request_answer)
{
    pscom_req_t *req_answer = get_req(request_answer);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));
    assert(req_answer->magic == MAGIC_REQUEST);
    pscom_mverify(req_answer);

    req_answer->pub.ops.io_done = pscom_request_free;

    pscom_post_send_direct(req_answer, PSCOM_MSGTYPE_RMA_READ_ANSWER);
}


static void _rma_write_done(void *priv, int error)
{
    pscom_req_t *req_answer     = (pscom_req_t *)priv;
    /* rma_write_done() could be called anytime by the lower level
     * protocol driver. The pscom.io_doneq queue is used to
     * postpone the pscom_post_send_direct(PSCOM_MSGTYPE_RMA_READ_ANSWER)
     * call until it is safe to call.
     */
    req_answer->pub.ops.io_done = error ? send_rma_read_answer_error
                                        : send_rma_read_answer;

    _pscom_req_done(req_answer);
}


static pscom_req_t *_pscom_get_rma_read_receiver(pscom_con_t *con,
                                                 pscom_header_net_t *nh)
{
    pscom_rendezvous_msg_t *rd_msg = (pscom_rendezvous_msg_t *)nh->xheader;
    pscom_req_t *req_answer =
        pscom_req_create(sizeof(pscom_xheader_rma_read_answer_t), 0);

    req_answer->pub.xheader.rma_read_answer.id = rd_msg->id;
    req_answer->pub.connection                 = &con->pub;

    if (nh->xheader_len == pscom_rendezvous_msg_len(0)) {
    fallback_to_sw_rndv:
        req_answer->pub.data_len = rd_msg->data_len;
        req_answer->pub.data     = rd_msg->data;

        D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                    pscom_debug_req_str(req_answer)));

        _send_rma_read_answer(req_answer);
    } else {
        assert(con->rndv.rma_write);

        req_answer->pub.data_len = 0;
        req_answer->pub.data     = NULL;

        D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                    pscom_debug_req_str(req_answer)));

        pscom_mverify(req_answer);
        if (con->rndv.rma_write(con, rd_msg->data, rd_msg, _rma_write_done,
                                req_answer)) {
            pscom.stat.fallback_to_sw_rndv++;
            goto fallback_to_sw_rndv;
        }
    }
    return NULL;
}


static void _pscom_rma_req_deregister(pscom_con_t *con,
                                      pscom_req_t *rma_read_req)
{
    if (con->rndv.mem_deregister && rma_read_req->rndv_data) {
        pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)
                                          rma_read_req->rndv_data;

        assert(rma_read_req->pub.data_len > pscom_rendezvous_msg_len(0));

        con->rndv.mem_deregister(con, rd);
        pscom_free(rd);
        rma_read_req->rndv_data = NULL;
    }
}


void _pscom_recvq_rma_terminate(pscom_con_t *con)
{
    while (!_pscom_recvq_rma_empty(con)) {
        pscom_req_t *rma_read_req = _pscom_recvq_rma_head(con);

        _pscom_recvq_rma_deq(con, rma_read_req);

        _pscom_rma_req_deregister(con, rma_read_req);

        rma_read_req->pub.state |= PSCOM_REQ_STATE_ERROR;
        _pscom_recv_req_done(rma_read_req);
    }
}


static pscom_req_t *_pscom_get_rma_read_answer_receiver(pscom_con_t *con,
                                                        pscom_header_net_t *nh)
{
    pscom_req_t *rma_read_req;

    assert(!list_empty(con->recvq_rma.next));

    rma_read_req = nh->xheader->rma_read_answer.id;

    if (!_pscom_recvq_rma_contains(con, rma_read_req)) {
        /* Received unknown rma_read_answer.id. Maybe this
         * rma request was already aborted.
         * Reject this message */
        return NULL; // reject
    }

    _pscom_recvq_rma_deq(con, rma_read_req);
    _pscom_rma_req_deregister(con, rma_read_req);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(rma_read_req)));
    return rma_read_req;
}


static void pscom_rendezvous_read_data_io_done(pscom_request_t *request)
{
    pscom_req_t *req      = get_req(request);
    pscom_req_t *user_req = req->partner_req;

    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)req->pub.user;

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));
    assert(req->magic == MAGIC_REQUEST);
    assert(user_req->magic == MAGIC_REQUEST);

    if (!pscom_req_state_successful(req->pub.state)) {
        user_req->pub.state |= PSCOM_REQ_STATE_ERROR;
    }
    pscom_recv_req_done(user_req);

    /* rewrite rendezvous_req for rendezvous fin message */
    req->pub.xheader.ren_fin.id = rd->msg.id;
    req->pub.xheader_len        = sizeof(req->pub.xheader.ren_fin);

    req->pub.data     = NULL;
    req->pub.data_len = 0;

    /* rendezvous_req->pub.connection already set */
    req->pub.ops.io_done = pscom_request_free;

    pscom_post_send_direct(req, PSCOM_MSGTYPE_RENDEZVOUS_FIN);
}


static void _pscom_rendezvous_read_data(pscom_req_t *user_recv_req,
                                        pscom_req_t *rendezvous_req)
{
    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)
                                      rendezvous_req->pub.user;

    size_t to_read   = pscom_min(rd->msg.data_len, user_recv_req->pub.data_len);
    pscom_con_t *con = get_con(rendezvous_req->pub.connection);

    assert(con->magic == MAGIC_CONNECTION);
    assert(rendezvous_req->magic == MAGIC_REQUEST);
    assert(user_recv_req->magic == MAGIC_REQUEST);

    D_TR(printf("%s:%u:%s(user: %s", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(user_recv_req)));
    D_TR(printf(", rndv: %s)\n", pscom_debug_req_str(rendezvous_req)));

    /* rewrite the rendezvous_req for read rma (read data) */
    rendezvous_req->pub.data_len = to_read;
    rendezvous_req->pub.data     = user_recv_req->pub.data;

    /* rendezvous_req->pub.connection already set */
    rendezvous_req->pub.xheader.rma_read.src     = rd->msg.data;
    rendezvous_req->pub.xheader.rma_read.src_len = to_read;
    rendezvous_req->pub.xheader.rma_read.id      = rd->msg.id;

    rendezvous_req->pub.ops.io_done = pscom_rendezvous_read_data_io_done;
    rendezvous_req->partner_req     = user_recv_req;

    if (rd->msg_arch_len && con->rndv.rma_read) {
// #define RMA_CNT
#ifdef RMA_CNT
        static unsigned work_cnt = 0;
        static unsigned fail_cnt = 0;
#endif
        perf_add("rndv_con_rma_read");
        if (con->rndv.rma_read(rendezvous_req, rd)) {
#ifdef RMA_CNT
            fail_cnt++;
            if (fail_cnt % 1000 == 0) {
                printf("WorkCnt:%u, FailCnt: %u\n", work_cnt, fail_cnt);
            }
#endif
            pscom.stat.fallback_to_sw_rndv++;
            goto rma_read_fallback;
        }
#ifdef RMA_CNT
        work_cnt++;
        if (work_cnt % 1000 == 0) {
            printf("WorkCnt:%u, FailCnt: %u\n", work_cnt, fail_cnt);
        }
#endif
    } else {
    rma_read_fallback:
        perf_add("rndv_fallback_rma_read");
        _pscom_post_rma_read_inline(rendezvous_req);
    }
}


static void _pscom_rendezvous_read_data_abort_arch(pscom_req_t *rendezvous_req)
{
    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)
                                      rendezvous_req->pub.user;

    assert(rendezvous_req->magic == MAGIC_REQUEST);

    // Do not use any remote memory information for rma_read anymore:
    rd->msg_arch_len = 0;
}


static pscom_req_t *pscom_get_rendezvous_receiver(pscom_con_t *con,
                                                  pscom_header_net_t *nh)
{
    perf_add("rndv_receiver");

    pscom_rendezvous_xheader_t *rx =
        (pscom_rendezvous_xheader_t *)(void *)&nh->xheader;

    size_t user_xheader_len      = rx->user_header_net.xheader_len;
    pscom_rendezvous_msg_t *rmsg = (pscom_rendezvous_msg_t *)(rx->user_xheader +
                                                              user_xheader_len);


    pscom_req_t *rndv_req = pscom_req_create(0, sizeof(pscom_rendezvous_data_t));

    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)rndv_req->pub.user;
    size_t arch_len             = pscom_rendezvous_arch_len(nh->xheader_len,
                                                            user_xheader_len);
    /* copy pscom_rendezvous_msg_t */
    memcpy(&rd->msg, rmsg, /* sizeof(rd->msg) */
           pscom_rendezvous_msg_len(arch_len));

    rd->msg_arch_len = arch_len;

    rndv_req->pub.connection = &con->pub;
    rndv_req->pub.state      = PSCOM_REQ_STATE_RMA_READ_REQUEST;

    /* find a matching request or genereate one as appropriate */
    pscom_req_t *user_req = _pscom_get_recv_req(con, &rx->user_header_net);

    pscom_req_prepare_recv(user_req, &rx->user_header_net, &con->pub);

    if (!(user_req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST)) {
        /* found user receive request. Initiate a rma_read. */
        _pscom_rendezvous_read_data(user_req, rndv_req);
    } else {
        /* found generated request.
           Continue after user post a recv. */
        user_req->partner_req = rndv_req;
        user_req->pub.state |= PSCOM_REQ_STATE_RENDEZVOUS_REQUEST;
    }

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(rndv_req)));

    assert(nh->data_len == 0);
    return NULL;
}


static pscom_req_t *_pscom_get_rendezvous_fin_receiver(pscom_con_t *con,
                                                       pscom_header_net_t *nh)
{
    pscom_req_t *user_req       = nh->xheader->ren_fin.id;
    pscom_req_t *req            = user_req->partner_req;
    pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)req->pub.user;

    assert(req->magic == MAGIC_REQUEST);
    assert(user_req->magic == MAGIC_REQUEST);

    if (con->rndv.mem_deregister &&
        (req->pub.data_len > pscom_rendezvous_msg_len(0))) {
        con->rndv.mem_deregister(con, rd);
    }

    pscom_request_free(&req->pub);

    perf_add("rndv_send_done");
    _pscom_read_pendingio_cnt_dec(
        con, user_req); // inc in pscom_prepare_send_rendezvous_inline()

    _pscom_send_req_done(user_req); // done

    return NULL;
}


static pscom_req_t *_pscom_get_eof_receiver(pscom_con_t *con,
                                            pscom_header_net_t *nh)
{
    DPRINT(D_DBG_V, "EOF recv   %s via %s", pscom_con_str(&con->pub),
           pscom_con_type_str(con->pub.type));

    con->state.eof_received = 1;
    pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_EOF);
    return NULL;
}


static void _pscom_req_suspend_io_done(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    pscom_con_t *con = get_con(req->pub.connection);
    pscom_lock();
    {
        _pscom_con_suspend_received(con, &req->pub.xheader.user,
                                    req->pub.xheader_len);
    }
    pscom_unlock();

    pscom_req_free(req);
}


static pscom_req_t *_pscom_get_suspend_receiver(pscom_con_t *con,
                                                pscom_header_net_t *nh)
{
    pscom_req_t *req;

    if (!nh->xheader_len) {
        return NULL; // Ignore message sent to resume the connection.
    }

    req = pscom_req_create(nh->xheader_len, 0);

    req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST;
    assert(nh->data_len == 0);

    req->pub.data        = NULL;
    req->pub.data_len    = 0;
    req->pub.xheader_len = nh->xheader_len;

    req->pub.ops.io_done = _pscom_req_suspend_io_done;

    return req;
}


/* return a request, which will receive this message.
   return NULL if this message should be discarded */
static pscom_req_t *_pscom_get_recv_req(pscom_con_t *con, pscom_header_net_t *nh)
{
    pscom_req_t *req;
    D_TR(printf("%s:%u:%s(con:%p, nh->msg_type:%s)\n", __FILE__, __LINE__,
                __func__, con, pscom_msgtype_str(nh->msg_type)));

    if (nh->msg_type == PSCOM_MSGTYPE_USER) {
        req = _pscom_get_user_receiver(con, nh);
        pscom_req_prepare_recv(req, nh, &con->pub);
    } else {
        switch (nh->msg_type) {
        /* receive header from RNDV write operation */
        case PSCOM_MSGTYPE_RMA_WRITE:
            req = pscom_get_rma_write_receiver(con, nh);
            break;
        /* receive read request from RNDV read operation */
        case PSCOM_MSGTYPE_RMA_READ:
            req = _pscom_get_rma_read_receiver(con, nh);
            break;
        /* receive read reply requested RNDV read operation */
        case PSCOM_MSGTYPE_RMA_READ_ANSWER:
            req = _pscom_get_rma_read_answer_receiver(con, nh);
            break;
        /* receive read request from RNDV operation */
        case PSCOM_MSGTYPE_RENDEZVOUS_REQ:
            req = pscom_get_rendezvous_receiver(con, nh);
            break;
        /* receive signal of finishing data transfer for RNDV */
        case PSCOM_MSGTYPE_RENDEZVOUS_FIN:
            req = _pscom_get_rendezvous_fin_receiver(con, nh);
            break;
        /* target receives RMA put operation */
        case PSCOM_MSGTYPE_RMA_PUT:
            req = pscom_get_rma_put_receiver(con, nh);
            break;
        /* target receives RMA get request */
        case PSCOM_MSGTYPE_RMA_GET_REQ:
            req = _pscom_get_rma_get_receiver(con, nh);
            break;
        /* origin receives reply from target reqested by RMA get operation */
        case PSCOM_MSGTYPE_RMA_GET_REP:
            req = _pscom_get_rma_get_answer_receiver(con, nh);
            break;
        /* target receives RMA acc operation */
        case PSCOM_MSGTYPE_RMA_ACCUMULATE:
            req = pscom_get_rma_accumulate_receiver(con, nh);
            break;
        /* target receives RMA get_accumulate request */
        case PSCOM_MSGTYPE_RMA_GET_ACCUMULATE_REQ:
            req = _pscom_get_rma_get_acc_receiver(con, nh);
            break;
        case PSCOM_MSGTYPE_RMA_GET_ACCUMULATE_REP:
        /*
         * origin receives reply from target requested by RMA get_accumulate or
         * FOP operation
         */
        case PSCOM_MSGTYPE_RMA_FETCH_AND_OP_REP:
            req = _pscom_get_rma_get_acc_answer_receiver(con, nh);
            break;
        /* target side receives RMA fetch&op request */
        case PSCOM_MSGTYPE_RMA_FETCH_AND_OP_REQ:
            req = _pscom_get_rma_fetch_op_receiver(con, nh);
            break;
        /* target side receives RMA C&S request */
        case PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REQ:
            req = _pscom_get_rma_compare_swap_receiver(con, nh);
            break;
        /* origin receives reply from target requested by RMA CAS operation */
        case PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REP:
            req = _pscom_get_rma_compare_swap_answer_receiver(con, nh);
            break;
        case PSCOM_MSGTYPE_BCAST:
            req = _pscom_get_bcast_receiver(con, nh);
            break;
        case PSCOM_MSGTYPE_BARRIER:
            req = _pscom_get_ctrl_receiver(con, nh);
            break;
        case PSCOM_MSGTYPE_EOF: req = _pscom_get_eof_receiver(con, nh); break;
        case PSCOM_MSGTYPE_SUSPEND:
            req = _pscom_get_suspend_receiver(con, nh);
            break;
        case PSCOM_MSGTYPE_GW_ENVELOPE:
            req = _pscom_get_gw_envelope_receiver
                      ? _pscom_get_gw_envelope_receiver(con, nh)
                      : NULL;
            break;
        default:
            DPRINT(D_BUG, "Receive unknown msg_type %u", nh->msg_type);
            req = NULL;
        }
        if (req) { pscom_req_prepare_recv(req, nh, &con->pub); }
    }

    D_TR(printf("%s:%u:%s(con:%p) : %s\n", __FILE__, __LINE__, __func__, con,
                pscom_debug_req_str(req)));
    return req;
}


// return true at the end of each message
int pscom_read_is_at_message_start(pscom_con_t *con)
{
    return !con->in.req && !con->in.skip;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_read_get_buf(pscom_con_t *con, char **buf, size_t *len)
{
    if (con->in.req) {
        pscom_req_t *req = con->in.req;
        *buf             = req->cur_data.iov_base;
        *len             = req->cur_data.iov_len;
        assert(req->cur_data.iov_len > 0);
    } else if (!con->in.skip) {
        size_t readlen = pscom.env.readahead;

        if (con->in.readahead.iov_len >= sizeof(pscom_header_net_t)) {
            readlen = header_length(
                (pscom_header_net_t *)con->in.readahead.iov_base);
        }
        _check_readahead(con, readlen);

        *buf = con->in.readahead.iov_base + con->in.readahead.iov_len;
        *len = readlen - con->in.readahead.iov_len;
    } else {
        size_t rlen = pscom_min(pscom.env.skipblocksize, con->in.skip);
        _check_readahead(con, rlen);
        *buf = con->in.readahead.iov_base;
        *len = rlen;
    }

    D_TR(printf("%s:%u:%s(con, *buf=%p, *len=%zu)\n", __FILE__, __LINE__,
                __func__, *buf, *len));
}


// ToDo: Use pscom_read_get_buf()/pscom_read_pending()/pscom_read_pending_done()
// instead of
//           pscom_read_get_buf_locked()/pscom_read_done_unlock()
PSCOM_PLUGIN_API_EXPORT
void pscom_read_get_buf_locked(pscom_con_t *con, char **buf, size_t *len)
{
    pscom_read_get_buf(con, buf, len);

    if (con->in.req &&
        (con->in.req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST)) {
        /* Only generated requests should be locked. Only
           _genreq_merge() check for req->in.req_lock. All
           other requests are already locked, until they are done
           (pscom_req_is_done() == true) */
        assert(!con->in.req_locked);
        con->in.req_locked = con->in.req;
    }
}


PSCOM_PLUGIN_API_EXPORT
void pscom_read_done_unlock(pscom_con_t *con, char *buf, size_t len)
{
    pscom_read_done(con, buf, len);

    if (con->in.req_locked) {
        pscom_req_t *req   = con->in.req_locked;
        con->in.req_locked = NULL;
        pscom_greq_check_free(con, req);
    }
}


PSCOM_PLUGIN_API_EXPORT
void pscom_read_pending_done(pscom_con_t *con, pscom_req_t *req)
{
    if (req) {
        assert(req->magic == MAGIC_REQUEST);

        assert(!(req->pub.state & PSCOM_REQ_STATE_IO_DONE));
        assert(req->pending_io != 0);

        if (_pscom_read_pendingio_cnt_dec(con, req)) {
            /*
             * check if all pending IO is done without updating
             * con->in.req (i.e., this has already been done in
             * pscom_read_pending())
             */
            _pscom_update_recv_req(req);

            if (req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST) {
                genreq_pending_io_done(req);
            }
        }
    }
}


PSCOM_PLUGIN_API_EXPORT
pscom_req_t *pscom_read_pending(pscom_con_t *con, size_t len)
{
    // Like pscom_read_done(), but without a buffer to copy.
    pscom_req_t *req = con->in.req;

    if (req) {
        size_t _len;

        _len = pscom_req_forward(req, len);
        assert(_len == len);

        _pscom_read_pendingio_cnt_inc(con, req);
        _pscom_update_in_recv_req(con, req);
    }
    return req;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_read_done(pscom_con_t *con, char *buf, size_t len)
{
    pscom_req_t *req = con->in.req;

    D_TR(printf("%s:%u:%s(con, buf=%p, len=%zu, %s)\n", __FILE__, __LINE__,
                __func__, buf, len, pscom_dumpstr(buf, pscom_min(len, 32))));

    if (!len) { goto err_eof; }

    if (req) {
        size_t _len;

        _len = pscom_req_write(req, buf, len);
        len -= _len;
        buf += _len;

        _pscom_update_in_recv_req(con, req);

        assert(!con->in.readahead.iov_len);

        if (!len) { return; }

        assert(!con->in.req);
    }

    if (con->in.readahead.iov_len) {
        char *dest;
        // append buf,len to readahead buffer
        assert(!con->in.skip);

        _check_readahead(con, con->in.readahead.iov_len + len);
        dest = ((char *)con->in.readahead.iov_base) + con->in.readahead.iov_len;
        if (buf != dest) { memcpy(dest, buf, len); }

        con->in.readahead.iov_len += len;

        buf = con->in.readahead.iov_base;
        len = con->in.readahead.iov_len;
    } else if (con->in.skip) {
        if (con->in.skip < len) {
            buf += con->in.skip;
            len -= con->in.skip;
            con->in.skip = 0;
        } else {
            con->in.skip -= len;
            return;
        }
    }


    while (header_complete(buf, len)) {
        // consume data
        pscom_header_net_t *header = (pscom_header_net_t *)buf;
        size_t hlen                = header_length(header);
        size_t l;

        con->in.req = _pscom_get_recv_req(con, header);
        req         = con->in.req;

        buf += hlen;
        len -= hlen;

        if (req) {
            req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;

            /*
             * stage buffer just before IO is started for the first time (i.e.,
             * when the actual connection type incl. GPU awareness is known) to
             * avoid undesired staging for on-demand connections
             */
            _pscom_stage_buffer(req, 0);

            /* only write to the request (memcpy) if len > 0 */
            if (len) {
                l = pscom_req_write(req, buf, len);
                buf += l;
                len -= l;
            }
        } else if (len) {
            /* Skip message */
            size_t skip = pscom_min(header->data_len, len);

            buf += skip;
            len -= skip;
            con->in.skip = header->data_len - skip;
        }

        _pscom_update_in_recv_req(con, req);
        assert(!con->in.skip || !len);
    }


    if (len && (con->in.readahead.iov_base != buf)) {
        // save unused data
        _check_readahead(con, len);
        memmove(con->in.readahead.iov_base, buf, len);
    }

    con->in.readahead.iov_len = len;

    return;
    /* --- */
err_eof:
    if (!con->state.eof_received && !con->state.close_called) {
        /* Received an transport layer eof, without
           a previous received PSCOM_MSGTYPE_EOF or call to close. -> Throw an
           IOERROR: */
        pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_IOERROR);
    }
    return;
}


PSCOM_PLUGIN_API_EXPORT
pscom_req_t *pscom_write_get_iov(pscom_con_t *con, struct iovec iov[2])
{
    if (!list_empty(&con->sendq)) {
        pscom_req_t *req = list_entry(con->sendq.next, pscom_req_t, next);

        iov[0] = req->cur_header;
        iov[1] = req->cur_data;

        if (req->cur_data.iov_len || req->cur_header.iov_len) {
            req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;

            /*
             * stage buffer just before IO is started for the first time (i.e.,
             * when the actual connection type incl. GPU awareness is known) to
             * avoid undesired staging for on-demand connections
             */
            _pscom_stage_buffer(req, 1);


            return req;
        }
    }

    /* Nothing to send. Wait for more data (up to req->skip bytes) */
    pscom_con_check_write_stop(con);
    return 0;
}


static int send_req_all_io_started(pscom_req_t *req)
{
    return !req->cur_data.iov_len && !req->cur_header.iov_len && !req->skip;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_write_done(pscom_con_t *con, pscom_req_t *req, size_t len)
{
    pscom_forward_iov(&req->cur_header, len);

    if (send_req_all_io_started(req)) {
        _pscom_sendq_deq(con, req);
        if (!req->pending_io) {
            _pscom_send_req_done(req); // done
        }
    }
}


PSCOM_PLUGIN_API_EXPORT
void pscom_write_pending(pscom_con_t *con, pscom_req_t *req, size_t len)
{
    pscom_forward_iov(&req->cur_header, len);

    _pscom_write_pendingio_cnt_inc(con, req);

    if (send_req_all_io_started(req)) {
        // Remove req from sendq. The req is still not done yet
        // (has pendingio)!
        _pscom_sendq_deq(con, req);
    }
}


PSCOM_PLUGIN_API_EXPORT
void pscom_write_pending_done(pscom_con_t *con, pscom_req_t *req)
{
    if (_pscom_write_pendingio_cnt_dec(con, req) &&
        send_req_all_io_started(req) &&
        !(req->pub.state & PSCOM_REQ_STATE_IO_DONE)) {
        _pscom_send_req_done(req); // done
    }
}


PSCOM_PLUGIN_API_EXPORT
void pscom_write_pending_error(pscom_con_t *con, pscom_req_t *req)
{
    req->pub.state |= PSCOM_REQ_STATE_ERROR;
    pscom_write_pending_done(con, req);
}


/* Use con to send req with msg_type. pscom_lock must be held. */
static inline void _pscom_post_send_direct_inline(pscom_con_t *con,
                                                  pscom_req_t *req,
                                                  pscom_msgtype_t msg_type)
{
    pscom_req_prepare_send(req, msg_type); // build header and iovec
    req->pub.connection = &con->pub;

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    _pscom_sendq_enq(con, req);
}


/* Use con to send req with msg_type. pscom_lock must be held. */
static void _pscom_post_send_direct(pscom_con_t *con, pscom_req_t *req,
                                    pscom_msgtype_t msg_type)
{
    _pscom_post_send_direct_inline(con, req, msg_type);
}


/* inline version of pscom_post_send_direct */
static inline void pscom_post_send_direct_inline(pscom_req_t *req,
                                                 pscom_msgtype_t msg_type)
{
    pscom_req_prepare_send(req, msg_type); // build header and iovec

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    pscom_lock();
    {
        _pscom_sendq_enq(get_con(req->pub.connection), req);
    }
    pscom_unlock();
}


/* _pscom_post_send_direct version, but pscom_lock NOT held. */
void pscom_post_send_direct(pscom_req_t *req, pscom_msgtype_t msg_type)
{
    pscom_post_send_direct_inline(req, msg_type);
}


static void _pscom_send(pscom_con_t *con, pscom_msgtype_t msg_type,
                        void *xheader, size_t xheader_len, void *data,
                        size_t data_len)
{
    pscom_req_t *req;

    req = pscom_req_create(xheader_len, data_len);

    req->pub.xheader_len = xheader_len;
    req->pub.data_len    = data_len;
    req->pub.data        = req->pub.user;

    memcpy(&req->pub.xheader, xheader, xheader_len);
    _pscom_memcpy_from_user(req->pub.data, data, data_len);

    req->pub.ops.io_done = pscom_request_free;

    _pscom_post_send_direct_inline(con, req, msg_type);
}


struct pscom_req_send_inplace_rdata {
    void (*io_done)(pscom_req_state_t state, void *priv);
    void *priv;
    char data[0];
};


static void pscom_send_inplace_io_done(pscom_request_t *req)
{
    struct pscom_req_send_inplace_rdata *rdata =
        (struct pscom_req_send_inplace_rdata *)req->user;

    if (rdata->io_done) { rdata->io_done(req->state, rdata->priv); }

    pscom_request_free(req);
}


void _pscom_send_inplace(pscom_con_t *con, pscom_msgtype_t msg_type,
                         void *xheader, size_t xheader_len, void *data,
                         size_t data_len,
                         void (*io_done)(pscom_req_state_t state, void *priv),
                         void *priv)
{
    pscom_req_t *req;

    struct pscom_req_send_inplace_rdata *rdata;

    req = pscom_req_create(xheader_len, sizeof(*rdata));

    req->pub.xheader_len = xheader_len;
    req->pub.data_len    = data_len;
    req->pub.data        = data;
    rdata                = (struct pscom_req_send_inplace_rdata *)req->pub.user;

    rdata->io_done = io_done;
    rdata->priv    = priv;

    memcpy(&req->pub.xheader, xheader, xheader_len);

    req->pub.ops.io_done = pscom_send_inplace_io_done;

    _pscom_post_send_direct_inline(con, req, msg_type);
}


static int _pscom_cancel_send(pscom_req_t *req)
{
    if (req->pub.state & PSCOM_REQ_STATE_IO_DONE) { return 0; }
    if (req->pub.state & PSCOM_REQ_STATE_IO_STARTED) { return 0; }

    _pscom_sendq_deq(get_con(req->pub.connection), req);

    req->pub.state |= PSCOM_REQ_STATE_CANCELED;
    _pscom_send_req_done(req); // done

    return 1;
}


static int _pscom_cancel_recv(pscom_req_t *req)
{
    if (req->pub.state & PSCOM_REQ_STATE_IO_DONE) { return 0; }
    if (req->pub.state & PSCOM_REQ_STATE_IO_STARTED) { return 0; }

    assert(_pscom_recvq_user_is_inside(req));

    _pscom_recvq_user_deq(req);

    if (req->pub.socket) {
        pscom_sock_t *sock = get_sock(req->pub.socket);
        _pscom_recvq_any_cleanup(&sock->recvq_any);
    } else {
        _pscom_recvq_any_cleanup(&pscom.recvq_any_global);
    }

    req->pub.state |= PSCOM_REQ_STATE_CANCELED;
    _pscom_recv_req_done(req); // done

    return 1;
}


/*
 * Prepares a rendezvous request by generating a message with the network layout
 * as defined in pscom_priv.h.
 *
 * This function is used for both the locked and the unlocked version of
 * pscom_post_send_rendezvous_inline().
 */
static inline pscom_req_t *pscom_prepare_send_rendezvous_inline(
    pscom_req_t *user_req, pscom_msgtype_t msg_type)
{

    pscom_req_t *rndv_req;
    pscom_rendezvous_xheader_t *rx;
    pscom_rendezvous_data_t *rd;

    pscom_con_t *con        = get_con(user_req->pub.connection);
    size_t user_xheader_len = user_req->pub.xheader_len;

    pscom.stat.rendezvous_reqs++;

    rndv_req = pscom_req_create(sizeof(pscom_rendezvous_xheader_t) +
                                    sizeof(pscom_rendezvous_data_t) +
                                    user_xheader_len,
                                0);

    /* user header and user xheader */
    rx = (pscom_rendezvous_xheader_t *)(void *)&rndv_req->pub.xheader;

    pscom_header_net_prepare(&rx->user_header_net, msg_type, user_xheader_len,
                             user_req->pub.data_len);

    memcpy(rx->user_xheader, &user_req->pub.xheader, user_xheader_len);

    /* rendezvous xheader = Rendezvous data, starting with
     * pscom_rendezvous_msg_t rd->msg */
    rd = (pscom_rendezvous_data_t *)(rx->user_xheader + user_xheader_len);

    rd->msg.id       = user_req;
    rd->msg.data     = user_req->pub.data;
    rd->msg.data_len = user_req->pub.data_len;

    rd->msg_arch_len = 0;

    rndv_req->pub.user = (void *)rd;

    /* net arch specific xheader: */
    if (con->rndv.mem_register && con->rndv.mem_register_check &&
        !con->rndv.mem_register_check(con, rd)) {
        goto fallback_to_eager;
    }

    int len_arch = 0;
    if (con->rndv.rma_read && con->rndv.mem_register) {
        len_arch = con->rndv.mem_register(con, rd);
        if (!len_arch) { goto fallback_to_eager; }
        rd->msg_arch_len = len_arch;
    }

    rndv_req->pub.xheader_len = pscom_rendezvous_xheader_len(len_arch,
                                                             user_xheader_len);

    D_TR(printf("%s:%u:%s(user:%s) ", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(user_req)));
    D_TR(printf("rndv:%s\n", pscom_debug_req_str(rndv_req)));

    rndv_req->pub.ops.io_done = NULL;

    pscom_req_prepare_send(user_req, msg_type);
    user_req->partner_req = rndv_req;
    user_req->pub.state   = PSCOM_REQ_STATE_RENDEZVOUS_REQUEST |
                          PSCOM_REQ_STATE_SEND_REQUEST | PSCOM_REQ_STATE_POSTED;

    /*
     * Pending rendezvous. Dec in _pscom_get_rendezvous_fin_receiver() or
     * _pscom_con_terminate_sendq()
     */
    _pscom_read_pendingio_cnt_inc(con, user_req);

    return rndv_req;

fallback_to_eager:
    pscom_req_free(rndv_req);
    pscom.stat.fallback_to_eager++;

    return NULL;
}

/*
 * Posts a rendezvous request with arbitrary message type
 *
 * The caller needs to use locks!
 */
static inline void _pscom_post_send_rendezvous_inline(pscom_req_t *user_req,
                                                      pscom_msgtype_t msg_type)
{
    pscom_con_t *con = get_con(user_req->pub.connection);
    pscom_req_t *req = pscom_prepare_send_rendezvous_inline(user_req, msg_type);

    if (!req) {
        _pscom_post_send_direct_inline(con, user_req, msg_type);
    } else {
        _pscom_post_send_direct_inline(con, req, PSCOM_MSGTYPE_RENDEZVOUS_REQ);
    }

    return;
}


static inline void _pscom_post_rma_read_inline(pscom_req_t *rma_read_req)
{
    pscom_con_t *con     = get_con(rma_read_req->pub.connection);
    pscom_req_t *req_rma = pscom_req_create(sizeof(pscom_rendezvous_data_t), 0);
    pscom_rendezvous_data_t *rd =
        (pscom_rendezvous_data_t *)&req_rma->pub.xheader.user;
    unsigned len_arch = 0;

    rma_read_req->pub.state = PSCOM_REQ_STATE_RMA_READ_REQUEST |
                              PSCOM_REQ_STATE_POSTED;
    _pscom_recvq_rma_enq(con, rma_read_req);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(rma_read_req)));

    rd->msg.id              = rma_read_req;
    rma_read_req->rndv_data = NULL;

    if (con->rndv.rma_write && con->rndv.mem_register) {

        rd->msg.data     = rma_read_req->pub.data;
        rd->msg.data_len = rma_read_req->pub.data_len;

        if (!con->rndv.mem_register_check ||
            (con->rndv.mem_register_check &&
             con->rndv.mem_register_check(con, rd))) {

            len_arch = con->rndv.mem_register(con, rd);

            if (len_arch && con->rndv.mem_deregister) {
                rma_read_req->rndv_data = pscom_malloc(
                    sizeof(pscom_rendezvous_data_t));
                memcpy(rma_read_req->rndv_data, rd,
                       sizeof(pscom_rendezvous_data_t)); // ToDo: _pscom_memcpy?
            }
        }

        if (!len_arch) { pscom.stat.fallback_to_sw_rndv++; }
    }

    rd->msg.data     = rma_read_req->pub.xheader.rma_read.src;
    rd->msg.data_len = rma_read_req->pub.xheader.rma_read.src_len;

    req_rma->pub.xheader_len = pscom_rendezvous_msg_len(len_arch);
    req_rma->pub.ops.io_done = pscom_request_free;
    _pscom_post_send_direct(con, req_rma, PSCOM_MSGTYPE_RMA_READ);
}

void _pscom_post_rma_read(pscom_req_t *rma_read_req)
{
    _pscom_post_rma_read_inline(rma_read_req);
}

/* post the receive request req.
   Receiving up to req->xheader_len bytes to req->xheader and
   up to req->data_len bytes to req->data from connection
   req->connection with message type req->header.msg_type.

   req->xheader_len
   req->xheader
   req->data_len
   req->data
   req->connection or req->connection==NULL and req->socket
   req->header.msg_type

   optional:
   req->ops.recv_accept
   req->ops.io_done
*/
void _pscom_post_recv_ctrl(pscom_req_t *req)
{
    pscom_req_t *genreq;

    assert(req->magic == MAGIC_REQUEST);
    assert(req->pub.state & PSCOM_REQ_STATE_DONE);
    assert(req->pub.connection != NULL);

    req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

    genreq = _pscom_net_recvq_ctrl_find(req);
    if (!genreq) {
        // Nothing received so far. Enqueue to recvq_ctrl.
        pscom_con_t *con = get_con(req->pub.connection);
        _pscom_recvq_ctrl_enq(con, req);
    } else {
        // Matching message already partial or in whole received.
        _pscom_net_recvq_ctrl_deq(genreq);
        _genreq_merge(req, genreq);
    }
}


void pscom_post_recv_ctrl(pscom_req_t *req)
{
    pscom_lock();
    {
        _pscom_post_recv_ctrl(req);
    }
    pscom_unlock();
}


static void _pscom_wait_any(void)
{
    if (pscom.stat.progresscounter == pscom.stat.progresscounter_check) {
        pscom_progress(pscom.ufd_timeout); // Wait
    } else {
        pscom_progress(0);
        pscom.stat.progresscounter_check = pscom.stat.progresscounter;
    }
}

/*
******************************************************************************
*/

PSCOM_API_EXPORT
pscom_request_t *pscom_request_create(size_t max_xheader_len, size_t user_size)
{
    pscom_req_t *req;

    req = pscom_req_create(max_xheader_len, user_size);

    return req ? &req->pub : NULL;
}


PSCOM_API_EXPORT
void pscom_request_free(pscom_request_t *request)
{
    pscom_req_free(get_req(request));
}


PSCOM_API_EXPORT
void pscom_post_recv(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    pscom_lock();
    {
        pscom_req_t *genreq;
        perf_add("pscom_post_recv");

        req->pub.state  = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;
        req->pending_io = 0;
        genreq          = _pscom_net_recvq_user_find(req);

        if (!genreq) {
            // Nothing received so far. Enqueue receive reques.
            _pscom_recvq_user_enq(req);
        } else {
            // Matching message already partial or in whole received.
            _pscom_net_recvq_user_deq(genreq);
            _genreq_merge(req, genreq);
        }
    }
    pscom_unlock();
}


/* return 1, if there is a matching receive. 0 otherwise.
 * in case 1: copy also the message header
 * caller have to call _pscom_recv_req_cnt_{inc,dec}()! */
static int _pscom_iprobe(pscom_req_t *req)
{
    int res;
    pscom_req_t *genreq;

    req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

    genreq = _pscom_net_recvq_user_find(req);

    if (!genreq) {
        /* not found: */
        res = 0;
    } else {
        res = 1;
        genreq_copy_header(req, genreq);
    }
    req->pub.state |= PSCOM_REQ_STATE_DONE;

    return res;
}


static void _pscom_probe(pscom_req_t *req)
{
    while (!_pscom_iprobe(req)) {
        _pscom_wait_any();

        // short release of the lock to call done callbacks:
        pscom_lock_yield();
    }
}


static unsigned int pscom_iprobe_progresscounter = ~0;
static unsigned int pscom_iprobe_count           = 0;

static inline int pscom_iprobe_make_progress(void)
{
    if (pscom_iprobe_progresscounter != pscom.stat.progresscounter) {
        pscom_iprobe_count           = 0;
        pscom_iprobe_progresscounter = pscom.stat.progresscounter;
        return 1;
    } else {
        pscom_iprobe_count++;
        if (pscom_iprobe_count >= pscom.env.iprobe_count) {
            pscom_iprobe_count = 0;
            return 1;
        }
    }
    return 0;
}


/* return 1, if there is a matching receive. 0 otherwise. */
/* in case 1: copy also the message header */
PSCOM_API_EXPORT
int pscom_iprobe(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    int res;
    int make_progress;

    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    if (request->connection) {
        /* probe on one connection */
        pscom_con_t *con = get_con(request->connection);

        pscom_lock();
        {
            pscom.stat.probes++;
            make_progress = pscom_iprobe_make_progress();

            if (make_progress) {
                _pscom_recv_req_cnt_inc(con);
                pscom_progress(0);
            }

            res = _pscom_iprobe(req);

            if (make_progress) { _pscom_recv_req_cnt_dec(con); }

            pscom.stat.iprobes_ok += res;
        }
        pscom_unlock();
    } else {
        /* probe on all connections */
        if (request->socket) {

            pscom_sock_t *sock = get_sock(request->socket);

            pscom_lock();
            {
                pscom.stat.probes++;
                pscom.stat.probes_any_source++;
                make_progress = pscom_iprobe_make_progress();

                if (make_progress) {
                    _pscom_recv_req_cnt_any_inc(sock);
                    pscom_progress(0);
                }

                res = _pscom_iprobe(req);
                if (make_progress) { _pscom_recv_req_cnt_any_dec(sock); }

                pscom.stat.iprobes_ok += res;
            }
            pscom_unlock();
        } else {
            pscom_lock();
            {
                pscom.stat.probes++;
                pscom.stat.probes_any_source++;
                make_progress = pscom_iprobe_make_progress();

                if (make_progress) {
                    _pscom_recv_req_cnt_any_global_inc();
                    pscom_progress(0);
                }

                res = _pscom_iprobe(req);
                if (make_progress) { _pscom_recv_req_cnt_any_global_dec(); }

                pscom.stat.iprobes_ok += res;
            }
            pscom_unlock();
        }
    }

    return res;
}


PSCOM_API_EXPORT
void pscom_probe(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);

    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);

    while (!pscom_iprobe(request)) {
        pscom_lock();
        {
            _pscom_wait_any();
        }
        pscom_unlock();
    }

    if (request->connection) {
        /* probe on one connection */
        pscom_con_t *con = get_con(request->connection);

        pscom_lock();
        {
            pscom.stat.probes++;

            _pscom_recv_req_cnt_inc(con);
            _pscom_probe(req);
            _pscom_recv_req_cnt_dec(con);
        }
        pscom_unlock();
    } else {
        /* probe on all connections */
        if (request->socket) {

            pscom_sock_t *sock = get_sock(request->socket);

            pscom_lock();
            {
                pscom.stat.probes++;
                pscom.stat.probes_any_source++;

                _pscom_recv_req_cnt_any_inc(sock);
                _pscom_probe(req);
                _pscom_recv_req_cnt_any_dec(sock);
            }
            pscom_unlock();
        } else {
            pscom_lock();
            {
                pscom.stat.probes++;
                pscom.stat.probes_any_source++;

                _pscom_recv_req_cnt_any_global_inc();
                _pscom_probe(req);
                _pscom_recv_req_cnt_any_global_dec();
            }
            pscom_unlock();
        }
    }
}

PSCOM_PLUGIN_API_EXPORT
void _pscom_post_send_msgtype(pscom_request_t *request, pscom_msgtype_t msg_type)
{
    pscom_req_t *req = get_req(request);
    pscom_con_t *con = get_con(request->connection);

    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);
    assert(request->connection != NULL);

    if (req->pub.data_len < con->rendezvous_size) {
        perf_add("reset_send_direct");
        _pscom_post_send_direct_inline(con, req, msg_type);
    } else {
        perf_add("reset_send_rndv");
        _pscom_post_send_rendezvous_inline(req, msg_type);
    }
}

PSCOM_PLUGIN_API_EXPORT
void pscom_post_send_msgtype(pscom_request_t *request, pscom_msgtype_t msg_type)
{
    pscom_lock();
    {
        _pscom_post_send_msgtype(request, msg_type);
    }
    pscom_unlock();
}

PSCOM_API_EXPORT
void pscom_post_send(pscom_request_t *request)
{
    pscom_post_send_msgtype(request, PSCOM_MSGTYPE_USER);
}


PSCOM_API_EXPORT
void pscom_send(pscom_connection_t *connection, void *xheader,
                size_t xheader_len, void *data, size_t data_len)
{
    pscom_lock();
    {
        _pscom_send(get_con(connection), PSCOM_MSGTYPE_USER, xheader,
                    xheader_len, data, data_len);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_send_inplace(pscom_connection_t *connection, void *xheader,
                        size_t xheader_len, void *data, size_t data_len,
                        void (*io_done)(pscom_req_state_t state, void *priv),
                        void *priv)
{
    pscom_lock();
    {
        _pscom_send_inplace(get_con(connection), PSCOM_MSGTYPE_USER, xheader,
                            xheader_len, data, data_len, io_done, priv);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
pscom_err_t pscom_recv(pscom_connection_t *connection, pscom_socket_t *socket,
                       void *xheader, size_t xheader_len, void *data,
                       size_t data_len)
{
    pscom_request_t *req = pscom_request_create(xheader_len, 0);
    pscom_err_t ret      = PSCOM_ERR_IOERROR;

    if (!req) { return PSCOM_ERR_STDERROR; }

    req->xheader_len = xheader_len;
    // memcpy(req->xheader.user, xheader, xheader_len);
    req->data_len    = data_len;
    req->data        = data;
    req->connection  = connection;
    req->socket      = socket;

    pscom_post_recv(req);

    pscom_wait(req);

    if (pscom_req_successful(req)) {
        memcpy(xheader, &req->xheader.user, xheader_len);
        ret = PSCOM_SUCCESS;
    }

    pscom_request_free(req);

    return ret;
}


PSCOM_API_EXPORT
void pscom_flush(pscom_connection_t *connection)
{
    if (!connection) { return; }
    pscom_con_t *con = get_con(connection);
    pscom_lock();
    {
        while (!list_empty(&con->sendq)) {
            _pscom_wait_any();

            // short release of the lock to call done callbacks:
            pscom_lock_yield();
        }
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_post_rma_write(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);
    assert(request->connection != NULL);

    pscom_req_prepare_rma_write(req); // build header and iovec

    pscom_post_send_direct(req, PSCOM_MSGTYPE_RMA_WRITE);
}


PSCOM_API_EXPORT
void pscom_post_rma_read(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);
    assert(request->connection != NULL);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    pscom_lock();
    {
        _pscom_post_rma_read_inline(req);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_wait_any(void)
{
    pscom_lock();
    {
        _pscom_wait_any();
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_wait(pscom_request_t *request)
{
    volatile pscom_req_state_t *state = &request->state;

    while (!(*state & PSCOM_REQ_STATE_DONE)) { pscom_wait_any(); }
}


PSCOM_API_EXPORT
void pscom_wait_all(pscom_request_t **requests)
{
    while (*requests) {
        pscom_wait(*requests);
        requests++;
    }
}


PSCOM_API_EXPORT
int pscom_cancel_send(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    int res;
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_SEND_REQUEST);
    if (request->state & PSCOM_REQ_STATE_DONE) { return 0; }

    pscom_lock();
    {
        res = _pscom_cancel_send(req);
    }
    pscom_unlock();

    return res;
}


PSCOM_API_EXPORT
int pscom_cancel_recv(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    int res;
    D_TR(printf("%s:%u:%s()\n", __FILE__, __LINE__, __func__));
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_RECV_REQUEST);
    if (request->state & PSCOM_REQ_STATE_DONE) { return 0; }

    pscom_lock();
    {
        res = _pscom_cancel_recv(req);
    }
    pscom_unlock();

    return res;
}


PSCOM_API_EXPORT
int pscom_cancel(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    assert(req->magic == MAGIC_REQUEST);

    if (request->state & PSCOM_REQ_STATE_SEND_REQUEST) {
        return pscom_cancel_send(request);
    } else if (request->state & PSCOM_REQ_STATE_RECV_REQUEST) {
        return pscom_cancel_recv(request);
    }
    return 0;
}


/* RMA communication functions */

static pscom_req_t *pscom_get_rma_put_receiver(pscom_con_t *con,
                                               pscom_header_net_t *nh)
{
    pscom_req_t *req;
    pscom_xheader_rma_put_t *rma_header = &nh->xheader->rma_put;

    /* create request to receive RMA info in xheader */
    req            = pscom_req_create(nh->xheader_len, 0);
    req->pub.state = PSCOM_REQ_STATE_RMA_WRITE_REQUEST |
                     PSCOM_REQ_STATE_PASSIVE_SIDE;

    /* necessary information */
    req->pub.data        = rma_header->common.dest;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = nh->xheader_len;
    req->pub.ops.io_done = pscom_rma_put_recv_io_done;
    req->pub.connection  = &con->pub;

    D_TR(printf("%s:%u:%s() %s dest=%p, len=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.data, req->pub.data_len));

    return req;
}


static pscom_req_t *pscom_get_rma_accumulate_receiver(pscom_con_t *con,
                                                      pscom_header_net_t *nh)
{
    /* create request to receive RMA information in xheader and the data
     * temporarily */
    pscom_req_t *req = pscom_req_create(nh->xheader_len, nh->data_len);
    req->pub.state   = PSCOM_REQ_STATE_RMA_WRITE_REQUEST |
                     PSCOM_REQ_STATE_PASSIVE_SIDE;

    /* receive the data tempoararily into req->pub.user */
    req->pub.data        = (void *)req->pub.user;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = nh->xheader_len;
    req->pub.ops.io_done = pscom_rma_accumulate_recv_io_done;
    req->pub.connection  = &con->pub;

    D_TR(printf("%s:%u:%s() %s dest=%p, len=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.data, req->pub.data_len));
    return req;
}


static pscom_req_t *_pscom_get_rma_get_receiver(pscom_con_t *con,
                                                pscom_header_net_t *nh)
{
    pscom_req_t *req_answer =
        pscom_req_create(sizeof(pscom_xheader_rma_get_answer_t), 0);
    pscom_xheader_rma_get_t *rma_header = &nh->xheader->rma_get;

    req_answer->pub.xheader.rma_get_answer.id = rma_header->common.id;
    req_answer->pub.connection                = &con->pub;

    req_answer->pub.data_len = rma_header->common.src_len;
    req_answer->pub.data     = rma_header->common.src;

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));

    assert(req_answer->magic == MAGIC_REQUEST);
    pscom_mverify(req_answer);

    req_answer->pub.ops.io_done = pscom_request_free;

    _pscom_post_send_direct_inline(get_con(req_answer->pub.connection),
                                   req_answer, PSCOM_MSGTYPE_RMA_GET_REP);

    return NULL;
}


static pscom_req_t *_pscom_get_rma_get_answer_receiver(pscom_con_t *con,
                                                       pscom_header_net_t *nh)
{
    pscom_req_t *rma_read_req;

    assert(!list_empty(con->recvq_rma.next));

    rma_read_req    = nh->xheader->rma_get_answer.id;
    /* do not overwrite xheader in rma_read_req */
    nh->xheader_len = 0;

    if (!_pscom_recvq_rma_contains(con, rma_read_req)) {
        /* Received unknown rma_read_answer.id. Maybe this
         * rma request was already aborted.
         * Reject this message */
        return NULL; // reject
    }

    _pscom_recvq_rma_deq(con, rma_read_req);
    //_pscom_rma_req_deregister(con, rma_read_req);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(rma_read_req)));
    return rma_read_req;
}


static void _send_rma_get_acc_answer(pscom_req_t *req_answer, uint8_t msg_type)
{
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));
    assert(req_answer->magic == MAGIC_REQUEST);
    pscom_mverify(req_answer);

    _pscom_post_send_direct_inline(get_con(req_answer->pub.connection),
                                   req_answer, msg_type);
}

static pscom_req_t *_pscom_get_rma_get_acc_receiver(pscom_con_t *con,
                                                    pscom_header_net_t *nh)
{
    /* create request to receive RMA information in xheader and the data
     * temporarily */
    pscom_req_t *req = pscom_req_create(nh->xheader_len, nh->data_len);
    req->pub.state   = PSCOM_REQ_STATE_RMA_WRITE_REQUEST |
                     PSCOM_REQ_STATE_PASSIVE_SIDE;

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));

    /* recv data temporarily in req->pub.user */
    req->pub.data        = (void *)req->pub.user;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = nh->xheader_len;
    req->pub.ops.io_done = pscom_rma_get_accumulate_recv_io_done;
    req->pub.connection  = &con->pub;

    D_TR(printf("%s:%u:%s() %s dest=%p, len=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.data, req->pub.data_len));

    return req;
}


static pscom_req_t *
_pscom_get_rma_get_acc_answer_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
    pscom_req_t *rma_read_req;

    assert(!list_empty(con->recvq_rma.next));

    rma_read_req = nh->xheader->rma_get_answer.id;

    /* pointer to data buffer */
    rma_read_req->pub.data = rma_read_req->rma_result;
    /* do not overwrite xheader in rma_read_req */
    nh->xheader_len        = 0;

    if (!_pscom_recvq_rma_contains(con, rma_read_req)) {
        /* Received unknown rma_read_answer.id. Maybe this
         * rma request was already aborted.
         * Reject this message */
        return NULL; // reject
    }

    _pscom_recvq_rma_deq(con, rma_read_req);
    //_pscom_rma_req_deregister(con, rma_read_req);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(rma_read_req)));
    return rma_read_req;
}

static pscom_req_t *_pscom_get_rma_fetch_op_receiver(pscom_con_t *con,
                                                     pscom_header_net_t *nh)
{
    /* create request to receive RMA information in xheader and the data
     * temporarily */
    pscom_req_t *req = pscom_req_create(nh->xheader_len, nh->data_len);
    req->pub.state   = PSCOM_REQ_STATE_RMA_WRITE_REQUEST |
                     PSCOM_REQ_STATE_PASSIVE_SIDE;

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));

    /* recv data temporarily in req->pub.user */
    req->pub.data        = (void *)req->pub.user;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = nh->xheader_len;
    req->pub.ops.io_done = pscom_rma_fetch_op_recv_io_done;
    req->pub.connection  = &con->pub;

    D_TR(printf("%s:%u:%s() %s dest=%p, len=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.data, req->pub.data_len));

    return req;
}


static pscom_req_t *_pscom_get_rma_compare_swap_receiver(pscom_con_t *con,
                                                         pscom_header_net_t *nh)
{
    pscom_req_t *req = pscom_req_create(nh->xheader_len, nh->data_len);
    req->pub.state   = PSCOM_REQ_STATE_RMA_WRITE_REQUEST |
                     PSCOM_REQ_STATE_PASSIVE_SIDE;

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req_answer)));

    /* recv data temporarily in req->pub.user */
    req->pub.data        = (void *)req->pub.user;
    req->pub.data_len    = nh->data_len;
    req->pub.xheader_len = nh->xheader_len;
    req->pub.ops.io_done = pscom_rma_compare_swap_recv_io_done;
    req->pub.connection  = &con->pub;

    D_TR(printf("%s:%u:%s() %s dest=%p, len=%zu\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req), req->pub.data, req->pub.data_len));

    return req;
}

static pscom_req_t *_pscom_get_rma_compare_swap_answer_receiver(
    pscom_con_t *con, pscom_header_net_t *nh)
{
    pscom_req_t *rma_read_req;

    assert(!list_empty(con->recvq_rma.next));

    rma_read_req = nh->xheader->rma_get_answer.id;

    /* rma_read_answer.req is stored at the target side. if compare_addr ==
     * result, do rma_put operation with this req. */

    /* do not overwrite xheader in rma_read_req */
    nh->xheader_len = 0;

    if (!_pscom_recvq_rma_contains(con, rma_read_req)) {
        /* Received unknown rma_read_answer.id. Maybe this
         * rma request was already aborted.
         * Reject this message */
        return NULL; // reject
    }

    _pscom_recvq_rma_deq(con, rma_read_req);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(rma_read_req)));
    return rma_read_req;
}


/* callback function at the target side when RMA request is finished */
static void pscom_rma_put_recv_io_done(pscom_request_t *request)
{
    /* invoke global callback of RMA put at target side  */
    pscom_xheader_rma_put_t *xheader_rma = &request->xheader.rma_put;
    pscom_memh_t memh = (pscom_memh_t)xheader_rma->common.memh;
    assert(memh->magic == MAGIC_MEMH);
    pscom_rma_op_t rma_cb_id = PSCOM_RMA_PUT;
    if (memh->target_cbs[rma_cb_id]) { memh->target_cbs[rma_cb_id](request); }

    /* free request */
    pscom_req_free(get_req(request));
}


static void pscom_rma_get_accumulate_recv_io_done(pscom_request_t *request)
{
    pscom_xheader_rma_get_accumulate_t *xheader_rma =
        (pscom_xheader_rma_get_accumulate_t *)&request->xheader;
    /* create request to send data back to origin side */
    pscom_req_t *req_answer = pscom_req_create(
        sizeof(pscom_xheader_rma_get_answer_t), 0 /* sizeof(unsigned int *) */);

    req_answer->pub.xheader.rma_get_answer.id = xheader_rma->common.id;
    req_answer->pub.connection                = request->connection;

    req_answer->pub.data_len    = xheader_rma->common.src_len;
    req_answer->pub.xheader_len = sizeof(pscom_xheader_rma_get_answer_t);


    /* size should be optimized, now it is set as 64 */
    if (xheader_rma->common.src_len < pscom.env.rma_get_acc_direct_mem_copy) {
        /* data size < 64b direct mem copy */
        req_answer->pub.data = malloc(xheader_rma->common.src_len);
        memcpy(req_answer->pub.data, xheader_rma->common.src,
               xheader_rma->common.src_len);
        req_answer->pub.ops.io_done = pscom_rma_request_free_send_buffer;
        _send_rma_get_acc_answer(req_answer,
                                 PSCOM_MSGTYPE_RMA_GET_ACCUMULATE_REP);
    } else {
        /* data size >= 64b wait for send request */
        req_answer->pub.data        = xheader_rma->common.src;
        req_answer->pub.ops.io_done = pscom_request_free;
        _send_rma_get_acc_answer(req_answer,
                                 PSCOM_MSGTYPE_RMA_GET_ACCUMULATE_REP);
        while (!(req_answer->pub.state & PSCOM_REQ_STATE_IO_DONE)) {
            _pscom_wait_any();
        }
    }

    /* target callback function to do MPI_OP */
    /* todo: not thread safe, perhaps lock is needed */
    pscom_memh_t memh = (pscom_memh_t)xheader_rma->common.memh;
    assert(memh->magic == MAGIC_MEMH);
    pscom_rma_op_t rma_cb_id = PSCOM_RMA_GET_ACCUMULATE;
    if (memh->target_cbs[rma_cb_id]) { memh->target_cbs[rma_cb_id](request); }

    pscom_req_free(get_req(request));
}

static void pscom_rma_fetch_op_recv_io_done(pscom_request_t *request)
{
    pscom_xheader_rma_fetch_op_t *xheader_rma =
        (pscom_xheader_rma_fetch_op_t *)&request->xheader;
    // send data back to origin side
    pscom_req_t *req_answer = pscom_req_create(
        sizeof(pscom_xheader_rma_get_answer_t), 0 /* sizeof(unsigned int *) */);

    req_answer->pub.xheader.rma_get_answer.id = xheader_rma->common.id;
    req_answer->pub.connection                = request->connection;

    req_answer->pub.data_len = xheader_rma->common.src_len;

    req_answer->pub.xheader_len = sizeof(pscom_xheader_rma_get_answer_t);
    req_answer->pub.ops.io_done = pscom_rma_request_free_send_buffer;

    /* direct memory copy and send data back*/
    req_answer->pub.data = malloc(xheader_rma->common.src_len);
    memcpy(req_answer->pub.data, xheader_rma->common.src,
           xheader_rma->common.src_len);
    _send_rma_get_acc_answer(req_answer, PSCOM_MSGTYPE_RMA_FETCH_AND_OP_REP);

    /* target callback function to do MPI_OP */
    /* todo: not thread safe, perhaps lock is needed */
    request->header.msg_type = PSCOM_MSGTYPE_RMA_FETCH_AND_OP_REP;
    pscom_memh_t memh        = (pscom_memh_t)xheader_rma->common.memh;
    assert(memh->magic == MAGIC_MEMH);
    pscom_rma_op_t rma_cb_id = PSCOM_RMA_FETCH_AND_OP;
    if (memh->target_cbs[rma_cb_id]) { memh->target_cbs[rma_cb_id](request); }

    pscom_req_free(get_req(request));
}

/* compare two buffer, used in RMA compare and swap */
/* todo replace it with lib function */
static int pscom_rma_compare_buffer(char *buffer1, char *buffer2,
                                    uint64_t length)
{
    if (!memcmp(buffer1, buffer2, length)) {
        return 1;
    } else {
        return 0;
    }
}

static void pscom_rma_compare_swap_recv_io_done(pscom_request_t *request)
{
    pscom_xheader_rma_compare_swap_t *xheader_rma =
        (pscom_xheader_rma_compare_swap_t *)&request->xheader;

    /* create request and send data back to origin side */
    pscom_req_t *req_answer =
        pscom_req_create(sizeof(pscom_xheader_rma_get_answer_t), 0);

    req_answer->pub.xheader.rma_get_answer.id  = xheader_rma->common.id;
    req_answer->pub.xheader.rma_get_answer.req = NULL;
    req_answer->pub.connection                 = request->connection;
    req_answer->pub.data_len                   = xheader_rma->common.src_len;
    req_answer->pub.xheader_len = sizeof(pscom_xheader_rma_get_answer_t);

    /* do we copy and send or wait for send
    // direct memory copy to send buffer
    req_answer->pub.data = malloc(xheader_rma->common.src_len);
    memcpy(req_answer->pub.data, xheader_rma->common.src,
    xheader_rma->common.src_len); req_answer->pub.ops.io_done =
    pscom_rma_request_free_send_buffer; _send_rma_get_acc_answer(req_answer,
    PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REP);
    */
    /* send the target buffer back to origin */
    req_answer->pub.data        = xheader_rma->common.src;
    req_answer->pub.ops.io_done = pscom_request_free;
    _send_rma_get_acc_answer(req_answer, PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REP);
    /* wait till the send (to orgin side) is finished */
    while (!(req_answer->pub.state & PSCOM_REQ_STATE_IO_DONE)) {
        _pscom_wait_any();
    }

    /* compare the target buffer and compare buffer */
    size_t data_len = xheader_rma->common.src_len; /* 2 buffers are received */
    if (pscom_rma_compare_buffer((char *)xheader_rma->common.src,
                                 (char *)request->data, data_len)) {
        /* the first part of request->data is compare buffer, the second part of
         * request->data is origin buffer */
        /* if equal, copy the data from origin buffer to target buffer, if not,
         * do nothing, free buffer later*/
        memcpy(xheader_rma->common.src, (char *)request->data + data_len,
               data_len);
    }

    /* target callback function to do MPI_OP */
    /* todo: not thread safe, perhaps lock is needed */
    request->header.msg_type = PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REP;
    pscom_memh_t memh        = (pscom_memh_t)xheader_rma->common.memh;
    assert(memh->magic == MAGIC_MEMH);
    pscom_rma_op_t rma_cb_id = PSCOM_RMA_COMPARE_AND_SWAP;
    if (memh->target_cbs[rma_cb_id]) { memh->target_cbs[rma_cb_id](request); }

    pscom_req_free(get_req(request));
}

static void pscom_rma_accumulate_recv_io_done(pscom_request_t *request)
{
    /* target callback function to do MPI_OP */
    pscom_xheader_rma_accumulate_t *xheader_rma =
        &request->xheader.rma_accumulate;
    pscom_memh_t memh = (pscom_memh_t)xheader_rma->common.memh;
    assert(memh->magic == MAGIC_MEMH);
    pscom_rma_op_t rma_cb_id = PSCOM_RMA_ACCUMULATE;
    if (memh->target_cbs[rma_cb_id]) { memh->target_cbs[rma_cb_id](request); }

    pscom_req_free(get_req(request));
}

void pscom_rma_request_free_send_buffer(pscom_request_t *request)
{
    /* free the space allocated for sending */
    free(request->data);
    pscom_req_free(get_req(request));
}
