/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_queues.h"

#include <assert.h>
#include <stddef.h>
#include <sys/uio.h>

#include "list.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_io.h"
#include "pscom_priv.h"

static inline int req_recv_user_accept(pscom_req_t *req,
                                       pscom_connection_t *connection,
                                       pscom_header_net_t *header)
{
    int (*recv_accept)(pscom_request_t *request, pscom_connection_t *connection,
                       pscom_header_net_t *header_net);

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    recv_accept = req->pub.ops.recv_accept;

    return !recv_accept || recv_accept(&req->pub, connection, header);
}


static inline int req_recv_ctrl_accept(pscom_req_t *req,
                                       pscom_connection_t *connection,
                                       pscom_header_net_t *header)
{
    int (*recv_accept)(pscom_request_t *request, pscom_connection_t *connection,
                       pscom_header_net_t *header_net);
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    if (req->pub.header.msg_type != header->msg_type) { return 0; }

    recv_accept = req->pub.ops.recv_accept;

    return !recv_accept || recv_accept(&req->pub, connection, header);
}


/*************
 * Sendq
 */


void _pscom_sendq_enq(pscom_con_t *con, pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    req->pub.state = PSCOM_REQ_STATE_SEND_REQUEST | PSCOM_REQ_STATE_POSTED;

    list_add_tail(&req->next, &con->sendq);

    con->write_start(con);
}


void _pscom_sendq_deq(pscom_con_t *con, pscom_req_t *req)
{
    assert(!(req->cur_header.iov_len + req->cur_data.iov_len) || /* io done or
                                                                  */
           !(req->pub.state & PSCOM_REQ_STATE_IO_STARTED)); /* io not started */

    list_del(&req->next); // dequeue

    pscom_con_check_write_stop(con);
}

void _pscom_sendq_steal(pscom_con_t *con, pscom_req_t *req)
{
    list_del(&req->next); // dequeue
}


/*************
 * Pending io queue
 */

static void _pscom_pendingio_enq(pscom_con_t *con, pscom_req_t *req)
{
    if (pscom.env.debug_req) { return; }
    /* all_req_next is shared with announce_new_req and announce_free_req! */

    list_add_tail(&req->all_req_next, &pscom.requests);
}


static void _pscom_pendingio_deq(pscom_con_t *con, pscom_req_t *req)
{
    if (pscom.env.debug_req) { return; }
    /* all_req_next is shared with announce_new_req and announce_free_req! */

    list_del_init(&req->all_req_next); // dequeue
}


void _pscom_pendingio_abort(pscom_con_t *con, pscom_req_t *req)
{
    assert(req->magic == MAGIC_REQUEST);

    if (!req->pending_io) {
        return; // nothing to abort.
    }

    // ToDo: Somehow abort RDMA requests?

    req->pub.state |= PSCOM_REQ_STATE_ERROR;

    /* pscom_read_pending_done() or pscom_write_pending_done()
       will call _pscom_send_req_done() or _pscom_recv_req_done(req)
       after the pending io is done. */
}


void _pscom_read_pendingio_cnt_inc(pscom_con_t *con, pscom_req_t *req)
{
    if (!req->pending_io++) {
        _pscom_pendingio_enq(con, req);

        /*
         * Keep reading on the connection for send and receive
         * requests with pending io. Don't count for generated
         * requests.
         * -> increase the recv requests counter
         */
        if (!(req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST)) {
            _pscom_recv_req_cnt_inc(con);
        }
    }
}


/* return 1, if cnt dropped to 0. */
int _pscom_read_pendingio_cnt_dec(pscom_con_t *con, pscom_req_t *req)
{
    int done = !(--req->pending_io);
    if (done) {
        /*
         * Decrease the recv requests counter.
         * cf. _pscom_pendingio_cnt_inc()
         */
        if (!(req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST)) {
            _pscom_recv_req_cnt_dec(con);
        }

        _pscom_pendingio_deq(con, req);
    }
    return done;
}


void _pscom_write_pendingio_cnt_inc(pscom_con_t *con, pscom_req_t *req)
{
    if (!req->pending_io++) {
        _pscom_pendingio_enq(con, req);

        /* keep writing on the connection */
        int start = !con->write_pending_io_cnt++;

        /* only start writing if there is no pending I/O */
        if (start) { pscom_con_check_write_start(con); }
    }
}


/* return 1, if cnt dropped to 0. */
int _pscom_write_pendingio_cnt_dec(pscom_con_t *con, pscom_req_t *req)
{
    int done = !(--req->pending_io);
    if (done) {
        con->write_pending_io_cnt--;
        _pscom_pendingio_deq(con, req);

        pscom_con_check_write_stop(con);
    }
    return done;
}
/*************
 * Sendq for suspending connections
 */

void _pscom_sendq_suspending_enq(pscom_con_t *con, pscom_req_t *req)
{
    pscom_sock_t *sock = get_sock(con->pub.socket);
    list_add_tail(&req->next, &sock->sendq_suspending);
}


void _pscom_sendq_suspending_deq(pscom_con_t *con, pscom_req_t *req)
{
    list_del(&req->next); // dequeue
}


/*************
 * Receive requests
 */

PSCOM_PLUGIN_API_EXPORT
void _pscom_recv_req_cnt_inc(pscom_con_t *con)
{
    int start = !con->recv_req_cnt;

    con->recv_req_cnt++;

    if (start) {
        /* First increment, than call read_start(con)!
           read_start(con) could recursive call _pscom_recv_req_cnt_inc() */
        con->read_start(con);
    }
}


PSCOM_PLUGIN_API_EXPORT
void _pscom_recv_req_cnt_dec(pscom_con_t *con)
{
    con->recv_req_cnt--;
}


void _pscom_recv_req_cnt_any_inc(pscom_sock_t *sock)
{
    struct list_head *pos;

    if (!sock->recv_req_cnt_any++) {
        // BUG(?): && !pscom.env.unexpected_receives) {
        // --> It at least may prevent the 'read_start' calls on the connections
        //     in the case on an RMA-related ANY_SOURCE dummy request if
        //     PSP_UNEXPECTED_RECEIVES=1 is set.

        /* Loop only the first time and if not unexpected_receives is enabled */

        list_for_each (pos, &sock->connections) {
            pscom_con_t *con = list_entry(pos, pscom_con_t, next);
            _pscom_recv_req_cnt_inc(con);
        }
    }
}

void _pscom_recv_req_cnt_any_global_inc()
{
    struct list_head *pos_con;
    struct list_head *pos_sock;

    if (!pscom.recv_req_cnt_any_global++) {

        list_for_each (pos_sock, &pscom.sockets) {
            pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

            list_for_each (pos_con, &sock->connections) {
                pscom_con_t *con = list_entry(pos_con, pscom_con_t, next);
                _pscom_recv_req_cnt_inc(con);
            }
        }
    }
}


void _pscom_recv_req_cnt_any_dec(pscom_sock_t *sock)
{
    struct list_head *pos;

    if (!--sock->recv_req_cnt_any && !pscom.env.unexpected_receives) {
        /* Loop only if recv_req_cnt_any is back zero and if
           not unexpected_receives is enabled */

        list_for_each (pos, &sock->connections) {
            pscom_con_t *con = list_entry(pos, pscom_con_t, next);
            _pscom_recv_req_cnt_dec(con);
        }
    }
}

void _pscom_recv_req_cnt_any_global_dec()
{
    struct list_head *pos_con;
    struct list_head *pos_sock;

    if (!--pscom.recv_req_cnt_any_global) {
        /* Loop only if recv_req_cnt_any_global is back zero */

        list_for_each (pos_sock, &pscom.sockets) {
            pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

            list_for_each (pos_con, &sock->connections) {
                pscom_con_t *con = list_entry(pos_con, pscom_con_t, next);
                _pscom_recv_req_cnt_dec(con);
            }
        }
    }
}


/*************
 * Recvq user
 */


static void _pscom_recvq_user_enq_con(pscom_con_t *con, pscom_req_t *req)
{
    list_add_tail(&req->next, &con->recvq_user);
    _pscom_recv_req_cnt_inc(con);
}


static void _pscom_recvq_user_reenq_con(pscom_con_t *con, pscom_req_t *req)
{
    list_del(&req->next); // probably from sock->recvq_any
    list_add_tail(&req->next, &con->recvq_user); // to con->recvq_user
                                                 /* No need for:
                                                    _pscom_recv_req_cnt_dec(con);
                                                    _pscom_recv_req_cnt_inc(con);
                                                 */
}


static void _pscom_recvq_user_deq_con(pscom_con_t *con, pscom_req_t *req)
{
    // req in sock->recvq_any or con->recvq_user
    list_del(&req->next);
    _pscom_recv_req_cnt_dec(get_con(req->pub.connection));
}


static void _pscom_recvq_user_enq_any(pscom_sock_t *sock, pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s req:%s add to sock->recvq_any:%p\n", __FILE__,
                __LINE__, __func__, pscom_debug_req_str(req), &sock->recvq_any));

    list_add_tail(&req->next, &sock->recvq_any);
    pscom.stat.recvq_any++;

    if (req->pub.connection) {
        _pscom_recv_req_cnt_inc(get_con(req->pub.connection));
    } else {
        _pscom_recv_req_cnt_any_inc(sock);
        pscom.stat.reqs_any_source++;
    }
}

static void _pscom_recvq_user_enq_any_global(pscom_req_t *req)
{
    list_add_tail(&req->next, &pscom.recvq_any_global);
    pscom.stat.recvq_any++;

    if (req->pub.connection) {
        _pscom_recv_req_cnt_inc(get_con(req->pub.connection));
    } else {
        _pscom_recv_req_cnt_any_global_inc();
        pscom.stat.reqs_any_source++;
    }
}


static void _pscom_recvq_user_deq_any(pscom_sock_t *sock, pscom_req_t *req)
{
    // req in sock->recvq_any
    list_del(&req->next);
    _pscom_recv_req_cnt_any_dec(sock);
}

static void _pscom_recvq_user_deq_any_global(pscom_req_t *req)
{
    // req in pscom.recvq_any_global
    list_del(&req->next);
    _pscom_recv_req_cnt_any_global_dec();
}


static void _pscom_recvq_terminate_any_global()
{
    while (!list_empty(&pscom.recvq_any_global)) {
        pscom_req_t *req = list_entry(pscom.recvq_any_global.next, pscom_req_t,
                                      next);

        list_del(&req->next);
        req->pub.state |= PSCOM_REQ_STATE_ERROR;
        _pscom_recv_req_done(req); // done
    }
}

void pscom_recvq_terminate_any_global()
{
    pscom_lock();
    {
        _pscom_recvq_terminate_any_global();
    }
    pscom_unlock();
}

void _pscom_recvq_user_enq(pscom_req_t *req)
{
    /* Please note that, if the upper psmpi layer passes a request with a socket
       attached (req->pub.connection != NULL), this request belongs to an
       MPI_COMM_WORLD-derived communicator, whereas in the other case, the
       communicator is one that covers processes from multiple MPI_COMM_WORLDs.
    */

    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    /* If no connection is given, then this is an any-source request that has to
       be enqueued either in the socket-related any-source queue (if a
       respective socket is given) or in the global any-source queue (when no
       socket is given).
    */
    if (!req->pub.connection) {
        if (req->pub.socket) {
            _pscom_recvq_user_enq_any(get_sock(req->pub.socket), req);
            return;
        } else {
            _pscom_recvq_user_enq_any_global(req);
            return;
        }
    }

    /* In the case that a connection is given, it has to be checked (for the
       sake of message ordering) whether there are already pending any-source
       requests, either within the socket-related queue (for
       MPI_COMM_WORLD-derived communicators) or within the global queue (for
       communicators covering multiple MPI_COMM_WORLDs). If there are such
       pending any-source requests, then enqueue the given request in the
       appropriate one of those queues instead of the connection-related queue.
    */
    if (req->pub.socket) {
        if (!list_empty(&get_sock(req->pub.socket)->recvq_any)) {
            _pscom_recvq_user_enq_any(get_sock(req->pub.socket), req);
            return;
        }
    } else {
        req->pub.socket = req->pub.connection->socket;
        if (!list_empty(&pscom.recvq_any_global)) {
            _pscom_recvq_user_enq_any_global(req);
            return;
        }
    }

    /* Finally, the default case remains, where the request goes into the
     * connection's queue. */
    _pscom_recvq_user_enq_con(get_con(req->pub.connection), req);
}


void _pscom_recvq_user_deq(pscom_req_t *req)
{
    if (req->pub.connection) {
        _pscom_recvq_user_deq_con(get_con(req->pub.connection), req);
    } else {
        if (req->pub.socket) {
            _pscom_recvq_user_deq_any(get_sock(req->pub.socket), req);
        } else {
            _pscom_recvq_user_deq_any_global(req);
        }
    }
}


pscom_req_t *_pscom_recvq_user_find_and_deq(pscom_con_t *con,
                                            pscom_header_net_t *header)
{
    struct list_head *pos;
    pscom_sock_t *sock;

    list_for_each (pos, &con->recvq_user) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, next);

        if (req_recv_user_accept(req, &con->pub, header)) {
            _pscom_recvq_user_deq_con(con, req);
            return req;
        }
    }

    sock = get_sock(con->pub.socket);

    list_for_each (pos, &sock->recvq_any) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, next);
        if (((!req->pub.connection) || (req->pub.connection == &con->pub)) &&
            req_recv_user_accept(req, &con->pub, header)) {
            _pscom_recvq_user_deq(req); // con or any request
            _pscom_recvq_any_cleanup(&sock->recvq_any);
            return req;
        }
    }

    /* check for ANY_SOURCE requests pending in global queue: */
    if (pscom.recv_req_cnt_any_global) {

        list_for_each (pos, &pscom.recvq_any_global) {
            pscom_req_t *req = list_entry(pos, pscom_req_t, next);
            if (((!req->pub.connection) || (req->pub.connection == &con->pub)) &&
                req_recv_user_accept(req, &con->pub, header)) {
                _pscom_recvq_user_deq(req); // con or any request
                _pscom_recvq_any_cleanup(&pscom.recvq_any_global);
                return req;
            }
        }
    }
    return NULL;
}


// for debug:
int _pscom_recvq_user_is_inside(pscom_req_t *req)
{
    struct list_head *pos;
    pscom_sock_t *sock;

    if (req->pub.connection) { // if req is not an ANY_SOURCE receive:
        pscom_con_t *con = get_con(req->pub.connection);

        assert(con->magic == MAGIC_CONNECTION);

        list_for_each (pos, &con->recvq_user) {
            pscom_req_t *qreq = list_entry(pos, pscom_req_t, next);

            if (qreq == req) { return 1; }
        }
    }

    if (req->pub.socket) {
        sock = get_sock(req->pub.socket);

        assert(sock->magic == MAGIC_SOCKET);

        list_for_each (pos, &sock->recvq_any) {
            pscom_req_t *qreq = list_entry(pos, pscom_req_t, next);
            if (qreq == req) { return 1; }
        }
    }

    list_for_each (pos, &pscom.recvq_any_global) {
        pscom_req_t *qreq = list_entry(pos, pscom_req_t, next);
        if (qreq == req) { return 1; }
    }

    return 0;
}


void _pscom_recvq_any_cleanup(struct list_head *recvq_any)
{
    struct list_head *pos, *next;

    list_for_each_safe (pos, next, recvq_any) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, next);
        if (req->pub.connection) {
            /* Move request from any queue to con queue */
            pscom_con_t *con = get_con(req->pub.connection);
            _pscom_recvq_user_reenq_con(con, req);
        } else {
            break;
        }
    }
}

/*************
 * Recvq ctrl
 */

void _pscom_recvq_ctrl_enq(pscom_con_t *con, pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s req:%s add to con(%p)->recvq_ctrl\n", __FILE__,
                __LINE__, __func__, pscom_debug_req_str(req), con));
    req->pub.connection = &con->pub;
    req->pub.socket     = con->pub.socket;

    list_add_tail(&req->next, &con->recvq_ctrl);
    _pscom_recv_req_cnt_inc(con);
}


void _pscom_recvq_ctrl_deq(pscom_con_t *con, pscom_req_t *req)
{
    list_del(&req->next);
    _pscom_recv_req_cnt_dec(con);
}


pscom_req_t *_pscom_recvq_ctrl_find_and_deq(pscom_con_t *con,
                                            pscom_header_net_t *header)
{
    struct list_head *pos;

    list_for_each (pos, &con->recvq_ctrl) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, next);

        if (req_recv_ctrl_accept(req, &con->pub, header)) {
            _pscom_recvq_ctrl_deq(con, req);
            return req;
        }
    }

    return NULL;
}


/*************
 * Net recvq user (network generated requests)
 */


static inline pscom_req_t *_pscom_net_recvq_user_find_from_con(pscom_con_t *con,
                                                               pscom_req_t *req)
{
    struct list_head *pos;

    D_TR(printf("%s:%u:%s(con:%p, %s)\n", __FILE__, __LINE__, __func__, con,
                pscom_debug_req_str(req)));

    list_for_each (pos, &con->net_recvq_user) {
        pscom_req_t *genreq = list_entry(pos, pscom_req_t, next);

        if (req_recv_user_accept(req, genreq->pub.connection,
                                 &genreq->pub.header)) {
            return genreq;
        }
    }
    return NULL;
}


static inline pscom_req_t *
_pscom_net_recvq_user_find_from_any(pscom_sock_t *sock, pscom_req_t *req)
{
    struct list_head *pos;
    D_TR(printf("%s:%u:%s(sock:%p, %s)\n", __FILE__, __LINE__, __func__, sock,
                pscom_debug_req_str(req)));

    list_for_each (pos, &sock->genrecvq_any) {
        pscom_req_t *genreq = list_entry(pos, pscom_req_t, next_alt);

        if (req_recv_user_accept(req, genreq->pub.connection,
                                 &genreq->pub.header)) {
            return genreq;
        }
    }
    return NULL;
}

static inline pscom_req_t *
_pscom_net_recvq_user_find_from_any_global(pscom_req_t *req)
{
    struct list_head *pos_req;
    struct list_head *pos_sock;

    /* loop over all sockets: */
    list_for_each (pos_sock, &pscom.sockets) {
        pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

        list_for_each (pos_req, &sock->genrecvq_any) {
            pscom_req_t *genreq = list_entry(pos_req, pscom_req_t, next_alt);

            if (req_recv_user_accept(req, genreq->pub.connection,
                                     &genreq->pub.header)) {
                return genreq;
            }
        }
    }
    return NULL;
}


void _pscom_net_recvq_user_enq(pscom_con_t *con, pscom_req_t *req)
{
    pscom_sock_t *sock = get_sock(con->pub.socket);

    D_TR(printf("%s:%u:%s req:%s add to con(%p)->net_recvq_user and "
                "sock->genrecvq_any\n",
                __FILE__, __LINE__, __func__, pscom_debug_req_str(req), con));

    list_add_tail(&req->next, &con->net_recvq_user);
    list_add_tail(&req->next_alt, &sock->genrecvq_any);
}


void _pscom_net_recvq_user_deq(pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s req:%s del req->next and req->next_alt\n", __FILE__,
                __LINE__, __func__, pscom_debug_req_str(req)));

    list_del(&req->next);
    list_del(&req->next_alt);
}


/* find net generated user request. */
pscom_req_t *_pscom_net_recvq_user_find(pscom_req_t *req)
{
    if (req->pub.connection) {
        return _pscom_net_recvq_user_find_from_con(get_con(req->pub.connection),
                                                   req);
    } else {
        // receive "any"
        if (req->pub.socket) {
            return _pscom_net_recvq_user_find_from_any(get_sock(req->pub.socket),
                                                       req);
        } else {
            return _pscom_net_recvq_user_find_from_any_global(req);
        }
    }
}


/*************
 * Net recvq ctrl (network generated requests)
 */


/* enqueue a network generated ctrl request */
void _pscom_net_recvq_ctrl_enq(pscom_con_t *con, pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s req:%s add to con(%p)->net_recvq_ctrl\n", __FILE__,
                __LINE__, __func__, pscom_debug_req_str(req), con));
    list_add_tail(&req->next, &con->net_recvq_ctrl);
}


void _pscom_net_recvq_ctrl_deq(pscom_req_t *req)
{
    list_del(&req->next);
}


/* find req matching net generated ctrl request. */
pscom_req_t *_pscom_net_recvq_ctrl_find(pscom_req_t *req)
{
    struct list_head *pos;

    pscom_con_t *con = get_con(req->pub.connection);

    D_TR(printf("%s:%u:%s(con:%p, %s)\n", __FILE__, __LINE__, __func__, con,
                pscom_debug_req_str(req)));

    list_for_each (pos, &con->net_recvq_ctrl) {
        pscom_req_t *genreq = list_entry(pos, pscom_req_t, next);

        if (req_recv_ctrl_accept(req, genreq->pub.connection,
                                 &genreq->pub.header)) {
            return genreq;
        }
    }
    return NULL;
}


/*************
 * Recvq RMA
 */


void _pscom_recvq_rma_enq(pscom_con_t *con, pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s req:%s add to con(%p)->recvq_rma\n", __FILE__,
                __LINE__, __func__, pscom_debug_req_str(req), con));
    list_add_tail(&req->next, &con->recvq_rma);
    _pscom_recv_req_cnt_inc(con);
}


void _pscom_recvq_rma_deq(pscom_con_t *con, pscom_req_t *req)
{
    list_del(&req->next);
    _pscom_recv_req_cnt_dec(con);
}


int _pscom_recvq_rma_contains(pscom_con_t *con, pscom_req_t *req_needle)
{
    struct list_head *pos;
    list_for_each (pos, &con->recvq_rma) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, next);
        if (req == req_needle) { return 1; }
    }
    return 0;
}


int _pscom_recvq_rma_empty(pscom_con_t *con)
{
    return list_empty(&con->recvq_rma);
}


pscom_req_t *_pscom_recvq_rma_head(pscom_con_t *con)
{
    return list_entry(con->recvq_rma.next, pscom_req_t, next);
}


/*************
 * Recvq bcast
 */


// void _pscom_recvq_bcast_deq(pscom_req_t *req)
//{
//	// ToDo:
//	// list_del(&req->next); // dequeue
// }
