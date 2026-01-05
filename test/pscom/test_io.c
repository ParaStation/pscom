/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>

#include <sys/uio.h>

#include "list.h"
#include "pscom.h"
#include "pscom_con.h"
#include "pscom_env.h"
#include "pscom_priv.h"
#include "pscom_queues.h"
#include "pscom_req.h"

#include "test_io.h"
#include "util/test_utils_con.h"

/* we need to access some static functions */
#include "pscom_io.c"
#include "pscom_sock.c"

////////////////////////////////////////////////////////////////////////////////
/// Helper for keeping track of the connection state
////////////////////////////////////////////////////////////////////////////////

typedef enum {
    TESTCON_STATE_CLOSED = 0,
    TESTCON_STATE_OPENED
} connection_state_t;
typedef enum {
    TESTCON_OP_NOP = 0,
    TESTCON_OP_STOP_RW,
    TESTCON_OP_START_RW
} connection_action_t;

connection_state_t transition_table[2][3] = {
    {TESTCON_STATE_CLOSED, TESTCON_STATE_CLOSED, TESTCON_STATE_OPENED},
    {TESTCON_STATE_OPENED, TESTCON_STATE_CLOSED, TESTCON_STATE_OPENED}};


static int connection_state(connection_action_t action)
{
    static connection_state_t connection_state = TESTCON_STATE_CLOSED;
    connection_state_t old_state               = connection_state;

    connection_state = transition_table[connection_state][action];

    return old_state;
}


static void check_rw_start_called(pscom_con_t *con)
{
    function_called();
    check_expected(con);

    connection_state(TESTCON_OP_START_RW);
}


static void check_rw_stop_called(pscom_con_t *con)
{
    function_called();
    check_expected(con);

    connection_state(TESTCON_OP_STOP_RW);
}

static void init_gen_req(pscom_connection_t *connection, pscom_req_t *gen_req)
{
    gen_req->pub.connection    = connection;
    gen_req->cur_data.iov_base = NULL;
    gen_req->partner_req       = NULL;
    pscom_header_net_prepare(&gen_req->pub.header, PSCOM_MSGTYPE_USER, 0, 0);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_post_recv()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_post_recv() for partially received message
 *
 * Given: A partially received message in a generated request
 * When: pscom_post_recv() is called
 * Then: the request should be merged properly and the connection should be
 *       open for reading.
 */
void test_post_recv_partial_genreq(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create generated requests and enqueue to the list of net requests */
    pscom_req_t *gen_req = pscom_req_create(0, 100);
    init_gen_req(&recv_con->pub, gen_req);
    _pscom_net_recvq_user_enq(recv_con, gen_req);

    /* set the read_start()/read_stop() functions */
    recv_con->read_start = &check_rw_start_called;
    recv_con->read_stop  = &check_rw_stop_called;

    /*
     * set the appropriate request state:
     * -> generated requests
     * -> IO has been started
     */
    gen_req->pub.state = PSCOM_REQ_STATE_GRECV_REQUEST;
    gen_req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;

    /* the request shall be the current request of the connection */
    recv_con->in.req = gen_req;

    /* create the receive request */
    pscom_request_t *recv_req = pscom_request_create(0, 100);
    recv_req->connection      = &recv_con->pub;

    /* read_start() should be called at least once */
    expect_function_call_any(check_rw_start_called);
    expect_value(check_rw_start_called, con, recv_con);

    /* post the actual receive request */
    pscom_post_recv(recv_req);

    /*
     * read_start() should be called lastly
     * TODO: check connection state, once this is available within the pscom
     */
    assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_OPENED);
}

/**
 * \brief Test pscom_post_recv() for generated requests
 *
 * Given: A generated request
 * When: pscom_post_recv() is called
 * Then: the matching user request should not be identified as a generated
 *       request
 */
void test_post_recv_genreq_state(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create generated requests and enqueue to the list of net requests */
    pscom_header_net_t nh = {
        .xheader_len = 0,
        .data_len    = 0,
    };
    pscom_req_t *gen_req = _pscom_generate_recv_req(NULL, &nh);
    init_gen_req(&recv_con->pub, gen_req);
    _pscom_net_recvq_user_enq(recv_con, gen_req);

    /*
     * set the appropriate request state:
     * -> generated requests
     * -> IO has been started
     */

    /* create the receive request *not* being a generated request */
    pscom_request_t *recv_req = pscom_request_create(0, 100);
    recv_req->state &= ~PSCOM_REQ_STATE_GRECV_REQUEST;
    recv_req->connection = &recv_con->pub;

    /* post the actual receive request */
    pscom_post_recv(recv_req);

    /* the recv request should *not* be marked as a generated request */
    assert_false(recv_req->state & PSCOM_REQ_STATE_GRECV_REQUEST);
}

/**
 * \brief Test pscom_post_recv() with a regular recv request with a given
 * connection
 *
 * Given: A public recv request handle with an associated connection but without
 * a socket When: pscom_post_recv() is called with this request Then: the
 * request is enqueued on the recvq_user of the connection
 */
void test_post_recv_on_con(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* assume that all queues are empty */
    assert_true(list_empty(&recv_con->recvq_user));
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = NULL;

    pscom_post_recv(recv_req);

    /* assume that the request is now enqueued on the recvq_user of the
     * connection */
    assert_int_equal(list_count(&recv_con->recvq_user), 1);
    assert_ptr_equal(list_entry(recv_con->recvq_user.next, pscom_req_t, next),
                     get_req(recv_req));

    /* assume that the request's socket has been set properly */
    assert_ptr_equal(recv_req->socket, recv_con->pub.socket);

    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);
}

/**
 * \brief Test pscom_post_recv() with an any-source recv request with a given
 * socket
 *
 * Given: A public recv request handle with an associated socket but without a
 * connection When: pscom_post_recv() is called with this any-source request
 * Then: the any-source request is enqueued on the recvq_any queue of the socket
 */
void test_post_any_recv_on_sock(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* assume that all queues are empty */
    assert_true(list_empty(&recv_con->recvq_user));
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post an any recv request on the socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = recv_con->pub.socket;

    pscom_post_recv(recv_any_req);

    /* assume that the request as been enqueued to the socket and that the
       global any-source queue is still empty */
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 1);
    assert_true(list_empty(&pscom.recvq_any_global));

    recv_any_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req);
}

/**
 * \brief Test pscom_post_recv() with an any-source recv request without a
 * socket
 *
 * Given: A public recv request handle with no socket and no connection given
 * When: pscom_post_recv() is called with this any-source request
 * Then: the any-source request is enqueued on the recvq_any_global queue
 */
void test_post_any_recv_on_global_queue(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* assume that all queues are empty */
    assert_true(list_empty(&recv_con->recvq_user));
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post an any recv request without a given socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = NULL;

    pscom_post_recv(recv_any_req);

    /* assume that the request as been enqueued to the global any-source queue
       and that the socket's any-source queue is still empty */
    assert_int_equal(list_count(&pscom.recvq_any_global), 1);
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    recv_any_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req);
}

/**
 * \brief Test pscom_post_recv() with a regular recv request after an any-source
 * request
 *
 * Given: An any-source request is enqueued on the recvq_any queue of a socket
 * When: pscom_post_recv() is called with a subsequent regular receive request
 * Then: both requests are enqueued on the recvq_any of the socket
 */
void test_post_recv_on_con_after_any_recv_on_sock(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* assume that all queues are empty */
    assert_true(list_empty(&recv_con->recvq_user));
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post an any recv request on the socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = recv_con->pub.socket; /* <- communicator is
                                                             socket-local */

    pscom_post_recv(recv_any_req);

    /* assume that the request as been enqueued to the socket and that the
       global any-source queue is still empty */
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 1);
    assert_true(list_empty(&pscom.recvq_any_global));

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket = recv_con->pub.socket; /* <- communicator is socket-local
                                              */

    pscom_post_recv(recv_req);

    /* assume that both requests are now enqueued on the recvq_any of the socket
     */
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 2);
    assert_true(list_empty(&recv_con->recvq_user));

    /* assume that the global any-source queue is still empty */
    assert_true(list_empty(&pscom.recvq_any_global));

    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);

    recv_any_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req);
}

/**
 * \brief Test pscom_post_recv() with a regular recv request after an any-source
 * request
 *
 * Given: An any-source request is enqueued on the global any-source queue
 * When: pscom_post_recv() is called with a subsequent regular receive request
 * Then: both requests are enqueued on recvq_any_global queue
 */
void test_post_recv_on_con_after_any_recv_on_global_queue(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* assume that all queues are empty */
    assert_true(list_empty(&recv_con->recvq_user));
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post an any recv request on the global queue */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = NULL; /* <- communicator is global */

    pscom_post_recv(recv_any_req);

    /* assume that the request as been enqueued to the global queue and that the
       any-source queueu of the socket is still empty */
    assert_int_equal(list_count(&pscom.recvq_any_global), 1);
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = NULL; /* <- communicator is global */

    pscom_post_recv(recv_req);

    /* assume that the request's socket has been set properly */
    assert_ptr_equal(recv_req->socket, recv_con->pub.socket);

    /* assume that both requests are now enqueued on the recvq_any_global queue
     */
    assert_int_equal(list_count(&pscom.recvq_any_global), 2);
    assert_true(list_empty(&recv_con->recvq_user));

    /* assume that the any-source queue of the socket is still empty */
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);

    recv_any_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req);
}

/**
 * \brief Test pscom_post_recv() with two any-source recvs following a regular
 * recv request
 *
 * Given: A regular request is enqueued on the recvq_user queue of a connection
 * When: pscom_post_recv() is called with two subsequent any-source requests,
 * one call with a given socket and one call with NULL as the socket (for global
 * any-src queue) Then: all three requests are enqueued to the separate queues
 * (con, sock, and global)
 */
void test_post_any_recvs_on_sock_and_global_after_recv_on_con(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* assume that all queues are empty */
    assert_true(list_empty(&recv_con->recvq_user));
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = recv_con->pub.socket;

    pscom_post_recv(recv_req);

    /* assume that the request as been enqueued to the connection queue and that
       the any-source queues are is still empty */
    assert_int_equal(list_count(&recv_con->recvq_user), 1);
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* create and post an any recv request on the socket */
    pscom_request_t *recv_any_req_sock = pscom_request_create(0, 0);
    recv_any_req_sock->connection      = NULL;
    recv_any_req_sock->socket          = recv_con->pub.socket;

    pscom_post_recv(recv_any_req_sock);

    /* assume that the request as been enqueued to the socket and that the
       global any-source queue is still empty */
    assert_int_equal(list_count(&recv_con->recvq_user), 1);
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 1);
    assert_true(list_empty(&pscom.recvq_any_global));

    /* create and post an any recv request to the global queue */
    pscom_request_t *recv_any_req_global = pscom_request_create(0, 0);
    recv_any_req_global->connection      = NULL;
    recv_any_req_global->socket          = NULL;

    pscom_post_recv(recv_any_req_global);

    /* assume that all three requests are now enqueued within the three separate
     * queues */
    assert_int_equal(list_count(&recv_con->recvq_user), 1);
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 1);
    assert_int_equal(list_count(&pscom.recvq_any_global), 1);

    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);

    recv_any_req_sock->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req_sock);

    recv_any_req_global->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req_global);
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_cancel()
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Test pscom_cancel() on a recv request posted on a connection
 *
 * Given: A posted recv request on a connection
 * When: pscom_cancel() is called on this request
 * Then: the request is removed from the recvq_user queue of the connection
 */
void test_post_recv_on_con_and_cancel(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = NULL;
    pscom_post_recv(recv_req);

    /* cancel and free the recv request */
    pscom_cancel(recv_req);
    pscom_request_free(recv_req);

    /* assume that the request has been removed from the queue */
    assert_true(list_empty(&recv_con->recvq_user));
}

/**
 * \brief Test pscom_cancel() on an any-source recv request posted on a socket
 *
 * Given: A posted any-source recv request on a socket plus a subsequent recv
 *        request posted on a connection
 * When: pscom_cancel() is called on the any-source request
 * Then: the any-source request is removed from the recvq_any queue of the
 * socket and the subsequent request is moved from the socket's recvq_any queue
 * to the recvq_user queue of the connection
 */
void test_post_any_recv_on_sock_and_cancel(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post an any recv request on the socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = recv_con->pub.socket;
    pscom_post_recv(recv_any_req);

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = recv_con->pub.socket;
    pscom_post_recv(recv_req);

    /* cancel and free the any recv request */
    pscom_cancel(recv_any_req);
    pscom_request_free(recv_any_req);

    /* assume that the any-source request is removed and that the subsequent
       request has been moved to the recvq_user of the connection */
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));
    assert_int_equal(list_count(&recv_con->recvq_user), 1);

    /* assume that the global any-source queue is still empty */
    assert_true(list_empty(&pscom.recvq_any_global));

    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);
}

/**
 * \brief Test pscom_cancel() on a recv request posted to global any-source
 * queue
 *
 * Given: A posted recv request on global any-source queue plus a subsequent
 * recv request posted on a connection When: pscom_cancel() is called on the
 * any-source request Then: the any-source request is removed from the
 * recvq_any_global queue and the subsequent request is moved from the the
 * recvq_any_global queue to the recvq_user queue of the connection
 */
void test_post_any_recv_on_global_queue_and_cancel(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post an any recv request without a given socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = NULL;
    pscom_post_recv(recv_any_req);

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = NULL;
    pscom_post_recv(recv_req);

    /* cancel and free the any recv request */
    pscom_cancel(recv_any_req);
    pscom_request_free(recv_any_req);

    /* assume that the any-source request is removed and that the subsequent
       request has been moved to the recvq_user of the connection */
    assert_true(list_empty(&pscom.recvq_any_global));
    assert_int_equal(list_count(&recv_con->recvq_user), 1);

    /* assume that the socket's any-source queue is still empty */
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);
}


////////////////////////////////////////////////////////////////////////////////
/// Termination of connection and any-source receive queues
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Test pscom_con_terminate_recvq() regarding specific-source requests
 *
 * Given: A posted receive request on a connection
 * When: pscom_con_terminate_recvq() is called on the receive queue of this
 * connection Then: the request has been removed from the recvq_user queue of
 * the connection and the request's status has been set to error state
 */
void test_post_recv_on_con_and_terminate_recvq(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = NULL;
    pscom_post_recv(recv_req);

    /* terminate the recvq of the con */
    pscom_con_terminate_recvq(recv_con);

    /* assume that the request has been removed from the queue */
    assert_true(list_empty(&recv_con->recvq_user));

    /* assume that the request status has been set to error state */
    assert_true(recv_req->state & PSCOM_REQ_STATE_ERROR);

    pscom_request_free(recv_req);
}

/**
 * \brief Test pscom_con_terminate_recvq() regarding socket-local any-source
 * requests
 *
 * Given: A posted any-source recv request on a socket plus a subsequent recv
 *        request posted on a connection
 * When: pscom_con_terminate_recvq() is called on the receive queue of this
 * connection Then: only the connection-related request is removed from the
 * any-source queue of the socket and the request's status has been set to error
 * state
 */
void test_post_any_recv_on_sock_and_terminate_recvq(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post an any recv request on the socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = recv_con->pub.socket;
    pscom_post_recv(recv_any_req);

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = recv_con->pub.socket;
    pscom_post_recv(recv_req);

    /* assume that both requests are now enqueued on the recvq_any of the socket
     */
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 2);
    assert_true(list_empty(&recv_con->recvq_user));

    /* terminate the recvq of the con */
    pscom_con_terminate_recvq(recv_con);

    /* assume that the con request has been removed from the socket's any-source
       queue and that the remaining request in this queueu is the any-source
       request */
    assert_int_equal(list_count(&get_sock(recv_con->pub.socket)->recvq_any), 1);
    assert_ptr_equal(&list_entry(get_sock(recv_con->pub.socket)->recvq_any.next,
                                 pscom_req_t, next)
                          ->pub,
                     recv_any_req);

    /* assume that the con request status has been set to error state */
    assert_true(recv_req->state & PSCOM_REQ_STATE_ERROR);

    pscom_request_free(recv_req);

    recv_any_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req);
}

/**
 * \brief Test pscom_con_terminate_recvq() regarding global any-source requests
 *
 * Given: A posted any-source recv request on the global queue plus a subsequent
 * recv request posted on a connection When: pscom_con_terminate_recvq() is
 * called on the receive queue of this connection Then: only the
 * connection-related request is removed from the global any-source queue and
 * the request's status has been set to error state
 */
void test_post_any_recv_on_global_queue_and_terminate_recvq(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post an any recv request without a given socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = NULL;
    pscom_post_recv(recv_any_req);

    /* create and post a regular recv request on the connection */
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &recv_con->pub;
    recv_req->socket          = NULL;
    pscom_post_recv(recv_req);

    /* assume that both requests are now enqueued on the recvq_any_global queue
     */
    assert_int_equal(list_count(&pscom.recvq_any_global), 2);
    assert_true(list_empty(&recv_con->recvq_user));

    /* terminate the recvq of the con */
    pscom_con_terminate_recvq(recv_con);

    /* assume that the con request has been removed from the global any-source
       queue and that the remaining request in this queueu is the any-source
       request */
    assert_int_equal(list_count(&pscom.recvq_any_global), 1);
    assert_ptr_equal(
        &list_entry(pscom.recvq_any_global.next, pscom_req_t, next)->pub,
        recv_any_req);

    /* assume that the con request status has been set to error state */
    assert_true(recv_req->state & PSCOM_REQ_STATE_ERROR);

    pscom_request_free(recv_req);

    recv_any_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_any_req);
}

/**
 * \brief Test _pscom_sock_terminate_all_recvs()
 *
 * Given: An any-source recv request on a socket-local any-source queue
 * When: _pscom_sock_terminate_all_recvs() is called
 * Then: the posted request is removed from the socket's any-source queue and
 * the request's status has been set to error state
 */
void test_post_any_recv_on_sock_and_terminate_sock_queue(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create and post an any recv request on the socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = recv_con->pub.socket;
    pscom_post_recv(recv_any_req);

    /* assume that the requests is now enqueued on the recvq_any of the socket
     */
    assert_ptr_equal(&list_entry(get_sock(recv_con->pub.socket)->recvq_any.next,
                                 pscom_req_t, next)
                          ->pub,
                     recv_any_req);

    /* terminate also the any-source queue of the socket */
    _pscom_sock_terminate_all_recvs(get_sock(recv_con->pub.socket));

    /* assume that the any-source request has been removed from the socket queue
     */
    assert_true(list_empty(&get_sock(recv_con->pub.socket)->recvq_any));

    /* assume that the any-source request status has been set to error state */
    assert_true(recv_any_req->state & PSCOM_REQ_STATE_ERROR);

    pscom_request_free(recv_any_req);
}

/**
 * \brief Test pscom_recvq_terminate_any_global()
 *
 * Given: A posted any-source recv request on the global queue
 * When: pscom_recvq_terminate_any_global() is called
 * Then: the posted request is removed from the global any-source queue and the
 *       request's status has been set to error state
 */
void test_post_any_recv_on_global_queue_and_terminate_global_queue(void **state)
{
    /* create and post an any recv request without a given socket */
    pscom_request_t *recv_any_req = pscom_request_create(0, 0);
    recv_any_req->connection      = NULL;
    recv_any_req->socket          = NULL;
    pscom_post_recv(recv_any_req);

    /* assume that the request is now enqueued on the recvq_any_global queue */
    assert_ptr_equal(
        &list_entry(pscom.recvq_any_global.next, pscom_req_t, next)->pub,
        recv_any_req);

    /* terminate the global any-source queue */
    pscom_recvq_terminate_any_global();

    /* assume that the any-source request has been removed from the global queue
     */
    assert_true(list_empty(&pscom.recvq_any_global));

    /* assume that the any-source request status has been set to error state */
    assert_true(recv_any_req->state & PSCOM_REQ_STATE_ERROR);

    pscom_request_free(recv_any_req);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_req_prepare_send_pending()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_req_prepare_send_pending() for a regular user request
 *
 * Given: A send request
 * When: pscom_req_prepare_send_pending() is called
 * Then: the request is prepared for sending
 */
void test_req_prepare_send_pending_valid_send_request(void **state)
{
    (void)state;

    const uint16_t xheader_len = 42;
    const size_t data_len      = 1024;
    pscom_req_t req            = {
                   .magic           = MAGIC_REQUEST,
                   .pub.xheader_len = xheader_len,
                   .pub.data_len    = data_len,
                   .pub.data        = (void *)0x42,
    };

    pscom_req_prepare_send_pending(&req, PSCOM_MSGTYPE_USER, 0);

    assert_int_equal(req.pub.header.msg_type, PSCOM_MSGTYPE_USER);
    assert_int_equal(req.pub.header.xheader_len, xheader_len);
    assert_int_equal(req.pub.header.data_len, data_len);

    assert_ptr_equal(req.cur_header.iov_base, &req.pub.header);
    assert_ptr_equal(req.cur_data.iov_base, req.pub.data);
    assert_int_equal(req.cur_header.iov_len,
                     sizeof(pscom_header_net_t) + req.pub.xheader_len);
    assert_int_equal(req.cur_data.iov_len, req.pub.data_len);

    assert_int_equal(req.skip, 0);
}

/**
 * \brief Test pscom_req_prepare_send_pending() very long data lengths
 *
 * Given: A send request with a data_len exceeding  PSCOM_DATA_LEN_MASK
 * When: pscom_req_prepare_send_pending() is called
 * Then: the data_len is truncated to PSCOM_DATA_LEN_MASK in the network header
 *
 * TODO: What is the purpose of this behavior?
 */
void test_req_prepare_send_pending_truncate_data_len(void **state)
{
    (void)state;

    const size_t data_len = PSCOM_DATA_LEN_MASK + 1024;
    pscom_req_t req       = {
              .magic        = MAGIC_REQUEST,
              .pub.data_len = data_len,
    };

    pscom_req_prepare_send_pending(&req, PSCOM_MSGTYPE_USER, 0);

    assert_true(req.pub.header.data_len <= PSCOM_DATA_LEN_MASK);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_get_rma_read_receiver_failing_rma_write()
////////////////////////////////////////////////////////////////////////////////
static int rma_write_error(pscom_con_t *con, void *src,
                           pscom_rendezvous_msg_t *des,
                           void (*io_done)(void *priv, int err), void *priv)
{
    /* simply call io_done with error */
    io_done(priv, 1);

    return 0;
}

/**
 * \brief Test pscom_get_rma_read_receiver() for an error in con->rndv.rma_write
 *
 * Given: A rendezvous send requests and incomming PSCOM_MSGTYPE_RMA_READ
 * When: con->rndv.rma_write() fails
 * Then: the request should be marked with an error; pending IO should be zero
 *       and the connection should be closed for writing
 */
void test_pscom_get_rma_read_receiver_failing_rma_write(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con    = (pscom_con_t *)(*state);
    recv_con->rndv.rma_read  = NULL;
    recv_con->rndv.rma_write = rma_write_error;

    /* poen connection for reading and writing */
    recv_con->pub.state = PSCOM_CON_STATE_RW;


    /* create the appropriate network header */
    pscom_header_net_t nh = {
        .msg_type = PSCOM_MSGTYPE_RMA_READ,
    };

    /* create user rndv request an append to pending IO queue */
    pscom_req_t *user_req = pscom_req_create(0, 100);
    user_req->pub.state   = PSCOM_REQ_STATE_RENDEZVOUS_REQUEST |
                          PSCOM_REQ_STATE_SEND_REQUEST | PSCOM_REQ_STATE_POSTED;
    user_req->pub.connection = &recv_con->pub;

    pscom_lock();
    {
        _pscom_write_pendingio_cnt_inc(recv_con, user_req);
        _pscom_get_rma_read_receiver(recv_con, &nh);
    }
    pscom_unlock();

    assert_true(user_req->pub.state & PSCOM_REQ_STATE_ERROR);
    assert_true(user_req->pending_io == 0);
    assert_false(recv_con->pub.state & PSCOM_CON_STATE_W);
}


////////////////////////////////////////////////////////////////////////////////
/// Rendezvous Receiver (RMA write)
////////////////////////////////////////////////////////////////////////////////
static int rma_write_null(pscom_con_t *con, void *src,
                          pscom_rendezvous_msg_t *des,
                          void (*io_done)(void *priv, int err), void *priv)
{
    /* do nothing here */

    return 0;
}
/**
 * \brief Test read error during rendezvous on the receiver side
 *
 * Given: An RMA read request on a connection relying on RMA put
 * When: a read error occurs
 * Then: the request should be marked with an error and the connection should
 *       be closed for reading
 */
void test_rndv_recv_read_error(void **state)
{
    const size_t data_len = 32768;

    /* obtain the dummy connections from the test setup */
    dummy_con_pair_t *con_pair = (dummy_con_pair_t *)(*state);
    pscom_con_t *recv_con, *send_con;

    recv_con                 = con_pair->recv_con;
    recv_con->rndv.rma_read  = NULL;
    recv_con->rndv.rma_write = rma_write_null;

    send_con                 = con_pair->send_con;
    send_con->rndv.rma_read  = NULL;
    send_con->rndv.rma_write = rma_write_null;

    /* open recv connection for reading and writing */
    recv_con->pub.state = PSCOM_CON_STATE_RW;

    /* create and post a user recv request on the recv con */
    pscom_request_t *user_recv_req = pscom_request_create(0, 100);
    user_recv_req->connection      = &recv_con->pub;
    user_recv_req->data_len        = data_len;
    pscom_post_recv(user_recv_req);

    /* create a matching send requests, i.e., the correct network header*/
    pscom_req_t *send_req    = pscom_req_create(100, 0);
    send_req->pub.data_len   = data_len;
    send_req->pub.connection = &send_con->pub;
    pscom_req_t *rndv_req =
        pscom_prepare_send_rendezvous_inline(send_req, PSCOM_MSGTYPE_USER);
    pscom_req_prepare_send(rndv_req, PSCOM_MSGTYPE_RENDEZVOUS_REQ);
    pscom_header_net_t *nh = &rndv_req->pub.header;

    /* assume we received a PSCOM_MSGTYPE_RENDEZVOUS_REQ */
    pscom_get_rendezvous_receiver(recv_con, nh);

    /* force READ error on the connection */
    pscom_lock();
    {
        pscom_read_done(recv_con, NULL, 0);
    }
    pscom_unlock();

    /* check request and conection state */
    assert_true(user_recv_req->state & PSCOM_REQ_STATE_ERROR);
    assert_false(recv_con->pub.state & PSCOM_CON_STATE_R);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_write_peding()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_write_pending() for first IO on this request and connection
 *
 * Given: A send request with no pending IO and connection closed for writing
 * When: pscom_write_peding() is called
 * Then: the connection is opened for writing
 */
void test_write_pending_first_io_con_closed(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *send_con = (pscom_con_t *)(*state);

    /* create send requests and enqueue to send queue */
    pscom_req_t *send_req    = pscom_req_create(0, 100);
    send_req->pub.connection = &send_con->pub;
    send_req->pub.data_len   = 42;
    pscom_req_prepare_send(send_req, 0);
    _pscom_sendq_enq(send_con, send_req);

    /* set the read_start()/read_stop() functions */
    send_con->write_start = &check_rw_start_called;
    send_con->write_stop  = &check_rw_stop_called;

    /* start pending write on the request and connection */
    expect_function_calls(check_rw_start_called, 1);
    expect_value(check_rw_start_called, con, send_con);
    pscom_write_pending(send_con, send_req, 42);


    /*
     * write_start() should be called lastly, i.e., the connection should be
     * open for writing.
     *
     * TODO: check connection state, once this is available within the pscom
     */
    assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_OPENED);
    assert_int_equal(send_req->pending_io, 1);
    assert_true(pscom_con_should_write(send_con));
}

/**
 * \brief Test pscom_write_pending() for first IO on this request
 *
 * Given: A send request with no pending IO and connection open for writing
 * When: pscom_write_peding() is called
 * Then: the connection state remains unchanged
 */
void test_write_pending_first_io_con_open(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *send_con = (pscom_con_t *)(*state);

    /* there is pending I/O on the connection, i.e., it is writing */
    send_con->write_pending_io_cnt = 1;

    /* create send requests and enqueue to send queue */
    pscom_req_t *send_req    = pscom_req_create(0, 100);
    send_req->pub.connection = &send_con->pub;
    send_req->pub.data_len   = 42;
    pscom_req_prepare_send(send_req, 0);
    _pscom_sendq_enq(send_con, send_req);

    /* set the rw_start()/rw_stop() functions */
    send_con->write_start = &check_rw_start_called;
    send_con->write_stop  = &check_rw_stop_called;

    /* open connection for writing */
    connection_state(TESTCON_OP_START_RW);


    /* start pending write on the request and connection */
    pscom_write_pending(send_con, send_req, 42);


    /*
     * the connection should be still open for writing
     *
     * TODO: check connection state, once this is available within the pscom
     */
    assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_OPENED);
    assert_int_equal(send_req->pending_io, 1);
    assert_true(pscom_con_should_write(send_con));
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_write_peding_done()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_write_pending_done() for last pending IO
 *
 * Given: A send request with a single pending IO and a connection with a single
 *        send request
 * When: pscom_write_peding_done() is called
 * Then: the connection should be closed
 */
void test_write_pending_done_last_io(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *send_con          = (pscom_con_t *)(*state);
    send_con->write_pending_io_cnt = 1;

    /* create send requests and enqueue to send queue */
    pscom_req_t *send_req    = pscom_req_create(0, 100);
    send_req->pub.connection = &send_con->pub;
    pscom_req_prepare_send(send_req, 0);
    send_req->pending_io = 1;

    /* add to pending_io queue mimic _pscom_pendingio_enq() */
    if (!pscom.env.debug_req) {
        list_add_tail(&send_req->all_req_next, &pscom.requests);
    }

    /* set the rw_start()/rw_stop() functions */
    send_con->write_start = &check_rw_start_called;
    send_con->write_stop  = &check_rw_stop_called;

    /* open connection for writing */
    connection_state(TESTCON_OP_START_RW);

    expect_function_calls(check_rw_stop_called, 1);
    expect_value(check_rw_stop_called, con, send_con);

    /* pending write is done */
    pscom_write_pending_done(send_con, send_req);

    /*
     * the connection should be closed for writing
     *
     * TODO: check connection state, once this is available within the pscom
     */
    assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_CLOSED);
    assert_int_equal(send_req->pending_io, 0);
    assert_false(pscom_con_should_write(send_con));
}

/**
 * \brief Test pscom_write_pending_done() for second last IO
 *
 * Given: A send request with a single pending IO and a connection with two
 *        send requests
 * When: pscom_write_peding_done() is called
 * Then: the connection state remains unchanged
 */
void test_write_pending_done_second_last_io(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *send_con = (pscom_con_t *)(*state);

    /* create send requests and enqueue to send queue */
    pscom_req_t *send_req    = pscom_req_create(0, 100);
    send_req->pub.connection = &send_con->pub;
    pscom_req_prepare_send(send_req, 0);
    send_req->pending_io = 1;

    /* add to pending_io queue mimic _pscom_pendingio_enq() */
    if (!pscom.env.debug_req) {
        list_add_tail(&send_req->all_req_next, &pscom.requests);
    }

    /* set the rw_start()/rw_stop() functions */
    send_con->write_start = &check_rw_start_called;
    send_con->write_stop  = &check_rw_stop_called;

    /* open connection for writing */
    connection_state(TESTCON_OP_START_RW);

    /* pending write is done */
    pscom_write_pending_done(send_con, send_req);

    /*
     * the connection should be closed for writing
     *
     * TODO: check connection state, once this is available within the pscom
     */
    assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_OPENED);
    assert_int_equal(send_req->pending_io, 0);
    assert_true(pscom_con_should_write(send_con));
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_read_peding_done()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_read_pending_done() for open generated request
 *
 * Given: A generated request that is currently processed (i.e., con->in.req)
 * When: pscom_read_peding_done() is called on another unrelated request
 * Then: the state of the generated request should remain unchanged
 */
void test_read_pending_done_unrelated_genreq(void **state)
{
    /* obtain the dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create generated requests and enqueue to the list of net requests */
    pscom_req_t *gen_req    = pscom_req_create(0, 100);
    gen_req->pub.connection = &recv_con->pub;
    _pscom_net_recvq_user_enq(recv_con, gen_req);

    /* set the read_start()/read_stop() functions */
    recv_con->read_start = &check_rw_start_called;
    recv_con->read_stop  = &check_rw_stop_called;

    /* create another receive request and start pending read */
    pscom_req_t *recv_req    = pscom_req_create(0, 100);
    recv_req->pub.connection = &recv_con->pub;
    pscom_header_net_t nh    = {0};
    pscom_req_prepare_recv(recv_req, &nh, &recv_con->pub);
    recv_con->in.req = recv_req;

    /* read_start() should be called at least once */
    expect_function_calls(check_rw_start_called, 1);
    expect_value(check_rw_start_called, con, recv_con);

    assert_int_equal(recv_req, pscom_read_pending(recv_con, 0));


    /*
     * set the appropriate request state:
     * -> generated requests
     * -> IO has been started
     */
    gen_req->pub.state = PSCOM_REQ_STATE_GRECV_REQUEST;
    gen_req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;

    /* the request shall be the current request of the connection */
    recv_con->in.req = gen_req;

    /* post the actual receive request */
    pscom_read_pending_done(recv_con, recv_req);

    /*
     * read_start() should be called lastly
     * TODO: check connection state, once this is available within the pscom
     */
    assert_int_equal(recv_con->in.req, gen_req);
    assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_OPENED);
}
