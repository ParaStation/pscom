/*
 * ParaStation
 *
 * Copyright (C) 2022-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>

#include <portals4.h>

#include "pscom_priv.h"
#include "pscom_utest.h"
#include "mocks/misc_mocks.h"
#include "mocks/portals4_mocks.h"

#include "pscom_portals.h"
#include "psptl.h"

#include "util/test_utils_con.h"

#include "pscom_portals.c" /* we need to access some static functions */
#include "psptl.c"         /* we need to access some static functions */

////////////////////////////////////////////////////////////////////////////////
/// Some forward declarations
////////////////////////////////////////////////////////////////////////////////
extern pscom_plugin_t pscom_plugin_portals;

////////////////////////////////////////////////////////////////////////////////
/// Some helper functions
////////////////////////////////////////////////////////////////////////////////
typedef struct dummy_con_state {
    pscom_con_t *con;
    uint8_t expect_me_unlink_on_close;
} dummy_con_state_t;

/**
 * @brief Create a dummy portals connection
 */
int setup_dummy_portals_con(void **state)
{
    pscom_con_t *con;

    /* create a pscom connection object */
    setup_dummy_con((void **)&con);

    /* initialize the environment configuration table */
    pscom_plugin_portals.init();

    /* set pscom4portal's init state */
    psptl.init_state = PSPORTALS_NOT_INITIALIZED;

    /* initialize the lower pscom4portals layer */
    expect_function_calls(__wrap_PtlInit, 1);
    expect_function_calls(__wrap_PtlMDBind, 2);
    expect_function_call_any(__wrap_PtlMEAppend);
    will_return_always(__wrap_PtlMEAppend, PTL_OK);


    pscom_plugin_portals.sock_init(get_sock(con->pub.socket));
    pscom_plugin_portals.con_init(con);

    /* initialize the pscom4portals connection */
    psptl_con_info_t *ci = psptl_con_create();
    psptl_sock_t *sock   = &get_sock(con->pub.socket)->portals;

    psptl_con_init(ci, (void *)con, sock, sock->priv);
    con->arch.portals.ci = ci;

    /* initialize the send and receiver buffers */
    psptl_info_msg_t info_msg;
    psptl_con_get_info_msg(ci, &info_msg);
    psptl_con_connect(ci, &info_msg);

    con->pub.type = PSCOM_CON_TYPE_PORTALS;

    /* eager communication */
    pscom_portals_configure_eager(con);

    /* rendezvous RMA write interface */
    pscom_portals_configure_rndv_write(con);

    con->close = pscom_portals_con_close;

    dummy_con_state_t *con_state = (dummy_con_state_t *)malloc(
        sizeof(*con_state));

    /* set the con state: this connection and unlink on close by default */
    con_state->con                       = con;
    con_state->expect_me_unlink_on_close = 1;

    *state = (void *)con_state;

    return 0;
}


static void rma_write_completion_io_done(void *priv, int err)
{
    function_called();
    check_expected(priv);
    check_expected(err);
}


/**
 * @brief Release resources of a dummy portals connection
 */
int teardown_dummy_portals_con(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *con             = con_state->con;

    /* close our connection */
    if (con_state->expect_me_unlink_on_close) {
        expect_function_call_any(__wrap_PtlMEUnlink);
    }

    /* close the pscom connection */
    con->close(con);

    if (!con_state->expect_me_unlink_on_close) {
        expect_function_call_any(__wrap_PtlMEUnlink);
    }
    expect_function_calls(__wrap_PtlMDRelease, 2);
    pscom_plugin_portals.sock_destroy(get_sock(con->pub.socket));
    pscom_plugin_portals.destroy();

    /* destroy the pscom connection object */
    teardown_dummy_con((void **)&con);

    free(con_state);

    return 0;
}


////////////////////////////////////////////////////////////////////////////////
/// Initialization
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test if PORTALS is initialized during plugin initialization by default
 *
 * Given: PORTALS has not been initialized
 * When: the first connection is initialized
 * Then: the lower PORTALS plugin layer and the socket are initialized as well
 */
void test_portals_first_initialization(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);
    psptl_sock_t *sock     = &get_sock(dummy_con->pub.socket)->portals;

    /* start socket initialization */
    pscom_plugin_portals.sock_init(get_sock(dummy_con->pub.socket));

    /* set the init state */
    psptl.init_state = PSPORTALS_NOT_INITIALIZED;

    /* PtlInit should be called once */
    expect_function_calls(__wrap_PtlInit, 1);
    expect_function_calls(__wrap_PtlMDBind, 2);

    /* initialize the pscom4portals plugin */
    pscom_plugin_portals.con_init(dummy_con);

    assert_true(psptl.init_state == PSPORTALS_INIT_DONE);
    assert_true(sock->init_state == PSCOM_PORTALS_SOCK_INIT_DONE);
}


/**
 * \brief Test if PORTALS is only initialized once
 *
 * Given: PORTALS and a socket have already been initialized
 * When: the a connection is initialized
 * Then: the lower PORTALS plugin layer is not initialized again
 */
void test_portals_second_initialization(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);
    psptl_sock_t *sock     = &get_sock(dummy_con->pub.socket)->portals;

    /* set the init state */
    psptl.init_state = PSPORTALS_INIT_DONE;
    sock->init_state = PSCOM_PORTALS_SOCK_INIT_DONE;

    /* initialize the connection */
    pscom_plugin_portals.con_init(dummy_con);

    assert_true(psptl.init_state == PSPORTALS_INIT_DONE);
    assert_true(sock->init_state == PSCOM_PORTALS_SOCK_INIT_DONE);
}


/**
 * \brief Test if PORTALS not initialized after failure
 *
 * Given: PORTALS already failed to initialize
 * When: a connection is initialized
 * Then: the lower PORTALS plugin layer is not initialized
 */
void test_portals_initialization_after_failure(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);

    /* set the init state */
    psptl.init_state = PSPORTALS_INIT_FAILED;

    /* initialize the second connection */
    int ret = pscom_plugin_portals.con_init(dummy_con);

    assert_true(ret == PSPORTALS_INIT_FAILED);
}


/**
 * \brief Test if connection initialization fails for failed socket
 *
 * Given: A pscom4portals socket already failed to initialize
 * When: a connection is initialized
 * Then: it fails to initialize
 */
void test_portals_initialization_after_socket_failure(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);
    psptl_sock_t *sock     = &get_sock(dummy_con->pub.socket)->portals;

    /* set the init state */
    psptl.init_state = PSPORTALS_INIT_DONE;
    sock->init_state = PSCOM_PORTALS_SOCK_INIT_FAILED;

    /* initialize the second connection */
    int ret = pscom_plugin_portals.con_init(dummy_con);

    assert_true(ret == PSCOM_PORTALS_SOCK_INIT_FAILED);
}

////////////////////////////////////////////////////////////////////////////////
/// Receiving
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test if pscom4portals is reading if a connection is opened for reading
 *
 * Given: pscom4portals is not in reading state
 * When: a connection is opened for reading
 * Then: the related socket is set to reading state
 */
void test_portals_read_after_con_read(void **state)
{
    pscom_con_t *dummy_con   = (pscom_con_t *)(*state);
    pscom_sock_t *dummy_sock = get_sock(dummy_con->pub.socket);
    dummy_con->read_start    = pscom_portals_read_start;
    dummy_con->read_stop     = pscom_portals_read_stop;

    /* set the reading state */
    dummy_sock->portals.reader_user = 0;

    /* start reading on the connection */
    dummy_con->read_start(dummy_con);

    /* ensure pscom4portals is in reading state */
    assert_true(dummy_sock->portals.reader_user == 1);

    /* cleanup the readers */
    dummy_con->read_stop(dummy_con);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test if pscom4portals is still reading after one connection stopped
 *        reading out of two
 *
 * Given: pscom4portals is in reading state
 * When: a connection is opened for reading
 * Then: the respective socket is set to reading state
 */
void test_portals_read_after_con_read_stop_out_of_two(void **state)
{
    pscom_con_t *dummy_con   = (pscom_con_t *)(*state);
    pscom_sock_t *dummy_sock = get_sock(dummy_con->pub.socket);
    dummy_con->read_stop     = pscom_portals_read_stop;

    /* set the reading state */
    dummy_con->arch.portals.reading = 1;
    dummy_sock->portals.reader_user = 2;

    /* stop reading on the connection */
    dummy_con->read_stop(dummy_con);

    /* ensure pscom4portals is in reading state */
    assert_true(dummy_sock->portals.reader_user == 1);
    assert_true(dummy_con->arch.portals.reading == 0);
}


/**
 * \brief Test if pscom4portals creates one reader per socket
 *
 * Given: a portals connection in reading state
 * When: a new connection is created on new socket and starts reading
 * Then: there should be two readers in the poll list
 */
void test_portals_one_reader_per_socket(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);

    /* initialize as portals connection */
    dummy_con->read_stop            = pscom_portals_read_stop;
    dummy_con->read_start           = pscom_portals_read_start;
    dummy_con->arch.portals.reading = 0;
    pscom_plugin_portals.sock_init(get_sock(dummy_con->pub.socket));

    /* start reading */
    dummy_con->read_start(dummy_con);

    /* create a new socket and a new connection */
    pscom_sock_t *new_sock = pscom_open_sock(0, 0);
    pscom_con_t *new_con   = pscom_con_create(new_sock);

    /* initialize the new connection as portals connection */
    new_con->read_stop            = pscom_portals_read_stop;
    new_con->read_start           = pscom_portals_read_start;
    new_con->arch.portals.reading = 0;
    pscom_plugin_portals.sock_init(get_sock(new_con->pub.socket));


    /* start reading */
    new_con->read_start(new_con);

    /* ensure pscom4portals is in reading state */
    assert_int_equal(list_count(&pscom.poll_read.head), 2);

    /* cleanup the readers */
    new_con->read_stop(dummy_con);
    new_con->read_stop(new_con);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test if the pscom makes IO progress on a request if a PUT event is
 *        issued
 *
 * Given: A pscom receive request
 * When: a PTL_EVENT_PUT occurs with expected sequence ID
 * Then: this should be reflected by the request's state
 */
void test_portals_read_on_event_put(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_sock_t *psptl_sock     = &get_sock(dummy_con->pub.socket)->portals;

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    dummy_sock->portals.reader_user = 0;

    /* create and post a any recv request */
    char recv_buf[128];
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &dummy_con->pub;
    recv_req->socket          = dummy_con->pub.socket;
    recv_req->data            = recv_buf;
    recv_req->data_len        = sizeof(recv_buf);

    pscom_post_recv(recv_req);

    /* receive ACK */
    uint64_t seq_id = 0x42;
    char *buf[128];
    psptl_ep_t *ep            = (psptl_ep_t *)psptl_sock->priv;
    psptl_con_info_t con_info = {
        .con_priv      = dummy_con,
        .recv_seq_id   = seq_id,
        .pending_recvs = LIST_HEAD_INIT(con_info.pending_recvs),
        .ep            = ep,
    };
    psptl_bucket_t bucket = {
        .con_info = &con_info,
        .buf      = (void *)&buf,
    };
    will_return(__wrap_PtlEQPoll, &bucket); /* put events expect a bucket */
    will_return(__wrap_PtlEQPoll, seq_id);  /* expected sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_PUT); /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);     /* no failure */
    will_return(__wrap_PtlEQPoll, sizeof(buf));   /* mlength */
    will_return(__wrap_PtlEQPoll, sizeof(buf));   /* rlength */
    will_return(__wrap_PtlEQPoll,
                ep->pti[PSPTL_PROT_EAGER]);          /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */

    /* bucket will be re-registered */
    expect_function_call(__wrap_PtlMEAppend);
    will_return(__wrap_PtlMEAppend, PTL_OK);

    pscom_poll(&pscom.poll_read);

    /* ensure pscom4portals is in reading state */
    assert_true(recv_req->state |= PSCOM_REQ_STATE_IO_STARTED);


    /* relese the request */
    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);

    /* cleanup the readers (enforce read_stop) */
    dummy_con->read_stop(dummy_con);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test correct ordering of out-of-order receives
 *
 * Given: Two occurrences of PTL_EVENT_PUT
 * When: they have out-of-oder sequence IDs
 * Then: they are processed in the correct oder
 */
void test_portals_read_out_of_order_receive(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_sock_t *psptl_sock     = &get_sock(dummy_con->pub.socket)->portals;

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    dummy_sock->portals.reader_user = 0;

    /* create and post a any recv request */
    char recv_buf[128]        = {0};
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &dummy_con->pub;
    recv_req->socket          = dummy_con->pub.socket;
    recv_req->data            = recv_buf;
    recv_req->data_len        = sizeof(recv_buf);

    pscom_post_recv(recv_req);

    /* receive the payload (seq ID: 1) */
    char buf[128]             = "This is the payload";
    psptl_ep_t *ep            = (psptl_ep_t *)psptl_sock->priv;
    psptl_con_info_t con_info = {
        .con_priv      = dummy_con,
        .recv_seq_id   = 0,
        .pending_recvs = LIST_HEAD_INIT(con_info.pending_recvs),
        .ep            = ep,
    };
    psptl_bucket_t bucket_payload = {
        .con_info = &con_info,
        .buf      = (void *)&buf,
    };
    will_return(__wrap_PtlEQPoll, &bucket_payload); /* bucket for put event */
    will_return(__wrap_PtlEQPoll, 1);               /* unexpected sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_PUT);   /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);       /* no failure */
    will_return(__wrap_PtlEQPoll, strlen(buf));     /* mlength */
    will_return(__wrap_PtlEQPoll, strlen(buf));     /* rlength */
    will_return(__wrap_PtlEQPoll,
                ep->pti[PSPTL_PROT_EAGER]);          /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */
    pscom_poll(&pscom.poll_read);

    /* receive the header (seq ID: 0) */
    pscom_header_net_t header_net = {
        .xheader_len = 0,
        .msg_type    = PSCOM_MSGTYPE_USER,
        .data_len    = strlen(buf) & PSCOM_DATA_LEN_MASK,
    };
    psptl_bucket_t bucket_header = {
        .con_info = &con_info,
        .buf      = (void *)&header_net,
    };
    will_return(__wrap_PtlEQPoll, &bucket_header); /* bucket for put event */
    will_return(__wrap_PtlEQPoll, 0);              /* expected sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_PUT);  /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);      /* no failure */
    will_return(__wrap_PtlEQPoll, sizeof(header_net)); /* mlength */
    will_return(__wrap_PtlEQPoll, sizeof(header_net)); /* rlength */
    will_return(__wrap_PtlEQPoll,
                ep->pti[PSPTL_PROT_EAGER]);          /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */

    /* buckets will be re-registered */
    expect_function_calls(__wrap_PtlMEAppend, 2);
    will_return_count(__wrap_PtlMEAppend, PTL_OK, 2);

    pscom_poll(&pscom.poll_read);


    /* ensure we received the expected payload */
    assert_int_equal(strncmp(recv_buf, buf, sizeof(recv_buf)), 0);

    /* release the request */
    pscom_request_free(recv_req);

    /* cleanup the readers */
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test correct ordering of out-of-order receives
 *
 * Given: Three occurrences of PTL_EVENT_PUT
 * When: they have out-of-oder sequence IDs
 * Then: they are processed in the correct oder
 */
void test_portals_read_three_out_of_order_receive(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_sock_t *psptl_sock     = &get_sock(dummy_con->pub.socket)->portals;

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    dummy_sock->portals.reader_user = 0;

    /* create and post a any recv request */
    char recv_buf[128]        = {0};
    pscom_request_t *recv_req = pscom_request_create(0, 0);
    recv_req->connection      = &dummy_con->pub;
    recv_req->socket          = dummy_con->pub.socket;
    recv_req->data            = recv_buf;
    recv_req->data_len        = sizeof(recv_buf);

    pscom_post_recv(recv_req);

    /* receive the payload part two (seq ID: 2) */
    size_t buf_one_len = 18;
    char buf_one[128]  = "This is the first part of the payload; This is the "
                         "second part of the payload";
    char *buf_two      = buf_one + buf_one_len;
    psptl_ep_t *ep     = (psptl_ep_t *)psptl_sock->priv;
    psptl_con_info_t con_info = {
        .con_priv      = dummy_con,
        .recv_seq_id   = 0,
        .pending_recvs = LIST_HEAD_INIT(con_info.pending_recvs),
        .ep            = ep,
    };
    psptl_bucket_t bckt_payload_two = {
        .con_info = &con_info,
        .buf      = (void *)buf_two,
    };
    will_return(__wrap_PtlEQPoll, &bckt_payload_two); /* bucket for put event */
    will_return(__wrap_PtlEQPoll, 2);             /* unexpected sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_PUT); /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);     /* no failure */
    will_return(__wrap_PtlEQPoll, strlen(buf_one) - buf_one_len); /* mlength */
    will_return(__wrap_PtlEQPoll, strlen(buf_one) - buf_one_len); /* rlength */
    will_return(__wrap_PtlEQPoll,
                ep->pti[PSPTL_PROT_EAGER]);          /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */
    pscom_poll(&pscom.poll_read);

    /* receive the payload part one (seq ID: 1) */
    psptl_bucket_t bckt_payload_one = {
        .con_info = &con_info,
        .buf      = (void *)&buf_one,
    };
    will_return(__wrap_PtlEQPoll, &bckt_payload_one); /* bucket for put event */
    will_return(__wrap_PtlEQPoll, 1);             /* unexpected sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_PUT); /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);     /* no failure */
    will_return(__wrap_PtlEQPoll, buf_one_len);   /* mlength */
    will_return(__wrap_PtlEQPoll, buf_one_len);   /* rlength */
    will_return(__wrap_PtlEQPoll,
                ep->pti[PSPTL_PROT_EAGER]);          /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */
    pscom_poll(&pscom.poll_read);

    /* receive the header (seq ID: 0) */
    pscom_header_net_t header_net = {
        .xheader_len = 0,
        .msg_type    = PSCOM_MSGTYPE_USER,
        .data_len    = strlen(buf_one) & PSCOM_DATA_LEN_MASK,
    };
    psptl_bucket_t bucket_header = {
        .con_info = &con_info,
        .buf      = (void *)&header_net,
    };
    will_return(__wrap_PtlEQPoll, &bucket_header); /* bucket for put event */
    will_return(__wrap_PtlEQPoll, 0);              /* expected sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_PUT);  /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);      /* no failure */
    will_return(__wrap_PtlEQPoll, sizeof(header_net)); /* mlength */
    will_return(__wrap_PtlEQPoll, sizeof(header_net)); /* rlength */
    will_return(__wrap_PtlEQPoll,
                ep->pti[PSPTL_PROT_EAGER]);          /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */

    /* buckets will be re-registered */
    expect_function_calls(__wrap_PtlMEAppend, 3);
    will_return_count(__wrap_PtlMEAppend, PTL_OK, 3);

    pscom_poll(&pscom.poll_read);


    /* ensure we received the expected payload */
    assert_int_equal(strncmp(recv_buf, buf_one, sizeof(recv_buf)), 0);

    /* release the request */
    pscom_request_free(recv_req);

    /* cleanup the readers */
    pscom_poll(&pscom.poll_read);
}


////////////////////////////////////////////////////////////////////////////////
/// Sending
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test if pscom4portals is reading if a send request was posted
 *
 * Given: pscom4portals is not in reading state
 * When: a send requested is posted on a connection
 * Then: the pscom4portals plugin is set to reading state
 */
void test_portals_read_after_send_request(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_sock_t *dummy_ptl_sock = &dummy_sock->portals;

    /* set the reading state */
    dummy_sock->portals.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;

    /* post a send request (i.e., start writing) */
    pscom_post_send(send_req);

    /* call the actual polling function */
    will_return(__wrap_PtlPut, PTL_OK);
    expect_function_call(__wrap_PtlPut);
    pscom_poll(&pscom.poll_write);

    /* ensure pscom4portals is in reading state */
    assert_true(dummy_sock->portals.reader_user == 1);

    /* stop writing and cleanup polling list */
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* ensure we are still in reading state (ACK not received yet) */
    assert_true(dummy_sock->portals.reader_user == 1);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;

    /* cleanup the readers */
    poll_reader_dec(dummy_ptl_sock);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test for PtlPut failure
 *
 * Given: A process starts writing on a pscom4portals connection
 * When: PtlPut() fails
 * Then: the connection's state is set to not reading
 */
void test_portals_put_fail(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);

    /* set the reading and connection state */
    dummy_sock->portals.reader_user = 0;
    dummy_con->pub.state            = PSCOM_CON_STATE_RW;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;

    /* post a send request (i.e., start writing) */
    pscom_post_send(send_req);

    /* call the actual polling function */
    will_return(__wrap_PtlPut, PTL_ARG_INVALID);
    expect_function_call(__wrap_PtlPut);

    /* poll two times to ensure the reader is actually removed */
    pscom_poll(&pscom.poll_write);
    pscom_poll(&pscom.poll_write);

    /* ensure pscom4portals is not reading state */
    assert_true(dummy_sock->portals.reader_user == 0);
    assert_int_equal(list_count(&pscom.poll_write.head), 0);
    assert_false(dummy_con->pub.state & PSCOM_CON_STATE_W);

    /* pretend EOF received -> no more reading on this connection */
    dummy_con->state.eof_received = 1;
}


/**
 * \brief Ensure connections with outstanding put requests are not closed
 *
 * Given: A pscom4portals connection with outstanding put requests
 * When: the connection is closed
 * Then: the actual release of resources is deferred
 */
void test_portals_defer_close_with_outstanding_put_requests(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_sock_t *dummy_ptl_sock = &dummy_sock->portals;
    psptl_con_info_t *con_info   = dummy_con->arch.portals.ci;
    uint32_t eager_pti           = con_info->ep->pti[PSPTL_PROT_EAGER];

    /* set the reading state */
    dummy_sock->portals.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;
    pscom_post_send(send_req);

    /* start writing on the connection */
    will_return(__wrap_PtlPut, PTL_OK);
    expect_function_call(__wrap_PtlPut);
    dummy_con->write_start(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* ACK not yet received */
    will_return(__wrap_PtlEQPoll, NULL); /* use saved user pointer */
    will_return(__wrap_PtlEQPoll, 0);    /* sequence ID not important */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_ACK);    /* just mock something */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);        /* no failed request */
    will_return(__wrap_PtlEQPoll, 0);                /* mlength */
    will_return(__wrap_PtlEQPoll, 0);                /* rlength */
    will_return(__wrap_PtlEQPoll, eager_pti);        /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_EQ_EMPTY);     /* do not issue an event */
    pscom_poll(&pscom.poll_read);

    /* stop writing and cleanup polling list */
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;

    /* cleanup the readers */
    poll_reader_dec(dummy_ptl_sock);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Ensure connections with no outstanding put requests are closed
 *
 * Given: A pscom4portals connection with outstanding put requests
 * When: the connection is closed
 * Then: the actual release of resources is deferred
 */
void test_portals_close_with_no_outstanding_put_requests(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_con_info_t *con_info   = dummy_con->arch.portals.ci;
    uint32_t eager_pti           = con_info->ep->pti[PSPTL_PROT_EAGER];

    /* set the reading state */
    dummy_sock->portals.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;
    pscom_post_send(send_req);

    /* start writing on the connection */
    will_return(__wrap_PtlPut, PTL_OK);
    expect_function_call(__wrap_PtlPut);
    dummy_con->write_start(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* receive ACK */
    will_return(__wrap_PtlEQPoll, NULL); /* use saved user pointer */
    will_return(__wrap_PtlEQPoll, 0);    /* sequence ID not important */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_ACK);    /* generate an ACK event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);        /* no failed request */
    will_return(__wrap_PtlEQPoll, 0);                /* mlength */
    will_return(__wrap_PtlEQPoll, 0);                /* rlength */
    will_return(__wrap_PtlEQPoll, eager_pti);        /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK); /* an event has been generated */
    pscom_poll(&pscom.poll_read);

    /* explicitly stop writing and remove both readers and writers */
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Ensure late ACKs (of closed connections) are processed correctly
 *
 * Given: A closed connection with outstanding PUT operations
 * When: an ACK event is generated by the Portals4 layer
 * Then: this should be processed
 */
void test_portals_ack_after_con_close(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    psptl_sock_t *dummy_sock     = &get_sock(dummy_con->pub.socket)->portals;
    psptl_con_info_t *con_info   = dummy_con->arch.portals.ci;
    uint32_t eager_pti           = con_info->ep->pti[PSPTL_PROT_EAGER];

    /* pretend we have outstanding PUT operations (i.e., waiting for ACKs) */
    con_info->outstanding_put_ops = 1;
    psptl_bucket_t bucket         = {
                .con_info = con_info,
                .buf      = NULL,
    };

    /* close the connection now */
    dummy_con->pub.state          = PSCOM_CON_STATE_CLOSE_WAIT;
    dummy_con->state.eof_received = 1;
    pscom_con_close(dummy_con);

    /* receive the missing ACK */
    poll_reader_inc(dummy_sock);
    will_return(__wrap_PtlEQPoll, &bucket); /* use saved user pointer */
    will_return(__wrap_PtlEQPoll, 0);       /* sequence ID not important */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_ACK);    /* generate an ACK event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);        /* no failed request */
    will_return(__wrap_PtlEQPoll, 0);                /* mlength */
    will_return(__wrap_PtlEQPoll, 0);                /* rlength */
    will_return(__wrap_PtlEQPoll, eager_pti);        /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK); /* an event has been generated */
    pscom_poll(&pscom.poll_read);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;

    /* cleanup the readers */
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test correct handling of message drops
 *
 * Given: A PTL_EVENT_ACK occurs
 * When: a failure is indicated by an event.ni_fail_type != PTL_NI_OK
 * Then: this is properly handled by pscom4portals.
 */
void test_portals_handle_message_drop(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    pscom_sock_t *dummy_sock     = get_sock(dummy_con->pub.socket);
    psptl_sock_t *dummy_ptl_sock = &dummy_sock->portals;

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    dummy_sock->portals.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;
    pscom_post_send(send_req);

    /* start writing on the connection */
    will_return(__wrap_PtlPut, PTL_OK);
    expect_function_call(__wrap_PtlPut);
    dummy_con->write_start(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* receive the payload (seq ID: 1) */
    char buf[128]             = "This is the payload";
    psptl_ep_t ep             = {0};
    psptl_con_info_t con_info = {
        .con_priv            = dummy_con,
        .recv_seq_id         = 0,
        .pending_recvs       = LIST_HEAD_INIT(con_info.pending_recvs),
        .outstanding_put_ops = 1, /* assume there is an outstanding put op */
        .ep                  = &ep,
    };
    psptl_bucket_t bucket = {
        .con_info = &con_info,
        .buf      = (void *)&buf,
    };
    will_return(__wrap_PtlEQPoll, &bucket);        /* bucket for ACK event */
    will_return(__wrap_PtlEQPoll, 0x42);           /* arbitrary sequence ID */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_ACK);  /* issue a PUT event */
    will_return(__wrap_PtlEQPoll, PTL_NI_DROPPED); /* message dropped by recv */
    will_return(__wrap_PtlEQPoll, strlen(buf));    /* arbitrary mlength */
    will_return(__wrap_PtlEQPoll, strlen(buf));    /* arbitrary rlength */
    will_return(__wrap_PtlEQPoll,
                ep.pti[PSPTL_PROT_EAGER]);           /* eager PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_EAGER); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);           /* event queue not empty */

    /* PtlPut will be called during retry */
    will_return(__wrap_PtlPut, PTL_OK);
    expect_function_call(__wrap_PtlPut);

    pscom_poll(&pscom.poll_read);

    /* ensure there is an outstanding put operation */
    assert_int_equal(con_info.outstanding_put_ops, 1);
    assert_true(dummy_sock->portals.reader_user == 1);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;

    /* cleanup the readers and writers */
    poll_reader_dec(dummy_ptl_sock);
    pscom_poll(&pscom.poll_read);
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);
}


////////////////////////////////////////////////////////////////////////////////
/// RMA write
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test memory registration
 *
 * Given: A memory region to be registered for receiving
 * When: con->rma_mem_register is called
 * Then: it is successfully registered with the low-level portals layer
 */
void test_portals_memory_registration(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    psptl_con_info_t *con_info   = dummy_con->arch.portals.ci;
    uint32_t rndv_pti            = con_info->ep->pti[PSPTL_PROT_RNDV];

    /* register a memory region  */
    char buf[42]               = {0};
    pscom_rendezvous_data_t rd = {
        .msg =
            {
                .data     = buf,
                .data_len = 42,
            },
    };
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(&rd);
    psptl_rma_mreg_t *psptl_rma_mreg = &rd_portals->rma_write_rx.rma_mreg;

    expect_function_call(__wrap_PtlMEAppend);
    will_return(__wrap_PtlMEAppend, PTL_OK);

    /*
     * Pre-allocate the rendezvous bucket to be returned by PtlEQPoll() while
     * waiting for the ME to be linked in psptl_rma_mem_register(). This is
     * realized by calling enable_malloc_mock() beforehand.
     */
    void *rndv_bucket = malloc(sizeof(psptl_bucket_t));

    will_return(__wrap_PtlEQPoll, rndv_bucket);     /* pre-allocated bucket */
    will_return(__wrap_PtlEQPoll, 0x42);            /* arbitrary hdr_data */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_LINK);  /* issue a LINK event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);       /* no link failure */
    will_return(__wrap_PtlEQPoll, strlen(buf));     /* arbitrary mlength */
    will_return(__wrap_PtlEQPoll, strlen(buf));     /* arbitrary rlength */
    will_return(__wrap_PtlEQPoll, rndv_pti);        /* rndv PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_RNDV); /* rndv EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK);          /* event queue not empty */

    enable_malloc_mock(rndv_bucket);

    assert_true(psptl_rma_mem_register(dummy_con->arch.portals.ci, rd.msg.data,
                                       rd.msg.data_len, psptl_rma_mreg) == 0);

    disable_malloc_mock();
}


/**
 * \brief Test failing memory registration
 *
 * Given: A memory region to be registered for receiving
 * When: con->rma_mem_register is called and the registration fails
 * Then: zero is returned
 */
void test_portals_failed_memory_registration(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;

    /* register a memory region  */
    char buf[42]               = {0};
    pscom_rendezvous_data_t rd = {
        .msg =
            {
                .data     = buf,
                .data_len = 42,
            },
    };

    will_return(__wrap_PtlMEAppend, PTL_NO_SPACE);
    expect_function_call(__wrap_PtlMEAppend);
    assert_true(dummy_con->rma_mem_register(dummy_con, &rd) == 0);
}


/**
 * \brief Test failing memory registration
 *
 * Given: A registered memory region with corresponding pscom_rendezvous_data_t
 * When: con->rma_mem_deregister is called
 * Then: the private data of the low-level layer should be released
 */
void test_portals_mem_deregister_releases_resources(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;

    /* allocate a dummy priv object  */
    psptl_con_info_t con_info;
    psptl_bucket_t *bucket = (psptl_bucket_t *)malloc(sizeof(*bucket));
    bucket->con_info       = &con_info;

    pscom_rendezvous_data_t rd;
    pscom_rendezvous_data_portals_t *rd_portals = get_req_data(&rd);
    rd_portals->rma_write_rx.rma_mreg.priv      = bucket;

    expect_function_call(__wrap_PtlMEUnlink);
    dummy_con->rma_mem_deregister(dummy_con, &rd);
}


/**
 * \brief Test RMA write
 *
 * Given: A rendezvous request
 * When: con->rma_write is called with correct parameters
 * Then: zero is returned
 */
void test_portals_rma_write(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;

    /* register a memory region  */
    char src_buf[42]                = {0};
    pscom_rendezvous_msg_t rndv_msg = {
        .data     = src_buf,
        .data_len = 42,
    };

    expect_function_call(__wrap_PtlPut);
    will_return(__wrap_PtlPut, PTL_OK);
    assert_true(
        dummy_con->rma_write(dummy_con, src_buf, &rndv_msg, NULL, NULL) == 0);
}


/**
 * \brief Test RMA write for failing put operations
 *
 * Given: A rendezvous request and con->rma_write is called
 * When: PtlPut fails
 * Then: it returns -1
 */
void test_portals_rma_write_fail_put(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;

    /* register a memory region  */
    char src_buf[42]                = {0};
    pscom_rendezvous_msg_t rndv_msg = {
        .data     = src_buf,
        .data_len = 42,
    };


    expect_function_call(__wrap_PtlPut);
    will_return(__wrap_PtlPut, PTL_ARG_INVALID);
    assert_true(
        dummy_con->rma_write(dummy_con, src_buf, &rndv_msg, NULL, NULL) == -1);
}


/**
 * \brief Test RMA write completion
 *
 * Given: A rendezvous request
 * When: the according PTL_EVENT_ACK occurs
 * Then: the io_done call is issued
 */
void test_portals_rma_write_completion(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    psptl_con_info_t *con_info   = dummy_con->arch.portals.ci;
    uint32_t rndv_pti            = con_info->ep->pti[PSPTL_PROT_RNDV];

    /* register a memory region  */
    char src_buf[42]                = {0};
    pscom_rendezvous_msg_t rndv_msg = {
        .data     = src_buf,
        .data_len = 42,
    };

    /* start writing on the connection (will be ensured by the control msgs) */
    dummy_con->read_start(dummy_con);

    /* issue the RMA write operation */
    expect_function_call(__wrap_PtlPut);
    will_return(__wrap_PtlPut, PTL_OK);
    void *priv = (void *)(0xDEADBEEF);
    dummy_con->rma_write(dummy_con, src_buf, &rndv_msg,
                         rma_write_completion_io_done, priv);


    /* receive ACK */
    will_return(__wrap_PtlEQPoll, NULL); /* use saved user pointer */
    will_return(__wrap_PtlEQPoll, 0);    /* sequence ID not important */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_ACK);   /* generate an ACK event */
    will_return(__wrap_PtlEQPoll, PTL_NI_OK);       /* no failed request */
    will_return(__wrap_PtlEQPoll, 0);               /* mlength */
    will_return(__wrap_PtlEQPoll, 0);               /* rlength */
    will_return(__wrap_PtlEQPoll, rndv_pti);        /* rendezvous PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_RNDV); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK); /* an event has been generated */

    /*  io_done is called with our 'priv' parameter and no error */
    expect_function_call(rma_write_completion_io_done);
    expect_value(rma_write_completion_io_done, priv, priv);
    expect_value(rma_write_completion_io_done, err, 0);

    pscom_poll(&pscom.poll_read);

    /* stop writing and cleanup polling list */
    dummy_con->read_stop(dummy_con);
    pscom_poll(&pscom.poll_read);
}


/**
 * \brief Test RMA write for long messages I
 *
 * Given: A rendezvous request of a long message exceeding the rendezvous
 *        fragmentation size
 * When: con->rma_write is called with correct parameters
 * Then: the request is processes by sending multiple fragments
 */
void test_portals_rma_write_fragmentation(void **state)
{
    const size_t fragment_size   = 2 * 1024;
    const size_t msg_size        = 64 * 1024;
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;

    /* set  the fragmentation size */
    psptl.con_params.rndv_fragment_size = fragment_size;

    /* register a memory region  */
    void *src_buf                   = malloc(msg_size);
    pscom_rendezvous_msg_t rndv_msg = {
        .data     = src_buf,
        .data_len = msg_size,
    };

    enable_extended_ptl_put_mock();

    expect_function_calls(__wrap_PtlPut, (int)(msg_size / fragment_size));
    will_return_always(__wrap_PtlPut, PTL_OK);

    /* check data buffers passed to PtlPut() */
    for (size_t offset = 0; offset < msg_size; offset += fragment_size) {
        expect_value(__wrap_PtlPut, local_offset, src_buf + offset);
        expect_value(__wrap_PtlPut, length, fragment_size);
    }

    assert_true(
        dummy_con->rma_write(dummy_con, src_buf, &rndv_msg, NULL, NULL) == 0);

    disable_extended_ptl_put_mock();

    free(src_buf);
}


/**
 * \brief Test RMA write for long messages II
 *
 * Given: A rendezvous request of a long message exceeding the rendezvous
 *        fragmentation size and remainder
 * When: con->rma_write is called with correct parameters
 * Then: the request is processes by sending multiple fragments
 */
void test_portals_rma_write_fragmentation_remainder(void **state)
{
    const size_t fragment_size     = 2 * 1024;
    const size_t msg_size          = 6 * 1024 + 1;
    const size_t full_fragment_cnt = msg_size / fragment_size;
    const size_t remainder         = msg_size % fragment_size;
    dummy_con_state_t *con_state   = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con         = con_state->con;

    /* set  the fragmentation size */
    psptl.con_params.rndv_fragment_size = fragment_size;

    /* register a memory region  */
    void *src_buf                   = malloc(msg_size);
    pscom_rendezvous_msg_t rndv_msg = {
        .data     = src_buf,
        .data_len = msg_size,
    };

    enable_extended_ptl_put_mock();

    expect_function_calls(__wrap_PtlPut, (int)full_fragment_cnt + 1);
    will_return_always(__wrap_PtlPut, PTL_OK);

    /* check data buffers passed to PtlPut() */
    for (size_t offset = 0; offset < full_fragment_cnt * fragment_size;
         offset += fragment_size) {
        expect_value(__wrap_PtlPut, local_offset, src_buf + offset);
        expect_value(__wrap_PtlPut, length, fragment_size);
    }
    expect_value(__wrap_PtlPut, local_offset,
                 src_buf + full_fragment_cnt * fragment_size);
    expect_value(__wrap_PtlPut, length, remainder);

    assert_true(
        dummy_con->rma_write(dummy_con, src_buf, &rndv_msg, NULL, NULL) == 0);

    disable_extended_ptl_put_mock();

    free(src_buf);
}


/**
 * \brief Test RMA write with NI failure
 *
 * Given: A rendezvous request being issued
 * When: the PTL_EVENT_ACK returns a ptl_ni_fail_t != PTL_NI_OK
 * Then: the failure is propagated to the upper layers
 */
void test_portals_rma_write_fail_ack(void **state)
{
    dummy_con_state_t *con_state = (dummy_con_state_t *)(*state);
    pscom_con_t *dummy_con       = con_state->con;
    psptl_con_info_t *con_info   = dummy_con->arch.portals.ci;
    uint32_t rndv_pti            = con_info->ep->pti[PSPTL_PROT_RNDV];

    /* register a memory region  */
    char src_buf[42]                = {0};
    pscom_rendezvous_msg_t rndv_msg = {
        .data     = src_buf,
        .data_len = 42,
    };

    /* start reading on the connection (will be ensured by the control msgs) */
    dummy_con->read_start(dummy_con);

    /* issue the RMA write operation */
    expect_function_call(__wrap_PtlPut);
    will_return(__wrap_PtlPut, PTL_OK);
    void *priv = (void *)(0xDEADBEEF);
    dummy_con->rma_write(dummy_con, src_buf, &rndv_msg,
                         rma_write_completion_io_done, priv);


    /* receive ACK */
    will_return(__wrap_PtlEQPoll, NULL); /* use saved user pointer */
    will_return(__wrap_PtlEQPoll, 0);    /* sequence ID not important */
    will_return(__wrap_PtlEQPoll, PTL_EVENT_ACK);   /* generate an ACK event */
    will_return(__wrap_PtlEQPoll, PTL_NI_DROPPED);  /* request failed */
    will_return(__wrap_PtlEQPoll, 0);               /* mlength */
    will_return(__wrap_PtlEQPoll, 0);               /* rlength */
    will_return(__wrap_PtlEQPoll, rndv_pti);        /* rendezvous PT index */
    will_return(__wrap_PtlEQPoll, PSPTL_PROT_RNDV); /* eager EQ index */
    will_return(__wrap_PtlEQPoll, PTL_OK); /* an event has been generated */

    /*  io_done is called with our 'priv' parameter and no error */
    expect_function_call(rma_write_completion_io_done);
    expect_value(rma_write_completion_io_done, priv, priv);
    expect_value(rma_write_completion_io_done, err, 1);

    pscom_poll(&pscom.poll_read);

    /* stop reading and cleanup polling list */
    dummy_con->read_stop(dummy_con);
    pscom_poll(&pscom.poll_read);
}
