/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
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
    pscom_plugin_portals.con_init(con);

    /* initialize the pscom4portals connection */
    psptl_con_info_t *ci = psptl_con_create();
    psptl_con_init(ci, (void *)con);
    con->arch.portals.ci = ci;

    /* initialize the send and receiver buffers */
    psptl_info_msg_t info_msg;
    psptl_con_get_info_msg(ci, &info_msg);
    psptl_con_connect(ci, &info_msg);


    con->pub.type = PSCOM_CON_TYPE_PORTALS;

    con->write_start = pscom_poll_write_start_portals;
    con->write_stop  = pscom_poll_write_stop;

    con->read_start = pscom_portals_read_start;
    con->read_stop  = pscom_portals_read_stop;

    con->close = pscom_portals_con_close;

    dummy_con_state_t *con_state = (dummy_con_state_t *)malloc(
        sizeof(*con_state));

    /* set the con state: this connection and unlink on close by default */
    con_state->con                       = con;
    con_state->expect_me_unlink_on_close = 1;

    *state = (void *)con_state;

    return 0;
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
    con->close(con);

    /* close the pscom connection */
    teardown_dummy_con((void **)&con);

    if (!con_state->expect_me_unlink_on_close) {
        expect_function_call_any(__wrap_PtlMEUnlink);
    }
    pscom_plugin_portals.destroy();

    /* ensure the readers are actually removed */
    pscom_poll(&pscom.poll_read);

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
 * Then: the lower PORTALS plugin layer is initialized as well
 */
void test_portals_first_initialization(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);

    /* set the init state */
    psptl.init_state = PSPORTALS_NOT_INITIALIZED;

    /* PtlInit should be called once */
    expect_function_calls(__wrap_PtlInit, 1);

    /* initialize the pscom4portals plugin */
    pscom_plugin_portals.con_init(dummy_con);

    assert_true(psptl.init_state == PSPORTALS_INIT_DONE);
}


/**
 * \brief Test if PORTALS is only initialized once
 *
 * Given: PORTALS has already been initialized
 * When: the second connection is initialized
 * Then: the lower PORTALS plugin layer is not initialized again
 */
void test_portals_second_initialization(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);

    /* set the init state */
    psptl.init_state = PSPORTALS_INIT_DONE;

    /* initialize the connection */
    pscom_plugin_portals.con_init(dummy_con);

    assert_true(psptl.init_state == PSPORTALS_INIT_DONE);
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


////////////////////////////////////////////////////////////////////////////////
/// Receiving
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test if pscom4portals is reading if a connection is opened for reading
 *
 * Given: pscom4portals is not in reading state
 * When: a connection is opened for reading
 * Then: the pscom4portals plugin is set to reading state
 */
void test_portals_read_after_con_read(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);
    dummy_con->read_start  = pscom_portals_read_start;
    dummy_con->read_stop   = pscom_portals_read_stop;

    /* set the reading state */
    pscom_portals_poll.reader_user = 0;

    /* start reading on the connection */
    dummy_con->read_start(dummy_con);

    /* ensure pscom4portals is in reading state */
    assert_true(pscom_portals_poll.reader_user == 1);

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
 * Then: the pscom4portals plugin is set to reading state
 */
void test_portals_read_after_con_read_stop_out_of_two(void **state)
{
    pscom_con_t *dummy_con = (pscom_con_t *)(*state);
    dummy_con->read_stop   = pscom_portals_read_stop;

    /* set the reading state */
    dummy_con->arch.portals.reading = 1;
    pscom_portals_poll.reader_user  = 2;

    /* stop reading on the connection */
    dummy_con->read_stop(dummy_con);

    /* ensure pscom4portals is in reading state */
    assert_true(pscom_portals_poll.reader_user == 1);
    assert_true(dummy_con->arch.portals.reading == 0);
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

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    pscom_portals_poll.reader_user  = 0;

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
    psptl_con_info_t con_info = {
        .con_priv      = dummy_con,
        .recv_seq_id   = seq_id,
        .pending_recvs = LIST_HEAD_INIT(con_info.pending_recvs),
    };
    psptl_bucket_t bucket = {
        .con_info = &con_info,
        .buf      = (void *)&buf,
    };
    will_return(__wrap_PtlEQGet, &bucket); /* put events expect a bucket */
    will_return(__wrap_PtlEQGet, seq_id);  /* expected sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_PUT); /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);     /* no failure */
    will_return(__wrap_PtlEQGet, sizeof(buf));   /* mlength */
    will_return(__wrap_PtlEQGet, sizeof(buf));   /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK);        /* event queue not empty */
    pscom_poll(&pscom.poll_read);

    /* ensure pscom4portals is in reading state */
    assert_true(recv_req->state |= PSCOM_REQ_STATE_IO_STARTED);


    /* relese the request */
    recv_req->state |= PSCOM_REQ_STATE_DONE;
    pscom_request_free(recv_req);
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

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    pscom_portals_poll.reader_user  = 0;

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
    psptl_con_info_t con_info = {
        .con_priv      = dummy_con,
        .recv_seq_id   = 0,
        .pending_recvs = LIST_HEAD_INIT(con_info.pending_recvs),
    };
    psptl_bucket_t bucket_payload = {
        .con_info = &con_info,
        .buf      = (void *)&buf,
    };
    will_return(__wrap_PtlEQGet, &bucket_payload); /* bucket for put event */
    will_return(__wrap_PtlEQGet, 1);               /* unexpected sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_PUT);   /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);       /* no failure */
    will_return(__wrap_PtlEQGet, strlen(buf));     /* mlength */
    will_return(__wrap_PtlEQGet, strlen(buf));     /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK);          /* event queue not empty */
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
    will_return(__wrap_PtlEQGet, &bucket_header);     /* bucket for put event */
    will_return(__wrap_PtlEQGet, 0);                  /* expected sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_PUT);      /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);          /* no failure */
    will_return(__wrap_PtlEQGet, sizeof(header_net)); /* mlength */
    will_return(__wrap_PtlEQGet, sizeof(header_net)); /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK); /* event queue not empty */
    pscom_poll(&pscom.poll_read);


    /* ensure we received the expected payload */
    assert_int_equal(strncmp(recv_buf, buf, sizeof(recv_buf)), 0);

    /* release the request */
    pscom_request_free(recv_req);
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

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    pscom_portals_poll.reader_user  = 0;

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
    psptl_con_info_t con_info = {
        .con_priv      = dummy_con,
        .recv_seq_id   = 0,
        .pending_recvs = LIST_HEAD_INIT(con_info.pending_recvs),
    };
    psptl_bucket_t bckt_payload_two = {
        .con_info = &con_info,
        .buf      = (void *)buf_two,
    };
    will_return(__wrap_PtlEQGet, &bckt_payload_two); /* bucket for put event */
    will_return(__wrap_PtlEQGet, 2);             /* unexpected sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_PUT); /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);     /* no failure */
    will_return(__wrap_PtlEQGet, strlen(buf_one) - buf_one_len); /* mlength */
    will_return(__wrap_PtlEQGet, strlen(buf_one) - buf_one_len); /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK); /* event queue not empty */
    pscom_poll(&pscom.poll_read);

    /* receive the payload part one (seq ID: 1) */
    psptl_bucket_t bckt_payload_one = {
        .con_info = &con_info,
        .buf      = (void *)&buf_one,
    };
    will_return(__wrap_PtlEQGet, &bckt_payload_one); /* bucket for put event */
    will_return(__wrap_PtlEQGet, 1);             /* unexpected sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_PUT); /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);     /* no failure */
    will_return(__wrap_PtlEQGet, buf_one_len);   /* mlength */
    will_return(__wrap_PtlEQGet, buf_one_len);   /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK);        /* event queue not empty */
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
    will_return(__wrap_PtlEQGet, &bucket_header);     /* bucket for put event */
    will_return(__wrap_PtlEQGet, 0);                  /* expected sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_PUT);      /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);          /* no failure */
    will_return(__wrap_PtlEQGet, sizeof(header_net)); /* mlength */
    will_return(__wrap_PtlEQGet, sizeof(header_net)); /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK); /* event queue not empty */
    pscom_poll(&pscom.poll_read);


    /* ensure we received the expected payload */
    assert_int_equal(strncmp(recv_buf, buf_one, sizeof(recv_buf)), 0);

    /* release the request */
    pscom_request_free(recv_req);
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

    /* set the reading state */
    pscom_portals_poll.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;

    /* post a send request (i.e., start writing) */
    pscom_post_send(send_req);

    /* call the actual polling function */
    pscom_poll(&pscom.poll_write);

    /* ensure pscom4portals is in reading state */
    assert_true(pscom_portals_poll.reader_user == 1);

    /* stop writing and cleanup polling list */
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* ensure we are still in reading state (ACK not received yet) */
    assert_true(pscom_portals_poll.reader_user == 1);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;
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

    /* set the reading state */
    pscom_portals_poll.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;
    pscom_post_send(send_req);

    /* start writing on the connection */
    dummy_con->write_start(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* ACK not yet received */
    will_return(__wrap_PtlEQGet, NULL);          /* use saved user pointer */
    will_return(__wrap_PtlEQGet, 0);             /* sequence ID not important */
    will_return(__wrap_PtlEQGet, PTL_EVENT_ACK); /* just mock something */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);     /* no failed request */
    will_return(__wrap_PtlEQGet, 0);             /* mlength */
    will_return(__wrap_PtlEQGet, 0);             /* rlength */
    will_return(__wrap_PtlEQGet, PTL_EQ_EMPTY);  /* do not issue an event */
    pscom_poll(&pscom.poll_read);

    /* stop writing and cleanup polling list */
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;
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

    /* set the reading state */
    pscom_portals_poll.reader_user = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;
    pscom_post_send(send_req);

    /* start writing on the connection */
    dummy_con->write_start(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* receive ACK */
    will_return(__wrap_PtlEQGet, NULL);          /* use saved user pointer */
    will_return(__wrap_PtlEQGet, 0);             /* sequence ID not important */
    will_return(__wrap_PtlEQGet, PTL_EVENT_ACK); /* generate an ACK event */
    will_return(__wrap_PtlEQGet, PTL_NI_OK);     /* no failed request */
    will_return(__wrap_PtlEQGet, 0);             /* mlength */
    will_return(__wrap_PtlEQGet, 0);             /* rlength */
    will_return(__wrap_PtlEQGet, PTL_OK); /* an event has been generated */
    pscom_poll(&pscom.poll_read);


    /* explicitly stop writing to remove the poller */
    dummy_con->write_stop(dummy_con);
    pscom_poll(&pscom.poll_write);
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

    /* set the reading state */
    dummy_con->arch.portals.reading = 0;
    pscom_portals_poll.reader_user  = 0;

    /* post a send request on the connection */
    pscom_request_t *send_req = pscom_request_create(0, 100);
    send_req->connection      = &dummy_con->pub;
    send_req->data_len        = 0;
    pscom_post_send(send_req);

    /* start writing on the connection */
    dummy_con->write_start(dummy_con);
    pscom_poll(&pscom.poll_write);

    /* receive the payload (seq ID: 1) */
    char buf[128]             = "This is the payload";
    psptl_hca_info_t hca_info = {0};
    psptl_con_info_t con_info = {
        .con_priv            = dummy_con,
        .recv_seq_id         = 0,
        .pending_recvs       = LIST_HEAD_INIT(con_info.pending_recvs),
        .outstanding_put_ops = 1, /* assume there is an outstanding put op */
        .hca_info            = &hca_info,
    };
    psptl_bucket_t bucket = {
        .con_info = &con_info,
        .buf      = (void *)&buf,
    };
    will_return(__wrap_PtlEQGet, &bucket);        /* bucket for ACK event */
    will_return(__wrap_PtlEQGet, 0x42);           /* arbitrary sequence ID */
    will_return(__wrap_PtlEQGet, PTL_EVENT_ACK);  /* issue a PUT event */
    will_return(__wrap_PtlEQGet, PTL_NI_DROPPED); /* message dropped by recv */
    will_return(__wrap_PtlEQGet, strlen(buf));    /* arbitrary mlength */
    will_return(__wrap_PtlEQGet, strlen(buf));    /* arbitrary rlength */
    will_return(__wrap_PtlEQGet, PTL_OK);         /* event queue not empty */
    pscom_poll(&pscom.poll_read);

    /* ensure there is an outstanding put operation */
    assert_int_equal(con_info.outstanding_put_ops, 1);
    assert_true(pscom_portals_poll.reader_user == 1);

    /* closing of the connection will be deferred until plugin destroy */
    con_state->expect_me_unlink_on_close = 0;
}
