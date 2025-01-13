/*
 * ParaStation
 *
 * Copyright (C) 2024-2025 ParTec AG, Munich
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

#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_sock.h"
#include "pscom_con.h"
#include "pscom_ufd.h"
#include "util/test_utils_listen.h"

/**
 * @brief Test starting and stopping of listening on pscom socket
 *
 * Given: Open pscom socket
 * When: Start listening prior to connection setup, stop listening after
 * connection setup
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_start_stop_listen_anyport(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.usercnt == 0);

    /* No fd anymore */
    assert_true(dummy_sock->listen.ufd_info.fd == -1);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Test starting and stopping of listening on a pscom socket where an
 * ondemand connection is being attached
 *
 * Given: Open pscom socket with an ondemand connection
 * When: Start listening prior to connection setup, stop listening after
 * connection setup
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_start_stop_listen_ondemand(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);
    unsigned int activecnt   = 0;
    unsigned int usercnt     = 0;

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Save previous values for later comparison */
    activecnt = dummy_sock->listen.activecnt;
    usercnt   = dummy_sock->listen.usercnt;

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);
    _pscom_con_connect_ondemand(con, 42, 42, "r1428571");

    /* The counter for listen users must be increased by one due to the ondemand
     * connection while the active listen counter must still be the same */
    assert_true(dummy_sock->listen.usercnt == usercnt + 1 && usercnt + 1 == 2);
    assert_true(dummy_sock->listen.activecnt == activecnt && activecnt == 1);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* There must still be the ondemand connection as a listen user */
    assert_true(dummy_sock->listen.usercnt == 1);
    assert_true(dummy_sock->listen.ufd_info.fd != -1);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the connection */
    pscom_con_close(con);

    /* The connection has been closed and fd and usercnt have been reset */
    assert_true(dummy_sock->listen.usercnt == 0);
    assert_true(dummy_sock->listen.ufd_info.fd == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Test starting and stopping of listening on a pscom socket where an
 * ondemand connection is being attached and a receive request is being posted
 *
 * Given: Open pscom socket with an ondemand connection
 * When: Start listening prior to connection setup, posting a receivev reuqest
 * after connection setup, and stop listening afterwards
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_start_stop_listen_ondemand_recv_req(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);
    unsigned int activecnt   = 0;
    unsigned int usercnt     = 0;

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);
    _pscom_con_connect_ondemand(con, 42, 42, "r1428571");

    /* Save previous values for later comparison */
    activecnt = dummy_sock->listen.activecnt;
    usercnt   = dummy_sock->listen.usercnt;

    /* Create a receive request and post it to the connection */
    pscom_request_t *req = pscom_request_create(0, 0);
    req->connection      = &con->pub;
    req->socket          = con->pub.socket;
    pscom_post_recv(req);

    /* The counter for listen users must still be the same whereas the active
     * counter must be increased by one due to the posting of the request */
    assert_true(dummy_sock->listen.usercnt == usercnt && usercnt == 2);
    assert_true(dummy_sock->listen.activecnt == activecnt + 1 &&
                activecnt + 1 == 2);

    /* Save previous values again for later comparison */
    activecnt = dummy_sock->listen.activecnt;
    usercnt   = dummy_sock->listen.usercnt;

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* There must still be the ondemand connection as a listen user */
    assert_true(dummy_sock->listen.usercnt == usercnt && usercnt == 2);

    /* Listener should still be in active state for the receive request
       posted on the ondemand connection but decremented by one  */
    assert_true(dummy_sock->listen.activecnt == activecnt - 1 &&
                activecnt - 1 == 1);

    /* Close the connection  */
    pscom_con_close(con);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.usercnt == 0);
    assert_true(dummy_sock->listen.activecnt == 0);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Suspend listening on pscom socket in between starting and stopping of
 * the listener
 *
 * Given: Open pscom socket
 * When: Suspend listening after connection setup
 * Then: All internal counters, the file descriptor and the suspend status of
 * the listener must have the correct values
 */
void test_suspend_listen(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Test suspend listening on socket */
    suspend_listen(dummy_sock);

    /* NO RESUME LISTEN HERE */

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.usercnt == 0);

    /* No fd anymore */
    assert_true(dummy_sock->listen.ufd_info.fd == -1);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Suspend and resume listening on pscom socket in between starting and
 * stopping of the listener
 *
 * Given: Open pscom socket
 * When: Suspend listening after connection setup, resume listening for new
 * connection setup
 * Then: All internal counters, the file descriptor and the suspend status of
 * the listener must have the correct values
 */
void test_suspend_resume_listen(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Test suspend listening on socket */
    suspend_listen(dummy_sock);

    /* Test resume listening on socket */
    resume_listen(dummy_sock);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.usercnt == 0);

    /* No fd anymore */
    assert_true(dummy_sock->listen.ufd_info.fd == -1);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Suspend and resume listening on pscom socket with an ondemand
 * connection
 *
 * Given: Open pscom socket with an ondemand connection
 * When: Suspend listening after connection setup, and resume listening directly
 * afterwards before stopping to listen and closing the connection
 * Then: All internal counters, the file descriptor and the suspend status of
 * the listener must have the correct values
 */
void test_suspend_resume_listen_ondemand(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);
    _pscom_con_connect_ondemand(con, 42, 42, "r1428571");

    /* Test suspend listening on socket */
    suspend_listen(dummy_sock);

    /* Test resume listening on socket */
    resume_listen(dummy_sock);

    /* Test stop listening on socket */
    stop_listen(dummy_sock);

    /* There must still be the ondemand connection as a listen user */
    assert_true(dummy_sock->listen.usercnt == 1);
    assert_true(dummy_sock->listen.ufd_info.fd != -1);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the connection */
    pscom_con_close(con);

    /* The connection has been closed and fd and usercnt have been reset */
    assert_true(dummy_sock->listen.usercnt == 0);
    assert_true(dummy_sock->listen.ufd_info.fd == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Suspend and resume listening on pscom socket with an ondemand
 * connection that has a posted receive request
 *
 * Given: Open pscom socket with an ondemand connection having a posted
 * receive request
 * When: Suspend listening after posting the receive request, and resume
 * listening directly afterwards before stopping to listen and closing the
 * connection
 * Then: All internal counters, the file descriptor and the suspend status
 * of the listener must have the correct values
 */
void test_suspend_resume_listen_ondemand_recv_req(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);
    _pscom_con_connect_ondemand(con, 42, 42, "r1428571");

    /* Create a receive request and post it to the connection */
    pscom_request_t *req = pscom_request_create(0, 0);
    req->connection      = &con->pub;
    req->socket          = con->pub.socket;
    pscom_post_recv(req);

    /* Test suspend listening on socket */
    suspend_listen(dummy_sock);

    /* Test resume listening on socket */
    resume_listen(dummy_sock);

    /* Test stop listening on socket */
    stop_listen(dummy_sock);

    /* Close the connection  */
    pscom_con_close(con);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.usercnt == 0);
    assert_true(dummy_sock->listen.activecnt == 0);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}
