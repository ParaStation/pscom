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
#include <string.h>

#include "list.h"
#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_sock.h"
#include "pscom_con.h"
#include "pscom_ufd.h"
#include "pscom_precon.h"
#include "util/test_utils_listen.h"

/**
 * @brief Test starting and stopping of listening on pscom socket
 *
 * Given: Open pscom socket
 * When: Start listening on a socket and stop listening
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

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Manually close fd before closing to test this function */
    pscom_listener_close_fd(&dummy_sock->listen);

    /* No fd */
    assert_true(dummy_sock->listen.ufd_info.fd == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}


/**
 * @brief Test stopping and restarting of listening on pscom socket
 *
 * Given: Open pscom socket
 * When: Start listening on a socket and stop listening then restart listening
 * and stop listening.
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_restart_listen_anyport(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* activecnt must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* restart listening with the any port */
    restart_listen(dummy_sock, PSCOM_ANYPORT);

    /* activecnt must be 1 */
    assert_true(dummy_sock->listen.activecnt == 1);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}


/**
 * @brief Test starting and stopping listening multiple times on pscom socket
 *
 * Given: Open pscom socket
 * When: Start listening on a socket twice, and stop listening.
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_start_listen_multiple(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* activecnt must be reset to 1 */
    assert_true(dummy_sock->listen.activecnt == 1);

    /* Test start listening on socket */
    restart_listen(dummy_sock, PSCOM_ANYPORT);

    /* listener is active, re-activate it will not increase activecnt */
    assert_true(dummy_sock->listen.activecnt == 1);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* activecnt must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}


/**
 * @brief Test stopping and restarting of listening on pscom socket
 *
 * Given: Open pscom socket
 * When: Start listening on a socket, stop listening then restart listening with
 * the same `portno` and stop listening, finally restart listening with a
 * different `portno` and stop listening
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_restart_listen_specific_port(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);
    int portno;

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* store the portno of the socket */
    portno = dummy_sock->pub.listen_portno;

    /* restart listening with the same port */
    restart_listen(dummy_sock, portno);

    /* activecnt must be 1 */
    assert_true(dummy_sock->listen.activecnt == 1);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* restart listening with a different port */
    restart_listen(dummy_sock, portno + 1);

    /* check if a new portno is assigned */
    assert_true(dummy_sock->pub.listen_portno == portno + 1);

    /* activecnt must be 1 */
    assert_true(dummy_sock->listen.activecnt == 1);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);

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

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Save previous values for later comparison */
    activecnt = dummy_sock->listen.activecnt;

    /* Check the active listen counter */
    assert_true(activecnt == 1);

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);

    /* set connection parameters */
    con->pub.remote_con_info.node_id    = 42;
    con->pub.remote_con_info.tcp.portno = 42;
    memcpy(con->pub.remote_con_info.name, "r1428571",
           sizeof(con->pub.remote_con_info.name));

    _pscom_con_connect_ondemand(con);

    /* The active listen counter must still be the same */
    assert_true(dummy_sock->listen.activecnt == activecnt);

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the connection */
    pscom_con_close(con);

    /* Close the socket */
    pscom_sock_close(dummy_sock);
}

/**
 * @brief Test starting and stopping of listening on a pscom socket where an
 * ondemand connection is being attached and a receive request is being posted
 *
 * Given: Open pscom socket with an ondemand connection
 * When: Start listening prior to connection setup, post a receive request
 * after connection setup, and stop listening afterwards
 * Then: All internal counters and the file descriptor of the listener must have
 * the correct values
 */
void test_start_stop_listen_ondemand_recv_req(void **state)
{
    pscom_sock_t *dummy_sock = (pscom_sock_t *)(*state);
    unsigned int activecnt   = 0;

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);

    /* set connection parameters */
    con->pub.remote_con_info.node_id    = 42;
    con->pub.remote_con_info.tcp.portno = 42;
    memcpy(con->pub.remote_con_info.name, "r1428571",
           sizeof(con->pub.remote_con_info.name));

    _pscom_con_connect_ondemand(con);

    /* Save previous values for later comparison */
    activecnt = dummy_sock->listen.activecnt;

    /* Check the active listen counter */
    assert_true(activecnt == 1);

    /* Create a receive request and post it to the connection */
    pscom_request_t *req = pscom_request_create(0, 0);
    req->connection      = &con->pub;
    req->socket          = con->pub.socket;
    pscom_post_recv(req);

    /* The active counter must be increased by one due to the posting of the
     * request */
    assert_true(dummy_sock->listen.activecnt == activecnt + 1);

    /* reduce activecnt by 1*/
    con->read_stop(con);

    /* The active counter is decreased by one due to read_stop */
    assert_true(dummy_sock->listen.activecnt == activecnt);

    /* Save previous values again for later comparison */
    activecnt = dummy_sock->listen.activecnt;

    /* Test stop listening */
    stop_listen(dummy_sock);

    /* Listener should still be in active state for the receive request
       posted on the ondemand connection but decremented by one  */
    assert_true(dummy_sock->listen.activecnt == activecnt - 1);

    /* Close the connection  */
    pscom_con_close(con);

    /* Both counters must be reset to 0 */
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

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Check if ufd_info is detached from the list */
    assert_true(list_empty(&(dummy_sock->listen.ufd_info.next)));

    /* Close the socket */
    pscom_sock_close(dummy_sock);

    /* Check if ufd_info is detached from the list */
    assert_true(list_empty(&(dummy_sock->listen.ufd_info.next)));
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

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the socket */
    pscom_sock_close(dummy_sock);

    /* Check if ufd_info is detached from the list */
    assert_true(list_empty(&(dummy_sock->listen.ufd_info.next)));
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

    /* set connection parameters */
    con->pub.remote_con_info.node_id    = 42;
    con->pub.remote_con_info.tcp.portno = 42;
    memcpy(con->pub.remote_con_info.name, "r1428571",
           sizeof(con->pub.remote_con_info.name));

    _pscom_con_connect_ondemand(con);

    /* Test suspend listening on socket */
    suspend_listen(dummy_sock);

    /* Test resume listening on socket */
    resume_listen(dummy_sock);

    /* Test stop listening on socket */
    stop_listen(dummy_sock);

    /* Listener should NOT be listening for incoming connections anymore */
    assert_true(dummy_sock->listen.activecnt == 0);
    assert_true(dummy_sock->listen.ufd_info.pollfd_idx == -1);

    /* Close the connection */
    pscom_con_close(con);

    /* Close the socket */
    pscom_sock_close(dummy_sock);

    /* Check if ufd_info is detached from the list */
    assert_true(list_empty(&(dummy_sock->listen.ufd_info.next)));
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
    unsigned int activecnt   = 0;

    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* Test start listening on socket */
    start_listen(dummy_sock);

    /* Create a dummy ondemand connection */
    pscom_con_t *con = pscom_con_create(dummy_sock);

    /* set connection parameters */
    con->pub.remote_con_info.node_id    = 42;
    con->pub.remote_con_info.tcp.portno = 42;
    memcpy(con->pub.remote_con_info.name, "r1428571",
           sizeof(con->pub.remote_con_info.name));

    _pscom_con_connect_ondemand(con);

    /* Save previous values for later comparison */
    activecnt = dummy_sock->listen.activecnt;

    /* Check the active listen counter */
    assert_true(activecnt == 1);

    /* Create a receive request and post it to the connection */
    pscom_request_t *req = pscom_request_create(0, 0);
    req->connection      = &con->pub;
    req->socket          = con->pub.socket;
    pscom_post_recv(req);

    /* The active counter must be increased by one due to the posting of the
     * request */
    assert_true(dummy_sock->listen.activecnt == activecnt + 1);

    /* reduce activecnt by 1*/
    con->read_stop(con);

    /* The active counter is decreased by one due to read_stop */
    assert_true(dummy_sock->listen.activecnt == activecnt);

    /* Test suspend listening on socket */
    suspend_listen(dummy_sock);

    assert_true(dummy_sock->listen.activecnt == 0);

    /* Test resume listening on socket */
    resume_listen(dummy_sock);

    assert_true(dummy_sock->listen.activecnt == 1);

    /* Test stop listening on socket */
    stop_listen(dummy_sock);

    /* Close the connection  */
    pscom_con_close(con);

    /* Both counters must be reset to 0 */
    assert_true(dummy_sock->listen.activecnt == 0);

    /* Close the socket */
    pscom_sock_close(dummy_sock);

    /* Check if ufd_info is detached from the list */
    assert_true(list_empty(&(dummy_sock->listen.ufd_info.next)));
}
