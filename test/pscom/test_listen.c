/*
 * ParaStation
 *
 * Copyright (C) 2024 ParTec AG, Munich
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

#include "pscom_priv.h"
#include "pscom_sock.h"
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
