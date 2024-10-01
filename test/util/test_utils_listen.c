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

#include "test_utils_listen.h"

#include "pscom.h"
#include "pscom_debug.h"
#include "pscom_priv.h"
#include "pscom_sock.h"

void start_listen(pscom_sock_t *sock)
{
    pscom_err_t rc = PSCOM_SUCCESS;

    assert_true(sock != NULL);

    pscom_sock_set_name(sock, "pscom_utest");
    pscom_debug_set_prefix("pscom_utest");

    /* Start listening on any available port (PSCOM_ANYPORT) */
    rc = _pscom_listen(sock, PSCOM_ANYPORT);
    assert_true(rc == PSCOM_SUCCESS);

    assert_true(sock->pub.listen_portno != -1);

    /* Both counters must be reset to 1 */
    assert_true(sock->listen.activecnt == 1);
    assert_true(sock->listen.usercnt == 1);

    /* Have active fd */
    assert_true(sock->listen.ufd_info.fd > 0);

    /* Listener should be listening for incoming connections */
    assert_true(sock->listen.ufd_info.pollfd_idx != -1);
}

void suspend_listen(pscom_sock_t *sock)
{
    unsigned int activecnt = 0;
    unsigned int usercnt   = 0;
    int port               = 0;

    /* Save previous values for later comparison */
    activecnt = sock->listen.activecnt;
    usercnt   = sock->listen.usercnt;
    port      = sock->pub.listen_portno;

    pscom_listener_suspend(&sock->listen);

    /* Must still have a listen port number assigned */
    assert_true(sock->pub.listen_portno == port);

    assert_true(sock->listen.suspend == 1);

    /* user counter must be incremented, active counter decremented */
    assert_true(sock->listen.activecnt == activecnt - 1);
    assert_true(sock->listen.usercnt == usercnt + 1);

    /* Still have active fd */
    assert_true(sock->listen.ufd_info.fd > 0);

    /* Listener MUST NOT be listening for incoming connections */
    assert_true(sock->listen.ufd_info.pollfd_idx == -1);
}

void resume_listen(pscom_sock_t *sock)
{
    unsigned int activecnt = 0;
    unsigned int usercnt   = 0;
    int port               = 0;

    /* Save previous values for later comparison */
    activecnt = sock->listen.activecnt;
    usercnt   = sock->listen.usercnt;
    port      = sock->pub.listen_portno;

    pscom_listener_resume(&sock->listen);

    /* Must still have a listen port number assigned */
    assert_true(sock->pub.listen_portno == port);

    assert_true(sock->listen.suspend == 0);

    /* user counter must be decremented, active counter incremented */
    assert_true(sock->listen.activecnt == activecnt + 1);
    assert_true(sock->listen.usercnt == usercnt - 1);

    /* Still have active fd */
    assert_true(sock->listen.ufd_info.fd > 0);

    /* Listener MUST be listening for incoming connections again */
    assert_true(sock->listen.ufd_info.pollfd_idx != -1);
}

void stop_listen(pscom_sock_t *sock)
{
    pscom_sock_stop_listen(sock);

    /* Port must be reset to -1 */
    assert_true(sock->pub.listen_portno == -1);
}
