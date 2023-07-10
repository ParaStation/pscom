/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "pscom_priv.h"
#include "pscom_con.h"

#include "test_utils_con.h"
#include "test_utils_sock.h"


int setup_dummy_con(void **state)
{
    /* ensure the polling lists are empty before test execution */
    assert_true(list_empty(&(&pscom.poll_read)->head));
    assert_true(list_empty(&(&pscom.poll_write)->head));

    /* create a dummy socket */
    pscom_sock_t *sock = NULL;
    setup_dummy_sock((void **)&sock);

    /* create a new connection on that sock */
    pscom_con_t *con = pscom_con_create(sock);

    *state = (void *)con;

    return 0;
}


int setup_dummy_con_pair(void **state)
{
    dummy_con_pair_t *con_pair = (dummy_con_pair_t *)malloc(
        sizeof(dummy_con_pair_t));

    setup_dummy_con(&con_pair->send_con);
    setup_dummy_con(&con_pair->recv_con);

    *state = (void *)con_pair;

    return 0;
}


int teardown_dummy_con(void **state)
{
    pscom_con_t *con   = (pscom_con_t *)(*state);
    pscom_sock_t *sock = get_sock(con->pub.socket);

    /* free connection-related resources */
    if (!con->state.destroyed) { pscom_con_ref_release(con); }

    /* destroy the dummy socket */
    teardown_dummy_sock((void **)&sock);

    return 0;
}


int teardown_dummy_con_pair(void **state)
{
    dummy_con_pair_t *con_pair = (dummy_con_pair_t *)(*state);

    teardown_dummy_con(&con_pair->send_con);
    teardown_dummy_con(&con_pair->recv_con);

    free(con_pair);

    return 0;
}
