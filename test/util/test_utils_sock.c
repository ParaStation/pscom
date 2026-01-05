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

#include "test_utils_sock.h"

#include <stdlib.h>

#include "list.h"
#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_sock.h"
#include "test_utils_provider.h"


int setup_dummy_sock(void **state)
{
    pscom_sock_t *new_sock = NULL;

    INIT_LIST_HEAD(&pscom.sockets);
    INIT_LIST_HEAD(&pscom.recvq_any_global);

    /* init precon provider with tcp*/
    setup_dummy_provider("tcp");

    new_sock = pscom_sock_create(0, 0, PSCOM_RANK_UNDEFINED,
                                 PSCOM_SOCK_FLAG_INTRA_JOB);
    *state   = (void *)new_sock;

    return 0;
}


int teardown_dummy_sock(void **state)
{
    pscom_sock_t *sock = (pscom_sock_t *)(*state);
    pscom_sock_unset_id(sock);
    free(sock);

    /* destroy provider */
    teardown_dummy_provider();

    return 0;
}
