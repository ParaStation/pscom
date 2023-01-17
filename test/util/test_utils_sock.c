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

#include <stdlib.h>

#include "pscom_priv.h"
#include "pscom_con.h"

#include "test_utils_sock.h"

int setup_dummy_sock(void **state)
{
	pscom_sock_t *new_sock = NULL;

	INIT_LIST_HEAD(&pscom.sockets);
	INIT_LIST_HEAD(&pscom.recvq_any_global);

	new_sock = pscom_open_sock(0, 0);
	*state = (void *)new_sock;

	return 0;
}


int teardown_dummy_sock(void **state)
{
	pscom_sock_t *sock = (pscom_sock_t *)(*state);

	free(sock);

	return 0;
}
