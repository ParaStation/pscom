/*
 * ParaStation
 *
 * Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Simon Pickartz <pickartz@par-tec.com>
 */

#include <stdlib.h>

#include "pscom_priv.h"
#include "pscom_con.h"

static
pscom_sock_t* create_dummy_sock(void)
{
	pscom_sock_t *sock = malloc(sizeof(pscom_sock_t));

	sock->magic = MAGIC_SOCKET;
	sock->recv_req_cnt_any = 0;

	INIT_LIST_HEAD(&sock->connections);
	INIT_LIST_HEAD(&sock->genrecvq_any);
	INIT_LIST_HEAD(&sock->recvq_any);

	return sock;
}

static
void destroy_dummy_sock(pscom_sock_t *sock)
{
	free(sock);
}

int setup_dummy_con(void **state)
{
	/* create a dummy socket */
	pscom_sock_t *sock = create_dummy_sock();

	/* create a new connection on that sock */
	pscom_con_t *con = pscom_con_create(sock);

	*state = (void*)con;

    return 0;
}

int teardown_dummy_con(void **state)
{
	pscom_con_t *con = (pscom_con_t*)(*state);
	pscom_sock_t *sock = get_sock(con->pub.socket);

	/* free connection-related resources */
	pscom_con_ref_release(con);

	/* destroy the dummy socket */
	destroy_dummy_sock(sock);

	return 0;
}
