/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdlib.h>

#include "pscom_priv.h"
#include "pscom_con.h"

#include "test_utils_con.h"

static
pscom_sock_t* create_dummy_sock(void)
{
	pscom_sock_t *sock = malloc(sizeof(pscom_sock_t));

	sock->magic = MAGIC_SOCKET;
	sock->recv_req_cnt_any = 0;

	INIT_LIST_HEAD(&sock->connections);
	INIT_LIST_HEAD(&sock->genrecvq_any);
	INIT_LIST_HEAD(&sock->recvq_any);
	INIT_LIST_HEAD(&sock->sendq_suspending);

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


int setup_dummy_con_pair(void **state)
{
	dummy_con_pair_t *con_pair = (dummy_con_pair_t*)malloc(sizeof(dummy_con_pair_t));

	setup_dummy_con(&con_pair->send_con);
	setup_dummy_con(&con_pair->recv_con);

	*state = (void*)con_pair;

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


int teardown_dummy_con_pair(void **state)
{
	dummy_con_pair_t *con_pair = (dummy_con_pair_t*)(*state);

	teardown_dummy_con(&con_pair->send_con);
	teardown_dummy_con(&con_pair->recv_con);

	free(con_pair);

	return 0;
}
