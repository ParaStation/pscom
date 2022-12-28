/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_group.h"
#include <stdlib.h>
#include <assert.h>


pscom_group_t *_pscom_group_find(pscom_sock_t *sock, uint32_t group_id)
{
	struct list_head *head = &sock->groups;
	struct list_head *pos;

	// ToDo: Use a hash from group_id and a hash_table!

	list_for_each(pos, head) {
		pscom_group_t *group = list_entry(pos, pscom_group_t, next);

		if (group->group_id == group_id) {
			return group;
		}
	}
	return NULL;
}



/***********************/
static
void _pscom_group_close(pscom_group_t *group)
{
	assert(group->magic == MAGIC_GROUP);
	group->magic = 0;

	list_del(&group->next); // dequeue from sock->groups list

	free(group->compat); group->compat = NULL;
	free(group->member); group->member = NULL;
	free(group);
}



static
pscom_group_t *pscom_group_create(pscom_socket_t *socket,
				  uint32_t group_id, uint32_t my_grank,
				  uint32_t group_size, pscom_connection_t **connections)
{
	pscom_sock_t *sock = get_sock(socket);
	pscom_group_t *group = malloc(sizeof(*group));
	group->magic = MAGIC_GROUP;

	group->group_id = group_id;
	group->my_grank = my_grank;
	group->group_size = group_size;

	group->member = malloc(sizeof(*group->member) * group_size);

	unsigned i;
	for (i = 0; i < group_size; i++) {
		pscom_group_mem_t *mem = group->member + i;

		mem->con = get_con(connections[i]);
		assert(mem->con && (mem->con->magic == MAGIC_CONNECTION));

		INIT_LIST_HEAD(&mem->genrecvq);
		INIT_LIST_HEAD(&mem->recvq);
	}

	group->sock = sock;

	/* Initialize communication pattern */
	pscom_group_gcompat_init(group);

	return group;
}


static
void _pscom_group_open(pscom_group_t *group)
{
	pscom_sock_t *sock = group->sock;

	/* Double usage of group_id? */
	assert(_pscom_group_find(sock, group->group_id) == NULL);

	/* Enqueue to socket */
	list_add(&group->next, &sock->groups);

	/* Replay already received bcast messages with this groupid */
	pscom_group_replay_bcasts(sock, group->group_id);
}


/*
******************************************************************************
*/

PSCOM_API_EXPORT
pscom_group_t *pscom_group_open(pscom_socket_t *socket,
				uint32_t group_id, uint32_t my_grank,
				uint32_t group_size, pscom_connection_t **connections)
{
	pscom_sock_t *sock = get_sock(socket);

	assert(my_grank < group_size);
	assert(sock->magic == MAGIC_SOCKET);

	pscom_group_t *group = pscom_group_create(socket, group_id, my_grank,
						  group_size, connections);
	pscom_lock(); {
		_pscom_group_open(group);
	} pscom_unlock();

	return group;
}


PSCOM_API_EXPORT
void pscom_group_close(pscom_group_t *group)
{
	pscom_lock(); {
		_pscom_group_close(group);
	} pscom_unlock();
}


/***********************************
 * Barrier
 */

static inline
pscom_req_t *pscom_barrier_create_req(pscom_group_t *group)
{
	pscom_req_t *req;

	req = pscom_req_create(sizeof(req->pub.xheader.bcast), 0);
	req->pub.xheader_len = sizeof(req->pub.xheader.bcast);
	req->pub.xheader.bcast.group_id = group->group_id;
	req->pub.data_len = 0;

	return req;
}


static
int recv_accept_barrier(pscom_request_t *request,
			pscom_connection_t *connection,
			pscom_header_net_t *header_net)
{
	return request->xheader.bcast.group_id == header_net->xheader->bcast.group_id;
}


PSCOM_API_EXPORT
void pscom_barrier(pscom_group_t *group)
{
	pscom_req_t *req_send;
	pscom_req_t *req_recv;
	unsigned offset;

	if (group->group_size <= 1) return; // simple case

	req_send = pscom_barrier_create_req(group);
	req_recv = pscom_barrier_create_req(group);

	req_recv->pub.header.msg_type = PSCOM_MSGTYPE_BARRIER;
	req_recv->pub.ops.recv_accept = recv_accept_barrier;

	/* Send messages to (myrank + 2^i). Receive messages from (myrank - 2^i).
	   If we receive something before a matching receive,
	   we generate a recv request in _pscom_get_ctrl_receiver() */
	for (offset = 1; offset < group->group_size; offset = offset * 2) {
		unsigned dest = (group->my_grank + offset) % group->group_size;
		unsigned src = (group->my_grank + group->group_size - offset) % group->group_size;

		req_recv->pub.connection = group_rank2connection(group, src);
		pscom_post_recv_ctrl(req_recv);

		req_send->pub.connection = group_rank2connection(group, dest);
		pscom_post_send_direct(req_send, PSCOM_MSGTYPE_BARRIER);

		pscom_wait(&req_send->pub);
		pscom_wait(&req_recv->pub);
	}

	pscom_req_free(req_recv);
	pscom_req_free(req_send);
}


/*
 * Group handling (translate between group_id and pscom_group_t)
 */

PSCOM_API_EXPORT
pscom_group_t *pscom_group_find(pscom_socket_t *socket, uint32_t group_id)
{
	pscom_sock_t *sock = get_sock(socket);
	pscom_group_t *group;

	assert(sock->magic == MAGIC_SOCKET);

	pscom_lock(); {
		group = _pscom_group_find(sock, group_id);
	} pscom_unlock();

	return group;
}


PSCOM_API_EXPORT
uint32_t pscom_group_get_id(pscom_group_t *group)
{
	assert(group->magic == MAGIC_GROUP);

	return group->group_id;
}
