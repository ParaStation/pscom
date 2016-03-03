/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pscom_sock.h"
#include "pscom_con.h"
#include "pscom_io.h"
#include "pslib.h"
#include "pscom_precon.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

static
void _pscom_sock_terminate_all_recvs(pscom_sock_t *sock)
{
	struct list_head *pos;

	// Recvq's of all connections
	list_for_each(pos, &sock->connections) {
		pscom_con_t *con = list_entry(pos, pscom_con_t, next);

		pscom_con_terminate_recvq(con);
	}


	// RecvAny Queue:
	while (!list_empty(&sock->recvq_any)) {
		pscom_req_t *req = list_entry(sock->recvq_any.next, pscom_req_t, next);

		list_del(&req->next);
		req->pub.state |= PSCOM_REQ_STATE_ERROR;
		_pscom_recv_req_done(req); // done
	}
}



static
void pscom_sock_stop_listen(pscom_sock_t *sock)
{
	assert(sock->magic == MAGIC_SOCKET);

	if (sock->pub.listen_portno == -1) // Already stopped?
		return;

	pscom_listener_active_dec(&sock->listen);
	sock->pub.listen_portno = -1;
}


static
void pscom_sock_close(pscom_sock_t *sock)
{
	assert(sock->magic == MAGIC_SOCKET);

retry:
	pscom_sock_stop_listen(sock);

	while (!list_empty(&sock->connections)) {
		pscom_con_t *con = list_entry(sock->connections.next, pscom_con_t, next);
		pscom_con_close(con);
	}

	_pscom_sock_terminate_all_recvs(sock);

	pscom_call_io_done();

	if (!list_empty(&sock->connections) ||
	    !list_empty(&sock->recvq_any) ||
	    sock->pub.listen_portno != -1)
		goto retry; // in the case the io_doneq callbacks post more work

	if (!list_empty(&sock->next)) {
		list_del_init(&sock->next);
	}
}


static
void pscom_sock_set_name(pscom_sock_t *sock, const char *name)
{
	memset(sock->pub.local_con_info.name, 0, sizeof(sock->pub.local_con_info.name));
	strncpy(sock->pub.local_con_info.name, name, sizeof(sock->pub.local_con_info.name));
	pscom_info_set("socket", pscom_con_info_str(&sock->pub.local_con_info));
}


static
void pscom_sock_init_con_info(pscom_sock_t *sock)
{
	pscom_con_info_t *con_info = &sock->pub.local_con_info;
	char name[20];

	con_info->node_id = pscom_get_nodeid();
	con_info->pid = getpid();
	con_info->id = NULL;

	snprintf(name, sizeof(name), "p%d", con_info->pid);
	pscom_sock_set_name(sock, name);
}


static
pscom_sock_t *pscom_sock_create(unsigned int userdata_size)
{
	pscom_sock_t *sock;
	sock = malloc(sizeof(*sock) + userdata_size);
	if (!sock) return NULL; // error


	sock->magic = MAGIC_SOCKET;
	sock->pub.ops.con_accept = NULL;
	sock->pub.ops.con_error = NULL;
	sock->pub.ops.default_recv = NULL;

	sock->pub.listen_portno = -1;
	pscom_listener_init(&sock->listen, pscom_con_accept, sock);

	sock->con_type_mask = ~0ULL;
	sock->pub.userdata_size = userdata_size;
	sock->pub.connection_userdata_size = 0;

	INIT_LIST_HEAD(&sock->connections);
	INIT_LIST_HEAD(&sock->genrecvq_any);
	INIT_LIST_HEAD(&sock->recvq_any);
	INIT_LIST_HEAD(&sock->groups);
	INIT_LIST_HEAD(&sock->group_req_unknown);
	INIT_LIST_HEAD(&sock->pendingioq);
	INIT_LIST_HEAD(&sock->sendq_suspending);

	sock->recv_req_cnt_any = 0;

	pscom_sock_init_con_info(sock);

	pscom_plugins_sock_init(sock);

	return sock;
}


static
void pscom_sock_destroy(pscom_sock_t *sock)
{
	assert(sock->magic == MAGIC_SOCKET);
	assert(list_empty(&sock->next));
	assert(list_empty(&sock->connections));
	assert(list_empty(&sock->genrecvq_any));
	assert(list_empty(&sock->recvq_any));

	assert(sock->pub.listen_portno == -1);

	pscom_plugins_sock_destroy(sock);

	sock->magic = 0;

	free(sock);
}


int _pscom_con_type_mask_is_set(pscom_sock_t *sock, pscom_con_type_t con_type)
{
	return !!(sock->con_type_mask & (1ULL << con_type));
}

/*
******************************************************************************
*/

pscom_socket_t *pscom_open_socket(unsigned int userdata_size,
				  unsigned int connection_userdata_size)
{
	pscom_sock_t *sock;

	sock = pscom_sock_create(userdata_size);
	if (!sock) return NULL; // error

	sock->pub.connection_userdata_size = connection_userdata_size;

	pscom_lock(); {
		list_add_tail(&sock->next, &pscom.sockets);
	} pscom_unlock();

	return &sock->pub;
}


void pscom_socket_set_name(pscom_socket_t *socket, const char *name)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		pscom_sock_set_name(sock, name);
		DPRINT(1, "Socket name: %s", name);
		pscom_debug_set_prefix(name);
	} pscom_unlock();
}


pscom_err_t _pscom_listen(pscom_sock_t *sock, int portno)
{
	pscom_err_t ret = PSCOM_SUCCESS;
	struct sockaddr_in sa;
	unsigned int size;
	int listen_fd = -1;
	int retry_cnt = 0;

	if (sock->pub.listen_portno != -1)
		goto err_already_listening;

retry_listen:
	listen_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) goto err_socket;

	{
		int val = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
			   (void*) &val, sizeof(val));
	}

	sa.sin_family = AF_INET;
	sa.sin_port = (portno == PSCOM_ANYPORT) ? 0 : htons(portno);
	sa.sin_addr.s_addr = INADDR_ANY;

	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto err_bind;

	size = sizeof(sa);
	if (getsockname(listen_fd, (struct sockaddr *)&sa, &size) < 0)
		goto err_getsockname;

	if (listen(listen_fd, pscom.env.tcp_backlog) < 0) {
		if ((portno == PSCOM_ANYPORT) && errno == EADDRINUSE) {
			// Yes, this happens on 64 core machines. bind() rarely assign the same portno twice.
			retry_cnt++; // Print warning every 10th retry, or with PSP_DEBUG >= 1
			DPRINT((retry_cnt % 10 == 0) ? 0 : 1,
			       "listen(port %d): Address already in use", (int)ntohs(sa.sin_port));
			close(listen_fd);
			sleep(1);
			goto retry_listen;
		}
		goto err_listen;
	}

	DPRINT(PRECON_LL, "precon: listen(%d, %d) on port %u", listen_fd,
	       pscom.env.tcp_backlog, ntohs(sa.sin_port));

	if (fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0)
		goto err_nonblock;

	sock->pub.listen_portno = ntohs(sa.sin_port);
	pscom_listener_set_fd(&sock->listen, listen_fd);

	pscom_listener_active_inc(&sock->listen);

	return ret;

	/* error codes */
err_nonblock:
	DPRINT(1, "fcntl(listen_fd, F_SETFL, O_NONBLOCK) : %s", strerror(errno));
	goto err_stderror;
err_getsockname:
	DPRINT(1, "getsockname(port %d): %s", (int)ntohs(sa.sin_port), strerror(errno));
	goto err_stderror;
err_listen:
	DPRINT(1, "listen(port %d): %s", (int)ntohs(sa.sin_port), strerror(errno));
	goto err_stderror;
err_bind:
	DPRINT(1, "bind(port %d): %s", (int)ntohs(sa.sin_port), strerror(errno));
	goto err_stderror;
err_socket:
	DPRINT(1, "socket(PF_INET, SOCK_STREAM, 0): %s", strerror(errno));
	goto err_stderror;
err_stderror:
	ret = PSCOM_ERR_STDERROR;
	goto err_out;
err_already_listening:
	ret = PSCOM_ERR_ALREADY;
	goto err_out;
err_out:
	if (listen_fd >= 0) close(listen_fd);
	return ret;
}


pscom_err_t pscom_listen(pscom_socket_t *socket, int portno)
{
	pscom_sock_t *sock = get_sock(socket);
	pscom_err_t ret;

	assert(sock->magic == MAGIC_SOCKET);

	pscom_lock(); {
		ret = _pscom_listen(sock, portno);
	} pscom_unlock();

	return ret;
}


void pscom_close_socket(pscom_socket_t *socket)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		pscom_sock_close(sock);
		pscom_sock_destroy(sock);
	} pscom_unlock();
}


void pscom_stop_listen(pscom_socket_t *socket)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		pscom_sock_stop_listen(sock);
	} pscom_unlock();
}


void pscom_con_type_mask_all(pscom_socket_t *socket)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		sock->con_type_mask = ~0ULL;
	} pscom_unlock();
}


void pscom_con_type_mask_only(pscom_socket_t *socket, pscom_con_type_t con_type)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		assert(con_type < 64);
		sock->con_type_mask = 1ULL << con_type;
	} pscom_unlock();
}


void pscom_con_type_mask_add(pscom_socket_t *socket, pscom_con_type_t con_type)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		assert(con_type < 64);
		sock->con_type_mask |= 1ULL << con_type;
	} pscom_unlock();
}


void pscom_con_type_mask_del(pscom_socket_t *socket, pscom_con_type_t con_type)
{
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		assert(con_type < 64);

		sock->con_type_mask &= ~(1ULL << con_type);
	} pscom_unlock();
}


int pscom_con_type_mask_is_set(pscom_socket_t *socket, pscom_con_type_t con_type)
{
	int res;
	pscom_lock(); {
		pscom_sock_t *sock = get_sock(socket);
		assert(sock->magic == MAGIC_SOCKET);
		assert(con_type < 64);

		res = _pscom_con_type_mask_is_set(sock, con_type);
	} pscom_unlock();
	return res;
}
