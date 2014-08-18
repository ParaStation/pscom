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

#include "pscom_con.h"
#include "pscom_str_util.h"
#include "pscom_io.h"
#include "pscom_queues.h"
#include "pscom_req.h"
#include "pslib.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <errno.h>

static
int mtry_connect(int sockfd, const struct sockaddr *serv_addr,
		 socklen_t addrlen)
{
/* In the case the backlog (listen) is smaller than the number of
   processes, the connect could fail with ECONNREFUSED even though
   there is a linstening socket. mtry_connect() retry four times
   the connect after one second delay.
*/
	unsigned int i;
	int ret = 0;
	struct sockaddr_in *sa = (struct sockaddr_in*)serv_addr;
	for (i = 0; i < pscom.env.retry; i++) {
		ret = connect(sockfd, serv_addr, addrlen);
		if (ret >= 0) break;
		if (errno != ECONNREFUSED) break;
		sleep(1);
		DPRINT(2, "Retry %d CONNECT to %s:%d",
		       i + 1,
		       pscom_inetstr(ntohl(sa->sin_addr.s_addr)),
		       ntohs(sa->sin_port));
	}
	return ret;
}


static
void pscom_con_info_set(pscom_con_t *con, const char *path, const char *val)
{
	char buf[80];
	snprintf(buf, sizeof(buf), "con/%.8s/%s",
		 con->pub.remote_con_info.name,
		 path);
	pscom_info_set(buf, val);
}


void pscom_no_rw_start_stop(pscom_con_t *con)
{
}


static
void tcp_configure(int fd)
{
	int ret;
	int val;

	if (pscom.env.so_sndbuf) {
		errno = 0;
		val = pscom.env.so_sndbuf;
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
		DPRINT(2, "setsockopt(%d, SOL_SOCKET, SO_SNDBUF, [%d], %ld) = %d : %s",
		       fd, val, (long)sizeof(val), ret, strerror(errno));
	}
	if (pscom.env.so_rcvbuf) {
		errno = 0;
		val = pscom.env.so_rcvbuf;
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
		DPRINT(2, "setsockopt(%d, SOL_SOCKET, SO_RCVBUF, [%d], %ld) = %d : %s",
		       fd, val, (long)sizeof(val), ret, strerror(errno));
	}
	errno = 0;
	val = pscom.env.tcp_nodelay;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	DPRINT(2, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY, [%d], %ld) = %d : %s",
	       fd, val, (long) sizeof(val), ret, strerror(errno));
}


// clear sendq. finish all send requests with error
static
void _pscom_con_terminate_sendq(pscom_con_t *con)
{
	while (!list_empty(&con->sendq)) {
		pscom_req_t *req = list_entry(con->sendq.next, pscom_req_t, next);

		list_del(&req->next); // dequeue

		req->pub.state |= PSCOM_REQ_STATE_ERROR;
		_pscom_send_req_done(req); // done
	}
}


// clear all recvq's of this connection. finish all recv requests
// of this connection with error. (keep recv any!)
void pscom_con_terminate_recvq(pscom_con_t *con)
{
	struct list_head *pos, *next;

	// current receive:
	if (con->in.req) {
		pscom_req_t *req = con->in.req;
		con->in.req = NULL;
		req->pub.state |= PSCOM_REQ_STATE_ERROR;
		_pscom_recv_req_done(req); // done
	}

	// Recv Queue:
	while (!list_empty(&con->recvq_user)) {
		pscom_req_t *req = list_entry(con->recvq_user.next, pscom_req_t, next);

		_pscom_recvq_user_deq(req); // dequeue

		req->pub.state |= PSCOM_REQ_STATE_ERROR;
		_pscom_recv_req_done(req); // done
	}

	// RecvAny Queue:
	list_for_each_safe(pos, next, &get_sock(con->pub.socket)->recvq_any) {
		pscom_req_t *req = list_entry(pos, pscom_req_t, next);

//		fprintf(stderr, "Test rm "RED"req %p  con %p == %p "NORM"\n", req, req->pub.connection, &con->pub);
		if (req->pub.connection == &con->pub) {
//			fprintf(stderr, RED "remove con %p\n"NORM, req);

			_pscom_recvq_user_deq(req); // dequeue

			req->pub.state |= PSCOM_REQ_STATE_ERROR;
			_pscom_recv_req_done(req); // done
		}
	}
}


static
void _pscom_con_terminate_net_queues(pscom_con_t *con)
{
	// genreqq:
	while (!list_empty(&con->net_recvq_user)) {
		pscom_req_t *req = list_entry(con->net_recvq_user.next, pscom_req_t, next);

		_pscom_net_recvq_user_deq(req);

		/* ToDo: if (genreq->partner_req) send rendezvous Cancel!!! */
		req->partner_req = NULL;

		_pscom_grecv_req_done(req); // done
		pscom_greq_check_free(con, req);
	}

#if 0
	// ToDo: terminate all bcast requests
	while (!list_empty(&con->net_recvq_bcast)) {
		pscom_req_t *req = list_entry(con->net_recvq_bcast.next, pscom_req_t, next);

		_pscom_net_recvq_bcast_deq(req);

		/* ToDo: something to cancel? forwards? user requests? */

		_pscom_req_bcast_done(req); // done
	}
#endif
}


static
void pscom_con_end_read(pscom_con_t *con)
{
	con->read_stop(con);
	con->pub.state &= ~PSCOM_CON_STATE_R; // clear R
	con->read_start = pscom_con_terminate_recvq;

	pscom_con_terminate_recvq(con);
}


static
void pscom_con_end_write(pscom_con_t *con)
{
	con->write_stop(con);
	con->pub.state &= ~PSCOM_CON_STATE_W; // clear W
	con->write_start = _pscom_con_terminate_sendq;

	_pscom_con_terminate_sendq(con);
}


static
void pscom_con_error_read_failed(pscom_con_t *con, pscom_err_t error)
{
	pscom_con_end_read(con);
	pscom_con_info_set(con, "state", pscom_con_state_str(con->pub.state));
}


static
void pscom_con_error_write_failed(pscom_con_t *con, pscom_err_t error)
{
	pscom_con_end_write(con);
	pscom_con_info_set(con, "state", pscom_con_state_str(con->pub.state));
}


void pscom_con_close(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);
	if (con->pub.state != PSCOM_CON_STATE_CLOSED) {
		D_TR(printf("pscom_con_close(con:%p) : state: %s\n", con,
			    pscom_con_state_str(con->pub.state)));
	retry:
		pscom_con_end_write(con);
		pscom_con_end_read(con);

		_pscom_con_terminate_net_queues(con);

		assert(con->pub.state == PSCOM_CON_STATE_NO_RW);
		assert(list_empty(&con->sendq));
		assert(list_empty(&con->recvq_user));
		assert(list_empty(&con->net_recvq_user));
		assert(con->in.req == NULL);
		// ToDo: check for group requests?
		// assert(list_empty(&group->???->recvq_bcast));
		// assert(list_empty(&group->???->net_recvq_bcast));
		pscom_call_io_done();

		if (!list_empty(&con->sendq) ||
		    !list_empty(&con->recvq_user) ||
		    !list_empty(&con->net_recvq_user) ||
		    // !list_empty(&con->recvq_bcast) ||
		    // !list_empty(&con->net_recvq_bcast) ||
		    con->in.req) goto retry; // in the case the io_doneq callbacks post more work

		if (con->close) con->close(con);

		list_del(&con->next);
		con->pub.state = PSCOM_CON_STATE_CLOSED;
		pscom_con_info_set(con, "state", pscom_con_state_str(con->pub.state));
		_pscom_step();
	}
}


void pscom_con_error(pscom_con_t *con, pscom_op_t operation, pscom_err_t error)
{
	assert(con->magic == MAGIC_CONNECTION);

	DPRINT(error != PSCOM_ERR_EOF ? 1 : 2,
	       "connection to %s (type:%s,state:%s) : %s : %s",
	       pscom_con_info_str(&con->pub.remote_con_info),
	       pscom_con_type_str(con->pub.type),
	       pscom_con_state_str(con->pub.state),
	       pscom_op_str(operation),
	       pscom_err_str(error));

	_pscom_step();

	switch (operation) {
	case PSCOM_OP_READ:
		pscom_con_error_read_failed(con, error);
		break;
	case PSCOM_OP_WRITE:
		pscom_con_error_write_failed(con, error);
		break;
	}

	if (con->pub.socket->ops.con_error) {
		con->pub.socket->ops.con_error(&con->pub, operation, error);
	}
}


void pscom_con_info(pscom_con_t *con, pscom_con_info_t *con_info)
{
	*con_info = con->pub.socket->local_con_info;
	con_info->id = &con->pub;
}


static
pscom_con_t *pscom_con_create(pscom_sock_t *sock)
{
	pscom_con_t *con;
	con = malloc(sizeof(*con) + sock->pub.connection_userdata_size);
	if (!con) return NULL;

	con->magic = MAGIC_CONNECTION;
	con->pub.socket = &sock->pub;
	con->pub.userdata_size = sock->pub.connection_userdata_size;
	con->pub.state = PSCOM_CON_STATE_CLOSED;
	con->pub.type = PSCOM_CON_TYPE_NONE;

	con->recv_req_cnt = 0;
	INIT_LIST_HEAD(&con->sendq);
	INIT_LIST_HEAD(&con->recvq_user);
	INIT_LIST_HEAD(&con->recvq_ctrl);
	INIT_LIST_HEAD(&con->recvq_rma);
	INIT_LIST_HEAD(&con->net_recvq_user);
	INIT_LIST_HEAD(&con->net_recvq_ctrl);

	INIT_LIST_HEAD(&con->poll_reader.next);
	INIT_LIST_HEAD(&con->poll_next_send);

	con->in.req	= 0;
	con->in.req_locked = 0;
	con->in.skip	= 0;

	con->in.readahead.iov_base = NULL;
	con->in.readahead.iov_len = 0;
	con->in.readahead_size = 0;

	con->write_start = pscom_no_rw_start_stop;
	con->write_stop = pscom_no_rw_start_stop;
	con->read_start = pscom_no_rw_start_stop;
	con->read_stop = pscom_no_rw_start_stop;
	con->poll_reader.do_read = NULL;
	con->do_write = NULL;
	con->close = pscom_no_rw_start_stop;
	/* RMA */
	con->rma_mem_register = NULL;
	con->rma_mem_deregister = NULL;
	con->rma_read = NULL;

	con->rendezvous_size = pscom.env.rendezvous_size;

	return con;
}


static
void pscom_con_destroy(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);
	assert(con->pub.state == PSCOM_CON_STATE_CLOSED);
	assert(list_empty(&con->poll_next_send));
	assert(list_empty(&con->poll_reader.next));

	con->magic = 0;
	free(con);
}


void pscom_con_setup(pscom_con_t *con)
{
	if (pscom_pslib_available) {
		pscom_con_info_set(con, "type", pscom_con_type_str(con->pub.type));
		pscom_con_info_set(con, "remote", pscom_con_info_str(&con->pub.remote_con_info));
	}

	if (con->recv_req_cnt || pscom.env.unexpected_receives) {
		con->read_start(con);
	}

	/* If there are anysrc receives posted, they have to be also
	   counted in this con (see pscom_queues.c:_pscom_recv_req_cnt_any_inc()).
	   To avoid a second call to con->read_start() this should be tested
	   AFTER the con->recv_req_cnt test above.*/
	pscom_sock_t *sock = get_sock(con->pub.socket);
	if (sock->recv_req_cnt_any) {
		_pscom_recv_req_cnt_inc(con);
	}


	if (!list_empty(&con->sendq)) {
		con->write_start(con);
	}
}


static
int pscom_is_valid_con(pscom_con_t *con)
{
	struct list_head *pos_sock;
	struct list_head *pos_con;
	list_for_each(pos_sock, &pscom.sockets) {
		pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

		list_for_each(pos_con, &sock->connections) {
			pscom_con_t *con2 = list_entry(pos_con, pscom_con_t, next);

			if (con2 == con) {
				D_TR(printf("pscom_is_valid_con(%p) = 1\n", con));
				return 1;
			}
		}
	}
	D_TR(printf("pscom_is_valid_con(%p) = 0\n", con));

	return 0;
}


#define PSCOM_INFO_EOF		0x100000	/* Last info message */
#define PSCOM_INFO_ANSWER	0x100001	/* request remote side, to send answers */
#define PSCOM_INFO_CON_INFO	0x100002	/* pscom_con_info_t */
#define PSCOM_INFO_VERSION	0x100003	/* pscom_info_version_t */
#define PSCOM_INFO_BACK_CONNECT	0x100004	/* pscom_con_info_t Request a back connect */


typedef struct {
	/* supported version range from sender,
	   overlap must be non empty. */
	uint32_t	ver_from;
	uint32_t	ver_to;
} pscom_info_version_t;

#define VER_FROM 0x0101
#define VER_TO   0x0101


static
int pscom_info_send(int fd, unsigned type, unsigned size, void *data)
{
	uint32_t ntype = htonl(type);
	uint32_t nsize = htonl(size);
	int err = 0;

	err = err || pscom_writeall(fd, &ntype, sizeof(ntype)) != sizeof(ntype);
	err = err || pscom_writeall(fd, &nsize, sizeof(nsize)) != sizeof(nsize);
	err = err || pscom_writeall(fd, data, size) != (int)size;

	return err;
}


/* will receive into *type, *size and *data = realloc(*data, *size) */
static
int pscom_info_recv(int fd, unsigned *type, unsigned *size, void **data)
{
	int err = 0;
	uint32_t ntype = 0;
	uint32_t nsize = 0;

	err = err || pscom_readall(fd, &ntype, sizeof(ntype)) != sizeof(ntype);
	err = err || pscom_readall(fd, &nsize, sizeof(nsize)) != sizeof(nsize);

	*size = ntohl(nsize);
	*type = ntohl(ntype);

	if (!err) {
		*data = realloc(*data, *size);
		err = err || pscom_readall(fd, *data, *size) != (int)*size;
	}

	if (err) {
		*type = PSCOM_INFO_EOF;
		*size = 0;
		free(*data);
		*data = NULL;
	}
	return err;
}


void pscom_ondemand_indirect_connect(pscom_con_t *con)
{
	int nodeid = con->arch.ondemand.node_id;
	int portno = con->arch.ondemand.portno;
	int fd;

	fd = pscom_tcp_connect(nodeid, portno);
	if (fd >= 0) {
		pscom_con_info_t con_info;
		pscom_con_info(con, &con_info);

		DPRINT(3, "RCONNECT%s", pscom_con_str_reverse(&con->pub));

		pscom_info_send(fd, PSCOM_INFO_BACK_CONNECT, sizeof(con_info), &con_info);
		close(fd);
	}
}


static
int pscom_info_exchange_send(int fd, pscom_con_t *con, unsigned end_with)
{
	pscom_con_info_t con_info;
	pscom_info_version_t ver;
	int err = 0;

	/* exchange connection information */
	pscom_con_info(con, &con_info);

	err = err || pscom_info_send(fd, PSCOM_INFO_CON_INFO, sizeof(con_info), &con_info);

	/* Send supported versions */
	ver.ver_from = VER_FROM;
	ver.ver_to   = VER_TO;
	err = err || pscom_info_send(fd, PSCOM_INFO_VERSION, sizeof(ver), &ver);

	/* eof of exchange */
	err = err || pscom_info_send(fd, end_with, 0, NULL);

	return err;
}


static
int pscom_info_exchange_recv(int fd, pscom_con_t **con, unsigned end_with, int passive)
{
	uint32_t type;
	uint32_t size;
	void *data = NULL;
	int err = 0;

	while (1) {
		err = err || pscom_info_recv(fd, &type, &size, &data);
		if (err) {
			errno = EBADE;
			break;
		}

		switch (type) {
		case PSCOM_INFO_EOF: /* fall through */
		case PSCOM_INFO_ANSWER:
			if (type != end_with) {
				errno = EBADE;
				err = -1;
			}
			goto out;
		case PSCOM_INFO_CON_INFO: {
			pscom_con_info_t *con_info = data;
			assert(size == sizeof(*con_info));
			if (passive) {
				// Search for an existing matching connection
				pscom_sock_t *sock = get_sock((*con)->pub.socket);
				pscom_con_t *con_exist = pscom_ondemand_get_con(sock, con_info->name);
				if (con_exist) {
					/* replace con by the existing one */
					pscom_con_destroy(*con);
					*con = con_exist;
				} else if (sock->pub.listen_portno == -1) {
					/* No con found AND not listening.
					   Reject this connection! */
					DPRINT(1, "Reject %s : unknown connection and not listening", pscom_con_info_str(con_info));
					errno = EINVAL;
					err = -1;
					goto out;
				}
			}
			(*con)->pub.remote_con_info = *con_info;
			break;
		}
		case PSCOM_INFO_VERSION: {
			pscom_info_version_t *ver = data;
			assert(size >= sizeof(*ver)); /* with space for the future */
			if ((VER_TO < ver->ver_from) || (ver->ver_to < VER_FROM)) {
				DPRINT(0, "CONNECT %s : Protocol version overlap empty [%04x..%04x] to [%04x..%04x]",
				       pscom_con_str(&(*con)->pub),
				       VER_FROM, VER_TO, ver->ver_from, ver->ver_to);
				errno = EPROTO;
				err = -1;
				goto out;
			}
			break;
		}
		case PSCOM_INFO_BACK_CONNECT: {
			pscom_con_info_t *con_info = data;
			assert(size == sizeof(*con_info));
			pscom_sock_t *sock = get_sock((*con)->pub.socket);
			// Search for an existing matching connection
			pscom_con_t *con_exist = pscom_ondemand_find_con(sock, con_info->name);

			if (passive && con_exist) {
				/* Trigger the back connect */
				DPRINT(3, "RACCEPT %s", pscom_con_str(&con_exist->pub));
				con_exist->write_start(con_exist);
			} else {
				DPRINT(3, "RACCEPT from %s skipped", pscom_con_info_str(con_info));
			}
			errno = 0; // No error
			err = -1; // but close this connection.
			goto out;
			break;
		}
		default: /* ignore all unknown info messages */
			;
		}
	} while (!err);
out:
	free(data);

	return err;
}


static
int pscom_info_exchange_active(int fd, pscom_con_t *con)
{
	int err = 0;
	pscom_con_t *con_bak = con;

	err = err || pscom_info_exchange_send(fd, con, PSCOM_INFO_ANSWER);
	err = err || pscom_info_exchange_recv(fd, &con, PSCOM_INFO_EOF, 0);
	assert(con == con_bak);

	return err;
}


static
int pscom_info_exchange_passive(int fd, pscom_con_t **con)
{
	int err = 0;

	err = err || pscom_info_exchange_recv(fd, con, PSCOM_INFO_ANSWER, 1);
	err = err || pscom_info_exchange_send(fd, *con, PSCOM_INFO_EOF);

	return err;
}


void pscom_con_accept(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
	pscom_sock_t *sock = ufd_info->priv;

	pscom_con_t *con, *con_bak;
	int con_fd;
	int is_ondemand;

	/* Open connection */
	con = pscom_con_create(sock);
	if (!con) goto err_connection_create;

	/* Open the socket */
	int listen_fd = pscom_listener_get_fd(&sock->listen);
	con_fd = accept(listen_fd, NULL, NULL);
	if (con_fd < 0) goto err_accept;

	tcp_configure(con_fd);

	/* pscom_info_exchange_passive() can change con to an existing one! */
	con_bak = con;
	if (pscom_info_exchange_passive(con_fd, &con))
		goto err_info_exchange;
	is_ondemand = con_bak != con;

	while (1) {
		int arch;

		if (pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch))
			goto err_init_failed;

		pscom_plugin_t *p = NULL;

		if (_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(arch))) {
			p = pscom_plugin_by_archid(arch);
		}
		if (p) {
			if (p->con_accept(con, con_fd)) goto out;
		} else {
			// Unknown or disabled arch
			arch = PSCOM_ARCH_ERROR;
			pscom_writeall(con_fd, &arch, sizeof(arch));
		}
	}
	/* --- */
out:
	if (1 <= pscom.env.debug) {
		DPRINT(1, "ACCEPT  %s via %s%s",
		       pscom_con_str_reverse(&con->pub),
		       pscom_con_type_str(con->pub.type),
		       is_ondemand ? "(demand)" : "");
	}

	list_add_tail(&con->next, &sock->connections);

	if (sock->pub.ops.con_accept && (!is_ondemand)) {
		// call con_accept only if this is NOT an on demand connection
		pscom_unlock(); {
			sock->pub.ops.con_accept(&con->pub);
		} pscom_lock();
	}

	// warning: sock->pub.ops.connection_accept() can call free(con)!
	if (pscom_is_valid_con(con)) {
		pscom_con_setup(con);
	}

	_pscom_step();

	return;
	/* --- */
err_init_failed:
	errno = EPIPE;
err_info_exchange:
	close(con_fd);
err_accept:
	pscom_con_destroy(con);
	if (errno) DPRINT(1, "ACCEPT failed : %s", strerror(errno));
	return;
	/* --- */
err_connection_create:
	DPRINT(1, "ACCEPT failed (create connection failed) : %s",
	       strerror(errno));
	return;
}


static
void pscom_sockaddr_init(struct sockaddr_in *si, int nodeid, int portno)
{
	/* Setup si for TCP */
	si->sin_family = PF_INET;
	si->sin_port = htons(portno);
	si->sin_addr.s_addr = htonl(nodeid);
}


int pscom_tcp_connect(int nodeid, int portno)
{
	struct sockaddr_in si;
	int fd;

	/* Open the socket */
	fd = socket(PF_INET , SOCK_STREAM, 0);
	if (fd < 0) goto err_socket;

	pscom_sockaddr_init(&si, nodeid, portno);

	/* Connect */
	if (mtry_connect(fd, (struct sockaddr*)&si, sizeof(si)) < 0) goto err_connect;

	tcp_configure(fd);

	return fd;
err_connect:
	close(fd);
err_socket:
	return -1;
}


pscom_err_t pscom_con_connect_via_tcp(pscom_con_t *con, int nodeid, int portno)
{
	int con_fd;
	int initialized = 0;
	pscom_con_info_t con_info;
	pscom_sock_t *sock = get_sock(con->pub.socket);

	pscom_con_info(con, &con_info);

	con_fd = pscom_tcp_connect(nodeid, portno);
	if (con_fd < 0) goto err_connect;

	if (pscom_info_exchange_active(con_fd, con))
		goto err_info_exchange;

	struct list_head *pos;

	/* Search for "best" connections */
	list_for_each(pos, &pscom_plugins) {
		pscom_plugin_t *p = list_entry(pos, pscom_plugin_t, next);

		if (!_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(p->arch_id))) {
			continue;
		}

		initialized = p->con_connect(con, con_fd);
		if (initialized) break;
	}

	if (!initialized)
		goto err_init_failed;

	DPRINT(1, "CONNECT %s via %s",
	       pscom_con_str(&con->pub),
	       pscom_con_type_str(con->pub.type));

	list_add_tail(&con->next, &sock->connections);

	pscom_con_setup(con);

	return PSCOM_SUCCESS;

	/* error code */
err_init_failed:
	errno = EUNATCH;
err_info_exchange:
	close(con_fd);
err_connect:
	DPRINT(1, "CONNECT %s to tcp:%s:%u FAILED : %s",
	       pscom_con_info_str(&con_info),
	       pscom_inetstr(nodeid),
	       portno,
	       strerror(errno));

	return PSCOM_ERR_STDERROR;
}


static void
loopback_write_start(pscom_con_t *con)
{
	int i;
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	// already inside the sending "while loop"?
	// (recursive called via pscom_read_done())
	if (con->arch.loop.sending) return;
	con->arch.loop.sending = 1;

	while (1) {
		req = pscom_write_get_iov(con, iov);
		if (!req) break;

		len = 0;
		for (i = 0; i < 2; i++) {
			len += iov[i].iov_len;
			if (iov[i].iov_len) {
				pscom_read_done(con, iov[i].iov_base, iov[i].iov_len);
			}
		}
		pscom_write_done(con, req, len);
	}

	con->arch.loop.sending = 0;
}


pscom_err_t pscom_con_connect_loopback(pscom_con_t *con)
{
	pscom_sock_t *sock = get_sock(con->pub.socket);

	/* exchange connection information */
	pscom_con_info(con, &con->pub.remote_con_info);

	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_LOOP;

	con->write_start = loopback_write_start;
//	con->rendezvous_size = (unsigned)~0; // disable rendezvous for loopback

	DPRINT(1, "CONNECT %s via %s",
	       pscom_con_str(&con->pub),
	       pscom_con_type_str(con->pub.type));

	list_add_tail(&con->next, &sock->connections);

	con->arch.loop.sending = 0;

	if (sock->pub.ops.con_accept) {
		pscom_unlock(); {
			sock->pub.ops.con_accept(&con->pub);
		} pscom_lock();
	}

	// warning: sock->pub.ops.connection_accept() can call free(con)!
	if (pscom_is_valid_con(con)) {
		pscom_con_setup(con);
	}

	return PSCOM_SUCCESS;
}


/*
******************************************************************************
*/

pscom_connection_t *pscom_open_connection(pscom_socket_t *socket)
{
	pscom_sock_t *sock = get_sock(socket);
	pscom_con_t *con;

	pscom_lock(); {
		con = pscom_con_create(sock);
	} pscom_unlock();

	return con ? &con->pub : NULL;
}


int pscom_is_local(pscom_socket_t *socket, int nodeid, int portno)
{
	return ((nodeid == -1) || (nodeid == INADDR_LOOPBACK) || (nodeid == pscom_get_nodeid())) &&
		((portno == -1) || (portno == socket->listen_portno));
}


pscom_err_t pscom_connect(pscom_connection_t *connection, int nodeid, int portno)
{
	pscom_con_t *con = get_con(connection);
	pscom_err_t rc;


	pscom_lock(); {
		if (pscom_is_local(con->pub.socket, nodeid, portno)) {
			rc = pscom_con_connect_loopback(con);
		} else {
			/* Initial connection via TCP */
			rc = pscom_con_connect_via_tcp(con, nodeid, portno);
		}
	} pscom_unlock();

	return rc;
}


void pscom_close_connection(pscom_connection_t *connection)
{
	pscom_lock(); {
		pscom_con_t *con = get_con(connection);
		pscom_con_close(con);
		pscom_con_destroy(con);
	} pscom_unlock();
}


pscom_connection_t *pscom_get_next_connection(pscom_socket_t *socket, pscom_connection_t *connection)
{
	pscom_sock_t *sock = get_sock(socket);
	pscom_con_t *res;

	assert(sock->magic == MAGIC_SOCKET);

	pscom_lock(); {
		if (!connection) {

			if (list_empty(&sock->connections)) {
				res = NULL;
			} else {
				res = list_entry(sock->connections.next, pscom_con_t, next);
			}
		} else {
			pscom_con_t *con = get_con(connection);
			assert(con->magic == MAGIC_CONNECTION);

			if (con->next.next != &sock->connections) {
				res = list_entry(con->next.next, pscom_con_t, next);
			} else {
				res = NULL;
			}
		}
	} pscom_unlock();

	return res ? &res->pub : NULL;
}
