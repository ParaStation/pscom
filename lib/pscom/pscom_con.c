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
#include "pscom_precon.h"
#include "pscom_plugin.h"
#include "pscom_async.h"
#include "pslib.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <errno.h>

static
void _pscom_con_destroy(pscom_con_t *con);

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


// clear sendq. finish all send requests with error
static
void _pscom_con_terminate_sendq(pscom_con_t *con)
{
	pscom_sock_t *sock = get_sock(con->pub.socket);
	struct list_head *pos, *next;

	// Sendq
	while (!list_empty(&con->sendq)) {
		pscom_req_t *req = list_entry(con->sendq.next, pscom_req_t, next);

		list_del(&req->next); // dequeue

		req->pub.state |= PSCOM_REQ_STATE_ERROR;
		_pscom_send_req_done(req); // done
	}

	// PendingIO queue
	list_for_each_safe(pos, next, &sock->pendingioq) {
		pscom_req_t *req = list_entry(pos, pscom_req_t, next);

		if (req->pub.connection == &con->pub) {
			req->pub.state |= PSCOM_REQ_STATE_ERROR;
		}
	}

	// Connection suspending? Terminate send requests from sock->sendq_suspending.
	list_for_each_safe(pos, next, &sock->sendq_suspending) {
		pscom_req_t *req = list_entry(pos, pscom_req_t, next);

		if (req->pub.connection == &con->pub) {
			list_del(&req->next); // dequeue

			req->pub.state |= PSCOM_REQ_STATE_ERROR;
			_pscom_send_req_done(req); // done
		}
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


static
void _pscom_con_cleanup(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);
	if (con->pub.state != PSCOM_CON_STATE_CLOSED) {
		D_TR(printf("%s:%u:%s(con:%p) : state: %s\n", __FILE__, __LINE__, __func__,
			    con, pscom_con_state_str(con->pub.state)));
	retry:
		pscom_con_end_write(con);
		pscom_con_end_read(con);

		_pscom_con_terminate_net_queues(con);

		assert(con->pub.state == PSCOM_CON_STATE_CLOSING);
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

		if (con->pub.state == PSCOM_CON_STATE_CLOSING) {
			DPRINT(1, "DISCONNECT %s via %s",
			       pscom_con_str(&con->pub),
			       pscom_con_type_str(con->pub.type));
		} else {
			DPRINT(5, "cleanup %s via %s : %s",
			       pscom_con_str(&con->pub),
			       pscom_con_type_str(con->pub.type),
			       pscom_con_state_str(con->pub.state));
		}

		if (con->close) con->close(con);

		list_del_init(&con->next);
		con->pub.state = PSCOM_CON_STATE_CLOSED;
		pscom_con_info_set(con, "state", pscom_con_state_str(con->pub.state));
		_pscom_step();
	} else {
		list_del_init(&con->next); // May dequeue multiple times.
	}

	if (con->pub.state == PSCOM_CON_STATE_CLOSED && con->state.close_called) {
		_pscom_con_destroy(con);
	}
}


static
void _write_start_closing(pscom_con_t *con)
{
	DPRINT(1, "Writing to the closed connection %s (%s)",
	       pscom_con_str(&con->pub), pscom_con_type_str(con->pub.type));
}


static
void io_done_send_eof(pscom_req_state_t state, void *priv_con)
{
	pscom_con_t *con = priv_con;
	pscom_lock(); {
		_pscom_con_cleanup(con);
	} pscom_unlock();

}


static
void pscom_con_send_eof(pscom_con_t *con)
{
	_pscom_send_inplace(con, PSCOM_MSGTYPE_EOF,
			    NULL, 0,
			    NULL, 0,
			    io_done_send_eof, con);
}


void pscom_con_close(pscom_con_t *con)
{
	int send_eof;
	assert(con->magic == MAGIC_CONNECTION);

	send_eof = ((con->pub.state & PSCOM_CON_STATE_W) == PSCOM_CON_STATE_W) && (con->pub.type != PSCOM_CON_TYPE_ONDEMAND);

	// ToDo: What to do, if (con->pub.state & PSCOM_CON_STATE_SUSPENDING) ?

	if (send_eof) {
		pscom_con_send_eof(con);
		con->write_start = _write_start_closing; // No further writes
	}

	con->pub.state = PSCOM_CON_STATE_CLOSING;

	if (!send_eof) {
		_pscom_con_cleanup(con);
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
	case PSCOM_OP_CONNECT:
	case PSCOM_OP_RW:
		pscom_con_error_write_failed(con, error);
		pscom_con_error_read_failed(con, error);
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


pscom_con_t *pscom_con_create(pscom_sock_t *sock)
{
	pscom_con_t *con;
	con = malloc(sizeof(*con) + sock->pub.connection_userdata_size);
	if (!con) return NULL;

	memset(con, 0, sizeof(*con));
	con->magic = MAGIC_CONNECTION;
	con->pub.socket = &sock->pub;
	con->pub.userdata_size = sock->pub.connection_userdata_size;
	con->pub.state = PSCOM_CON_STATE_CLOSED;
	con->pub.type = PSCOM_CON_TYPE_NONE;

	con->recv_req_cnt = 0;
	INIT_LIST_HEAD(&con->next);
	INIT_LIST_HEAD(&con->sendq);
	INIT_LIST_HEAD(&con->recvq_user);
	INIT_LIST_HEAD(&con->recvq_ctrl);
	INIT_LIST_HEAD(&con->recvq_rma);
	INIT_LIST_HEAD(&con->net_recvq_user);
	INIT_LIST_HEAD(&con->net_recvq_ctrl);

	INIT_LIST_HEAD(&con->poll_reader.next);
	INIT_LIST_HEAD(&con->poll_next_send);

	con->con_guard.fd = -1;
	con->precon = NULL;
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

	/* State */
	con->state.eof_received = 0;
	con->state.close_called = 0;
	con->state.suspend_active = 0;

	return con;
}


static
void _pscom_con_destroy(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);
	if (con->pub.state != PSCOM_CON_STATE_CLOSED) {
		DPRINT(0, "pscom_con_destroy(con) : con state %s",
		       pscom_con_state_str(con->pub.state));
	}
	assert(con->pub.state == PSCOM_CON_STATE_CLOSED);
	assert(list_empty(&con->poll_next_send));
	assert(list_empty(&con->poll_reader.next));

	if(con->in.readahead.iov_base) {
		free(con->in.readahead.iov_base);
	}

	if (con->con_guard.fd != -1) {
		pscom_con_guard_stop(con);
	}

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
	_pscom_step();
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
				D_TR(printf("%s:%u:%s(%p) = 1\n", __FILE__, __LINE__, __func__, con));
				return 1;
			}
		}
	}
	D_TR(printf("%s:%u:%s(%p) = 0\n", __FILE__, __LINE__, __func__, con));

	return 0;
}


void pscom_ondemand_indirect_connect(pscom_con_t *con)
{
	int nodeid = con->arch.ondemand.node_id;
	int portno = con->arch.ondemand.portno;
	int rc;

	precon_t *pre = pscom_precon_create(con);

	rc = pscom_precon_tcp_connect(pre, nodeid, portno);
	if (rc >= 0) {
		/* Request a back connect. There are three reasons for
		   a failing tcp_connect: 1.) Problems to connect,
		   caused by network congestion or busy peer (e.g. tcp
		   backlog to small). In this case the connection con
		   should be terminated with an error. 2.) Peer is
		   connecting to us at the same time and the listening
		   tcp port is already closed. This is not an error
		   and we must not terminate the connection con.  As
		   we can not distinct between 1 and 2, we ignore
		   tcp_connect errors in the hope it was 2. In the
		   worst case this deadlock parallel applications!
		   3.) Peer has no receive request on this con and is
		   not watching for POLLIN on the listening fd. This
		   is currently unhandled! */

		/* Send a rconnect request */
		DPRINT(PRECON_LL, "precon(%p): send backcon %.8s to %.8s", pre,
		       con->pub.socket->local_con_info.name, con->pub.remote_con_info.name);
		pscom_precon_send_PSCOM_INFO_CON_INFO(pre, PSCOM_INFO_BACK_CONNECT);
		pre->con = NULL; /* Forget the con to avoid a race
				  *  with a simultanous PSCOM_INFO_CON_INFO_DEMAND
				  */
		pscom_precon_recv_start(pre); // Wait for the PSCOM_INFO_BACK_ACK
	} else {
		pscom_precon_destroy(pre);
	}
}


void pscom_con_setup_failed(pscom_con_t *con, pscom_err_t err)
{
	precon_t *pre = con->precon;

	if (pre) {
		pscom_precon_close(pre);
		/* pre destroys itself in pscom_precon_check_end()
		   after the send buffer is drained.*/
		// pscom_precon_destroy(pre); con->precon = NULL;
	}

	con->pub.state = PSCOM_CON_STATE_CLOSED;
	pscom_con_error(con, PSCOM_OP_CONNECT, err);
}


void pscom_con_setup_ok(pscom_con_t *con)
{
	precon_t *pre = con->precon;
	pscom_sock_t *sock = get_sock(con->pub.socket);
	pscom_con_state_t con_state = con->pub.state;

	if (pre) {
		pscom_precon_destroy(pre);
		con->precon = NULL;
	}
	if (list_empty(&con->next)) {
		list_add_tail(&con->next, &sock->connections);
	}

	con->pub.state = PSCOM_CON_STATE_RW;

	if (con_state == PSCOM_CON_STATE_CONNECTING) {
		DPRINT(1, "CONNECT %s via %s",
		       pscom_con_str(&con->pub),
		       pscom_con_type_str(con->pub.type));
	} else if (con_state == PSCOM_CON_STATE_ACCEPTING) {
		DPRINT(1, "ACCEPT  %s via %s",
		       pscom_con_str_reverse(&con->pub),
		       pscom_con_type_str(con->pub.type));

		if (sock->pub.ops.con_accept) {
			// ToDo: Is it save to unlock here?
			pscom_unlock(); {
				sock->pub.ops.con_accept(&con->pub);
			} pscom_lock();
		}
	} else {
		DPRINT(0, "pscom_con_setup_ok() : connection in wrong state : %s (%s)",
		       pscom_con_state_str(con_state),
		       pscom_con_type_str(con->pub.type));
	}
	pscom_con_setup(con);
}


pscom_err_t pscom_con_connect_via_tcp(pscom_con_t *con, int nodeid, int portno)
{
	pscom_sock_t *sock = get_sock(con->pub.socket);
	precon_t *pre;

	/* ToDo: Set connection state to "connecting". Suspend send and recieve queues! */
	pre = pscom_precon_create(con);
	con->precon = pre;
	con->pub.remote_con_info.node_id = nodeid;
	if (!con->pub.remote_con_info.name[0]) {
		snprintf(con->pub.remote_con_info.name, sizeof(con->pub.remote_con_info.name),
			 ":%u", portno);
	}
	pre->plugin = NULL;

	if (list_empty(&con->next)) {
		list_add_tail(&con->next, &sock->connections);
	}

	if (pscom_precon_tcp_connect(pre, nodeid, portno) < 0)
		goto err_connect;

	con->pub.state = PSCOM_CON_STATE_CONNECTING;
	pscom_precon_handshake(pre);

	return PSCOM_SUCCESS;
	/* --- */
//err_init_failed:
err_connect:
	pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
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

	assert(list_empty(&con->next));
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


static
void pscom_con_guard_error(void *_con) {
	pscom_con_t *con = (pscom_con_t *)_con;

	pscom_con_error(con, PSCOM_OP_RW, PSCOM_ERR_IOERROR);
}

#define GUARD_BYE 0x25

static
void pscom_guard_readable(ufd_t *ufd, ufd_info_t *ufd_info) {
	pscom_con_t *con = (pscom_con_t *)ufd_info->priv;
	char msg = 0;
	int error = 0;

	read(ufd_info->fd, &msg, 1); // Good bye or error?
	error = msg != GUARD_BYE;

	/* Callback called in the async thread!! */
	DPRINT(error ? 1 : 2, "pscom guard con:%p %s", con, error ? "terminated" : "closed");

	// Stop listening
	ufd_event_clr(ufd, ufd_info, POLLIN);

	if (error) {
		// Call pscom_con_guard_error in the main thread
		pscom_backlog_push(pscom_con_guard_error, con);
	}
}


void pscom_con_guard_start(pscom_con_t *con)
{
	precon_t *pre = con->precon;
	int fd;
	assert(pre);
	assert(pre->magic == MAGIC_PRECON);
	if (!pscom.env.guard) return;

	fd = pre->ufd_info.fd;
	pre->closefd_on_cleanup = 0;
	con->con_guard.fd = fd;
	DPRINT(5, "precon(%p): Start guard on fd %d", pre, fd);
	pscom_async_on_readable(fd, pscom_guard_readable, con);
}


void pscom_con_guard_stop(pscom_con_t *con)
{
	int fd = con->con_guard.fd;
	if (fd != -1) {
		char msg = GUARD_BYE;
		write(con->con_guard.fd, &msg, 1); // Good bye

		con->con_guard.fd = -1;
		pscom_async_off_readable(fd, pscom_guard_readable, con);
		close(fd);
	}
	DPRINT(5, "Stop guard on fd %d", fd);
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


	/* Block until we are connected.*/
	if (!rc) {
		while (con->pub.type == PSCOM_CON_TYPE_NONE && con->pub.state == PSCOM_CON_STATE_CONNECTING) {
			pscom_wait_any();
		}
	}

	return rc;
}


void pscom_close_connection(pscom_connection_t *connection)
{
	pscom_lock(); {
		pscom_con_t *con = get_con(connection);
		con->state.close_called = 1;
		pscom_con_close(con);
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
