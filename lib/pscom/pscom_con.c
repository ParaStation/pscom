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
#include "pscom_cuda.h"
#include "pslib.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <errno.h>


static void _pscom_con_destroy(pscom_con_t *con);


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

	// PendingIO ob some requests?
	list_for_each_safe(pos, next, &pscom.requests) {
		pscom_req_t *req = list_entry(pos, pscom_req_t, all_req_next);

		if (req->pub.connection == &con->pub) {
			_pscom_pendingio_abort(con, req);

			pscom_req_state_t mask_rndv_send_posted = (
				PSCOM_REQ_STATE_RENDEZVOUS_REQUEST |
				PSCOM_REQ_STATE_SEND_REQUEST |
				PSCOM_REQ_STATE_POSTED);

			if ((mask_rndv_send_posted & req->pub.state) == mask_rndv_send_posted) {
				// Rendezvous send requests are waiting for an ACK message. If the connection dies,
				// the ACK will never arrive. Therefor we decrement the pending counter here.
				if (!(req->pub.state & PSCOM_REQ_STATE_IO_DONE)) {
					_pscom_pendingio_cnt_dec(con, req);  // inc in pscom_prepare_send_rendezvous_inline()
					_pscom_send_req_done(req); // done with error (error flag set in _pscom_pendingio_abort)
				}
			}

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

	assert(con->magic == MAGIC_CONNECTION);

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
	pscom_sock_t *sock = get_sock(con->pub.socket);

	assert(sock->magic == MAGIC_SOCKET);

	list_for_each_safe(pos, next, &sock->recvq_any) {
		pscom_req_t *req = list_entry(pos, pscom_req_t, next);

//		fprintf(stderr, "Test rm "RED"req %p  con %p == %p "NORM"\n", req, req->pub.connection, &con->pub);
		if (req->pub.connection == &con->pub) {
//			fprintf(stderr, RED "remove con %p\n"NORM, req);

			_pscom_recvq_user_deq(req); // dequeue

			req->pub.state |= PSCOM_REQ_STATE_ERROR;
			_pscom_recv_req_done(req); // done
		}
	}

	// RMA read requests:
	_pscom_recvq_rma_terminate(con);
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

	assert(con->magic == MAGIC_CONNECTION);

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
void pscom_con_close_write(pscom_con_t *con)
{
	con->pub.state &= ~PSCOM_CON_STATE_W; // clear W
	// con->write_start = _pscom_con_reject_send_req;
}


static
void pscom_con_error_read_failed(pscom_con_t *con, pscom_err_t error)
{
	pscom_con_end_read(con);
	pscom_con_info_set(con, "state", pscom_con_state_str(con->pub.state));
	if (error == PSCOM_ERR_EOF) {
		con->state.eof_received = 1;
	} else {
		con->state.read_failed = 1;
	}
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
	if (con->state.con_cleanup) return; // Reentrant call
	con->state.con_cleanup = 1;

	if (con->pub.state != PSCOM_CON_STATE_CLOSED) {
		D_TR(printf("%s:%u:%s(con:%p) : state: %s\n", __FILE__, __LINE__, __func__,
			    con, pscom_con_state_str(con->pub.state)));
	retry:
		pscom_con_end_write(con);
		pscom_con_end_read(con);

		// Stop polling, if used. Usually pscom_con_end_{read,write} have
		// already called pscom_poll_{read,write}_stop. The con->poll_read
		// and con->poll_write might be still in a pscom_poll_list_t list.
		// De-queue now. It is safe to de-queue multiple times:
		pscom_poll_cleanup_init(&con->poll_read);
		pscom_poll_cleanup_init(&con->poll_write);

		assert(con->pub.state == PSCOM_CON_STATE_CLOSE_WAIT);
		assert(list_empty(&con->sendq));
		assert(list_empty(&con->recvq_user));
		assert(list_empty(&con->net_recvq_user) || !con->state.close_called);
		assert(con->in.req == NULL);
		// ToDo: check for group requests?
		// assert(list_empty(&group->???->recvq_bcast));
		// assert(list_empty(&group->???->net_recvq_bcast));
		pscom_call_io_done();

		if (!list_empty(&con->sendq) ||
		    !list_empty(&con->recvq_user) ||
		    (!list_empty(&con->net_recvq_user) && con->state.close_called) ||
		    // !list_empty(&con->recvq_bcast) ||
		    // !list_empty(&con->net_recvq_bcast) ||
		    con->in.req) goto retry; // in the case the io_doneq callbacks post more work

		if (con->pub.state == PSCOM_CON_STATE_CLOSE_WAIT) {
			DPRINT(con->pub.type != PSCOM_CON_TYPE_ONDEMAND ? D_INFO : D_DBG,
			       "DISCONNECT %s via %s",
			       pscom_con_str(&con->pub),
			       pscom_con_type_str(con->pub.type));
		} else {
			DPRINT(D_DBG, "cleanup    %s via %s : %s",
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

	con->state.con_cleanup = 0;

	if (con->pub.state == PSCOM_CON_STATE_CLOSED &&
	    (con->state.close_called)) {
		_pscom_con_destroy(con);
	}
}


static
void io_done_send_eof(pscom_req_state_t state, void *priv_con)
{
	pscom_con_t *con = priv_con;
	assert(con->magic == MAGIC_CONNECTION);
	pscom_lock(); {
		if (con->pub.state == PSCOM_CON_STATE_CLOSING) {
			con->pub.state = PSCOM_CON_STATE_CLOSE_WAIT;
			pscom_con_closing(con);
		}
		assert(con->magic == MAGIC_CONNECTION);
		_pscom_con_ref_release(con);
	} pscom_unlock();

}


static
void pscom_con_send_eof(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);
	DPRINT(D_DBG_V, "EOF send   %s via %s",
	       pscom_con_str(&con->pub),
	       pscom_con_type_str(con->pub.type));

	_pscom_con_ref_hold(con);
	_pscom_send_inplace(con, PSCOM_MSGTYPE_EOF,
			    NULL, 0,
			    NULL, 0,
			    io_done_send_eof, con);
}


static
void pscom_con_recv_eof_start_check(pscom_con_t *con)
{
	if (!con->state.eof_expect) {
		if ((!con->state.eof_received) &&
		    ((con->pub.state & PSCOM_CON_STATE_R) == PSCOM_CON_STATE_R)) {
			// start reading from this connection, expecting an EOF
			con->state.eof_expect = 1;
			_pscom_recv_req_cnt_inc(con);
		}
	}
}


static
void pscom_con_recv_eof_stop_check(pscom_con_t *con)
{
	if (con->state.eof_expect) {
		if (con->state.eof_received || con->state.read_failed) {
			con->state.eof_expect = 0;
			_pscom_recv_req_cnt_dec(con);
		}
	}
}


void pscom_con_closing(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);

	DPRINT(D_DBG_V, "...closing %s via %s %s :%s%s%s%s",
	       pscom_con_str(&con->pub),
	       pscom_con_type_str(con->pub.type),
	       pscom_con_state_str(con->pub.state),
	       con->state.close_called ? " usr_closed" : "",
	       con->state.eof_expect ? " exp_eof" : "",
	       con->state.eof_received ? " r_eof" : "",
	       con->state.read_failed  ? " r_fail" : "");

	// ToDo: What to do, if (con->pub.state & PSCOM_CON_STATE_SUSPENDING) ?

	if ((con->pub.type == PSCOM_CON_TYPE_ONDEMAND) &&
	    ((con->pub.state & PSCOM_CON_STATE_W) == PSCOM_CON_STATE_W)) {
		// on demand connection and could write: emulate a received EOF
		con->state.eof_received = 1;
		pscom_con_close_write(con); // No more writes
	}

	pscom_con_recv_eof_start_check(con);

	if (((con->pub.state & PSCOM_CON_STATE_W) == PSCOM_CON_STATE_W)) {
		// We can write: send_eof
		pscom_con_send_eof(con);
		pscom_con_close_write(con); // No further pscom_post_send

		con->pub.state = PSCOM_CON_STATE_CLOSING;
	} else {
		switch (con->pub.state) {
		case PSCOM_CON_STATE_CLOSING:
			// waiting for a io_done call of the pscom_con_send_eof()
			break;
		default:
			DPRINT(D_WARN, "pscom_con_closing() : unexpected connection state : %s (%s)",
			       pscom_con_state_str(con->pub.state),
			       pscom_con_type_str(con->pub.type));

			pscom_con_end_write(con);

			/* fall through */
		case PSCOM_CON_STATE_R:
		case PSCOM_CON_STATE_NO_RW:

			con->pub.state = PSCOM_CON_STATE_CLOSE_WAIT;

			/* fall through */
		case PSCOM_CON_STATE_CLOSE_WAIT:
			pscom_con_recv_eof_stop_check(con);

			if (con->state.eof_received || con->state.read_failed) {
				_pscom_con_cleanup(con);
				con = NULL; // Do not use con after _pscom_con_cleanup
			}
			break;
		case PSCOM_CON_STATE_CLOSED:
			break;
		}
	}
}


PSCOM_PLUGIN_API_EXPORT
void pscom_con_close(pscom_con_t *con)
{
	int close_called = con->state.close_called;
	con->state.close_called = 1;

	/* Terminate the net queues right here and not in pscom_con_closing()
	   since the latter also handles remotely initiated closing via EOF
	   where the net queues are to be kept so that once generated net
	   requests may still be matched even after the disconnect.
	*/
	_pscom_con_terminate_net_queues(con);

	if (!close_called) pscom_con_closing(con);
}


typedef struct {
	pscom_op_t operation;
	pscom_err_t error;
} pscom_req_io_con_error_t;


static
void pscom_con_error_io_done(pscom_request_t *request)
{
	pscom_con_t *con = get_con(request->connection);
	pscom_req_t *req = get_req(request);

	pscom_req_io_con_error_t *rdata = (pscom_req_io_con_error_t *)request->user;

	assert(con->magic == MAGIC_CONNECTION);

	if (request->socket->ops.con_error &&
	    !con->state.close_called) {
		// Call socket->ops.con_error hook if pscom_close_connection() is not yet called.
		request->socket->ops.con_error(
			request->connection, rdata->operation, rdata->error
		);
	}

	pscom_lock(); {
		pscom_req_free(req);

		// Proceed with CLOSE_WAIT:
		pscom_con_closing(con);
		_pscom_con_ref_release(con);
	} pscom_unlock();
}


static
void pscom_con_error_deferred(pscom_con_t *con, pscom_op_t operation, pscom_err_t error)
{
	pscom_req_t *req;
	pscom_req_io_con_error_t *rdata;

	assert(con->magic == MAGIC_CONNECTION);

	req = pscom_req_create(0, sizeof(pscom_req_io_con_error_t));
	rdata = (pscom_req_io_con_error_t *)req->pub.user;

	rdata->operation = operation;
	rdata->error = error;

	req->pub.socket = con->pub.socket;
	req->pub.connection = &con->pub;
	req->pub.ops.io_done = pscom_con_error_io_done;

	_pscom_con_ref_hold(con);

	_pscom_req_done(req);
}


PSCOM_PLUGIN_API_EXPORT
void pscom_con_error(pscom_con_t *con, pscom_op_t operation, pscom_err_t error)
{
	assert(con->magic == MAGIC_CONNECTION);
	DPRINT((error != PSCOM_ERR_EOF) // EOF is mostly ok (D_DBG), except when receiving...
	       || (con->pub.type == PSCOM_CON_TYPE_NONE) // ...EOF while still handshaking (No plugin choosen) is an D_ERR.
	       ? D_ERR : D_DBG,
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
	assert(con->magic == MAGIC_CONNECTION);

	pscom_con_error_deferred(con, operation, error);
	// con->pub.socket->ops.con_error(&con->pub, operation, error);
}


static pscom_con_t **pscom_con_ids = NULL;
static pscom_con_id_t pscom_con_ids_mask = 0;
static pscom_con_id_t pscom_con_id_last = 0; // Start with con_id == 1.


static
void pscom_con_id_increase(void) {
	pscom_con_id_t size = pscom_con_ids_mask + 1; // = power of 2
	pscom_con_id_t i;

	// Double the array size
	pscom_con_ids = realloc(pscom_con_ids, sizeof(pscom_con_t*) * 2 * size);

	assert(pscom_con_ids_mask < 0xffffffff);

	// new mask with one more bit set
	pscom_con_ids_mask = (pscom_con_ids_mask << 1) | 1;

	if (size == 1) pscom_con_ids[0] = NULL;

	// Reassign existing connections to new slots and initialize unused slots.
	for (i = 0; i < size; i++) {
		pscom_con_t *con = pscom_con_ids[i];
		pscom_con_id_t id = con ? con->id : i;

		pscom_con_ids[id & pscom_con_ids_mask] = con;
		pscom_con_ids[(id + size) & pscom_con_ids_mask] = NULL; // empty slot
	}
}


static
pscom_con_id_t pscom_con_next_id(void) {
	pscom_con_id_t id;

	while (1) {
		for (id = pscom_con_id_last + 1;
		     (id & pscom_con_ids_mask) != (pscom_con_id_last & pscom_con_ids_mask);
		     id++) {
			assert(pscom_con_ids);
			if ((id != 0) && !pscom_con_ids[id & pscom_con_ids_mask]) {
				return id;
			}
		}
		pscom_con_id_increase();
	}
}


static
pscom_con_id_t pscom_con_id_register(pscom_con_t *con) {
	assert(!pscom_con_ids_mask || pscom_con_ids[con->id & pscom_con_ids_mask] != con);

	con->id = pscom_con_next_id();

	pscom_con_id_last = con->id;

	pscom_con_ids[con->id & pscom_con_ids_mask] = con;

	return con->id;
}


static
void pscom_con_id_unregister(pscom_con_t *con) {
	unsigned i;
	if ((!pscom_con_ids_mask) ||
	    (pscom_con_ids[con->id & pscom_con_ids_mask] != con)) {
		pscom_con_t *con_reg = pscom_con_ids_mask ?
			pscom_con_ids[con->id & pscom_con_ids_mask] : NULL;
		DPRINT(D_WARN, "warning: pscom_con_id_unregister(con:%p [con_reg:%p]) called more than once!",
		       con, con_reg);
		// assert(pscom_con_ids[con->id & pscom_con_ids_mask] == con);
		return;
	}

	pscom_con_ids[con->id & pscom_con_ids_mask] = NULL;

	// All con unregistered?
	for (i = 0; i <= pscom_con_ids_mask; i++) {
		if (pscom_con_ids[i]) return;
	}

	// Yes, cleanup.
	free(pscom_con_ids);
	pscom_con_ids = NULL;
	pscom_con_ids_mask = 0;
}


PSCOM_PLUGIN_API_EXPORT
pscom_con_id_t pscom_con_to_id(pscom_con_t *con)
{
	return con->id;
}


PSCOM_PLUGIN_API_EXPORT
pscom_con_t *pscom_id_to_con(pscom_con_id_t id)
{
	pscom_con_t *con = pscom_con_ids[id & pscom_con_ids_mask];
	if (!con || (con->id != id)) con = NULL;
	return con;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_con_info(pscom_con_t *con, pscom_con_info_t *con_info)
{
	*con_info = con->pub.socket->local_con_info;
	con_info->id = (void*)(unsigned long)pscom_con_to_id(con);
}


PSCOM_PLUGIN_API_EXPORT
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

#ifdef PSCOM_CUDA_AWARENESS
	con->is_gpu_aware = 0;
#endif

	con->recv_req_cnt = 0;
	INIT_LIST_HEAD(&con->next);
	INIT_LIST_HEAD(&con->sendq);
	INIT_LIST_HEAD(&con->recvq_user);
	INIT_LIST_HEAD(&con->recvq_ctrl);
	INIT_LIST_HEAD(&con->recvq_rma);
	INIT_LIST_HEAD(&con->net_recvq_user);
	INIT_LIST_HEAD(&con->net_recvq_ctrl);
	INIT_LIST_HEAD(&con->sendq_gw_fw);

	pscom_con_id_register(con);

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
	con->close = pscom_no_rw_start_stop;

	pscom_poll_init(&con->poll_read);
	pscom_poll_init(&con->poll_write);

	/* RMA */
	con->rma_mem_register_check = NULL;
	con->rma_mem_register = NULL;
	con->rma_mem_deregister = NULL;
	con->rma_read = NULL;
	con->rma_write = NULL;

	con->rendezvous_size = pscom.env.rendezvous_size;

	/* State */
	con->state.eof_expect = 0;
	con->state.eof_received = 0;
	con->state.read_failed = 0;
	con->state.close_called = 0;
	con->state.destroyed = 0;
	con->state.suspend_active = 0;
	con->state.con_cleanup = 0;
	con->state.internal_connection = 0;
	con->state.use_count = 1; // until _pscom_con_destroy

	return con;
}


PSCOM_PLUGIN_API_EXPORT
void _pscom_con_ref_release(pscom_con_t *con) {
	assert(con->magic == MAGIC_CONNECTION);
	assert(con->state.use_count);

	con->state.use_count--;
	if (!con->state.use_count) {
		pscom_con_id_unregister(con);
		con->magic = 0;
		free(con);
	}
}


void pscom_con_ref_release(pscom_con_t *con) {
	pscom_lock(); {
		_pscom_con_ref_release(con);
	} pscom_unlock();
}


static
void _pscom_con_destroy(pscom_con_t *con)
{
	assert(con->magic == MAGIC_CONNECTION);
	if (con->state.destroyed) return; // Already destroyed (why?)
	con->state.destroyed = 1;

	if (con->pub.state != PSCOM_CON_STATE_CLOSED) {
		DPRINT(D_BUG, "pscom_con_destroy(con) : con state %s",
		       pscom_con_state_str(con->pub.state));
	}
	assert(con->pub.state == PSCOM_CON_STATE_CLOSED);
	assert(!pscom_poll_is_inuse(&con->poll_read));
	assert(!pscom_poll_is_inuse(&con->poll_write));

	if(con->in.readahead.iov_base) {
		free(con->in.readahead.iov_base);
	}

	if (con->con_guard.fd != -1) {
		pscom_con_guard_stop(con);
	}

	_pscom_con_ref_release(con);
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
		   and we must not terminate the connection con.
		   3.) Peer has no receive request on this con and is
		   not watching for POLLIN on the listening fd. This
		   is currently unhandled and cause a connection error! */

		/* Send a rconnect request */
		DPRINT(D_PRECON_TRACE, "precon(%p): send backcon %.8s to %.8s", pre,
		       con->pub.socket->local_con_info.name, con->pub.remote_con_info.name);
		pscom_precon_send_PSCOM_INFO_CON_INFO(pre, PSCOM_INFO_BACK_CONNECT);

		pre->back_connect = 1; /* This is a back connect. */

		pscom_precon_recv_start(pre); // Wait for the PSCOM_INFO_BACK_ACK
	} else {
		pscom_precon_destroy(pre);
	}
}


PSCOM_PLUGIN_API_EXPORT
void pscom_con_setup_failed(pscom_con_t *con, pscom_err_t err)
{
	precon_t *pre = con->precon;
	int call_cleanup = (con->pub.state == PSCOM_CON_STATE_ACCEPTING);
	if (pre) {
		pscom_precon_close(pre);
		/* pre destroys itself in pscom_precon_check_end()
		   after the send buffer is drained.*/
		// pscom_precon_destroy(pre); con->precon = NULL;
	}

	con->pub.state = PSCOM_CON_STATE_CLOSED;
	pscom_con_error(con, PSCOM_OP_CONNECT, err);

	if (call_cleanup) {
		assert(con->state.internal_connection);
		_pscom_con_cleanup(con);
	}
}


PSCOM_PLUGIN_API_EXPORT
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

	switch (con_state) {
	case PSCOM_CON_STATE_CONNECTING:
		DPRINT(D_CONTYPE, "CONNECT %s via %s%s",
		       pscom_con_str(&con->pub),
		       pscom_con_type_str(con->pub.type),
		       PSCOM_IF_CUDA(con->is_gpu_aware, 0) ? " (cuda)" : "");
		break;
	case PSCOM_CON_STATE_ACCEPTING:
		DPRINT(D_CONTYPE, "ACCEPT  %s via %s%s",
		       pscom_con_str_reverse(&con->pub),
		       pscom_con_type_str(con->pub.type),
		       PSCOM_IF_CUDA(con->is_gpu_aware, 0) ? " (cuda)" : "");

		con->state.internal_connection = 0; // Now the user has to call pscom_close_connection() on con.
		if (sock->pub.ops.con_accept) {
			// ToDo: Is it save to unlock here?
			pscom_unlock(); {
				sock->pub.ops.con_accept(&con->pub);
			} pscom_lock();
		}
		break;
	case PSCOM_CON_STATE_CONNECTING_ONDEMAND:
		DPRINT(D_CONTYPE, "CONNECT ONDEMAND %s via %s%s",
		       pscom_con_str(&con->pub),
		       pscom_con_type_str(con->pub.type),
		       PSCOM_IF_CUDA(con->is_gpu_aware, 0) ? " (cuda)" : "");
		break;
	case PSCOM_CON_STATE_ACCEPTING_ONDEMAND:
		DPRINT(D_CONTYPE, "ACCEPT  ONDEMAND %s via %s%s",
		       pscom_con_str_reverse(&con->pub),
		       pscom_con_type_str(con->pub.type),
		       PSCOM_IF_CUDA(con->is_gpu_aware, 0) ? " (cuda)" : "");
		break;
	default:
		DPRINT(D_BUG, "pscom_con_setup_ok() : connection in wrong state : %s (%s)",
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

	if(con->pub.state == PSCOM_CON_STATE_CLOSED)
		goto err_connect;

	return PSCOM_SUCCESS;
	/* --- */
//err_init_failed:
err_connect:
	if (errno != ENOPROTOOPT) {
		// if (errno == ENOPROTOOPT) _plugin_connect_next() already called pscom_con_setup_failed().
		pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
	}
	return PSCOM_ERR_STDERROR;
}


static void
loopback_write_start(pscom_con_t *con)
{
	int i;
	size_t len;
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

#ifdef PSCOM_CUDA_AWARENESS
	con->is_gpu_aware = pscom.env.cuda;
#endif

	con->write_start = loopback_write_start;
//	con->rendezvous_size = (unsigned)~0; // disable rendezvous for loopback

	DPRINT(D_CONTYPE, "CONNECT %s via %s%s",
	       pscom_con_str(&con->pub),
	       pscom_con_type_str(con->pub.type),
	       PSCOM_IF_CUDA(con->is_gpu_aware, 0) ? " (cuda)" : "");

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


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_con_connect(pscom_con_t *con, int nodeid, int portno)
{
	pscom_err_t rc;

	if (pscom_is_local(con->pub.socket, nodeid, portno)) {
		rc = pscom_con_connect_loopback(con);
	} else {
		/* Initial connection via TCP */
		rc = pscom_con_connect_via_tcp(con, nodeid, portno);
	}
	return rc;
}


static
void pscom_con_guard_error(void *_con) {
	pscom_con_t *con = (pscom_con_t *)_con;

	assert(con->magic == MAGIC_CONNECTION);

	if (con->pub.state != PSCOM_CON_STATE_CLOSED) {
		pscom_con_error(con, PSCOM_OP_RW, PSCOM_ERR_IOERROR);
	}
	_pscom_con_ref_release(con);
}


#define GUARD_BYE 0x25

static
void pscom_guard_readable(ufd_t *ufd, ufd_info_t *ufd_info) {
	pscom_con_t *con = (pscom_con_t *)ufd_info->priv;
	char msg = 0;
	int error = 0;
	ssize_t rc;

	rc = read(ufd_info->fd, &msg, 1); // Good bye or error?
	error = (rc <= 0) || (msg != GUARD_BYE);

	/* Callback called in the async thread!! */
	DPRINT(error ? D_ERR : D_DBG, "pscom guard con:%p %s", con, error ? "terminated" : "closed");

	// Stop listening
	ufd_event_clr(ufd, ufd_info, POLLIN);

	if (error) {
		// Call pscom_con_guard_error in the main thread
		_pscom_con_ref_hold(con);
		pscom_backlog_push(pscom_con_guard_error, con);
	}
}


PSCOM_PLUGIN_API_EXPORT
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
	DPRINT(D_PRECON_TRACE, "precon(%p): Start guard on fd %d", pre, fd);
	_pscom_con_ref_hold(con);
	pscom_async_on_readable(fd, pscom_guard_readable, con);
}


PSCOM_PLUGIN_API_EXPORT
void pscom_con_guard_stop(pscom_con_t *con)
{
	int fd = con->con_guard.fd;
	if (fd != -1) {
		char msg = GUARD_BYE;
		(void)(write(con->con_guard.fd, &msg, 1) || 0); // Send "Good bye", ignore result

		con->con_guard.fd = -1;
		pscom_async_off_readable(fd, pscom_guard_readable, con);
		_pscom_con_ref_release(con);
		close(fd);
	}
	DPRINT(D_DBG_V, "Stop guard on fd %d", fd);
}


/*
******************************************************************************
*/

PSCOM_API_EXPORT
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


PSCOM_API_EXPORT
pscom_err_t pscom_connect(pscom_connection_t *connection, int nodeid, int portno)
{
	pscom_con_t *con = get_con(connection);
	pscom_err_t rc;


	pscom_lock(); {
		rc = pscom_con_connect(con, nodeid, portno);
	} pscom_unlock();


	/* Block until we are connected.*/
	if (!rc) {
		while (con->pub.type == PSCOM_CON_TYPE_NONE && con->pub.state == PSCOM_CON_STATE_CONNECTING) {
			pscom_wait_any();
		}
	}

	return rc;
}


PSCOM_API_EXPORT
void pscom_close_connection(pscom_connection_t *connection)
{
	pscom_lock(); {
		pscom_con_t *con = get_con(connection);
		assert(con->magic == MAGIC_CONNECTION);
		pscom_con_close(con);

		// Speedup sending of EOFs by progressing now:
		pscom_progress(0);
	} pscom_unlock();
}


static
int pscom_connection_is_closing(pscom_connection_t *connection) {
	switch (connection->state) {
	case PSCOM_CON_STATE_CLOSED:
	case PSCOM_CON_STATE_CLOSE_WAIT:
	case PSCOM_CON_STATE_CLOSING:
		return 1;
	default:
		return 0;
	}
}


PSCOM_API_EXPORT
pscom_connection_t *pscom_get_next_connection(pscom_socket_t *socket, pscom_connection_t *connection)
{
	pscom_sock_t *sock = get_sock(socket);

	assert(sock->magic == MAGIC_SOCKET);

	pscom_lock(); {
		do {
			struct list_head *next;

			if (!connection) {
				// First element
				next = sock->connections.next;
			} else {
				// Next element
				pscom_con_t *con = get_con(connection);
				assert(con->magic == MAGIC_CONNECTION);

				next = con->next.next;
			}
			if (next == &sock->connections) {
				// No connection found.
				connection = NULL;
			} else {
				// Next connection from next element
				pscom_con_t *con = list_entry(next, pscom_con_t, next);
				assert(con->magic == MAGIC_CONNECTION);
				connection = &con->pub;
			}
		} while (connection && pscom_connection_is_closing(connection));
	} pscom_unlock();

	return connection;
}
