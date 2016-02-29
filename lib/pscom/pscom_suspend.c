/*
 * ParaStation
 *
 * Copyright (C) 2016 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pscom_con.h"
#include "pscom_queues.h"

static
void _write_start_suspending(pscom_con_t *con)
{
	struct list_head *pos, *next;
	int suspend_found = 0;

	// Move all send requests posted after PSCOM_MSGTYPE_SUSPEND to sendq_suspending.
	// If there is no PSCOM_MSGTYPE_SUSPEND, it is already sent and all reqs will be moved.
	while (1) {
		list_for_each_safe(pos, next, &con->sendq) {
			pscom_req_t *req = list_entry(pos, pscom_req_t, next);

			if (req->pub.header.msg_type == PSCOM_MSGTYPE_SUSPEND) {
				suspend_found = 1;
			} else if (suspend_found) {
				_pscom_sendq_steal(con, req); // dequeue from sendq
				_pscom_sendq_suspending_enq(con, req); // enqueue to suspend queue
			}
		}
		if (suspend_found) {
			break;
		}
		// Loop a second time. Now requeue EVERY request.
		suspend_found = 1;
	}
}


static
void suspend_init_con(pscom_con_t *con)
{
	pscom_sock_t *sock = get_sock(con->pub.socket);
	struct list_head *pos, *next;

	con->pub.type = PSCOM_CON_TYPE_SUSPENDED;
	con->pub.state = PSCOM_CON_STATE_RW;

	pscom_con_info_set(con, "type", pscom_con_type_str(con->pub.type));

	// Move all send requests from suspend queue to sendq
	list_for_each_safe(pos, next, &sock->sendq_suspending) {
		pscom_req_t *req = list_entry(pos, pscom_req_t, next);
		if (req->pub.connection == &con->pub) {
			_pscom_sendq_suspending_deq(con, req);
			_pscom_sendq_enq(con, req);
		}
	}

	con->write_start = pscom_no_rw_start_stop;
	con->write_stop = pscom_no_rw_start_stop;
	con->read_start = pscom_no_rw_start_stop;
	con->read_stop = pscom_no_rw_start_stop;
	con->close = NULL;
}


static
void _pscom_con_check_suspended(pscom_con_t *con)
{
	if (!(con->pub.state & PSCOM_CON_STATE_SUSPENDED)) return;

	// Already suspended? (Should not happen)
	if (con->pub.type == PSCOM_CON_TYPE_SUSPENDED) return;

	// Close old architecture
	if (con->close) con->close(con);

	suspend_init_con(con);

	DPRINT(1, "SUSPENDED %s", pscom_con_str(&con->pub));
}


static
void io_done_send_suspend(pscom_req_state_t state, void *priv_con)
{
	pscom_con_t *con = priv_con;

	DPRINT(2, "SUSPEND sent %s", pscom_con_str(&con->pub));
	con->pub.state |= PSCOM_CON_STATE_SUSPEND_SENT;

	_pscom_con_check_suspended(con);
}


static
void _pscom_con_send_suspend(pscom_con_t *con, int portno)
{
	_pscom_send_inplace(con, PSCOM_MSGTYPE_SUSPEND,
			    &portno, sizeof(portno),
			    NULL, 0,
			    io_done_send_suspend, con);
}


void _pscom_con_suspend(pscom_con_t *con)
{
	int portno;
	pscom_sock_t *sock = get_sock(con->pub.socket);

	assert(con->magic == MAGIC_CONNECTION);

	if (con->pub.type == PSCOM_CON_TYPE_ONDEMAND) return; // Nothing to do
	if ((con->pub.state & PSCOM_CON_STATE_SUSPENDING) != 0) return; // Already called
	if ((con->pub.state & PSCOM_CON_STATE_W) == 0) return; // Can't write

	pscom_listener_user_inc(&sock->listen);
	portno = pscom_get_portno(&sock->pub);

	_pscom_con_send_suspend(con, portno);
	con->write_start = _write_start_suspending; // Queue further writes

	con->pub.state = PSCOM_CON_STATE_SUSPENDING;
}


void _pscom_con_suspend_received(pscom_con_t *con, void *xheader, unsigned xheaderlen)
{
	int portno;
	assert(xheaderlen == (unsigned)sizeof(portno));
	portno = *(int*)xheader;

	DPRINT(2, "SUSPEND received on %s", pscom_con_str(&con->pub));

	if (!(con->pub.state & PSCOM_CON_STATE_SUSPENDING)) {
		// i am a passive site. Drain sendq.
		_pscom_con_suspend(con);
	}

	con->pub.state |= PSCOM_CON_STATE_SUSPEND_RECEIVED;

	_pscom_con_check_suspended(con);
}
