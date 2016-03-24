/*
 * ParaStation
 *
 * Copyright (C) 2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_util.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <assert.h>

#include <fcntl.h>
#include <sched.h>
#include <netdb.h>
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include "list.h"
#include "getid.c"
#include "pscom_ufd.h"
#include "pscom_str_util.h"
#include "pscom_con.h"
#include "pscom_env.h"
#include "pslib.h"
#include "pscom_async.h"

pscom_t pscom = {
	.threaded = 0, /* default is unthreaded */
	/* parameter from environment */
	.env = PSCOM_ENV_defaults,
	/* statistic */
	.stat = {
		.reqs = 0,
		.gen_reqs = 0,
		.gen_reqs_used = 0,
		.progresscounter = 0,
		.progresscounter_check = 0,
		.reqs_any_source = 0,
		.recvq_any = 0,
		.probes = 0,
		.iprobes_ok = 0,
		.probes_any_source = 0,
		.shm_direct = 0,
		.shm_direct_nonshmptr = 0,
		.shm_direct_failed = 0,
	},
};


int pscom_writeall(int fd, const void *buf, int count)
{
	int len;
	int c = count;

	while (c > 0) {
		len = write(fd, buf, c);
		if (len < 0) {
			if ((errno == EINTR) || (errno == EAGAIN)) {
				sched_yield();
				continue;
			} else
				return -1;
		}
		c -= len;
		buf = ((char*)buf) + len;
	}

	return count;
}


int pscom_readall(int fd, void *buf, int count)
{
	int len;
	int c = count;

	while (c > 0) {
		len = read(fd, buf, c);
		if (len <= 0) {
			if (len < 0) {
				if ((errno == EINTR) || (errno == EAGAIN)) {
					sched_yield();
					continue;
				} else
					return -1;
			} else {
				return count - c;
			}
		}
		c -= len;
		buf = ((char*)buf) + len;
	}

	return count;
}


#define PSP_NDCBS 10
void pscom_unlock(void)
{
	int ndcbs;
	int i;
	int more;
	struct {
		pscom_req_t *req;
	} dcbs[PSP_NDCBS];

restart:
	more = 0;
	ndcbs = 0;
	if (list_empty(&pscom.io_doneq)) {
		_pscom_unlock();
		return;
	}


	while (!list_empty(&pscom.io_doneq)) {
		pscom_req_t *req = list_entry(pscom.io_doneq.next, pscom_req_t, next);
		list_del(&req->next);
		dcbs[ndcbs].req = req;
		ndcbs++;
		if (ndcbs == PSP_NDCBS) {
			more = 1;
			break;
		}
	}

	_pscom_unlock();

	/* execute the done callbacks (without any lock) */
	for(i = 0; i < ndcbs; i++) {
		pscom_req_t *req = dcbs[i].req;

		req->pub.state |= PSCOM_REQ_STATE_DONE;
		req->pub.ops.io_done(&req->pub);
		// do not use req after io_done()! io_done could call free(req)
	}
	if (more) {
		/* There are more requests left */
		pscom_lock();
		goto restart;
	}
}


void pscom_poll_write_stop(pscom_con_t *con)
{
	/* it's save to dequeue more then once */
	list_del_init(&con->poll_next_send);
}


void pscom_poll_write_start(pscom_con_t *con)
{
	if (list_empty(&con->poll_next_send)) {
		list_add_tail(&con->poll_next_send, &pscom.poll_sender);
	}
	con->do_write(con);
	/* Dont do anything after this line.
	   do_write() can reenter pscom_poll_write_start()! */
}


void pscom_poll_read_start(pscom_con_t *con)
{
	pscom_poll_reader_t *reader = &con->poll_reader;
	if (list_empty(&reader->next)) {
		list_add_tail(&reader->next, &pscom.poll_reader);
	}

	reader->do_read(reader);
	/* Dont do anything after this line.
	   do_read() can reenter pscom_poll_read_start()! */
}


void pscom_poll_read_stop(pscom_con_t *con)
{
	pscom_poll_reader_t *reader = &con->poll_reader;

	/* it's save to dequeue more then once */
	list_del_init(&reader->next);
}


int pscom_progress(int timeout)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &pscom.poll_sender) {
		pscom_con_t *con = list_entry(pos, pscom_con_t, poll_next_send);
		con->do_write(con);
		timeout = 0; // enable polling
	}

	list_for_each_safe(pos, next, &pscom.poll_reader) {
		pscom_poll_reader_t *reader = list_entry(pos, pscom_poll_reader_t, next);
		if (reader->do_read(reader)) {
#if 0
			/* Fixme: reader might be dequeued in reader->do_read()
			 * with list_del() instead of list_del_init(). This could
			 * result in race here. */
			if(!list_empty(pos)) {
				/* avoid starvation: move reader to the back! */
				list_del(pos);
				list_add_tail(pos, &pscom.poll_reader);
			}
#endif
			return 1;
		}
		timeout = 0; // enable polling
	}

	if (unlikely(!pscom_backlog_empty())) {
		pscom_backlog_execute();
	}

	if (likely(!pscom.threaded)) {
		if (ufd_poll(&pscom.ufd, timeout)) {
			return 1;
		}
	} else {
		if (ufd_poll_threaded(&pscom.ufd, timeout)) {
			return 1;
		}
	}
	if (pscom.env.sched_yield) {
		sched_yield();
	}
	return 0;
}


static
void pscom_cleanup(void)
{
	DPRINT(3,"pscom_cleanup()");
	while (!list_empty(&pscom.sockets)) {
		pscom_sock_t *sock = list_entry(pscom.sockets.next, pscom_sock_t, next);
		pscom_close_socket(&sock->pub);
	}
	pscom_plugins_destroy();
	pscom_pslib_cleanup();
	if (pscom.env.debug_stats) pscom_dump_reqstat(pscom_debug_stream());
	perf_print();
	DPRINT(1,"Byee.");
}


static
void _pscom_suspend_resume(void *dummy)
{
	static int suspend = 1;
	struct list_head *pos_sock;
	struct list_head *pos_con;

	if (suspend) {
		DPRINT(1, "SUSPEND signal received");
	} else {
		DPRINT(1, "RESUME signal received");
	}
	// ToDo: Use pscom_lock() and fix the race with this handler and the main thread.

	list_for_each(pos_sock, &pscom.sockets) {
		pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

		list_for_each(pos_con, &sock->connections) {
			pscom_con_t *con = list_entry(pos_con, pscom_con_t, next);

			if (suspend) {
				con->state.suspend_active = 1;
				_pscom_con_suspend(con);
			} else {
				_pscom_con_resume(con);
			}
		}
	}
	suspend = !suspend;
}


static
void _pscom_suspend_sighandler(int signum)
{
	// Call _pscom_suspend_resume in main thread:
	pscom_backlog_push(_pscom_suspend_resume, NULL);
}

/*
******************************************************************************
*/

void pscom_set_debug(unsigned int level)
{
	pscom.env.debug = level;
}


int pscom_init(int pscom_version)
{
	static int init=0;

	perf_add("init");

	if (((pscom_version & 0xff00) != (PSCOM_VERSION & 0xff00)) ||
	    (pscom_version > PSCOM_VERSION)) {
		// different major number, or minor number bigger
		// (new libs support old api, if major number is equal)
		return PSCOM_ERR_UNSUPPORTED_VERSION;
	}
	if (init)
		return PSCOM_SUCCESS;
	init = 1;

	{
		int res_mutex_init;
		res_mutex_init = pthread_mutex_init(&pscom.global_lock, NULL);
		assert(res_mutex_init == 0);
		res_mutex_init = pthread_mutex_init(&pscom.lock_requests, NULL);
		assert(res_mutex_init == 0);
		res_mutex_init = pthread_mutex_init(&pscom.backlog_lock, NULL);
		assert(res_mutex_init == 0);
	}

	ufd_init(&pscom.ufd);
	INIT_LIST_HEAD(&pscom.sockets);
	INIT_LIST_HEAD(&pscom.requests);
	INIT_LIST_HEAD(&pscom.io_doneq);

	INIT_LIST_HEAD(&pscom.poll_reader);
	INIT_LIST_HEAD(&pscom.poll_sender);
	INIT_LIST_HEAD(&pscom.backlog);

	pscom_pslib_init();
	pscom_env_init();
	pscom_debug_init();

	if (pscom.env.sigsuspend) {
		signal(pscom.env.sigsuspend, _pscom_suspend_sighandler);
	}

	atexit(pscom_cleanup);
	return PSCOM_SUCCESS;
}


int pscom_init_thread(int pscom_version)
{
	pscom.threaded = 1;
	return pscom_init(pscom_version);
}


int pscom_get_nodeid(void)
{
	static uint32_t id = 0;
	/*  p4s_node_id(void) expect the IP of this node! */

	if (!id) {
		id = psp_getid(); /* Use env PSP_NETWORK to get an IP */
	}
	return id;
}


int pscom_get_portno(pscom_socket_t *socket)
{
	return socket->listen_portno;
}


int pscom_test_any(void)
{
	int ret;
	pscom_lock(); {
		ret = pscom_progress(0);
	} pscom_unlock();

	return ret;
}
