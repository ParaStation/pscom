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
#include "pscom_cuda.h"
#include "pscom_env.h"
#include "pslib.h"
#include "pscom_async.h"

PSCOM_PLUGIN_API_EXPORT
pscom_t pscom = {
	.sockets     = LIST_HEAD_INIT(pscom.sockets),
	.requests    = LIST_HEAD_INIT(pscom.requests),
	.ufd_timeout = -1,

	.recvq_any_global        = LIST_HEAD_INIT(pscom.recvq_any_global),
	.recv_req_cnt_any_global = 0,

	.global_lock   = PTHREAD_MUTEX_INITIALIZER,
	.lock_requests = PTHREAD_MUTEX_INITIALIZER,
	.threaded      = 0, /* default is unthreaded */

	.io_doneq = LIST_HEAD_INIT(pscom.io_doneq),

	.poll_read   = POLL_LIST_HEAD_INIT(pscom.poll_read),
	.poll_write  = POLL_LIST_HEAD_INIT(pscom.poll_write),
	.backlog     = LIST_HEAD_INIT(pscom.backlog),

	.backlog_lock = PTHREAD_MUTEX_INITIALIZER,

	/* parameter from environment */
	.env = PSCOM_ENV_defaults,

	/* statistic */
	.stat = {
		.reqs = 0,
		.gen_reqs = 0,
		.gen_reqs_used = 0,
		.rendezvous_reqs = 0,
		.fallback_to_eager = 0,
		.fallback_to_sw_rndv = 0,
		.progresscounter = 0,
		.progresscounter_check = 0,
		.reqs_any_source = 0,
		.recvq_any = 0,
		.recvq_any_global = 0,
		.probes = 0,
		.iprobes_ok = 0,
		.probes_any_source = 0,
		.shm_direct = 0,
		.shm_direct_nonshmptr = 0,
		.shm_direct_failed = 0,
	},
};


PSCOM_API_EXPORT
ssize_t pscom_writeall(int fd, const void *buf, size_t count)
{
	ssize_t len;
	size_t c = count;

	while (c > 0) {
		len = write(fd, buf, c);
		if (len < 0) {
			if ((errno == EINTR) || (errno == EAGAIN)) {
				sched_yield();
				continue;
			} else
				return -1;
		}
		c -= (size_t)len;
		buf = ((char*)buf) + len;
	}

	return (ssize_t)count;
}


PSCOM_API_EXPORT
ssize_t pscom_readall(int fd, void *buf, size_t count)
{
	ssize_t len;
	size_t c = count;

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
				return (ssize_t)(count - c);
			}
		}
		c -= (size_t)len;
		buf = ((char*)buf) + len;
	}

	return (ssize_t)count;
}


#define PSP_NDCBS 10
PSCOM_PLUGIN_API_EXPORT
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


PSCOM_PLUGIN_API_EXPORT_ONLY
void pscom_poll_write_stop(pscom_con_t *con)
{
	pscom_poll_stop(&con->poll_write);
}


PSCOM_PLUGIN_API_EXPORT_ONLY
void pscom_poll_read_stop(pscom_con_t *con)
{
	pscom_poll_stop(&con->poll_read);
}


PSCOM_PLUGIN_API_EXPORT
int pscom_progress(int timeout)
{
	struct list_head *pos, *next;

	pscom_poll(&pscom.poll_write);

	if (pscom_poll(&pscom.poll_read)) {
		return 1;
	}

	if (!pscom_poll_list_empty(&pscom.poll_write) ||
	    !pscom_poll_list_empty(&pscom.poll_read)) {
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
	DPRINT(D_DBG_V, "pscom_cleanup()");
	while (!list_empty(&pscom.sockets)) {
		pscom_sock_t *sock = list_entry(pscom.sockets.next, pscom_sock_t, next);
		pscom_close_socket(&sock->pub);
	}

	pscom_plugins_destroy();
	pscom_pslib_cleanup();
	if (pscom.env.debug >= D_STATS) pscom_dump_reqstat(pscom_debug_stream());
	perf_print();
	DPRINT(D_INFO, "Byee.");
}


static
void _pscom_suspend_resume(void *dummy)
{
	static int suspend = 1;
	struct list_head *pos_sock;
	struct list_head *pos_con;

	if (suspend) {
		DPRINT(D_SUSPEND_DBG, "SUSPEND signal received");
	} else {
		DPRINT(D_SUSPEND_DBG, "RESUME signal received");
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

PSCOM_API_EXPORT
void pscom_set_debug(int level)
{
	pscom.env.debug = level;
}


PSCOM_API_EXPORT
pscom_err_t pscom_init(int pscom_version)
{
	static int init=1;

	perf_add("init");
	if (!(PSCOM_VERSION & 0x8000) && (pscom_version & 0x8000)) {
		DPRINT(D_FATAL, "Error: libpscom: Application defined PSCOM_CUDA_AWARENESS, but this libpscom is build without.");
		return PSCOM_ERR_UNSUPPORTED_VERSION;
	}
	if (((pscom_version & 0x7f00) != (PSCOM_VERSION & 0x7f00)) ||
	    ((pscom_version & 0xff) > (PSCOM_VERSION & 0xff))) {
		// different major number, or minor number bigger
		// (new libs support old api, if major number is equal)
		DPRINT(D_FATAL, "Error: libpscom ABI version mismatch! Application requested V%u.%u but libpscom is V%u.%u.",
		       (pscom_version >> 8) & 0x7f, pscom_version & 0xff,
		       (PSCOM_VERSION >> 8) & 0x7f, PSCOM_VERSION & 0xff
		);
		return PSCOM_ERR_UNSUPPORTED_VERSION;
	}

	if (init <= 0) goto out;
	init = PSCOM_SUCCESS;

	ufd_init(&pscom.ufd);

	pscom_pslib_init();
	pscom_env_init();
	pscom_debug_init();

#ifdef PSCOM_CUDA_AWARENESS
	if ((init = pscom_cuda_init()) != PSCOM_SUCCESS)  goto out;
#endif

	if (pscom.env.sigsegv) {
		pscom_backtrace_onsigsegv_enable();
	}
	if (pscom.env.sigsuspend) {
		signal(pscom.env.sigsuspend, _pscom_suspend_sighandler);
	}

	atexit(pscom_cleanup);

out:
	return init;
}


PSCOM_API_EXPORT
pscom_err_t pscom_init_thread(int pscom_version)
{
	pscom.threaded = 1;
	return pscom_init(pscom_version);
}


PSCOM_API_EXPORT
int pscom_get_nodeid(void)
{
	static int id = 0;
	/*  p4s_node_id(void) expect the IP of this node! */

	if (!id) {
		id = psp_getid(); /* Use env PSP_NETWORK to get an IP */
	}
	return id;
}


PSCOM_PLUGIN_API_EXPORT
in_addr_t pscom_hostip(char *name)
{
	return ntohl(psp_hostip(name));
}


PSCOM_API_EXPORT
int pscom_get_portno(pscom_socket_t *socket)
{
	return socket->listen_portno;
}


PSCOM_API_EXPORT
int pscom_test_any(void)
{
	int ret;
	pscom_lock(); {
		ret = pscom_progress(0);
	} pscom_unlock();

	return ret;
}
