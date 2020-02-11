/*
 * ParaStation
 *
 * Copyright (C) 2015 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#define _GNU_SOURCE
#include <fcntl.h> // Obtain O_* constant definitions
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include <assert.h>
#include "pscom_async.h"
#include "pscom_debug.h"
#include "pscom_io.h"
#include "pscom_priv.h"

typedef struct pscom_async_ipc_s pscom_async_ipc_t;

struct pscom_async_ipc_s {
	pthread_t		thread_id;
	ufd_t			ufd;
	int			pipe[2];
	pthread_mutex_t		pipe_c2s_lock;
	unsigned		running : 1;

	ufd_info_t		ufd_service;
};

enum pscom_async_msg_type_e {
	PSCOM_ASYNC_MSG_NONE = 0,
	PSCOM_ASYNC_MSG_ATTACH = 1,
	PSCOM_ASYNC_MSG_DETACH = 2,
	PSCOM_ASYNC_MSG_TIMER = 3
};

#define PSCOM_ASYNC_MSG_COMMON \
	enum pscom_async_msg_type_e	msg_type; \
	volatile int			*ack; /* *ack=1 after message dispatch */

struct pscom_async_msg_common_s {
	PSCOM_ASYNC_MSG_COMMON
};

struct pscom_async_msg_attach_s {
	PSCOM_ASYNC_MSG_COMMON
	int		fd;
	async_cb_t	*async_cb;
	void		*priv;
};

struct pscom_async_msg_detach_s {
	PSCOM_ASYNC_MSG_COMMON
	int		fd;
	async_cb_t	*async_cb;
	void		*priv;
};

struct pscom_async_msg_timer_s {
	PSCOM_ASYNC_MSG_COMMON
	unsigned	msec;
	pscom_timer_cb_t *timer_cb;
	void		*priv;
};

static const
unsigned pscom_async_msg_sizes[] = {
	sizeof(struct pscom_async_msg_common_s),
	sizeof(struct pscom_async_msg_attach_s),
	sizeof(struct pscom_async_msg_detach_s),
	sizeof(struct pscom_async_msg_timer_s),
};


typedef union pscom_async_msg_u pscom_async_msg_t;
union pscom_async_msg_u {
	struct pscom_async_msg_common_s msg_common;
	struct pscom_async_msg_attach_s msg_attach;
	struct pscom_async_msg_detach_s msg_detach;
	struct pscom_async_msg_timer_s msg_timer;
};


typedef struct pscom_async_guard_s pscom_async_guard_t;
struct pscom_async_guard_s {
	ufd_info_t ufd_info;
};


typedef struct pscom_timer_s pscom_timer_t;
struct pscom_timer_s {
	struct list_head	next;
	unsigned long		timeout;
	pscom_timer_cb_t	*timer_cb;
	void			*priv;
};


static
pscom_async_ipc_t pscom_async_ipc = {
	.running = 0,
};


static
struct list_head pscom_timerq = LIST_HEAD_INIT(pscom_timerq);


#if 0
static
pscom_backlog_t *pscom_backlog_pop(void) {
	pscom_backlog_t *bl;
	pthread_mutex_lock(&pscom.backlog_lock);{
		if (list_empty(&pscom.backlog)) {
			bl = NULL;
		} else {
			// pop first entry
			bl = list_entry(pscom.backlog.next, pscom_backlog_t, next);
			list_del(&bl->next);
		}
	} pthread_mutex_unlock(&pscom.backlog_lock);
	return bl;
}
#endif

static
void pscom_backlog_getall(struct list_head *backlog) {
	pthread_mutex_lock(&pscom.backlog_lock);{
		list_add(backlog, &pscom.backlog); // Set new head
		list_del_init(&pscom.backlog); // detach from old head
	} pthread_mutex_unlock(&pscom.backlog_lock);
}


void pscom_backlog_push(void (*call)(void *priv), void *priv) {
	pscom_backlog_t *bl = malloc(sizeof(*bl));
	pthread_mutex_lock(&pscom.backlog_lock);{
		bl->call = call;
		bl->priv = priv;
		list_add_tail(&bl->next, &pscom.backlog);
	} pthread_mutex_unlock(&pscom.backlog_lock);
}


int pscom_backlog_del(void (*call)(void *priv), void *priv) {
	int ret = 0;
	pthread_mutex_lock(&pscom.backlog_lock);{
		struct list_head *pos, *next;

		list_for_each_safe(pos, next, &pscom.backlog) {
			pscom_backlog_t *bl = list_entry(pos, pscom_backlog_t, next);

			if ((bl->call == call) && (bl->priv == priv)) {
				list_del(pos);
				free(bl);
				ret = 1;
				break;
			}
		}
	} pthread_mutex_unlock(&pscom.backlog_lock);
	return ret;
}


void pscom_backlog_execute() {
	struct list_head backlog;
	struct list_head *pos, *next;

	pscom_backlog_getall(&backlog);

	list_for_each_safe(pos, next, &backlog) {
		pscom_backlog_t *bl = list_entry(pos, pscom_backlog_t, next);

		_pscom_step();
		bl->call(bl->priv);
		free(bl);
	}
}


static
void pscom_async_msg_attach(pscom_async_ipc_t *ipc, int fd, async_cb_t async_cb, void *priv) {
	pscom_async_guard_t *guard = malloc(sizeof(*guard));

	DPRINT(D_TRACE, "pscom_async_msg_attach fd:%d priv:%p", fd, priv);

	memset(guard, 0, sizeof(*guard));
	guard->ufd_info.fd = fd;
	guard->ufd_info.can_read = async_cb;
	guard->ufd_info.priv = priv;

	ufd_add(&ipc->ufd, &guard->ufd_info);
	ufd_event_set(&ipc->ufd, &guard->ufd_info, POLLIN);
}


static
void pscom_async_msg_detach(pscom_async_ipc_t *ipc, int fd, async_cb_t async_cb, void *priv) {
	ufd_info_t *ufd_info;
	pscom_async_guard_t *guard;

	DPRINT(D_TRACE, "pscom_async_msg_detach fd:%d priv:%p", fd, priv);

	ufd_info = ufd_info_find_fd(&ipc->ufd, fd);

	assert(ufd_info);
	assert(ufd_info->can_read == async_cb);
	assert(ufd_info->priv == priv);

	guard = list_entry(ufd_info, pscom_async_guard_t, ufd_info);

	ufd_del(&ipc->ufd, &guard->ufd_info);
	guard->ufd_info.fd = -1;

	free(guard);
}


static
unsigned long getmsec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}


long pscom_time_diff(unsigned long t1, unsigned long t2) {
	return t2 - t1;
}


static
void pscom_timer_add(pscom_timer_t *timer) {
	struct list_head *pos;

	list_for_each(pos, &pscom_timerq) {
		pscom_timer_t *t = list_entry(pos, pscom_timer_t, next);
		if (pscom_time_diff(timer->timeout, t->timeout) > 0) {
			list_add_tail(&timer->next, &t->next);
			return;
		}
	}
	list_add_tail(&timer->next, &pscom_timerq);
}


static
void pscom_timer_del(pscom_timer_t *timer) {
	list_del(&timer->next);
}


// Execute all expired timers. Return msec remaining to the next timer or -1 if none.
static
int pscom_timer_exec(void) {
	struct list_head *pos, *next;
	unsigned long now = getmsec();
	int timeout = -1;

	list_for_each_safe(pos, next, &pscom_timerq) {
		pscom_timer_t *timer = list_entry(pos, pscom_timer_t, next);
		long delta = pscom_time_diff(now, timer->timeout);
		if (delta <= 0) {
			pscom_backlog_push(timer->timer_cb, timer->priv);
			pscom_timer_del(timer);
			free(timer);
		} else {
			timeout = delta > INT_MAX ? INT_MAX : (int)delta;
			break;
		}
	}

	pscom.ufd_timeout = timeout; // ToDo: Fix potential race on pscom.ufd_timeout
	return timeout;
}


static
void pscom_async_msg_timer(pscom_async_ipc_t *ipc, unsigned msec, pscom_timer_cb_t timer_cb, void *priv) {
	pscom_timer_t *timer = malloc(sizeof(*timer));
	assert(timer);

	DPRINT(D_TRACE, "pscom_async_msg_timer msec:%u priv:%p", msec, priv);

	timer->timeout = getmsec() + msec;
	timer->timer_cb = timer_cb;
	timer->priv = priv;

	pscom_timer_add(timer);
}


static
void pscom_async_thread_service_read(ufd_t *ufd, ufd_info_t *ufd_service) {
	pscom_async_ipc_t *ipc = (pscom_async_ipc_t *)ufd_service->priv;
	int fd = ufd_service->fd;
	pscom_async_msg_t msg;
	int rlen;
	int msg_rest_len;

	rlen = (int)read(fd, &msg.msg_common, sizeof(msg.msg_common)); // blocking!
	assert(rlen == sizeof(msg.msg_common));

	msg_rest_len = pscom_async_msg_sizes[msg.msg_common.msg_type] - (unsigned)sizeof(msg.msg_common);
	rlen = (int)read(fd, (&msg.msg_common) + 1, msg_rest_len);
	assert(rlen == msg_rest_len);


	// Dispatch msg
	switch (msg.msg_common.msg_type) {
	case PSCOM_ASYNC_MSG_NONE:
		break;
	case PSCOM_ASYNC_MSG_ATTACH:
		pscom_async_msg_attach(ipc, msg.msg_attach.fd, msg.msg_attach.async_cb, msg.msg_attach.priv);
		break;
	case PSCOM_ASYNC_MSG_DETACH:
		pscom_async_msg_detach(ipc, msg.msg_detach.fd, msg.msg_detach.async_cb, msg.msg_detach.priv);
		break;
	case PSCOM_ASYNC_MSG_TIMER:
		pscom_async_msg_timer(ipc, msg.msg_timer.msec, msg.msg_timer.timer_cb, msg.msg_timer.priv);
		break;
	}

	// Send ack
	if (msg.msg_common.ack) *msg.msg_common.ack = 1;
}


static
void *pscom_async_thread(void *_ipc) {
	pscom_async_ipc_t *ipc = (pscom_async_ipc_t *)_ipc;
	ufd_info_t *ufd_service = &ipc->ufd_service;

	// Listen for reads on service fd
	memset(ufd_service, 0, sizeof(*ufd_service));
	ufd_service->fd = ipc->pipe[0]; // read end of pipe
	ufd_service->can_read = pscom_async_thread_service_read;
	ufd_service->priv = ipc;
	ufd_add(&ipc->ufd, ufd_service);
	ufd_event_set(&ipc->ufd, ufd_service, POLLIN);

	while (1) {
		int timeout = pscom_timer_exec();
		ufd_poll(&ipc->ufd, timeout);
	}
	return NULL;
}

static
void pscom_async_start_thread_once(pscom_async_ipc_t *ipc) {
	int rc;
	if (ipc->running) return; // Already started

	ufd_init(&ipc->ufd);

	rc = pipe2(ipc->pipe, O_CLOEXEC);
	assert(!rc);

	rc = pthread_create(&ipc->thread_id, NULL, pscom_async_thread, ipc);
	assert(!rc);

	ipc->running = 1;
}

static
void pscom_async_client_send(pscom_async_msg_t *msg) {
	int rlen;
	pscom_async_ipc_t *ipc = &pscom_async_ipc;
	volatile int ack = 0;
	int len = pscom_async_msg_sizes[msg->msg_common.msg_type];

	pscom_async_start_thread_once(ipc); // Start thread?

	msg->msg_common.ack = &ack;

	rlen = (int)write(ipc->pipe[1], msg, len); // Will block if pipe is full.
	assert(rlen == (int)len);

	// Busy wait for ack
	while (!ack) {
		sched_yield();
	}
}


void pscom_async_on_readable(int fd, async_cb_t *async_cb, void *priv)
{
	pscom_async_client_send(&(pscom_async_msg_t){
			.msg_attach = {
				.msg_type = PSCOM_ASYNC_MSG_ATTACH,
				.fd = fd,
				.async_cb = async_cb,
				.priv = priv
			}
		});
}


void pscom_async_off_readable(int fd, async_cb_t *async_cb, void *priv)
{
	pscom_async_client_send(&(pscom_async_msg_t){
			.msg_detach = {
				.msg_type = PSCOM_ASYNC_MSG_DETACH,
				.fd = fd,
				.async_cb = async_cb,
				.priv = priv
			}
		});
}


PSCOM_PLUGIN_API_EXPORT
void pscom_timer(unsigned msec, pscom_timer_cb_t *timer_cb, void *priv)
{
	if ((pscom.ufd_timeout == -1) ||
	    ((unsigned)pscom.ufd_timeout > msec)) {
		pscom.ufd_timeout = msec;
	}
	pscom_async_client_send(&(pscom_async_msg_t){
			.msg_timer = {
				.msg_type = PSCOM_ASYNC_MSG_TIMER,
				.msec = msec,
				.timer_cb = timer_cb,
				.priv = priv
			}
		});
}
