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
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <assert.h>
#include "pscom_async.h"
#include "pscom_debug.h"
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
	PSCOM_ASYNC_MSG_DETACH = 2
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

static const
unsigned pscom_async_msg_sizes[] = {
	sizeof(struct pscom_async_msg_common_s),
	sizeof(struct pscom_async_msg_attach_s),
	sizeof(struct pscom_async_msg_detach_s)
};


typedef union pscom_async_msg_u pscom_async_msg_t;
union pscom_async_msg_u {
	struct pscom_async_msg_common_s msg_common;
	struct pscom_async_msg_attach_s msg_attach;
	struct pscom_async_msg_detach_s msg_detach;
};


typedef struct pscom_async_guard_s pscom_async_guard_t;
struct pscom_async_guard_s {
	ufd_info_t ufd_info;
};


static
pscom_async_ipc_t pscom_async_ipc = {
	.running = 0,
};


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


void pscom_backlog_execute() {
	struct list_head backlog;
	struct list_head *pos, *next;

	pscom_backlog_getall(&backlog);

	list_for_each_safe(pos, next, &backlog) {
		pscom_backlog_t *bl = list_entry(pos, pscom_backlog_t, next);

		bl->call(bl->priv);
		free(bl);
	}
}


static
void pscom_async_msg_attach(pscom_async_ipc_t *ipc, int fd, async_cb_t async_cb, void *priv) {
	pscom_async_guard_t *guard = malloc(sizeof(*guard));

	DPRINT(10, "pscom_async_msg_attach fd:%d priv:%p", fd, priv);

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

	DPRINT(10, "pscom_async_msg_detach fd:%d priv:%p", fd, priv);

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
		ufd_poll(&ipc->ufd, -1);
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
