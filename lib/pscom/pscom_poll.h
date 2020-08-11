/*
 * ParaStation
 *
 * Copyright (C) 2013 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _PSCOM_POLL_H_
#define _PSCOM_POLL_H_

#include "list.h"

typedef struct pscom_poll pscom_poll_t;

typedef int pscom_poll_func_t(pscom_poll_t *poll);

struct pscom_poll {
	struct list_head	next; // Used by pscom_poll_list_t.list
	pscom_poll_func_t	*do_poll; // return 1 to exit polling loop (e.g. you made progress)
};

typedef struct {
	struct list_head	head;
} pscom_poll_list_t;

void pscom_poll_list_init(pscom_poll_list_t *poll_list);
int pscom_poll(pscom_poll_list_t *poll_list);

// Is poll list empty?
static inline
int pscom_poll_list_empty(pscom_poll_list_t *poll_list) {
	return list_empty(&poll_list->head);
}

#define POLL_LIST_HEAD_INIT(POLL_LIST) {	\
	.head = LIST_HEAD_INIT(POLL_LIST.head)	\
}


/**
 * Initialize poll.
 */
void pscom_poll_init(pscom_poll_t *poll);


/**
 * Start polling on poll. It is safe to call pscom_poll_start()
 * multiple times on the same poll.  pscom_poll_init(poll) must be
 * called before usage with start/stop
 */
void pscom_poll_start(pscom_poll_t *poll, pscom_poll_func_t *do_poll, pscom_poll_list_t *poll_list);


/**
 * Stop polling on poll. It is safe to call pscom_poll_stop() multiple
 * times on the same poll.  Afterwards poll is still en-queued in
 * pscom_poll_list_t, but marked for de-queuing in pscom_poll().
 */
void pscom_poll_stop(pscom_poll_t *poll);

/**
 * Stop polling on poll and de-queue it from pscom_poll_list_t. You
 * must not call pscom_poll_cleanup_init() while iterating via
 * pscom_poll() over pscom_poll_list_t. Use pscom_poll_stop() instead.
 * Afterwards, poll is not used by any list and could be free()d or used
 * again by pscom_poll_start().
 */
void pscom_poll_cleanup_init(pscom_poll_t *poll);


#endif /* _PSCOM_POLL_H_ */
