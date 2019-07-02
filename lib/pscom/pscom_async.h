/*
 * ParaStation
 *
 * Copyright (C) 2015 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _PSCOM_ASYNC_H_
#define _PSCOM_ASYNC_H_

#include "pscom_ufd.h"
#include "pscom_priv.h"

typedef void async_cb_t(ufd_t *ufd, ufd_info_t *ufd_info);
typedef void pscom_timer_cb_t(void *priv);

void pscom_async_on_readable(int fd, async_cb_t *async_cb, void *priv);
void pscom_async_off_readable(int fd, async_cb_t *async_cb, void *priv);
void pscom_timer(unsigned msec, pscom_timer_cb_t *timer_cb, void *priv);

void pscom_backlog_push(void (*call)(void *priv), void *priv);
// Delete first backlog entry with equal call and priv.
// return number of deleted entries (= 0 or 1)
int pscom_backlog_del(void (*call)(void *priv), void *priv);
void pscom_backlog_execute();
static inline
int pscom_backlog_empty(void) {
	return list_empty(&pscom.backlog);
}


#endif /* _PSCOM_ASYNC_H_ */
