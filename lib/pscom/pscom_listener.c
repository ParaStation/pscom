/*
 * ParaStation
 *
 * Copyright (C) 2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pscom_priv.h"



void pscom_listener_init(struct pscom_listener *listener,
			 void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info),
			 void *priv)
{
	memset(listener, 0, sizeof(*listener));
	listener->ufd_info.fd = -1;
	listener->ufd_info.can_read = can_read;
	listener->ufd_info.priv = priv;

	listener->usercnt = 0;
	listener->activecnt = 0;
}


void pscom_listener_set_fd(struct pscom_listener *listener, int fd)
{
	assert(fd >= 0);
	assert(listener->ufd_info.fd == -1);

	listener->ufd_info.fd = fd;
}


int pscom_listener_get_fd(struct pscom_listener *listener)
{
	return listener->ufd_info.fd;
}


void pscom_listener_user_inc(struct pscom_listener *listener)
{
	listener->usercnt++;
}


void pscom_listener_user_dec(struct pscom_listener *listener)
{
	assert(listener->usercnt > 0);

	listener->usercnt--;

	if (!listener->usercnt) {
		assert(!listener->activecnt);

		int fd = pscom_listener_get_fd(listener);
		if (fd >= 0) {
			close(fd);
		} else {
			DPRINT(D_WARN, "warning: %s() fd already closed", __func__);
		}
		listener->ufd_info.fd = -1;
	}
}


void pscom_listener_active_inc(struct pscom_listener *listener)
{
	int start = !listener->activecnt;

	listener->activecnt++;

	if (start) {
		pscom_listener_user_inc(listener);

		ufd_add(&pscom.ufd, &listener->ufd_info);
		ufd_event_set(&pscom.ufd, &listener->ufd_info, POLLIN);
	}
}


void pscom_listener_active_dec(struct pscom_listener *listener)
{
	listener->activecnt--;

	if (!listener->activecnt) {
		ufd_del(&pscom.ufd, &listener->ufd_info);

		pscom_listener_user_dec(listener);
	}
}
