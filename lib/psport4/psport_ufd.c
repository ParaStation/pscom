/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psport_ufd.c: File handling
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "psport_ufd.h"
#include "psport_priv.h" /* likely and unlikely makro */

void ufd_init(ufd_t *ufd)
{
    memset(ufd, 0, sizeof(*ufd));
    /* ufd->nufds = 0; */
}

int ufd_add(ufd_t *ufd, int fd,
	    void (*can_read)(ufd_t *ufd, int ufd_idx),
	    void (*can_write)(ufd_t *ufd, int ufd_idx),
	    int (*poll)(ufd_t *ufd, int ufd_idx, int timeout),
	    int *pindex,
	    void *priv)
{
    int idx = ufd->nufds;
    struct pollfd *u = &ufd->ufds[idx];
    ufd_funcinfo_t *ui = &ufd->ufds_info[idx];

    ufd->nufds++;

    if (ufd->nufds > PSP_MAX_UFDS) goto error;

    u->fd = fd;
    u->events = 0;
    u->revents = 0;
    ui->can_read = can_read;
    ui->can_write = can_write;
    ui->poll = poll;
    ui->pindex = pindex;
    ui->priv = priv;

    if (ui->pindex)
	*ui->pindex = idx;
    return idx;
    /* --- */
 error:
    fprintf(stderr, "%s(): assert(ufd->nufds > PSP_MAX_UFDS) failed!\n", __FUNCTION__);
    exit(1);
}

void ufd_del(ufd_t *ufd, int fd)
{
    int idx;
    int i;

    for (idx = 0; idx < ufd->nufds; idx++) {
	if (ufd->ufds[idx].fd == fd) {
	    ufd->nufds--;
	    /* move list down. */
	    for (i = idx; i < ufd->nufds; i++) {
		ufd->ufds[i] = ufd->ufds[i + 1];
		ufd->ufds_info[i] = ufd->ufds_info[i + 1];
		if (ufd->ufds_info[i].pindex) /* index update */
		    *ufd->ufds_info[i].pindex = i;
	    }
	    break;
	}
    }

    return;
}

void ufd_event_set(ufd_t *ufd, int idx, int event)
{
    ufd->ufds[idx].events |= event;
}

void ufd_event_clr(ufd_t *ufd, int idx, int event)
{
    ufd->ufds[idx].events &= ~event;
}

int ufd_poll(ufd_t *ufd, int timeout)
{
    int nfds;
    int i;

//    printf("Poll with timeout %d\n", timeout);

    if (unlikely(!ufd->nufds)) return 0;

    if ((ufd->nufds == 1) &&
	(ufd->ufds_info[0].poll)) {
	int ret;
	/* Just wait for one event (Maybe one blocking receive) */
	ret = ufd->ufds_info[0].poll(ufd, 0, timeout);
	if (ret) return 1;
	/* fallback to poll */
    }

    nfds = poll(ufd->ufds, ufd->nufds, timeout);

    if (nfds <= 0) return 0;

    for (i = 0; i < ufd->nufds; i++) {
	if (ufd->ufds[i].revents & POLLIN) {
	    ufd->ufds[i].revents &= ~POLLIN;
	    ufd->ufds_info[i].can_read(ufd, i);

	    if (ufd->ufds[i].revents & POLLOUT) {
		ufd->ufds[i].revents &= ~POLLOUT;
		ufd->ufds_info[i].can_write(ufd, i);
	    }
	    if (!(--nfds)) return 1;
	} else if (ufd->ufds[i].revents & POLLOUT) {
	    ufd->ufds[i].revents &= ~POLLOUT;
	    ufd->ufds_info[i].can_write(ufd, i);
	    if (!(--nfds)) return 1;
	}
    }
    return 1;
}
