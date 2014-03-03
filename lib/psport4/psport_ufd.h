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
 * psport_ufd.h: File handling
 */

#ifndef _PSPORT_UFD_H_
#define _PSPORT_UFD_H_

#include <sys/poll.h>

struct ufd_s;
typedef struct ufd_funcinfo_s ufd_funcinfo_t;
typedef struct ufd_s ufd_t;

struct ufd_funcinfo_s {
    void (*can_read)(ufd_t *ufd, int ufd_idx);
    void (*can_write)(ufd_t *ufd, int ufd_idx);
    int (*poll)(ufd_t *ufd, int ufd_idx, int timeout);
    int  *pindex;

    void *priv;

    void *_fill1_;
    void *_fill2_;
    void *_fill3_;
};

#define PSP_MAX_UFDS 4096

struct ufd_s {
    struct pollfd	ufds[PSP_MAX_UFDS];
    ufd_funcinfo_t	ufds_info[PSP_MAX_UFDS];
    int			nufds;
};

void ufd_init(ufd_t *ufd);
int ufd_add(ufd_t *ufd, int fd,
	    void (*can_read)(ufd_t *ufd, int ufd_idx),
	    void (*can_write)(ufd_t *ufd, int ufd_idx),
	    int (*poll)(ufd_t *ufd, int ufd_idx, int timeout),
	    int *pindex,
	    void *priv);
void ufd_del(ufd_t *ufd, int fd);
void ufd_event_set(ufd_t *ufd, int idx, int event);
void ufd_event_clr(ufd_t *ufd, int idx, int event);
int ufd_poll(ufd_t *ufd, int timeout);

#endif /* _PSPORT_UFD_H_ */
