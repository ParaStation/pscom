/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_ufd.h: File handling
 */

#ifndef _PSCOM_UFD_H_
#define _PSCOM_UFD_H_

#include <sys/poll.h>
#include "list.h"

struct ufd_s;
typedef struct ufd_info_s ufd_info_t;
typedef struct ufd_s ufd_t;
typedef ufd_info_t ufd_funcinfo_t;

struct ufd_info_s {
    struct list_head next; /* Used by: - list ufd_t.ufd_info */
    int fd;                /* fd to monitor */
    int pollfd_idx;        /* position in ufd_pollfd or -1 */

    void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info);
    void (*can_write)(ufd_t *ufd, ufd_info_t *ufd_info);
    int (*poll)(ufd_t *ufd, ufd_info_t *ufd_info, int timeout);

    void *priv; /* free usage */
};

#define PSCOM_MAX_UFDS (256 * 1024)

struct ufd_s {
    struct list_head ufd_info; // List of ufd_info_t.next
    struct pollfd ufd_pollfd[PSCOM_MAX_UFDS];
    ufd_info_t *ufd_pollfd_info[PSCOM_MAX_UFDS]; // point back from idx
                                                 // ufd_pollfd[idx] to ufd_info

    unsigned int n_ufd_pollfd;
};

void ufd_init(ufd_t *ufd);

void ufd_add(ufd_t *ufd, ufd_info_t *ufd_info);
/*
   void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info),
   void (*can_write)(ufd_t *ufd, ufd_info_t *ufd_info),
   int (*poll)(ufd_t *ufd, ufd_info_t *ufd_info, inr timeout), void *priv);
*/
void ufd_del(ufd_t *ufd, ufd_info_t *ufd_info);
void ufd_event_set(ufd_t *ufd, ufd_info_t *ufd_info, short event)
    __attribute__((nonnull(1, 2)));
void ufd_event_clr(ufd_t *ufd, ufd_info_t *ufd_info, short event)
    __attribute__((nonnull(1, 2)));

/* find ufd_info_t associated with fd. Return NULL if not found. */
ufd_info_t *ufd_info_find_fd(ufd_t *ufd, int fd);

/* return associated pollfd from ufd_info. Return NULL if no event set
   with udf_event_set */
struct pollfd *ufd_get_pollfd(ufd_t *ufd, ufd_info_t *ufd_info)
    __attribute__((nonnull(1, 2)));

int ufd_poll(ufd_t *ufd, int timeout);

/* Threadsafe version of ufd_poll. Will release the pscom_lock() when sleeping.
 */
int ufd_poll_threaded(ufd_t *ufd, int timeout);

#endif /* _PSCOM_UFD_H_ */
