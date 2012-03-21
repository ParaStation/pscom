/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * p4prot_pub.h: p4prot public Prototypes
 */

#ifndef _P4PROT_PUB_H_
#define _P4PROT_PUB_H_

typedef struct p4_pollfunc_s {
    struct list_head next;
    void (*func)(void);
} p4_pollfunc_t;

void p4_poll_add(p4_pollfunc_t *pollfunc);
void p4_poll_del(p4_pollfunc_t *pollfunc);

#endif /* _P4PROT_PUB_H_ */
