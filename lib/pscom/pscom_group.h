/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_GROUP_H_
#define _PSCOM_GROUP_H_

#include "pscom_priv.h"
#include "pscom_io.h"
#include "pscom_req.h"
#include "pscom_queues.h"


typedef struct PSCOM_group_mem {
    pscom_con_t *con;

    struct list_head genrecvq; // List of pscom_req_t.next_alt
    struct list_head recvq;    // List of pscom_req_t.next_alt
} pscom_group_mem_t;


#define RANK_NONE ((unsigned)-1)


#define MAGIC_GROUP 0x02627061
struct PSCOM_group {
    unsigned long magic;
    struct list_head next; /* used by sock->groups */

    uint32_t group_id;
    uint32_t my_grank;

    unsigned group_size;

    unsigned *compat;          /* communication pattern (recvc[group_size]) */
    pscom_group_mem_t *member; /* list connections for all members */

    pscom_sock_t *sock;
};


pscom_group_t *_pscom_group_find(pscom_sock_t *sock, uint32_t group_id);

void pscom_group_gcompat_init(pscom_group_t *group);
void pscom_group_replay_bcasts(pscom_sock_t *sock, unsigned group_id);


static inline pscom_con_t *group_rank2con(pscom_group_t *group, unsigned grank)
{
    return group->member[grank].con;
}


static inline pscom_connection_t *group_rank2connection(pscom_group_t *group,
                                                        unsigned grank)
{
    return &group->member[grank].con->pub;
}

#endif /* _PSCOM_GROUP_H_ */
