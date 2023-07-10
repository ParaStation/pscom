/*
 * ParaStation
 *
 * Copyright (C) 2013-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_poll.h"
#include "pscom_priv.h"

void pscom_poll_list_init(pscom_poll_list_t *poll_list)
{
    INIT_LIST_HEAD(&poll_list->head);
}


int pscom_poll(pscom_poll_list_t *poll_list)
{
    struct list_head *pos, *next;

    list_for_each_safe (pos, next, &poll_list->head) {
        pscom_poll_t *poll = list_entry(pos, pscom_poll_t, next);
        if (poll->do_poll) {
            if (poll->do_poll(poll)) { return 1; }
        } else {
            pscom_poll_cleanup_init(poll);
        }
    }
    return 0;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_poll_init(pscom_poll_t *poll)
{
    INIT_LIST_HEAD(&poll->next);
    poll->do_poll = NULL;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_poll_start(pscom_poll_t *poll, pscom_poll_func_t *do_poll,
                      pscom_poll_list_t *poll_list)
{
    poll->do_poll = do_poll;
    if (list_empty(&poll->next)) {
        // Enqueue
        list_add_tail(&poll->next, &poll_list->head);
    }
}


PSCOM_PLUGIN_API_EXPORT
void pscom_poll_stop(pscom_poll_t *poll)
{
    poll->do_poll = NULL; // Mark for de-queue
}


PSCOM_PLUGIN_API_EXPORT
void pscom_poll_cleanup_init(pscom_poll_t *poll)
{
    // De-queue
    list_del_init(&poll->next);
}
