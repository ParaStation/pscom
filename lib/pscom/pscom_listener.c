/*
 * ParaStation
 *
 * Copyright (C) 2009-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <assert.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "pscom_debug.h"
#include "pscom_priv.h"
#include "pscom_ufd.h"


void pscom_listener_init(struct pscom_listener *listener,
                         void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info),
                         void *priv)
{
    memset(listener, 0, sizeof(*listener));
    listener->ufd_info.fd       = -1;
    listener->ufd_info.can_read = can_read;
    listener->ufd_info.priv     = priv;

    listener->usercnt   = 0;
    listener->activecnt = 0;
    listener->suspend   = 0;
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
    /* In suspended state we can have active counter == 0 when entering this
     * function; make sure that we do not decrement 0. */
    if (listener->activecnt > 0) {
        listener->activecnt--;
    } else {
        assert(listener->suspend == 1);
    }

    if (!listener->activecnt) {
        ufd_del(&pscom.ufd, &listener->ufd_info);

        pscom_listener_user_dec(listener);
    }
}


/* Add ufd_info back to the pscom ufd list and start listening again,
 * must be used in pair with pscom_listener_suspend */
void pscom_listener_resume(struct pscom_listener *listener)
{
    assert(listener->suspend == 1);
    assert(listener->usercnt > 1);

    listener->suspend = 0;
    listener->activecnt++;

    /* Start polling again on fd */
    ufd_add(&pscom.ufd, &listener->ufd_info);
    ufd_event_set(&pscom.ufd, &listener->ufd_info, POLLIN);

    /* Decrement user counter again (undo increment from previous suspend) */
    pscom_listener_user_dec(listener);
}


/* Remove ufd_info from the pscom ufd list and stop listening
 * The fd is not closed! Use pscom_listener_resume to start listening again. */
void pscom_listener_suspend(struct pscom_listener *listener)
{
    assert(listener->suspend == 0);
    assert(listener->activecnt > 0);

    listener->suspend = 1;

    /* Need to decrement active counter here so that ondemand connections
     * can re-add the fd to the udf list to complete their connections and
     * remove it again once they are done. */
    listener->activecnt--;

    /* Remove fd from polling */
    ufd_del(&pscom.ufd, &listener->ufd_info);

    /* Increment user counter to prevent fd from being closed in suspended
     * state, this is needed for ondemand connections */
    pscom_listener_user_inc(listener);
}
