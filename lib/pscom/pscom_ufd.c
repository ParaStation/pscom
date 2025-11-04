/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */


/**
 * @file pscom_ufd.c
 * @brief The pscom ufd mechanism simplifies and abstracts the handling of
 * file descriptors to be monitored by using the standard C poll() function.
 *
 * ufd_poll() or ufd_poll_threaded() functions will progress whenever
 * there are pollfds available, i.e., ufd->n_ufd_pollfd > 0.
 * When calling ufd_event_set(), a POLLIN or POLLOUT event will be
 * added to the pollfd associated with the ufd_info provided in the
 * mentioned function. In case of the first event being added,
 * the pollfd will be created and ufd->n_ufd_pollfd will increase.
 * In the opposite side we have ufd_event_clr(), which will remove
 * a POLLIN or POLLOUT event from the pollfd associated with the
 * ufd_info provided in this function. In case there are no more
 * events remaining in the pollfd afterwards, ufd->n_ufd_pollfd
 * will decrease and the mentioned pollfd will be removed.
 *
 * There is one ufd object per process and one ufd_info associated
 * with every precon. Also, there can be others ufd_info objects
 * associated with other structures like the pscom listener.
 * The ufd_info contains a file descriptor, a pollfd index that
 * can be -1 if there is no pollfd associated, a priv pointer for
 * free usage (usually to store a reference to a precon object) and
 * pointers to different functions like can_read() and can_write().
 * can_read() and can_write() will handle incoming and outcoming
 * messages, respectively.
 *
 * On the other hand, the ufd handles a list of ufd_info, an array
 * of pollfds, the current number of pollfds being monitored and an array of
 * ufd_info indexes.
 * The list stores all the ufd_info available at a given moment and can be
 * handle by ufd_add() and ufd_del() as explained later. Additionally, we have a
 * forward pointer from ufd_info via pollfd_idx (ufd_info->pollfd_idx) to
 * ufd->ufd_pollfd[idx], that is, the respective entry in the pollfd array.
 * ufd_info->pollfd_idx might be -1 in case there is no associated pollfd. On
 * the other hand, we have a reverse pointer from ufd in ufd_pollfd_info[idx] to
 * the ufd_info.
 *
 * While ufd_add() and ufd_del() will add and delete an ufd_info to and from
 * the list, respectively, ufd_event_set() and ufd_event_clr() will
 * add and remove a pollfd entry to and from the ufd_pollfd array, respectively.
 * Therefore, there can be an ufd_info object without and assigned ufd_pollfd
 * entry at a given moment, which is then indicated by an index of -1 in
 * ufd_info.
 *
 * In the threaded case, each thread makes a local copy of the global ufd
 * object and its arrays, and then calls the poll() function with this copy.
 * The local results are then processed concurrently in a lock-protected loop
 * in which the lock can, however, be temporarily released again.
 * To prevent threads from working on outdated ufd elements, unique tags in the
 * form of serial numbers are assigned to them. Only if the tag of the global
 * ufd array entry and that of the previously copied local entry are still the
 * same, the array element and its associated poll events are processed.
 */

#include "pscom_ufd.h"

#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include "pscom_debug.h"
#include "pscom_env.h"

void pscom_dump_info(FILE *out);


void ufd_init(ufd_t *ufd)
{
    memset(ufd, 0, sizeof(*ufd));
    INIT_LIST_HEAD(&ufd->ufd_info);
    ufd->n_ufd_pollfd = 0;

    if (pscom.threaded) {
        /* In the threaded case, we also need the array for ufd tags to
         * coordinate the threaded work */
        ufd->ufd_tag = malloc(sizeof(*ufd->ufd_tag) * sizeof(ufd->ufd_pollfd) /
                              sizeof(ufd->ufd_pollfd[0]));
    }
}

void ufd_cleanup(ufd_t *ufd)
{
    if (ufd->ufd_tag) {
        free(ufd->ufd_tag);
        ufd->ufd_tag = NULL;
    }

    while (!list_empty(&ufd->ufd_info)) {
        ufd_info_t *ufd_info = list_entry(ufd->ufd_info.next, ufd_info_t, next);
        ufd_del(ufd, ufd_info);
    }
    assert(ufd->n_ufd_pollfd == 0);
}

/**
 * @brief Local copy for multi-threaded
 *
 * This function creates a thread local copy of the ufd
 *
 * @param [in] dest  local ufd
 * @param [in] src   global ufd
 */
static void ufd_copy(ufd_t *dest, ufd_t *src)
{
    dest->ufd_info = src->ufd_info;
    memcpy(dest->ufd_pollfd, src->ufd_pollfd,
           src->n_ufd_pollfd * sizeof(dest->ufd_pollfd[0]));
    memcpy(dest->ufd_pollfd_info, src->ufd_pollfd_info,
           src->n_ufd_pollfd * sizeof(dest->ufd_pollfd_info[0]));
    memcpy(dest->ufd_tag, src->ufd_tag,
           src->n_ufd_pollfd * sizeof(dest->ufd_tag[0]));
    dest->n_ufd_pollfd = src->n_ufd_pollfd;
};


void ufd_add(ufd_t *ufd, ufd_info_t *ufd_info)
{
    list_add_tail(&ufd_info->next, &ufd->ufd_info);
    ufd_info->pollfd_idx = -1;
}


struct pollfd *ufd_get_pollfd(ufd_t *ufd, ufd_info_t *ufd_info)
{
    int idx = ufd_info->pollfd_idx;

    return idx >= 0 ? &ufd->ufd_pollfd[idx] : NULL;
}


void ufd_del(ufd_t *ufd, ufd_info_t *ufd_info)
{
    struct pollfd *pollfd = ufd_get_pollfd(ufd, ufd_info);
    if (pollfd) {
        pollfd->revents = 0; /* No further processing in ufd_poll(),
                                if called from on_read() callback */
        /* remove me from ufd->ufd_pollfd */
        ufd_event_clr(ufd, ufd_info, pollfd->events);
        assert(ufd_get_pollfd(ufd, ufd_info) == NULL);
    }

    /* Remove me from list (only once to prevent broken list) */
    list_del_init(&ufd_info->next);
}


/**
 * @brief Generate a new unique tag for an ufd array entry
 *
 * This function tags the ufd array entry at the given
 * index with a unique sequence number.
 *
 * @param [in] ufd       ufd pointer
 * @param [in] idx       array index
 *
 * @@return newly assigned sequence number
 */
static inline uint64_t pscom_ufd_update_tag(ufd_t *ufd, int idx)
{
    static uint64_t seq_nbr = 0;

    /* If no ufd_tag array has been allocated (non-threaded case),
       then also no tags will be assigned here. Therefore, in the
       non-threaded case, this function is basically a no-op.
    */
    if (ufd->ufd_tag) {
        seq_nbr++;
        ufd->ufd_tag[idx] = seq_nbr;
    }

    return seq_nbr;
}

/**
 * @brief Allocate a free entry in the ufd_pollfd array
 *
 * This function increases the number of currently monitored pollfds.
 * The new pollfd is stored in the last index.
 * It also stores the associated ufd_info and
 * the latter stores the index of the pollfd
 *
 * @param [in] ufd       ufd pointer
 * @param [in] ufd_info  ufd_info pointer
 *
 * @@return pointer to assigned array entry
 */
static struct pollfd *_ufd_get_pollfd_idx(ufd_t *ufd, ufd_info_t *ufd_info)
{
    int idx = ufd->n_ufd_pollfd;
    /* Increase number of currently monitored pollfds */
    ufd->n_ufd_pollfd++;

    // ToDo: Use malloced mem for ufd->ufd_pollfd_info and ufd->ufd_pollfd
    if (ufd->n_ufd_pollfd > PSCOM_MAX_UFDS) { goto error; }

    ufd->ufd_pollfd_info[idx] = ufd_info; // reverse pointer
    ufd_info->pollfd_idx      = idx;      // forward pointer

    /* Generate a unique tag for this ufd entry */
    pscom_ufd_update_tag(ufd, idx);

    return &ufd->ufd_pollfd[idx];
error:
    fprintf(stderr, "%s(): run out of file descriptors (PSCOM_MAX_UFDS=%u)!\n",
            __func__, PSCOM_MAX_UFDS);
    exit(1);
}


/**
 * @brief Release an assigned entry in the ufd_pollfd array
 *
 * This function decreases the number of currently monitored pollfds.
 * The last pollfd will be moved to the position
 * of the removed one and it will take its index.
 * The previous last position will be deleted.
 *
 * @param [in] ufd       ufd pointer
 * @param [in] ufd_info  ufd_info pointer
 */
static void _ufd_put_pollfd_idx(ufd_t *ufd, ufd_info_t *ufd_info)
{
    /* replace [idx] by [last] */
    int idx = ufd_info->pollfd_idx;
    int idx_last;
    /* Decrease number of currently monitored pollfds */
    ufd->n_ufd_pollfd--;

    idx_last = ufd->n_ufd_pollfd;

    /* Move last pollfd to the position of the removed one */
    ufd->ufd_pollfd[idx]      = ufd->ufd_pollfd[idx_last];
    ufd->ufd_pollfd_info[idx] = ufd->ufd_pollfd_info[idx_last]; // reverse
                                                                // pointer
    ufd->ufd_pollfd_info[idx]->pollfd_idx = idx; // forward pointer

    ufd->ufd_pollfd_info[idx_last] = NULL; // invalidate old pointer
    ufd_info->pollfd_idx           = -1;   // invalidate old pointer

    /* Update tags to notify other threads */
    pscom_ufd_update_tag(ufd, idx);
    pscom_ufd_update_tag(ufd, idx_last);
}


void ufd_event_set(ufd_t *ufd, ufd_info_t *ufd_info, short event)
{
    struct pollfd *pollfd = ufd_get_pollfd(ufd, ufd_info);

    if (pollfd) {
        /* In case of existing pollfd, add the corresponding event */
        pollfd->events |= event;

        /* Update tag to notify other threads */
        pscom_ufd_update_tag(ufd, ufd_info->pollfd_idx);

    } else {
        /* No event set */
        if (!event) { return; }

        /* Created a new pollfd */
        pollfd = _ufd_get_pollfd_idx(ufd, ufd_info);

        /* File descriptor to poll */
        pollfd->fd      = ufd_info->fd;
        /* Given type of event the poller will care about */
        pollfd->events  = event;
        /* Initialization to 0 of the event that will occur later */
        pollfd->revents = 0;
    }
}


void ufd_event_clr(ufd_t *ufd, ufd_info_t *ufd_info, short event)
{
    /* obtain pollfd from ufd_info */
    struct pollfd *pollfd = ufd_get_pollfd(ufd, ufd_info);

    if (!pollfd) {
        return; // already empty
    }

    /* Remove the given event */
    pollfd->events &= (short)~event;

    /* Update tag to notify other threads */
    pscom_ufd_update_tag(ufd, ufd_info->pollfd_idx);

    if (!pollfd->events) {
        // empty events
        _ufd_put_pollfd_idx(ufd, ufd_info);

        // Move ufd_info to the tail (speedup ufd_poll)
        list_del(&ufd_info->next);
        list_add_tail(&ufd_info->next, &ufd->ufd_info);
    }
}


ufd_info_t *ufd_info_find_fd(ufd_t *ufd, int fd)
{
    struct list_head *pos;

    list_for_each (pos, &ufd->ufd_info) {
        ufd_info_t *ufd_info = list_entry(pos, ufd_info_t, next);

        if (ufd_info->fd == fd) { return ufd_info; }
    }
    return NULL;
}


int ufd_poll_threaded(ufd_t *ufd, int timeout)
{
    int nfds;
    unsigned int i;
    ufd_t *ufd_local;

    if (unlikely(!ufd->n_ufd_pollfd)) {
        if (timeout <= 0) {
            /* timeout == 0 : polling mode.

               timeout < 0 : Maybe a race with another thread?
                             To prevent a deadlock return with 0
                             and behave, as if we would poll. */
            pscom_unlock();
            sched_yield(); // allow other threads to progress.
            pscom_lock();
            // pscom_lock_yield(); // allow other threads to progress.
            return 0;
        }
    }

    /* create a thread local copy of ufd. */
    ufd_local          = malloc(sizeof(*ufd_local));
    ufd_local->ufd_tag = malloc(sizeof(*ufd->ufd_tag) * ufd->n_ufd_pollfd);
    ufd_copy(ufd_local, ufd);

    /*
      Process local communication between threads handled with polling?
      How to handle races in ufd->ufd_info.next ?
    */
    pscom_unlock();

    timeout = 0;   // workaround to avoid starvation
    sched_yield(); // allow other threads to progress.

    nfds = poll(ufd_local->ufd_pollfd, ufd_local->n_ufd_pollfd, timeout);

    pscom_lock();

    if (nfds <= 0) {
        goto return_0; // Timeout or failure
    }

    /* Loop around all pollfds available */
    for (i = 0; i < ufd_local->n_ufd_pollfd; i++) {
        ufd_info_t *ufd_info         = ufd_local->ufd_pollfd_info[i];
        struct pollfd *local_pollfd  = &ufd_local->ufd_pollfd[i];
        struct pollfd *global_pollfd = &ufd->ufd_pollfd[i];

        /* Check that the global ufd array entry is still valid and
           that we are dealing with a still pending POLLIN event */
        if ((ufd_local->ufd_tag[i] == ufd->ufd_tag[i]) &&
            (local_pollfd->revents & POLLIN)) {
            assert(global_pollfd->events & POLLIN);
            local_pollfd->revents &= ~POLLIN;
            /* Before handling the event, assign a new tag to mark it as
               invalid for other threads but remember it for this thread */
            ufd_local->ufd_tag[i] = pscom_ufd_update_tag(ufd, i);
            ufd_info->can_read(ufd, ufd_info);

            /* Check that the global ufd array entry is still valid and
               that we are dealing with a still pending POLLOUT event */
            if ((ufd_local->ufd_tag[i] == ufd->ufd_tag[i]) &&
                (local_pollfd->revents & POLLOUT)) {
                assert(global_pollfd->events & POLLOUT);
                local_pollfd->revents &= ~POLLOUT;
                /* Before handling the event, assign a new tag
                   to mark it as invalid for other threads */
                pscom_ufd_update_tag(ufd, i);
                ufd_info->can_write(ufd, ufd_info);
            }
            if (!(--nfds)) { goto return_1; }

            /* Check that the global ufd array entry is still valid and
               that we are dealing with a still pending POLLOUT event */
        } else if ((ufd_local->ufd_tag[i] == ufd->ufd_tag[i]) &&
                   (local_pollfd->revents & POLLOUT)) {
            assert(global_pollfd->events & POLLOUT);
            local_pollfd->revents &= ~POLLOUT;
            /* Before handling the event, assign a new tag
               to mark it as invalid for other threads */
            pscom_ufd_update_tag(ufd, i);
            ufd_info->can_write(ufd, ufd_info);
            if (!(--nfds)) { goto return_1; }
        }
    }
    /* Never be here. nfds == 0. */

return_1:
    free(ufd_local->ufd_tag);
    free(ufd_local);
    return 1;
    /* --- */
return_0:
    free(ufd_local->ufd_tag);
    free(ufd_local);
    return 0;
}


int ufd_poll(ufd_t *ufd, int timeout)
{
    int nfds;
    unsigned i;

    /* No pollfds available */
    if (unlikely(!ufd->n_ufd_pollfd)) {
        if (timeout == 0) { return 0; }
        if (timeout < 0) {
            static int warn = 0;
            if (warn == pscom.env.deadlock_warnings) {
                DPRINT(D_FATAL,
                       "Deadlock detected! Process %u will wait forever "
                       "('wait' called without outstanding send or recv "
                       "requests). Exit!\n",
                       getpid());
                DEXEC(D_DBG_V, pscom_dump_info(stderr));
                fflush(stderr);

                _exit(112); // Deadlock means: wait for ever. Better to
                            // terminate.
            }
            if (pscom.env.deadlock_warnings != -1) {
                warn++;
                DPRINT(D_BUG,
                       "Warning of deadlock in Process %u for %d times!\n",
                       getpid(), warn);
            }
            sleep(1);
            return 0;
        }
    }

    nfds = poll(ufd->ufd_pollfd, ufd->n_ufd_pollfd, timeout);

    if (nfds <= 0) {
        return 0; // Timeout or failure
    }

    /* Loop around all pollfds available */
    for (i = ufd->n_ufd_pollfd; i--;) {
        ufd_info_t *ufd_info  = ufd->ufd_pollfd_info[i];
        struct pollfd *pollfd = &ufd->ufd_pollfd[i];

        if (pollfd->revents & POLLIN) {
            pollfd->revents &= ~POLLIN;
            ufd_info->can_read(ufd, ufd_info);

            /* if can_read() calls ufd_del(), *pollfd is
               replaced by the last pollfd (associated with
               a different ufd_info. As the loop start at
               the end, this (pollfd->revents & POLLOUT) is
               already 0 or (i >= ufd->n_ufd_pollfd). */
            if ((i < ufd->n_ufd_pollfd) && (pollfd->revents & POLLOUT)) {
                pollfd->revents &= ~POLLOUT;
                ufd_info->can_write(ufd, ufd_info);
            }
            if (!(--nfds)) { return 1; }
        } else if (pollfd->revents & POLLOUT) {
            pollfd->revents &= ~POLLOUT;
            ufd_info->can_write(ufd, ufd_info);
            if (!(--nfds)) { return 1; }
        }
    }

    /* Could be here (nfds != 0), if someone calls ufd_del(). */
    return 1;
}
