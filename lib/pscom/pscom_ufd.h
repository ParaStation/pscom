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


#ifndef _PSCOM_UFD_H_
#define _PSCOM_UFD_H_

#include <poll.h>
#include "list.h"

struct ufd_s;
typedef struct ufd_info_s ufd_info_t;
typedef struct ufd_s ufd_t;
typedef ufd_info_t ufd_funcinfo_t;


/**
 * @brief Information about the ufd
 */
struct ufd_info_s {
    struct list_head next; /**< Used by: - list ufd_t.ufd_info */
    int fd;                /**< fd to monitor */
    int pollfd_idx;        /**< position in ufd_pollfd or -1 */

    void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info); /**< can_read() function
                                                           pointer */
    void (*can_write)(ufd_t *ufd, ufd_info_t *ufd_info);        /**< can_write()
                                                                   function pointer */
    int (*poll)(ufd_t *ufd, ufd_info_t *ufd_info, int timeout); /**< poll()
                                                                   function
                                                                   pointer */

    void *priv; /**< free usage */
};


#define PSCOM_MAX_UFDS (256 * 1024) /**< Maximum number of pollfds */


/**
 * @brief List of ufd_info and their associated pollfds
 */
struct ufd_s {
    struct list_head ufd_info;                   /**< List of ufd_info_t.next */
    struct pollfd ufd_pollfd[PSCOM_MAX_UFDS];    /**< Array of pollfds */
    ufd_info_t *ufd_pollfd_info[PSCOM_MAX_UFDS]; /**< point back from idx
                                                    ufd_pollfd[idx] to ufd_info
                                                  */

    unsigned int n_ufd_pollfd; /**< current number of pollfds */
};


/**
 * @brief Initialize ufd
 *
 * This function starts the ufd
 *
 * @param [in] ufd     ufd pointer
 */
void ufd_init(ufd_t *ufd);


/**
 * @brief Adds a ufd_info
 *
 * This function adds a new ufd_info to the ufd
 *
 * @param [in] ufd       ufd pointer
 * @param [in] ufd_info  ufd_info pointer
 */
void ufd_add(ufd_t *ufd, ufd_info_t *ufd_info);


/**
 * @brief Removes a ufd_info
 *
 * This function removes a curret ufd_info from the ufd
 *
 * @param [in] ufd       ufd pointer
 * @param [in] ufd_info  ufd_info pointer
 */
void ufd_del(ufd_t *ufd, ufd_info_t *ufd_info);


/**
 * @brief Sets a new event
 *
 * This function sets an event to ufd_info
 *
 * @param [in] ufd       ufd_pointer
 * @param [in] ufd_info  ufd_info pointer
 * @param [in] event     POLLIN or/and POLLOUT
 */
void ufd_event_set(ufd_t *ufd, ufd_info_t *ufd_info, short event)
    __attribute__((nonnull(1, 2)));


/**
 * @brief Clears a current event
 *
 * This function removes an event from ufd_info
 *
 * @param [in] ufd       ufd_pointer
 * @param [in] ufd_info  ufd_info pointer
 * @param [in] event     POLLIN or/and POLLOUT
 */
void ufd_event_clr(ufd_t *ufd, ufd_info_t *ufd_info, short event)
    __attribute__((nonnull(1, 2)));


/**
 * @brief Checks for the ufd_info associated with the file descriptor
 *
 * This function tries to find an ufd_info associated with the given file
 * descriptor
 *
 * @param [in] ufd     ufd pointer
 * @param [in] fd      file descriptor
 *
 * @return ::ufd_info_t  The associated file descriptor is found.
 *
 * @return ::NULL        The associated file descriptor is not found.
 */
ufd_info_t *ufd_info_find_fd(ufd_t *ufd, int fd);


/**
 * @brief Checks for a pollfd given a ufd_info
 *
 * This function tries to find an associated pollfd from ufd_info
 * in case an ufd event is set
 *
 * @param [in] ufd       ufd_pointer
 * @param [in] ufd_info  ufd_info pointer
 *
 * @return ::pollfd  In case event is set with udf_event_set
 *
 * @return ::NULL    In case event is not set with udf_event_set
 */
struct pollfd *ufd_get_pollfd(ufd_t *ufd, ufd_info_t *ufd_info)
    __attribute__((nonnull(1, 2)));


/**
 * @brief Starts polling for new events
 *
 * This function will poll for new events and will trigger
 * can_read or/and can_write if certain conditions are met
 *
 * @param [in] ufd      ufd pointer
 * @param [in] timeout  time out
 *
 * @return ::0  Timeout or failure
 *
 * @return ::1  Success
 */
int ufd_poll(ufd_t *ufd, int timeout);


/**
 * @brief Starts polling for new events (multi-threaded version)
 *
 * This threadsafe function of ufd_poll will
 * release the pscom_lock() when sleeping.
 *
 * @param [in] ufd      ufd pointer
 * @param [in] timeout  time out in seconds
 *
 * @return ::0  Timeout or failure
 *
 * @return ::1  Success
 */
int ufd_poll_threaded(ufd_t *ufd, int timeout);

#endif /* _PSCOM_UFD_H_ */
