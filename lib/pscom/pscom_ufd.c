/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_ufd.c: File handling
 */

#include "pscom_ufd.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

void pscom_dump_info(FILE *out);


void ufd_init(ufd_t *ufd)
{
	memset(ufd, 0, sizeof(*ufd));
	INIT_LIST_HEAD(&ufd->ufd_info);
	ufd->n_ufd_pollfd = 0;
}


static
void ufd_copy(ufd_t *dest, ufd_t *src)
{
	dest->ufd_info = src->ufd_info;
	memcpy(dest->ufd_pollfd, src->ufd_pollfd,
	       src->n_ufd_pollfd * sizeof(dest->ufd_pollfd[0]));
	memcpy(dest->ufd_pollfd_info, src->ufd_pollfd_info,
	       src->n_ufd_pollfd * sizeof(dest->ufd_pollfd_info[0]));
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
	list_del(&ufd_info->next);
}


static
struct pollfd *_ufd_get_pollfd_idx(ufd_t *ufd, ufd_info_t *ufd_info)
{
	int idx = ufd->n_ufd_pollfd;
	ufd->n_ufd_pollfd++;

	// ToDo: Use malloced mem for ufd->ufd_pollfd_info and ufd->ufd_pollfd
	if (ufd->n_ufd_pollfd > PSCOM_MAX_UFDS) goto error;

	ufd->ufd_pollfd_info[idx] = ufd_info; // reverse pointer
	ufd_info->pollfd_idx = idx; // forward pointer

	return &ufd->ufd_pollfd[idx];
error:
	fprintf(stderr,
		"%s(): run out of file descriptors (PSCOM_MAX_UFDS=%u)!\n",
		__func__, PSCOM_MAX_UFDS);
	exit(1);
}


static
void _ufd_put_pollfd_idx(ufd_t *ufd, ufd_info_t *ufd_info)
{
	/* replace [idx] by [last] */
	int idx = ufd_info->pollfd_idx;
	int idx_last;
	ufd->n_ufd_pollfd--;

	idx_last = ufd->n_ufd_pollfd;

	ufd->ufd_pollfd[idx] = ufd->ufd_pollfd[idx_last];
	ufd->ufd_pollfd_info[idx] = ufd->ufd_pollfd_info[idx_last];  // reverse pointer
	ufd->ufd_pollfd_info[idx]->pollfd_idx = idx; // forward pointer

	ufd->ufd_pollfd_info[idx_last] = NULL; // invalidate old pointer
	ufd_info->pollfd_idx = -1; // invalidate old pointer
}


void ufd_event_set(ufd_t *ufd, ufd_info_t *ufd_info, short event)
{
	struct pollfd *pollfd = ufd_get_pollfd(ufd, ufd_info);

	if (pollfd) {
		pollfd->events |= event;
	} else {
		if (!event) return;

		pollfd = _ufd_get_pollfd_idx(ufd, ufd_info);

		pollfd->fd = ufd_info->fd;
		pollfd->events = event;
		pollfd->revents = 0;
	}
}


void ufd_event_clr(ufd_t *ufd, ufd_info_t *ufd_info, short event)
{
	struct pollfd *pollfd = ufd_get_pollfd(ufd, ufd_info);

	if (!pollfd) return; // already empty

	pollfd->events &= (short)~event;

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

	list_for_each(pos, &ufd->ufd_info) {
		ufd_info_t *ufd_info = list_entry(pos, ufd_info_t, next);

		if (ufd_info->fd == fd) return ufd_info;
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
	/*
	  if (ufd->n_ufd_pollfd == 1) { ...

	  Don't use the n_ufd_pollfd == 1 optimization in threaded environment.
	  ufd_info_t.poll() can block and is not thread save!
	*/


	/* create a thread local copy of ufd. */
	ufd_local = malloc(sizeof(*ufd_local));
	ufd_copy(ufd_local, ufd);

	/*
	  Process local communication between threads handled with polling?
	  How to handle races in ufd->ufd_info.next ?
	*/
	pscom_unlock();

	timeout  = 0; // workaround to avoid starvation
	sched_yield(); // allow other threads to progress.

	nfds = poll(ufd_local->ufd_pollfd, ufd_local->n_ufd_pollfd, timeout);

	pscom_lock();

	if (nfds <= 0) goto return_0; // Timeout or failure

	for (i = 0; i < ufd_local->n_ufd_pollfd; i++) {
		ufd_info_t *ufd_info = ufd_local->ufd_pollfd_info[i];
		struct pollfd *pollfd = &ufd_local->ufd_pollfd[i];

		/* ToDo: ufd_info still valid? Another thread might destruct *ufd_info */

		if (pollfd->revents & POLLIN) {
			pollfd->revents &= ~POLLIN;
			ufd_info->can_read(ufd, ufd_info);

			/* if can_read() calls ufd_del(), *pollfd is
			   replaced by the last pollfd and therefore
			   associated with a different ufd_info.  this
			   could be checked with
			   (ufd_local->ufd_pollfd_info[i] == ufd_info) */
			if ((pollfd->revents & POLLOUT) &&
			    (ufd_local->ufd_pollfd_info[i] == ufd_info)) {
				pollfd->revents &= ~POLLOUT;
				ufd_info->can_write(ufd, ufd_info);
			}
			if (!(--nfds)) goto return_1;
		} else if (pollfd->revents & POLLOUT) {
			pollfd->revents &= ~POLLOUT;
			ufd_info->can_write(ufd, ufd_info);
			if (!(--nfds)) goto return_1;
		}
	}
	/* Never be here. nfds == 0. */

return_1:
	free(ufd_local);
	return 1;
	/* --- */
return_0:
	free(ufd_local);
	return 0;
}


int ufd_poll(ufd_t *ufd, int timeout)
{
	int nfds;
	struct list_head *pos, *next;
	unsigned i;

	if (unlikely(!ufd->n_ufd_pollfd)) {
		if (timeout == 0) return 0;
		if (timeout < 0) {
			static int warn = 0;
			if (!warn) {
				fprintf(stderr, "Deadlock detected! Process %u will wait forever.\n",
					getpid());
				fprintf(stderr, "('wait' called without outstanding send or recv requests).\n");
				pscom_dump_info(stderr);
				fflush(stderr);
				warn = 60; // warn again after warn timeouts
				sleep(1);
				_exit(112); // Deadlock means: wait for ever. Better to terminate.
			}
			warn --;
			// timeout = 10 * 1000; // overwrite infinity timeout
		}
	}

	if (ufd->n_ufd_pollfd == 1) {
		ufd_info_t *ui_first = list_entry(ufd->ufd_info.next, ufd_info_t, next);
		if (ui_first->poll) {
			int ret;
			/* Just wait for one event (Maybe one blocking receive) */
			ret = ui_first->poll(ufd, ui_first, timeout);
			if (ret) return 1;
			/* fallback to poll */
		}
	}

	nfds = poll(ufd->ufd_pollfd, ufd->n_ufd_pollfd, timeout);

	if (nfds <= 0) return 0; // Timeout or failure

	for (i = ufd->n_ufd_pollfd; i--;) {
		ufd_info_t *ufd_info = ufd->ufd_pollfd_info[i];
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
			if (!(--nfds)) {
				return 1;
			}
		} else if (pollfd->revents & POLLOUT) {
			pollfd->revents &= ~POLLOUT;
			ufd_info->can_write(ufd, ufd_info);
			if (!(--nfds)) {
				return 1;
			}
		}
	}

	/* Could be here (nfds != 0), if someone calls ufd_del(). */
	return 1;
}
