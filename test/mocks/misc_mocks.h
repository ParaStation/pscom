/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _MOCKS_H_
#define _MOCKS_H_

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>

#include "pscom_utest.h"

ssize_t __real_read(int __fd, void *__buf, size_t __nbytes);
ssize_t __real_send(int __fd, const void *__buf, size_t __n, int __flags);
void *__real_memcpy(void *restrict dst, const void *restrict src, size_t nbytes);
void *__real_malloc(size_t size);
void __real_free(void *ptr);
int __real_sched_yield(void);

/* Mocking functions */

void *__wrap_memcpy(void *restrict dst, const void *restrict src, size_t nbytes);
void *__wrap_malloc(size_t size);
void __wrap_free(void *ptr);
void *__wrap_dlsym(void *restrict handle, const char *restrict symbol);
void *__wrap_dlopen(const char *filename, int flags);
int __wrap_dlclose(void *handle);
char *__wrap_dlerror(void);
ssize_t __wrap_read(int fd, void *buf, size_t count);
ssize_t __wrap_send(int sockfd, const void *buf, size_t len, int flags);
int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int __wrap_setsockopt(int sockfd, int level, int optname, const void *optval,
                      socklen_t optlen);
int __wrap_sched_yield(void);

typedef int (*pscom_utest_sched_yield_mock_t)(void *arg);

static inline void enable_memcpy_mock(void)
{
    pscom_utest.mock_functions.memcpy = 1;
}
static inline void disable_memcpy_mock(void)
{
    pscom_utest.mock_functions.memcpy = 0;
}

static inline void enable_malloc_mock(void *addr)
{
    pscom_utest.mock_functions.malloc.addr    = addr;
    pscom_utest.mock_functions.malloc.enabled = 1;
}
static inline void disable_malloc_mock(void)
{
    pscom_utest.mock_functions.malloc.addr    = NULL;
    pscom_utest.mock_functions.malloc.enabled = 0;
}

static inline void enable_free_mock(void)
{
    pscom_utest.mock_functions.free = 1;
}
static inline void disable_free_mock(void)
{
    pscom_utest.mock_functions.free = 0;
}

static inline void enable_read_mock(void)
{
    pscom_utest.mock_functions.read = 1;
}
static inline void disable_read_mock(void)
{
    pscom_utest.mock_functions.read = 0;
}

static inline void enable_sched_yield_mock(void)
{
    pscom_utest.mock_functions.sched_yield = 1;
}
static inline void disable_sched_yield_mock(void)
{
    pscom_utest.mock_functions.sched_yield = 0;
}

#endif /* _MOCKS_H_ */
