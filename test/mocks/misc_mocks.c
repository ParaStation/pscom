/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <errno.h>
#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <sys/socket.h>
#include <sys/types.h>
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>
#include <poll.h>

#include "mocks/misc_mocks.h"
#include "pscom_utest.h"

/**
 * \brief Mocking function for memcpy()
 */
void *__wrap_memcpy(void *restrict dst, const void *restrict src, size_t nbytes)
{
    /* only mock memcpy if this is set for the current test */
    if (pscom_utest.mock_functions.memcpy) {
        function_called();
        check_expected(dst);
        check_expected(src);
        check_expected(nbytes);
    }

    return __real_memcpy(dst, src, nbytes);
}


/**
 * \brief Mocking function for malloc()
 */
void *__wrap_malloc(size_t size)
{
    /*
     * only mock malloc if this is set for the current test via
     * enable_malloc_mock()
     *
     * NOTE: Currently, this only supports single calls to malloc()!
     *       (there is no stack implemented)
     */
    if (pscom_utest.mock_functions.malloc.enabled) {
        return pscom_utest.mock_functions.malloc.addr;
    }

    return __real_malloc(size);
}


/**
 * \brief Mocking function for free()
 */
void __wrap_free(void *ptr)
{
    /* only mock malloc if this is set for the current test */
    if (pscom_utest.mock_functions.free) { check_expected(ptr); }

    /* call the original free() */
    __real_free(ptr);

    return;
}


/**
 * \brief Mocking function for dlsym()
 */
void *__wrap_dlsym(void *restrict handle, const char *restrict symbol)
{
    check_expected(symbol);

    return mock_type(void *);
}


/**
 * \brief Mocking function for dlopen()
 */
void *__wrap_dlopen(const char *filename, int flags)
{
    check_expected(filename);

    return mock_type(void *);
}


/**
 * \brief Mocking function for dlclose()
 */
int __wrap_dlclose(void *handle)
{
    return 0;
}


/**
 * \brief Mocking function for dlerror()
 */
char *__wrap_dlerror(void)
{
    return NULL;
}


/**
 * \brief Mocking function for read()
 */
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if (pscom_utest.mock_functions.read) {
        errno = mock_type(int);
        return mock_type(ssize_t);
    }

    return __real_read(fd, buf, count);
}


/**
 * \brief Mocking function for send()
 */
ssize_t __wrap_send(int sockfd, const void *buf, size_t len, int flags)
{
    errno = mock_type(int);
    return mock_type(ssize_t);
}


/**
 * \brief Mocking function for poll()
 */
int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    fds->revents = mock_type(short);
    return mock_type(int);
}


/**
 * \brief Mocking function for setsockopt()
 */
int __wrap_setsockopt(int sockfd, int level, int optname, const void *optval,
                      socklen_t optlen)
{
    return 0;
}


/**
 * \brief Mocking function for sched_yield()
 */
int __wrap_sched_yield(void)
{
    if (pscom_utest.mock_functions.sched_yield) {
        pscom_utest_sched_yield_mock_t mock_func = mock_type(
            pscom_utest_sched_yield_mock_t);
        void *mock_arg = mock_type(void *);

        return mock_func(mock_arg);
    }

    return __real_sched_yield();
}
