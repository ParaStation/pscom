/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_H_
#define _PSCOM_UTIL_H_

#include <sys/uio.h>
#include <sys/time.h>

#include "pscom_priv.h"

#ifndef pscom_min
#define pscom_min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef pscom_max
#define pscom_max(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* preprocessor helpers */
#define _PSCOM_MAKE_STRING(x) #x
#define PSCOM_MAKE_STRING(x)  _PSCOM_MAKE_STRING(x)

/* Somewhere in the middle of the GCC 2.96 development cycle, we implemented
   a mechanism by which the user can annotate likely branch directions and
   expect the blocks to be reordered appropriately.  Define __builtin_expect
   to nothing for earlier compilers.  */
#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif

#ifndef likely
#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
#endif

void pscom_memcpy_gpu_safe_default(void *dst, const void *src, size_t len);
void pscom_memcpy_gpu_safe_from_user(void *dst, const void *src, size_t len);
void pscom_memcpy_gpu_safe_to_user(void *dst, const void *src, size_t len);
int pscom_memcmp_gpu_safe(const void *buf_a, const void *buf_b, size_t length);


/**
 * \brief Compare two memory buffers
 *
 * \param [in] buf_a  First buffer to be compared.
 * \param [in] buf_b  Second buffer to be compared.
 * \param [in] length Length of both buffers `buf_a` and `buf_b`.
 *
 * \return An integer less than, equal to, or greater than zero if the first
 *         `length` bytes of `buf_a` is found, respectively, to be less than,
 *         to match, or be greater than the first `length` bytes of `buf_b`.
 */
static inline int pscom_memcmp(const void *buf_a, const void *buf_b,
                               size_t length)
{
#ifdef PSCOM_CUDA_AWARENESS
    return pscom_memcmp_gpu_safe(buf_a, buf_b, length);
#else
    return memcmp(buf_a, buf_b, length);
#endif /* PSCOM_CUDA_AWARENESS */
}

/* Define different memcpy() variants making assumptions about the the user
 * buffer (which may be device memory). At this point, we map to their
 * pscom_memcpy_gpu_safe_*() counterpart to avoid CUDA dependencies, e.g.,
 * within the pscom plugins.
 */

/**
 * \brief Default synchronous memcpy variant
 *
 * This variant does not make any assumptions on the source and destination
 * buffers.
 *
 * \param [in] dst Pointer to the destination buffer.
 * \param [in] src Pointer to the source buffer.
 * \param [in] len Amount of bytes to be copied.
 */
static inline void _pscom_memcpy_default(void *dst, const void *src, size_t len)
{
#ifdef PSCOM_CUDA_AWARENESS
    pscom_memcpy_gpu_safe_default(dst, src, len);
#else
    memcpy(dst, src, len);
#endif
}

/**
 * \brief Synchronous memcpy from user memory to host memory.
 *
 * \param [in] dst Pointer to the destination buffer (within host memory).
 * \param [in] src Pointer to the source buffer.
 * \param [in] len Amount of bytes to be copied.
 */
static inline void _pscom_memcpy_from_user(void *dst, const void *src,
                                           size_t len)
{
#ifdef PSCOM_CUDA_AWARENESS
    pscom_memcpy_gpu_safe_from_user(dst, src, len);
#else
    memcpy(dst, src, len);
#endif
}

/**
 * \brief Synchronous memcpy from host memory to user memory.
 *
 * \param [in] dst Pointer to the destination buffer.
 * \param [in] src Pointer to the source buffer (within host memory).
 * \param [in] len Amount of bytes to be copied.
 */
static inline void _pscom_memcpy_to_user(void *dst, const void *src, size_t len)
{
#ifdef PSCOM_CUDA_AWARENESS
    pscom_memcpy_gpu_safe_to_user(dst, src, len);
#else
    memcpy(dst, src, len);
#endif
}

/* iovlen : number of blocks in iov. return bytelen of iov */
static inline size_t pscom_iovec_len(struct iovec *iov, size_t iovlen)
{
    size_t len = 0;
    while (iovlen) {
        len += iov->iov_len;
        iov++;
        iovlen--;
    }
    return len;
}


static inline void pscom_read_from_iov(char *data, struct iovec *iov, size_t len)
{
    while (len > 0) {
        if (iov->iov_len) {
            size_t copy = pscom_min(len, iov->iov_len);
            _pscom_memcpy_from_user(data, iov->iov_base, copy);
            len -= copy;
            data += copy;
            iov->iov_base = (void *)((char *)iov->iov_base + copy);
            iov->iov_len -= copy;
        }
        iov++;
    }
}


static inline void pscom_write_to_iov(struct iovec *iov, char *data, size_t len)
{
    while (len > 0) {
        if (iov->iov_len) {
            size_t copy = pscom_min(len, iov->iov_len);
            _pscom_memcpy_to_user(iov->iov_base, data, copy);
            len -= copy;
            data += copy;
            iov->iov_base = (void *)((char *)iov->iov_base + copy);
            iov->iov_len -= copy;
        }
        iov++;
    }
}


static inline void pscom_forward_iov(struct iovec *iov, size_t len)
{
    while (len > 0) {
        if (iov->iov_len) {
            size_t copy = pscom_min(len, iov->iov_len);
            len -= copy;
            iov->iov_base = (void *)((char *)iov->iov_base + copy);
            iov->iov_len -= copy;
        }
        iov++;
    }
}


static inline void pscom_memcpy_to_iov(const struct iovec *iov, char *data,
                                       size_t len)
{
    while (len > 0) {
        if (iov->iov_len) {
            size_t copy = pscom_min(len, iov->iov_len);
            _pscom_memcpy_to_user(iov->iov_base, data, copy);
            len -= copy;
            data += copy;
        }
        iov++;
    }
}


static inline void pscom_memcpy_from_iov(char *data, const struct iovec *iov,
                                         size_t len)
{
    while (len > 0) {
        if (iov->iov_len) {
            size_t copy = pscom_min(len, iov->iov_len);
            _pscom_memcpy_from_user(data, iov->iov_base, copy);
            len -= copy;
            data += copy;
        }
        iov++;
    }
}

/* strncpy with forced null-termination. Similar to strlcpy(), but with
   additional filling of dest with null bytes from strncpy. */
static inline char *pscom_strncpy0(char *dest, const char *src, size_t n)
{
    strncpy(dest, src, n - 1);
    dest[n - 1] = 0;
    return dest;
}

static inline void pscom_gettimeofday(struct timeval *tv)
{
    if (gettimeofday(tv, NULL)) {
        // Error
        tv->tv_sec = tv->tv_usec = 0;
    }
}

static inline unsigned long pscom_wtime_usec(void)
{
    struct timeval tv;
    pscom_gettimeofday(&tv);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

static inline unsigned long pscom_wtime_msec(void)
{
    struct timeval tv;
    pscom_gettimeofday(&tv);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static inline unsigned long pscom_wtime_sec(void)
{
    struct timeval tv;
    pscom_gettimeofday(&tv);
    return tv.tv_sec;
}

#endif /* _PSCOM_UTIL_H_ */
