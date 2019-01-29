/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_UTIL_H_
#define _PSCOM_UTIL_H_

#include <sys/uio.h>

#include "pscom_types.h"

#ifndef pscom_min
#define pscom_min(a,b)      (((a)<(b))?(a):(b))
#endif
#ifndef pscom_max
#define pscom_max(a,b)      (((a)>(b))?(a):(b))
#endif


/* Somewhere in the middle of the GCC 2.96 development cycle, we implemented
   a mechanism by which the user can annotate likely branch directions and
   expect the blocks to be reordered appropriately.  Define __builtin_expect
   to nothing for earlier compilers.  */
#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif

#ifndef likely
#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)
#endif

void pscom_memcpy_gpu_safe(void* dst, const void* src, size_t len);

static inline
void _pscom_memcpy(void* dst, const void* src, size_t len)
{
#ifdef PSCOM_CUDA_AWARENESS
	if(pscom.env.cuda) {
		pscom_memcpy_gpu_safe(dst, src, len);
	} else
#endif
	{
		memcpy(dst, src, len);
	}
}

/* iovlen : number of blocks in iov. return bytelen of iov */
static inline
size_t pscom_iovec_len(struct iovec *iov, size_t iovlen)
{
    size_t len = 0;
    while (iovlen) {
	len += iov->iov_len;
	iov++;
	iovlen--;
    }
    return len;
}


static inline
void pscom_read_from_iov(char *data, struct iovec *iov, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			size_t copy = pscom_min(len, iov->iov_len);
			_pscom_memcpy(data, iov->iov_base, copy);
			len -= copy;
			data += copy;
			iov->iov_base += copy;
			iov->iov_len -= copy;
		}
		iov++;
	}
}


static inline
void pscom_write_to_iov(struct iovec *iov, char *data, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			size_t copy = pscom_min(len, iov->iov_len);
			_pscom_memcpy(iov->iov_base, data, copy);
			len -= copy;
			data += copy;
			iov->iov_base += copy;
			iov->iov_len -= copy;
		}
		iov++;
	}
}


static inline
void pscom_forward_iov(struct iovec *iov, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			size_t copy = pscom_min(len, iov->iov_len);
			len -= copy;
			iov->iov_base += copy;
			iov->iov_len -= copy;
		}
		iov++;
	}
}


static inline
void pscom_memcpy_to_iov(const struct iovec *iov, char *data, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			size_t copy = pscom_min(len, iov->iov_len);
			_pscom_memcpy(iov->iov_base, data, copy);
			len -= copy;
			data += copy;
		}
		iov++;
	}
}


static inline
void pscom_memcpy_from_iov(char *data, const struct iovec *iov, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			size_t copy = pscom_min(len, iov->iov_len);
			_pscom_memcpy(data, iov->iov_base, copy);
			len -= copy;
			data += copy;
		}
		iov++;
	}
}

/* strncpy with forced null-termination. Similar to strlcpy(), but with
   additional filling of dest with null bytes from strncpy. */
static inline
char *pscom_strncpy0(char *dest, const char *src, size_t n)
{
    strncpy(dest, src, n - 1);
    dest[n - 1] = 0;
    return dest;
}

#endif /* _PSCOM_UTIL_H_ */
