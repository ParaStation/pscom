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

#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)


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
			int copy = pscom_min(len, iov->iov_len);
			memcpy(data, iov->iov_base, copy);
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
			int copy = pscom_min(len, iov->iov_len);
			memcpy(iov->iov_base, data, copy);
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
			int copy = pscom_min(len, iov->iov_len);
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
			int copy = pscom_min(len, iov->iov_len);
			memcpy(iov->iov_base, data, copy);
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
			int copy = pscom_min(len, iov->iov_len);
			memcpy(data, iov->iov_base, copy);
			len -= copy;
			data += copy;
		}
		iov++;
	}
}

#endif /* _PSCOM_UTIL_H_ */
