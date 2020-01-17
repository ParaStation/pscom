#ifndef _MOCKS_H_
#define _MOCKS_H_

#include <stddef.h>

void *__real_memcpy(void *restrict dst, const void *restrict src, size_t nbytes);

#endif /* _MOCKS_H_ */
