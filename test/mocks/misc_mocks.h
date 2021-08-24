/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _MOCKS_H_
#define _MOCKS_H_

#include <stddef.h>

#include "pscom_utest.h"

void *__real_memcpy(void *restrict dst, const void *restrict src, size_t nbytes);
void *__real_malloc(size_t size);

static inline void enable_memcpy_mock(void) { pscom_utest.mock_functions.memcpy = 1; }
static inline void disable_memcpy_mock(void) { pscom_utest.mock_functions.memcpy = 0; }

static inline void enable_malloc_mock(void) { pscom_utest.mock_functions.malloc = 1; }
static inline void disable_malloc_mock(void) { pscom_utest.mock_functions.malloc = 0; }

#endif /* _MOCKS_H_ */
