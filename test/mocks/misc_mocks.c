/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

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
	/* only mock malloc if this is set for the current test */
	if (pscom_utest.mock_functions.malloc) {
		return NULL;
	}

	return __real_malloc(size);
}
