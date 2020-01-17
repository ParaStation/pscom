/*
 * ParaStation
 *
 * Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Simon Pickartz <pickartz@par-tec.com>
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