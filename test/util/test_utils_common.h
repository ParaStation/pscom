/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_COMMON_H_
#define _PSCOM_UTIL_COMMON_H_

#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>


/* Since older versions of cmocka have limited support for the
 * "equal" assertion across different data types, we are using
 * our own macro here for unsigned int. In the future, when a
 * broader support (cmocka 2.0.0) is more commonly available,
 * this own macro here shall be removed again.
 */
#ifndef assert_uint_equal
#define assert_uint_equal(_a, _b)                                              \
    do {                                                                       \
        uintmax_t __ua = (uintmax_t)(_a);                                      \
        uintmax_t __ub = (uintmax_t)(_b);                                      \
        assert_true(__ua <= INTMAX_MAX && __ub <= INTMAX_MAX);                 \
        assert_int_equal((intmax_t)__ua, (intmax_t)__ub);                      \
    } while (0)
#endif

typedef struct {
    const char *const name; /* envvar name (input) */
    const char *value;      /* new value to set (input) */
    int overwrite;          /* flag for `setenv()` (input) */
    char *old_value;        /* own backup string (internal) */
    int initialized;        /* flag for backup state (internal) */
} test_utils_common_envvar_backup_t;

void test_utils_common_envvar_backup_capture(
    test_utils_common_envvar_backup_t *backup);
void test_utils_common_envvar_backup_restore(
    test_utils_common_envvar_backup_t *backup);

#endif /* _PSCOM_UTIL_COMMON_H_ */
