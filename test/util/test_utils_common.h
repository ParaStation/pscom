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
