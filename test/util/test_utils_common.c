/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdlib.h>
#include <string.h>
#include "test_utils_common.h"

void test_utils_common_envvar_backup_capture(
    test_utils_common_envvar_backup_t *backup)
{
    /* save the old envvar value (if set) and overwrite it (if requested) */
    const char *orig  = getenv(backup->name);
    backup->old_value = orig ? strdup(orig) : NULL;

    /* set/overwrite or unset */
    if (backup->value) {
        setenv(backup->name, backup->value, backup->overwrite);
    } else {
        unsetenv(backup->name);
    }

    /* mark backup struct as initialized */
    backup->initialized = 1;
}

void test_utils_common_envvar_backup_restore(
    test_utils_common_envvar_backup_t *backup)
{
    /* do nothing if backup struct is not initialized */
    if (!backup->initialized) { return; };

    /* restore or unset the envvar to its state saved before the test */
    if (backup->old_value) {
        setenv(backup->name, backup->old_value, 1);
        free(backup->old_value);
        backup->old_value = NULL;
    } else {
        unsetenv(backup->name);
    }

    /* mark backup struct as uninitialized */
    backup->initialized = 0;
}
