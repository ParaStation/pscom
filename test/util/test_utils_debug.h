/*
 * ParaStation
 *
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_DEBUG_H_
#define _PSCOM_UTIL_DEBUG_H_

typedef struct env_vars_backup {
        size_t count;
        char **backup_values;
} env_vars_backup_t;

int backup_env_vars(void **state);
int restore_env_vars(void **state);


int capture_fd(int fd);
void restore_fd(int fd);

#endif /* _PSCOM_UTIL_DEBUG_H_*/
