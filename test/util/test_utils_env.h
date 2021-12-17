/*
 * ParaStation
 *
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_ENV_H_
#define _PSCOM_UTIL_ENV_H_

typedef struct env_var_backup {
        const char *name;
        char *value;
        char *parent_value;
        char *prefix;
} env_var_backup_t;

int backup_test_val_env(void **state);
int restore_test_val_env(void **state);
int backup_test_val_env_and_parent(void **state);
int restore_test_val_env_and_parent(void **state);
int backup_three_test_val_env(void **state);
int restore_three_test_val_env(void **state);

#endif /* _PSCOM_UTIL_ENV_H_*/
