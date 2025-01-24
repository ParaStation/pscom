/*
 * ParaStation
 *
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdlib.h>
#include <stdio.h>

#include "test_utils_env.h"

int backup_test_val_env(void **state)
{
    static env_var_backup_t env_var_backup = {.name = "TEST_VAR"};

    /* backup environment variable */
    env_var_backup.value = getenv(env_var_backup.name);

    /* unset environment variable */
    unsetenv(env_var_backup.name);

    *state = (void *)&env_var_backup;

    return 0;
}

int restore_test_val_env(void **state)
{
    env_var_backup_t *env_var_backup = (env_var_backup_t *)(*state);

    if (env_var_backup->value) {
        setenv(env_var_backup->name, env_var_backup->value, 1);
    } else {
        unsetenv(env_var_backup->name);
    }

    return 0;
}

int backup_test_val_env_and_parent(void **state)
{
    static env_var_backup_t env_var_backup = {.name   = "TEST_VAR",
                                              .prefix = "SUBPREFIX_"};

    /* backup environment variable */
    char envvar[128];
    snprintf(envvar, sizeof(envvar) - 1, "%s%s", env_var_backup.prefix,
             env_var_backup.name);

    env_var_backup.value = getenv(envvar);

    /* backup parent variable */
    env_var_backup.parent_value = getenv(env_var_backup.name);


    /* unset environment variables */
    unsetenv(envvar);
    unsetenv(env_var_backup.name);

    *state = (void *)&env_var_backup;

    return 0;
}

int restore_test_val_env_and_parent(void **state)
{
    env_var_backup_t *env_var_backup = (env_var_backup_t *)(*state);

    /* restore parent */
    if (env_var_backup->parent_value) {
        setenv(env_var_backup->name, env_var_backup->parent_value, 1);
    } else {
        unsetenv(env_var_backup->name);
    }

    /* restore environment variable */
    char envvar[128];
    snprintf(envvar, sizeof(envvar) - 1, "%s%s", env_var_backup->prefix,
             env_var_backup->name);
    if (env_var_backup->value) {
        setenv(envvar, env_var_backup->value, 1);
    } else {
        unsetenv(envvar);
    }

    return 0;
}


int backup_three_test_val_env(void **state)
{
    int i;

    static env_var_backup_t env_var_backup[3] = {
        {.name = "TEST_VAR_INT"},
        {.name = "TEST_VAR_UINT"},
        {.name = "TEST_VAR_STR"},
    };

    for (i = 0; i < 3; ++i) {
        /* backup environment variable */
        env_var_backup[i].value = getenv(env_var_backup[i].name);

        /* unset environment variable */
        unsetenv(env_var_backup[i].name);
    }


    *state = (void *)&env_var_backup;

    return 0;
}

int restore_three_test_val_env(void **state)
{
    int i;
    env_var_backup_t *env_var_backup = (env_var_backup_t *)(*state);

    for (i = 0; i < 3; ++i) {
        if (env_var_backup[i].value) {
            setenv(env_var_backup[i].name, env_var_backup[i].value, 1);
        } else {
            unsetenv(env_var_backup[i].name);
        }
    }

    return 0;
}
