/*
 * ParaStation
 *
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_utils_debug.h"

static const char *env_vars_from_pscom[] = {
    "PSP_DEBUG",
    "PSP_DEBUG_OUT",
};

int
backup_env_vars(void **state)
{
        static env_vars_backup_t env_vars_backup = {
            .count = sizeof(env_vars_from_pscom) / sizeof(*env_vars_from_pscom),
        };
        env_vars_backup.backup_values =
            (char **)malloc(env_vars_backup.count * sizeof(char *));

        /* backup and unset all environment variables in env_vars_from_pscom */
        for (size_t i = 0; i < env_vars_backup.count; ++i) {
                env_vars_backup.backup_values[i] =
                    getenv(env_vars_from_pscom[i]);

                unsetenv(env_vars_from_pscom[i]);
        }

        *state = (void *)&env_vars_backup;

        return 0;
}


int
restore_env_vars(void **state)
{
        env_vars_backup_t *env_vars_backup = (env_vars_backup_t *)(*state);

        /* restore all environment variables in env_vars_from_pscom */
        for (size_t i = 0; i < env_vars_backup->count; ++i) {
                if (env_vars_backup->backup_values[i]) {
                        setenv(env_vars_from_pscom[i],
                               env_vars_backup->backup_values[i], 1);
                } else {
                        unsetenv(env_vars_from_pscom[i]);
                }
        }

        /* free the backup space */
        free(env_vars_backup->backup_values);

        return 0;
}


int redir_pipe[2];
int saved_fd;


int capture_fd(int fd)
{
        /* save file descriptor for later restore */
        saved_fd = dup(fd);

        /* create a pipe and redirect file descriptor to this pipe */
        assert(pipe(redir_pipe) == 0);

        dup2(redir_pipe[1], fd);
        close(redir_pipe[1]);

        return redir_pipe[0];
}


void restore_fd(int fd)
{
        dup2(saved_fd, fd);
        assert(close(saved_fd) == 0);
}
