/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>

#include <stdlib.h>

#include "test_utest_utils.h"
#include "util/test_utils_common.h"

////////////////////////////////////////////////////////////////////////////////
/// Setup/teardown helpers
////////////////////////////////////////////////////////////////////////////////

#define DUMMY_ENVVAR_NAME_1st  "PSCOM_UTEST_UTILS_DUMMY_ENV_NAME_FOO"
#define DUMMY_ENVVAR_NAME_2nd  "PSCOM_UTEST_UTILS_DUMMY_ENV_NAME_BAR"
#define DUMMY_ENVVAR_VALUE_1st "Lorem ipsum dolor sit amet"
#define DUMMY_ENVVAR_VALUE_2nd "consectetur adipiscing elit"

int setup_dummy_envvars(void **state)
{
    /* force 1st dummy environment variable to be set */
    setenv(DUMMY_ENVVAR_NAME_1st, DUMMY_ENVVAR_VALUE_1st, 1);

    /* ensure that the 2nd variable name is not set/used */
    unsetenv(DUMMY_ENVVAR_NAME_2nd);

    return 0;
}

int teardown_dummy_envvars(void **state)
{
    /* ensure that all used dummy envvars are unset again */
    unsetenv(DUMMY_ENVVAR_NAME_1st);
    unsetenv(DUMMY_ENVVAR_NAME_2nd);

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
/// The utest utils tests
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Test the backup of environment variables when being overwritten
 *
 * Given: The dummy environment variable DUMMY_ENVVAR_NAME_1st set to
 * DUMMY_ENVVAR_VALUE_1st. When: A backup is captured when the variable is
 * overwritten with DUMMY_ENVVAR_VALUE_2nd. Then: After restore, the value of
 * the variable is DUMMY_ENVVAR_VALUE_1st again.
 */
void test_utest_utils_common_envvar_backup_overwrite(void **state)
{
    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);

    test_utils_common_envvar_backup_t backup = {.name  = DUMMY_ENVVAR_NAME_1st,
                                                .value = DUMMY_ENVVAR_VALUE_2nd,
                                                .overwrite = 1};

    test_utils_common_envvar_backup_capture(&backup);

    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_2nd);

    test_utils_common_envvar_backup_restore(&backup);

    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);
}

/**
 * \brief Test the backup of environment variables when not being overwritten
 *
 * Given: The dummy environment variable DUMMY_ENVVAR_NAME_1st set to
 * DUMMY_ENVVAR_VALUE_1st. When: A backup is captured when the variable is not
 * overwritten with DUMMY_ENVVAR_VALUE_2nd. Then: The value of the variable is
 * DUMMY_ENVVAR_VALUE_1st after both capture and restore.
 */
void test_utest_utils_common_envvar_backup_no_overwrite(void **state)
{
    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);

    test_utils_common_envvar_backup_t backup = {.name  = DUMMY_ENVVAR_NAME_1st,
                                                .value = DUMMY_ENVVAR_VALUE_2nd,
                                                .overwrite = 0};

    test_utils_common_envvar_backup_capture(&backup);

    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);

    test_utils_common_envvar_backup_restore(&backup);

    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);
}

/**
 * \brief Test the backup of environment variables when not set before
 *
 * Given: The environment variable DUMMY_ENVVAR_NAME_2nd is not set.
 * When: A backup is captured when the variable is set to DUMMY_ENVVAR_VALUE_1st
 *       (with overwrite = 0).
 * Then: After restore, the value of the variable is unset again.
 */
void test_utest_utils_common_envvar_backup_unset(void **state)
{
    assert_null(getenv(DUMMY_ENVVAR_NAME_2nd));

    test_utils_common_envvar_backup_t backup = {.name  = DUMMY_ENVVAR_NAME_2nd,
                                                .value = DUMMY_ENVVAR_VALUE_1st,
                                                .overwrite = 0};

    test_utils_common_envvar_backup_capture(&backup);

    assert_non_null(getenv(DUMMY_ENVVAR_NAME_2nd));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_2nd), DUMMY_ENVVAR_VALUE_1st);

    test_utils_common_envvar_backup_restore(&backup);

    assert_null(getenv(DUMMY_ENVVAR_NAME_2nd));
}

/**
 * \brief Test the backup of environment variables when unset during backup.
 *
 * Given: The dummy environment variable DUMMY_ENVVAR_NAME_1st set to
 * DUMMY_ENVVAR_VALUE_1st. When: A backup is captured when the variable is unset
 * again (i.e., value = NULL). Then: After restore, the value of the variable is
 * DUMMY_ENVVAR_VALUE_1st again.
 */
void test_utest_utils_common_envvar_backup_reset(void **state)
{
    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);

    test_utils_common_envvar_backup_t backup = {.name  = DUMMY_ENVVAR_NAME_1st,
                                                .value = NULL,
                                                .overwrite = 1};

    test_utils_common_envvar_backup_capture(&backup);

    assert_null(getenv(DUMMY_ENVVAR_NAME_1st));

    test_utils_common_envvar_backup_restore(&backup);

    assert_non_null(getenv(DUMMY_ENVVAR_NAME_1st));
    assert_string_equal(getenv(DUMMY_ENVVAR_NAME_1st), DUMMY_ENVVAR_VALUE_1st);
}
