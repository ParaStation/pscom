/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_UTEST_UTILS_H_
#define _TEST_UTEST_UTILS_H_

int setup_dummy_envvars(void **state);
int teardown_dummy_envvars(void **state);
void test_utest_utils_common_envvar_backup(void **state);
void test_utest_utils_common_envvar_backup_overwrite(void **state);
void test_utest_utils_common_envvar_backup_no_overwrite(void **state);
void test_utest_utils_common_envvar_backup_unset(void **state);
void test_utest_utils_common_envvar_backup_reset(void **state);

#endif /* _TEST_UTEST_UTILS_H_ */
