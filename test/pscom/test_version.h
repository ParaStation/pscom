/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_VERSION_H_
#define _TEST_VERSION_H_

void test_pscom_version_cuda_support_success(void **state);
void test_pscom_version_cuda_support_failure(void **state);
void test_pscom_version_no_cuda_support(void **state);

void test_pscom_version_major_failure(void **state);
void test_pscom_version_major_success(void **state);

void test_pscom_version_minor_failure(void **state);
void test_pscom_version_minor_success(void **state);

#endif /* _TEST_VERSION_H_ */
