/*
 * ParaStation
 *
 * Copyright (C) 2025      ParTec AG, Munich
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

#include "test_version.h"

#include "pscom.h"
#include "pscom_version.h"

/**
 * \brief Test version handling for requested CUDA support (success).
 *
 * Given: CUDA support is requested
 * When: the provided pscom version states CUDA support
 * Then: the version check should succeed
 */
void test_pscom_version_cuda_support_success(void **state)
{
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(1, 3, 11),
                                          PSCOM_VERSION_BUILD(1, 3, 11));
    assert_true(ret == PSCOM_SUCCESS);
}


/**
 * \brief Test version handling for requested CUDA support (failure).
 *
 * Given: CUDA support is requested
 * When: the provided pscom version lacks CUDA support
 * Then: the version check should fail
 */
void test_pscom_version_cuda_support_failure(void **state)
{
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(1, 3, 11),
                                          PSCOM_VERSION_BUILD(0, 3, 11));
    assert_true(ret == PSCOM_ERR_UNSUPPORTED_VERSION);
}


/**
 * \brief Test version handling for non-requested CUDA support.
 *
 * Given: CUDA support is not requested
 * When: the provided pscom version either supports CUDA or not
 * Then: the version check should succeed
 */
void test_pscom_version_no_cuda_support(void **state)
{
    /* no CUDA support */
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 3, 12),
                                          PSCOM_VERSION_BUILD(0, 3, 12));
    assert_true(ret == PSCOM_SUCCESS);

    /* CUDA support */
    ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 3, 11),
                              PSCOM_VERSION_BUILD(1, 3, 11));
    assert_true(ret == PSCOM_SUCCESS);
}

/**
 * \brief Test version handling for major number (failure)
 *
 * Given: A requested pscom version with major number
 * When: the provided pscom version has a larger/smaller major number
 * Then: the version check should fail
 */
void test_pscom_version_major_failure(void **state)
{
    /* smaller major number */
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 5, 11),
                                          PSCOM_VERSION_BUILD(0, 3, 11));
    assert_true(ret == PSCOM_ERR_UNSUPPORTED_VERSION);

    /* larger major number */
    ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 3, 11),
                              PSCOM_VERSION_BUILD(0, 5, 11));
    assert_true(ret == PSCOM_ERR_UNSUPPORTED_VERSION);
}

/**
 * \brief Test version handling for major number (success)
 *
 * Given: A requested pscom version with major number
 * When: the provided pscom version has the same major number
 * Then: the version check should succeed
 */
void test_pscom_version_major_success(void **state)
{
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 4, 2),
                                          PSCOM_VERSION_BUILD(0, 4, 2));
    assert_true(ret == PSCOM_SUCCESS);
}

/**
 * \brief Test version handling for minor number (success)
 *
 * Given: A requested pscom version with minor number
 * When: the provided pscom version has the same or higher minor number
 * Then: the version check should succeed
 */
void test_pscom_version_minor_success(void **state)
{
    /* equal minor number */
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 3, 11),
                                          PSCOM_VERSION_BUILD(0, 3, 11));
    assert_true(ret == PSCOM_SUCCESS);

    /* higher minor number */
    ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 3, 11),
                              PSCOM_VERSION_BUILD(0, 3, 12));
    assert_true(ret == PSCOM_SUCCESS);
}

/**
 * \brief Test version handling for minor number (success)
 *
 * Given: A requested pscom version with minor number
 * When: the provided pscom version has a lower minor number
 * Then: the version check should fail
 */
void test_pscom_version_minor_failure(void **state)
{
    pscom_err_t ret = pscom_version_check(PSCOM_VERSION_BUILD(0, 3, 11),
                                          PSCOM_VERSION_BUILD(0, 3, 10));
    assert_true(ret == PSCOM_ERR_UNSUPPORTED_VERSION);
}
