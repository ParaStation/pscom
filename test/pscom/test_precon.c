/*
 * ParaStation
 *
 * Copyright (C) 2025      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#define _GNU_SOURCE
#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>

#include "test_precon.h"
#include "pscom_precon.h"
#include "util/test_utils_provider.h"

////////////////////////////////////////////////////////////////////////////////
/// pscom_precon_provider_lookup()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_precon_provider_init() for existing provider
 *
 * Given: An existing name of a precon provider is given
 * When: pscom_provider_init() is called
 * Then: pscom_precon_provider is set to the corresponding provider
 */
void test_provider_init_existing_name(void **state)
{
    /* init provider with tcp */
    setup_dummy_provider("tcp");

    pscom_precon_provider_t *provider_tcp = pscom_precon_provider_lookup("tcp");
    assert_ptr_equal(pscom_precon_provider, provider_tcp);

    teardown_dummy_provider();
}


/**
 * \brief Test pscom_precon_provider_init() for non-existing provider
 *
 * Given: A non-existing name of a precon provider is given
 * When: pscom_provider_init() is called
 * Then: pscom_precon_provider is set to the default provider
 */
void test_provider_init_missing_name(void **state)
{
    /* init provider with a non-existing name */
    setup_dummy_provider("foobar");

    pscom_precon_provider_t *provider_tcp = pscom_precon_provider_lookup("tcp");
    assert_ptr_equal(pscom_precon_provider, provider_tcp);

    teardown_dummy_provider();
}


/**
 * \brief Test pscom_provider_lookup() for empty string
 *
 * Given: An empty string is provided as provider type
 * When: pscom_provider_init() is called
 * Then: pscom_precon_provider is set to the default provider
 */
void test_provider_init_empty_name(void **state)
{
    /* init provider with an empty string*/
    setup_dummy_provider("");

    pscom_precon_provider_t *provider_tcp = pscom_precon_provider_lookup("tcp");
    assert_ptr_equal(pscom_precon_provider, provider_tcp);

    teardown_dummy_provider();
}
