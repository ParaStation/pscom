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

#include <stdlib.h>

#include "pscom_precon.h"

/* we need to access some static functions */
// #include "pscom_precon.c"

extern pscom_precon_provider_t pscom_provider_tcp;

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
    setenv("PSP_PRECON_TYPE", "tcp", 1);
    pscom_precon_provider_init();

    assert_int_equal(pscom_precon_provider.precon_type,
                     pscom_precon_provider_lookup("tcp")->precon_type);
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
    setenv("PSP_PRECON_TYPE", "foobar", 1);
    pscom_precon_provider_init();

    assert_int_equal(pscom_precon_provider.precon_type,
                     pscom_precon_provider_lookup("tcp")->precon_type);
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
    setenv("PSP_PRECON_TYPE", "", 1);
    pscom_precon_provider_init();

    assert_int_equal(pscom_precon_provider.precon_type,
                     pscom_precon_provider_lookup("tcp")->precon_type);
}
