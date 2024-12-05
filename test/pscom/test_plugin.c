/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
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

#include <stdio.h>

#include "pscom_plugin.h"

/*
 * we need to access some static functions
 * TODO: Refactor pscom_plugin to avoid this
 */
#define LIBDIR
#include "pscom_plugin.c"

////////////////////////////////////////////////////////////////////////////////
/// load_plugin_lib()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test load_plugin_lib for valid input
 *
 * Given: A valid plugin name and path
 * When: load_plugin_lib() is called
 * Then: it returns a pointer to the plugin structure
 */
void test_load_plugin_lib(void **state)
{
    pscom_plugin_t plugin_mock = {
        .version = PSCOM_PLUGIN_VERSION,
    };
    char plugin_path[] = "/path/to/plugin/lib";
    char arch[]        = "myarch";
    char plugin_name[128];
    snprintf(plugin_name, sizeof(plugin_name), "pscom_plugin_%s", arch);

    will_return(__wrap_dlopen, 0xDEADBEEF);
    will_return(__wrap_dlsym, &plugin_mock);
    expect_value(__wrap_dlopen, filename, plugin_path);
    expect_string(__wrap_dlsym, symbol, plugin_name);

    pscom_plugin_t *plugin = load_plugin_lib(plugin_path, arch);

    assert_true(plugin == &plugin_mock);
}


/**
 * \brief Test load_plugin_lib for invalid plugin version
 *
 * Given: A valid plugin name and path but invalid plugin version
 * When: load_plugin_lib() is called
 * Then: it returns NULL
 */
void test_load_plugin_lib_invalid_version(void **state)
{
    pscom_plugin_t plugin_mock = {
        .version = (PSCOM_PLUGIN_VERSION ^ 0x1),
    };
    char plugin_path[] = "/path/to/plugin/lib";
    char arch[]        = "myarch";
    char plugin_name[128];
    snprintf(plugin_name, sizeof(plugin_name), "pscom_plugin_%s", arch);

    will_return(__wrap_dlopen, 0xDEADBEEF);
    will_return(__wrap_dlsym, &plugin_mock);
    expect_value(__wrap_dlopen, filename, plugin_path);
    expect_string(__wrap_dlsym, symbol, plugin_name);

    pscom_plugin_t *plugin = load_plugin_lib(plugin_path, arch);

    assert_false(plugin);
}

/**
 * \brief Test load_plugin_lib for invalid plugin name
 *
 * Given: A valid plugin path but invalid plugin name
 * When: load_plugin_lib() is called
 * Then: it returns NULL
 */
void test_load_plugin_lib_invalid_name(void **state)
{
    char plugin_path[] = "/path/to/plugin/lib";
    char arch[]        = "myarch";
    char plugin_name[128];
    snprintf(plugin_name, sizeof(plugin_name), "pscom_plugin_%s", arch);

    will_return(__wrap_dlopen, 0xDEADBEEF);
    will_return(__wrap_dlsym, NULL);
    expect_value(__wrap_dlopen, filename, plugin_path);
    expect_string(__wrap_dlsym, symbol, plugin_name);

    pscom_plugin_t *plugin = load_plugin_lib(plugin_path, arch);

    assert_false(plugin);
}


/**
 * \brief Test load_plugin_lib for invalid plugin path
 *
 * Given: An invalid plugin path
 * When: load_plugin_lib() is called
 * Then: it returns NULL
 */
void test_load_plugin_lib_invalid_path(void **state)
{
    char plugin_path[] = "/invalid/path";

    expect_value(__wrap_dlopen, filename, plugin_path);
    will_return(__wrap_dlopen, NULL);

    pscom_plugin_t *plugin = load_plugin_lib(plugin_path, "myarch");

    assert_false(plugin);
}
