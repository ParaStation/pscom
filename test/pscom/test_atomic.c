/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "test_atomic.h"

#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>
#include <stdbool.h>
#include <unistd.h>

#include "util/test_utils_common.h"
#include "pscom_atomic.h"

/* Note: only `uint64_t` is tested in the following utests. */

/**
 * \brief Test cacheline size
 *
 */
void test_atomic_cacheline_size(void **state)
{
    /* Get runtime cacheline, better to run this on compute node. */
    uint64_t runtime_cacheline = (uint64_t)sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

    assert_true(PSCOM_CACHELINE_SIZE >= 32 && PSCOM_CACHELINE_SIZE <= 256);
    assert_uint_equal(runtime_cacheline, PSCOM_CACHELINE_SIZE);

    PSCOM_CACHELINE_ALIGNED int test_int;
    PSCOM_CACHELINE_ALIGNED char test_char;

    assert_true(((uintptr_t)&test_int % PSCOM_CACHELINE_SIZE) == 0);
    assert_true(((uintptr_t)&test_char % PSCOM_CACHELINE_SIZE) == 0);
}

/**
 * \brief Test atomic load and store
 *
 */
void test_atomic_load_store(void **state)
{
    pscom_atomic_uint64_t v = 100;

    assert_uint_equal(pscom_atomic_relaxed_load_uint64(&v), 100);

    pscom_atomic_relaxed_store_uint64(&v, 200);

    assert_uint_equal(pscom_atomic_acquire_load_uint64(&v), 200);
}

/**
 * \brief Test atomic fetch add and sub
 *
 */
void test_atomic_fetch_add_sub(void **state)
{
    pscom_atomic_uint64_t v = 10;

    uint64_t old;

    old = pscom_atomic_fetch_add_uint64(&v, 10);

    assert_uint_equal(old, 10);

    assert_uint_equal(pscom_atomic_relaxed_load_uint64(&v), 20);

    old = pscom_atomic_fetch_sub_uint64(&v, 8);

    assert_uint_equal(old, 20);

    assert_uint_equal(pscom_atomic_relaxed_load_uint64(&v), 12);
}

/**
 * \brief Test atomic swap
 *
 */
void test_atomic_swap(void **state)
{
    pscom_atomic_uint64_t v = 100;

    uint64_t old;

    old = pscom_atomic_swap_uint64(&v, 999);

    assert_uint_equal(old, 100);

    assert_uint_equal(pscom_atomic_relaxed_load_uint64(&v), 999);
}

/**
 * \brief Test atomic cas
 *
 */
void test_atomic_cas(void **state)
{
    pscom_atomic_uint64_t v = 123;

    uint64_t expected = 123;

    bool ret;

    /* cas succeeds */
    ret = pscom_atomic_cas_uint64(&v, &expected, 456);

    assert_true(ret);

    assert_uint_equal(pscom_atomic_relaxed_load_uint64(&v), 456);

    /* cas fails, expected is updated to v */
    expected = 100;

    pscom_atomic_relaxed_store_uint64(&v, 200);

    ret = pscom_atomic_cas_uint64(&v, &expected, 300);

    assert_true(!ret);

    assert_uint_equal(expected, 200);

    assert_uint_equal(pscom_atomic_relaxed_load_uint64(&v), 200);
}
