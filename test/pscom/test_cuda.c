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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>

#include "pscom_utest.h"
#include "mocks/misc_mocks.h"

#include "pscom_priv.h"
#include "pscom_cuda.h"
#include "pscom_util.h"
#include "pscom_req.h"

////////////////////////////////////////////////////////////////////////////////
/// Some test setup functions
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Setup cuInit() with CUDA_SUCCESS
 */
static inline void setup_enable_cuda_and_initialize(size_t device_count)
{
    pscom.env.cuda = 1;
    if (device_count) {
        will_return(__wrap_cuInit, CUDA_SUCCESS);
    } else {
        will_return(__wrap_cuInit, CUDA_ERROR_NO_DEVICE);
    }
}


/**
 * \brief Setup cuPointerGetAttributes_device_ptr() returning dev pointer
 */
static inline void setup_cuPointerGetAttributes(const void *dev_ptr,
                                                CUmemorytype mem_type,
                                                unsigned int is_managed,
                                                unsigned int sync_memops,
                                                CUresult ret_val)
{
    expect_value(__wrap_cuPointerGetAttributes, numAttributes, 3);
    expect_value(__wrap_cuPointerGetAttributes, ptr, dev_ptr);
    will_return(__wrap_cuPointerGetAttributes, mem_type);
    will_return(__wrap_cuPointerGetAttributes, is_managed);
    will_return(__wrap_cuPointerGetAttributes, sync_memops);
    will_return(__wrap_cuPointerGetAttributes, ret_val);
}


/**
 * \brief Setup UVA tests
 */
static inline void setup_uva_tests(void)
{
    /* cuDeviceGetCount() shall return CUDA_SUCCESS and 1 */
    will_return(__wrap_cuDeviceGetCount, 1);
    will_return(__wrap_cuDeviceGetCount, CUDA_SUCCESS);

    /* cuDeviceGetAttribute() expectes CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING
     * and device 0 as arguments
     */
    expect_value(__wrap_cuDeviceGetAttribute, attrib,
                 CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING);
    expect_value(__wrap_cuDeviceGetAttribute, dev, 0);
}


/**
 * \brief Setup successful context wth active devie
 */
static inline void setup_valid_ctx_with_active_device(void)
{
    /* we need a valid context */
    will_return(__wrap_cuCtxGetCurrent, 0x42);
    will_return(__wrap_cuCtxGetCurrent, CUDA_SUCCESS);
    will_return(__wrap_cuCtxGetDevice, CUDA_SUCCESS);

    /* the associated device should be active */
    will_return(__wrap_cuDevicePrimaryCtxGetState, 1);
    will_return(__wrap_cuDevicePrimaryCtxGetState, CUDA_SUCCESS);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_is_cuda_enabled()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_is_cuda_enabled() for disabled CUDA-awareness
 *
 * Given: CUDA-awareness is disabled
 * When: pscom_is_cuda_enabled() is called
 * Then: it returns 0
 */
void test_is_cuda_enabled_returns_zero_if_disabled(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 0;

    assert_int_equal(pscom_is_cuda_enabled(), 0);
}

/**
 * \brief Test pscom_is_cuda_enabled() for disabled CUDA-awareness
 *
 * Given: CUDA-awareness is enabled
 * When: pscom_is_cuda_enabled() is called
 * Then: it returns 1
 */
void test_is_cuda_enabled_returns_one_if_enabled(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 1;

    assert_int_equal(pscom_is_cuda_enabled(), 1);
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_cuda_init()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_cuda_init() for disabled CUDA-awareness
 *
 * Given: CUDA-awareness is disabled
 * When: pscom_cuda_init() is called
 * Then: it returns PSCOM_SUCCESS
 */
void test_cuda_init_returns_success_if_disabled(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 0;

    assert_int_equal(pscom_cuda_init(), PSCOM_SUCCESS);
}

/**
 * \brief Test pscom_cuda_init() for cuInit() error
 *
 * Given: CUDA-awareness is enabled
 * When: cuInit() does not return CUDA_SUCCESS
 * Then: pscom_cuda_init() returns PSCOM_ERR_STDERROR/EFAULT
 */
void test_cuda_init_cuInit_error(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;
#ifdef CUDA_ERROR_COMPAT_NOT_SUPPORTED_ON_DEVICE
    will_return(__wrap_cuInit, CUDA_ERROR_COMPAT_NOT_SUPPORTED_ON_DEVICE);
#else
    will_return(__wrap_cuInit, CUDA_ERROR_NOT_SUPPORTED);
#endif
    assert_int_equal(pscom_cuda_init(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}

/**
 * \brief Test pscom_cuda_init() for cuDeviceGetCount() error
 *
 * Given: CUDA-awareness is enabled
 * When: cuDeviceGetCount() does not return CUDA_SUCCESS
 * Then: pscom_cuda_init() returns PSCOM_ERR_STDERROR/EFAULT
 */
void test_cuda_init_device_count_error(void **state)
{
    (void)state;

    setup_enable_cuda_and_initialize(1);

    /* cuDeviceGetCount() shall return CUDA_ERROR_NOT_INITIALIZED */
    will_return(__wrap_cuDeviceGetCount, 0x42);
    will_return(__wrap_cuDeviceGetCount, CUDA_ERROR_NOT_INITIALIZED);

    assert_int_equal(pscom_cuda_init(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}

/**
 * \brief Test pscom_cuda_init() for zero CUDA devices
 *
 * Given: CUDA-awareness is enabled
 * When: no CUDA device is present
 * Then: pscom_cuda_init() returns PSCOM_SUCCESS but disables the CUDA awareness
 */
void test_cuda_init_device_count_zero(void **state)
{
    (void)state;

    setup_enable_cuda_and_initialize(0);

    assert_int_equal(pscom_cuda_init(), PSCOM_SUCCESS);
    assert_int_equal(pscom.env.cuda, 0);
}

/**
 * \brief Test pscom_cuda_init() for failing UVA check
 *
 * Given: CUDA-awareness is enabled
 * When: UVA check fails
 * Then: pscom_cuda_init() returns PSCOM_ERR_STDERROR/ENOTSUP
 */
void test_cuda_init_uva_check_fails(void **state)
{
    (void)state;

    setup_enable_cuda_and_initialize(1);
    setup_uva_tests();

    /* cuDeviceGetAttribute() fails */
    will_return(__wrap_cuDeviceGetAttribute, 0);
    will_return(__wrap_cuDeviceGetAttribute, CUDA_ERROR_INVALID_VALUE);

    assert_int_equal(pscom_cuda_init(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}

/**
 * \brief Test pscom_cuda_init() for missing UVA support
 *
 * Given: CUDA-awareness is enabled
 * When: UVA is not supported
 * Then: pscom_cuda_init() returns PSCOM_ERR_STDERROR/ENOTSUP
 */
void test_cuda_init_no_uva_support(void **state)
{
    (void)state;

    setup_enable_cuda_and_initialize(1);
    setup_uva_tests();

    /* cuDeviceGetAttribute() shall return CUDA_SUCCES but no UVA support */
    will_return(__wrap_cuDeviceGetAttribute, 0);
    will_return(__wrap_cuDeviceGetAttribute, CUDA_SUCCESS);

    assert_int_equal(pscom_cuda_init(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, ENOTSUP);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_cuda_cleanup()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_cuda_cleanup() for disabled CUDA-awareness
 *
 * Given: CUDA-awareness is disabled
 * When: pscom_cuda_cleanup() is called
 * Then: it returns PSCOM_SUCCESS
 */
void test_cuda_cleanup_returns_success_if_disabled(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 0;

    assert_int_equal(pscom_cuda_cleanup(), PSCOM_SUCCESS);
}


/**
 * \brief Test pscom_cuda_cleanup() for valid CUDA context
 *
 * Given: There is a valid CUDA context
 * When: pscom_cuda_cleanup() is called
 * Then: the CUDA streams are destroyed
 */
void test_cuda_cleanup_destroys_cuda_streams(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 1;

    setup_valid_ctx_with_active_device();

    will_return(__wrap_cuStreamDestroy_v2, CUDA_SUCCESS);
    will_return(__wrap_cuStreamDestroy_v2, CUDA_SUCCESS);
    will_return(__wrap_cuStreamDestroy_v2, CUDA_SUCCESS);
    expect_function_calls(__wrap_cuStreamDestroy_v2, 3);


    assert_int_equal(pscom_cuda_cleanup(), PSCOM_SUCCESS);
}

/**
 * \brief Test pscom_cuda_cleanup() for failing stream destroy
 *
 * Given: There is a valid CUDA context with active device
 * When: but the CUDA streams cannot be destroyed
 * Then: pscom_cuda_cleanup() fails
 */
void test_cuda_cleanup_for_failing_stream_destroy(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 1;

    setup_valid_ctx_with_active_device();

    will_return(__wrap_cuStreamDestroy_v2, CUDA_ERROR_DEINITIALIZED);
    will_return(__wrap_cuStreamDestroy_v2, CUDA_ERROR_DEINITIALIZED);
    will_return(__wrap_cuStreamDestroy_v2, CUDA_ERROR_DEINITIALIZED);
    expect_function_calls(__wrap_cuStreamDestroy_v2, 3);

    assert_int_equal(pscom_cuda_cleanup(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}


/**
 * \brief Test pscom_cuda_cleanup() for inactive device
 *
 * Given: There is a valid CUDA context but inactive device
 * When: pscom_cuda_cleanup() is called
 * Then: the CUDA streams are not destroyed
 */
void test_cuda_cleanup_for_inactive_device(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 1;

    /* simply return a dummy context and active device*/
    will_return(__wrap_cuCtxGetCurrent, 0x42);
    will_return(__wrap_cuCtxGetCurrent, CUDA_SUCCESS);
    will_return(__wrap_cuCtxGetDevice, CUDA_SUCCESS);
    will_return(__wrap_cuDevicePrimaryCtxGetState, 0);
    will_return(__wrap_cuDevicePrimaryCtxGetState, CUDA_SUCCESS);

    assert_int_equal(pscom_cuda_cleanup(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}


/**
 * \brief Test pscom_cuda_cleanup() for issues determining device status
 *
 * Given: There is a valid CUDA context but the device status cannot be
 * determined When: pscom_cuda_cleanup() is called Then: the CUDA streams are
 * not destroyed
 */
void test_cuda_cleanup_for_unclear_device_status(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 1;

    /* simply return a dummy context and active device*/
    will_return(__wrap_cuCtxGetCurrent, 0x42);
    will_return(__wrap_cuCtxGetCurrent, CUDA_SUCCESS);
    will_return(__wrap_cuCtxGetDevice, CUDA_SUCCESS);
    will_return(__wrap_cuDevicePrimaryCtxGetState, 1);
    will_return(__wrap_cuDevicePrimaryCtxGetState, CUDA_ERROR_INVALID_DEVICE);

    assert_int_equal(pscom_cuda_cleanup(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}


/**
 * \brief Test pscom_cuda_cleanup() for CUDA driver already shutting down
 *
 * Given: There is a valid CUDA context but the associated device cannot be
 * determined When: pscom_cuda_cleanup() is called Then: the CUDA streams are
 * not destroyed
 */
void test_cuda_cleanup_for_cuda_deinitialized(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 1;

    /* simply return a dummy context and active device*/
    will_return(__wrap_cuCtxGetCurrent, 0x42);
    will_return(__wrap_cuCtxGetCurrent, CUDA_SUCCESS);
    will_return(__wrap_cuCtxGetDevice, CUDA_ERROR_DEINITIALIZED);

    assert_int_equal(pscom_cuda_cleanup(), PSCOM_ERR_STDERROR);
    assert_int_equal(errno, EFAULT);
}


////////////////////////////////////////////////////////////////////////////////
/// _pscom_buffer_needs_staging()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_buffer_needs_staging() for disabled CUDA-awareness
 *
 * Given: CUDA-awareness is disabled
 * When: _pscom_buffer_needs_staging() is called
 * Then: it returns 0 for any given input.
 */
void test_buffer_needs_staging_if_cuda_disabled(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 0;

    pscom_con_t *null_con = NULL;
    pscom_con_t *any_con  = (void *)0x42;
    void *any_ptr         = (void *)0x42;
    assert_int_equal(_pscom_buffer_needs_staging(NULL, null_con), 0);
    assert_int_equal(_pscom_buffer_needs_staging(NULL, any_con), 0);
    assert_int_equal(_pscom_buffer_needs_staging(any_ptr, null_con), 0);
    assert_int_equal(_pscom_buffer_needs_staging(any_ptr, any_con), 0);
}

/**
 * \brief Test _pscom_buffer_needs_staging() for non-CUDA-aware connection
 *
 * Given: CUDA-awareness is enabled
 * When: con is not CUDA-aware or not specified
 * Then: _pscom_buffer_needs_staging() returns 1 for any device pointer
 */
void test_buffer_needs_staging_con_not_cuda_aware(void **state)
{
    (void)state;

    /* disable CUDA support and create non-CUDA-aware connection*/
    pscom.env.cuda       = 1;
    pscom_con_t test_con = {.is_gpu_aware = 0};

    /* test non-CUDA-aware connection */
    const void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_SUCCESS);
    assert_int_equal(_pscom_buffer_needs_staging(test_addr, &test_con), 1);

    /* connection not specified */
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_SUCCESS);
    assert_int_equal(_pscom_buffer_needs_staging(test_addr, NULL), 1);
}

/**
 * \brief Test _pscom_buffer_needs_staging() for CUDA-aware connection
 *
 * Given: CUDA-awareness is enabled
 * When: con is CUDA-aware
 * Then: _pscom_buffer_needs_staging() returns 0 for any pointer
 */
void test_buffer_needs_staging_con_cuda_aware(void **state)
{
    (void)state;

    /* disable CUDA support and create non-CUDA-aware connection*/
    pscom.env.cuda       = 1;
    pscom_con_t test_con = {.is_gpu_aware = 1};

    /* test any pointer */
    assert_int_equal(_pscom_buffer_needs_staging((void *)0x42, &test_con), 0);
    assert_int_equal(_pscom_buffer_needs_staging(NULL, &test_con), 0);
}

////////////////////////////////////////////////////////////////////////////////
/// _pscom_is_gpu_mem()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_is_gpu_mem() for disabled CUDA-awareness
 *
 * Given: CUDA-awareness is disabled
 * When: _pscom_is_gpu_mem() is called
 * Then: it returns 0 for any given input.
 */
void test_is_gpu_mem_if_cuda_disabled(void **state)
{
    (void)state;

    /* disable CUDA support */
    pscom.env.cuda = 0;

    void *any_ptr = (void *)0x42;
    assert_int_equal(_pscom_is_gpu_mem(NULL, 0), 0);
    assert_int_equal(_pscom_is_gpu_mem(any_ptr, 0), 0);
    assert_int_equal(_pscom_is_gpu_mem(NULL, 42), 0);
    assert_int_equal(_pscom_is_gpu_mem(any_ptr, 42), 0);
}

/**
 * \brief Test _pscom_is_gpu_mem() for failing cuPointerGetAttributes()
 *
 * Given: CUDA-awareness is enabled
 * When: cuPointerGetAttributes() fails
 * Then: _pscom_is_gpu_mem() returns 0 for any ptr
 */
void test_is_gpu_mem_get_attributes_fails(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_ERROR_INVALID_VALUE);
    assert_int_equal(_pscom_is_gpu_mem(test_addr, 0), 0);
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_ERROR_INVALID_VALUE);
    assert_int_equal(_pscom_is_gpu_mem(test_addr, 42), 0);
}

/**
 * \brief Test _pscom_is_gpu_mem() for managed memory
 *
 * Given: CUDA-awareness is enabled
 * When: pointer belongs to CUDA managed memory
 * Then: _pscom_is_gpu_mem() returns 0 for any ptr
 */
void test_is_gpu_mem_managed_memory(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 1, 1,
                                 CUDA_SUCCESS);
    assert_int_equal(_pscom_is_gpu_mem(test_addr, 1), 0);
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_HOST, 1, 1,
                                 CUDA_SUCCESS);
    assert_int_equal(_pscom_is_gpu_mem(test_addr, 1), 0);
}

/**
 * \brief Test _pscom_is_gpu_mem() for device memory
 *
 * Given: CUDA-awareness is enabled
 * When: pointer is a CUDA device pointer
 * Then: _pscom_is_gpu_mem() returns 1
 */
void test_is_gpu_mem_device_memory(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_SUCCESS);
    assert_int_equal(_pscom_is_gpu_mem(test_addr, 1), 1);
}

/**
 * \brief Test pscom_is_gpu_mem() for device memory
 *
 * This test is similar to test_is_gpu_mem_device_memory but uses the wrapper
 * for exeternal libraries.
 *
 * Given: CUDA-awareness is enabled
 * When: pointer is a CUDA device pointer
 * Then: pscom_is_gpu_mem() returns 1
 */
void test_is_gpu_mem_wrapper_device_memory(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_SUCCESS);
    assert_int_equal(pscom_is_gpu_mem(test_addr), 1);
}

/**
 * \brief Test _pscom_is_gpu_mem() for disabled memop synchronization
 *
 * Given: CUDA-awareness is enabled
 * When: pointer is a CUDA device pointer and memop synchornization is not set
 * Then: _pscom_is_gpu_mem() calls cuDeviceSetAttribute() accordingly
 */
void test_is_gpu_mem_sync_memop_disabled(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 0,
                                 CUDA_SUCCESS);

    int val = 1;
    expect_memory(__wrap_cuPointerSetAttribute, value, &val, sizeof(val));
    expect_value(__wrap_cuPointerSetAttribute, ptr, test_addr);
    will_return(__wrap_cuPointerSetAttribute, CUDA_SUCCESS);
    expect_function_calls(__wrap_cuPointerSetAttribute, 1);
    assert_int_equal(_pscom_is_gpu_mem(test_addr, 1), 1);
}

/**
 * \brief Test _pscom_is_gpu_mem() for enabled memop synchronization
 *
 * Given: CUDA-awareness is enabled
 * When: pointer is a CUDA device pointer and memop synchornization is set
 * Then: _pscom_is_gpu_mem() does not call cuDeviceSetAttribute()
 */
void test_is_gpu_mem_sync_memop_enabled(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    void *test_addr = (void *)0x42;
    setup_cuPointerGetAttributes(test_addr, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_SUCCESS);

    assert_int_equal(_pscom_is_gpu_mem(test_addr, 1), 1);
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_memcpy_gpu_safe_from_user()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_memcpy_gpu_safe_from_user() for host memory
 *
 * Given: src and dst point to host memory
 * When: _pscom_memcpy_gpu_safe_from_user() ist called
 * Then: it invokes the standard memcpy() with according parameters
 */
void test_pscom_memcpy_gpu_safe_from_user_host_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    /* cuPointerGetAttributes() is only called for src */
    setup_cuPointerGetAttributes(&src, CU_MEMORYTYPE_HOST, 0, 1, CUDA_SUCCESS);

    enable_memcpy_mock();
    expect_function_calls(__wrap_memcpy, 1);
    expect_value(__wrap_memcpy, dst, &dst);
    expect_value(__wrap_memcpy, src, &src);
    expect_value(__wrap_memcpy, nbytes, sizeof(int));

    pscom_memcpy_gpu_safe_from_user(&dst, &src, sizeof(int));

    disable_memcpy_mock();

    assert_int_equal(dst, src);
}

/**
 * \brief Test _pscom_memcpy_gpu_safe_from_user() for device memory
 *
 * Given: src points to device memory
 * When: _pscom_memcpy_gpu_safe_from_user() ist called
 * Then: it invokes the standard cuMemcpyDtoH() with according parameters
 */
void test_pscom_memcpy_gpu_safe_from_user_device_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    /* cuPointerGetAttributes() is only called for src */
    setup_cuPointerGetAttributes(&src, CU_MEMORYTYPE_DEVICE, 0, 1, CUDA_SUCCESS);

    expect_function_calls(cuMemcpy_generic, 1);
    expect_function_calls(__wrap_cuStreamSynchronize, 1);
    expect_value(cuMemcpy_generic, dst, &dst);
    expect_value(cuMemcpy_generic, src, &src);
    expect_value(cuMemcpy_generic, nbytes, sizeof(int));
    will_return(cuMemcpy_generic, CUDA_SUCCESS);

    pscom_memcpy_gpu_safe_from_user(&dst, &src, sizeof(int));
}

/**
 * \brief Test _pscom_memcpy_gpu_safe_from_user() creates CUDA stream
 *
 * Given: src points to device memory
 * When: pscom_memcpy_gpu_safe_from_user() ist called and the CUDA stream for
 *       device2host memcpy has not been created
 * Then: it invokes the standard cuMemcpyDtoH() with according parameters
 */
void test_pscom_memcpy_gpu_safe_from_user_creates_cuda_stream(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    /* cuPointerGetAttributes() is only called for src */
    setup_cuPointerGetAttributes(&src, CU_MEMORYTYPE_DEVICE, 0, 1, CUDA_SUCCESS);

    expect_function_calls(__wrap_cuStreamCreate, 1);
    will_return(__wrap_cuStreamCreate, 0x42);
    will_return(__wrap_cuStreamCreate, CUDA_SUCCESS);

    expect_function_calls(cuMemcpy_generic, 1);
    expect_function_calls(__wrap_cuStreamSynchronize, 1);
    expect_value(cuMemcpy_generic, dst, &dst);
    expect_value(cuMemcpy_generic, src, &src);
    expect_value(cuMemcpy_generic, nbytes, sizeof(int));
    will_return(cuMemcpy_generic, CUDA_SUCCESS);

    pscom_memcpy_gpu_safe_from_user(&dst, &src, sizeof(int));
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_memcpy_gpu_safe_to_user()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_memcpy_gpu_safe_to_user() for host memory
 *
 * Given: src and dst point to host memory
 * When: _pscom_memcpy_gpu_safe_to_user() ist called
 * Then: it invokes the standard memcpy() with according parameters
 */
void test_pscom_memcpy_gpu_safe_to_user_host_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    /* cuPointerGetAttributes() is only called for src */
    setup_cuPointerGetAttributes(&dst, CU_MEMORYTYPE_HOST, 0, 1, CUDA_SUCCESS);

    enable_memcpy_mock();
    expect_function_calls(__wrap_memcpy, 1);
    expect_value(__wrap_memcpy, dst, &dst);
    expect_value(__wrap_memcpy, src, &src);
    expect_value(__wrap_memcpy, nbytes, sizeof(int));

    pscom_memcpy_gpu_safe_to_user(&dst, &src, sizeof(int));

    disable_memcpy_mock();

    assert_int_equal(dst, src);
}

/**
 * \brief Test _pscom_memcpy_gpu_safe_to_user() for device memory
 *
 * Given: src points to device memory
 * When: _pscom_memcpy_gpu_safe_to_user() ist called
 * Then: it invokes the standard cuMemcpyHtoD() with according parameters
 */
void test_pscom_memcpy_gpu_safe_to_user_device_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    /* cuPointerGetAttributes() is only called for dst */
    setup_cuPointerGetAttributes(&dst, CU_MEMORYTYPE_DEVICE, 0, 1, CUDA_SUCCESS);

    expect_function_calls(cuMemcpy_generic, 1);
    expect_function_calls(__wrap_cuStreamSynchronize, 1);
    expect_value(cuMemcpy_generic, dst, &dst);
    expect_value(cuMemcpy_generic, src, &src);
    expect_value(cuMemcpy_generic, nbytes, sizeof(int));
    will_return(cuMemcpy_generic, CUDA_SUCCESS);

    pscom_memcpy_gpu_safe_to_user(&dst, &src, sizeof(int));
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_memcpy_gpu_safe_default()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_memcpy_gpu_safe_default() for host memory
 *
 * Given: src and dst point to host memory
 * When: _pscom_memcpy_gpu_safe_default() ist called
 * Then: it invokes the standard memcpy() with according parameters
 */
void test_pscom_memcpy_gpu_safe_default_host_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    setup_cuPointerGetAttributes(&dst, CU_MEMORYTYPE_HOST, 0, 1, CUDA_SUCCESS);
    setup_cuPointerGetAttributes(&src, CU_MEMORYTYPE_HOST, 0, 1, CUDA_SUCCESS);

    enable_memcpy_mock();
    expect_function_calls(__wrap_memcpy, 1);
    expect_value(__wrap_memcpy, dst, &dst);
    expect_value(__wrap_memcpy, src, &src);
    expect_value(__wrap_memcpy, nbytes, sizeof(int));

    pscom_memcpy_gpu_safe_default(&dst, &src, sizeof(int));
    disable_memcpy_mock();
    assert_int_equal(dst, src);
}

/**
 * \brief Test _pscom_memcpy_gpu_safe_default() for device memory
 *
 * Given: src and dst point to device memory
 * When: _pscom_memcpy_gpu_safe_default() ist called
 * Then: it invokes the standard cuMemcpy() with according parameters
 */
void test_pscom_memcpy_gpu_safe_default_device_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    /* cuPointerGetAttributes() is only called for src */
    setup_cuPointerGetAttributes(&dst, CU_MEMORYTYPE_DEVICE, 0, 1, CUDA_SUCCESS);

    expect_function_calls(cuMemcpy_generic, 1);
    expect_function_calls(__wrap_cuStreamSynchronize, 1);
    expect_value(cuMemcpy_generic, dst, &dst);
    expect_value(cuMemcpy_generic, src, &src);
    expect_value(cuMemcpy_generic, nbytes, sizeof(int));
    will_return(cuMemcpy_generic, CUDA_SUCCESS);

    pscom_memcpy_gpu_safe_default(&dst, &src, sizeof(int));
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_memcpy()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_memcpy() for host memory
 *
 * Given: src and dst point to host memory
 * When: pscom_memcpy() ist called
 * Then: it invokes the standard memcpy() with according parameters
 */
void test_pscom_memcpy_host_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    int dst = 0;
    int src = 42;

    setup_cuPointerGetAttributes(&dst, CU_MEMORYTYPE_HOST, 0, 1, CUDA_SUCCESS);
    setup_cuPointerGetAttributes(&src, CU_MEMORYTYPE_HOST, 0, 1, CUDA_SUCCESS);

    enable_memcpy_mock();
    expect_function_calls(__wrap_memcpy, 1);
    expect_value(__wrap_memcpy, dst, &dst);
    expect_value(__wrap_memcpy, src, &src);
    expect_value(__wrap_memcpy, nbytes, sizeof(int));

    pscom_memcpy(&dst, &src, sizeof(int));

    disable_memcpy_mock();

    assert_int_equal(dst, src);
}

////////////////////////////////////////////////////////////////////////////////
/// _pscom_stage_buffer()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_stage_buffer() for device memory
 *
 * Given: a memory buffer within the device memory
 * When: no connection is specified within the pscom_req_t
 * Then: _pscom_stage_buffer() stages the buffer within the host memory
 */
void test_pscom_stage_buffer_dev_mem_no_con(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* create a pscom request */
    pscom_req_t *req    = pscom_req_create(0, 0);
    int buffer          = 42;
    req->pub.connection = NULL;
    req->pub.data       = (void *)&buffer;
    req->pub.data_len   = sizeof(buffer);

    /* prepare mocking functions */
    setup_cuPointerGetAttributes(&buffer, CU_MEMORYTYPE_DEVICE, 0, 1,
                                 CUDA_SUCCESS);
    expect_function_calls(cuMemcpy_generic, 1);
    expect_function_calls(__wrap_cuStreamSynchronize, 1);
    expect_value(cuMemcpy_generic, src, &buffer);
    expect_any(cuMemcpy_generic, dst);
    expect_value(cuMemcpy_generic, nbytes, sizeof(buffer));
    will_return(cuMemcpy_generic, CUDA_SUCCESS);

    assert_true(req->stage_buf == NULL);
    _pscom_stage_buffer(req, 1);
    assert_true(req->stage_buf != NULL);
    assert_int_equal(*(int *)req->stage_buf, buffer);

    /* free the request */
    pscom_req_free(req);
}

/**
 * \brief Test _pscom_stage_buffer() for host memory
 *
 * Given: a memory buffer within the host memory
 * When: _pscom_stage_buffer() is called
 * Then: req->stage_buf remains NULL
 */
void test_pscom_stage_buffer_host_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* create a pscom request */
    pscom_req_t *req    = pscom_req_create(0, 0);
    int buffer          = 42;
    req->pub.connection = NULL;
    req->pub.data       = (void *)&buffer;
    req->pub.data_len   = sizeof(buffer);

    setup_cuPointerGetAttributes(&buffer, CU_MEMORYTYPE_HOST, 0, 1,
                                 CUDA_SUCCESS);

    _pscom_stage_buffer(req, 1);
    assert_true(req->stage_buf == NULL);

    setup_cuPointerGetAttributes(&buffer, CU_MEMORYTYPE_HOST, 0, 1,
                                 CUDA_SUCCESS);

    _pscom_stage_buffer(req, 0);
    assert_true(req->stage_buf == NULL);

    /* free the request */
    pscom_req_free(req);
}

////////////////////////////////////////////////////////////////////////////////
/// _pscom_unstage_buffer()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test _pscom_unstage_buffer() for device memory
 *
 * Given: a request with stage_buf != NULL
 * When: _pscom_unstage_buffer() is called with copy = 1
 * Then: the data is unstaged to req->pub.data
 */
void test_pscom_unstage_buffer_dev_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* create a pscom request */
    pscom_req_t *req         = pscom_req_create(0, 0);
    int buffer               = -1;
    int *stage_buffer        = (int *)malloc(sizeof(int));
    *stage_buffer            = 0xdeadbeef;
    req->pub.connection      = NULL;
    req->pub.data            = (void *)stage_buffer;
    req->pub.data_len        = sizeof(buffer);
    req->pub.header.data_len = sizeof(buffer);
    req->stage_buf           = (void *)&buffer;

    /* prepare mocking functions */
    expect_function_calls(cuMemcpy_generic, 1);
    expect_function_calls(__wrap_cuStreamSynchronize, 1);
    expect_value(cuMemcpy_generic, src, stage_buffer);
    expect_value(cuMemcpy_generic, dst, &buffer);
    expect_value(cuMemcpy_generic, nbytes, sizeof(buffer));
    will_return(cuMemcpy_generic, CUDA_SUCCESS);

    _pscom_unstage_buffer(req, 1);
    assert_true(req->stage_buf == NULL);
    assert_int_equal(req->pub.data, &buffer);
    int testval = 0xdeadbeef;
    assert_memory_equal(&buffer, &testval, 4);

    /* free the request */
    pscom_req_free(req);
}

/**
 * \brief Test _pscom_unstage_buffer() for error case
 *
 * Given: a request with stage_buf != NULL but with
 *        PSCOM_REQ_STATE_ERROR set in pub.state
 * When: _pscom_unstage_buffer() is called with copy = 1
 * Then: req->pub.data still remains unchanged
 */
void test_pscom_unstage_buffer_dev_mem_err_req(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* create a pscom request */
    pscom_req_t *req         = pscom_req_create(0, 0);
    int buffer               = 0xdeadbeef;
    int *stage_buffer        = (int *)malloc(sizeof(int));
    *stage_buffer            = 42;
    req->pub.connection      = NULL;
    req->pub.data            = (void *)stage_buffer;
    req->pub.data_len        = sizeof(buffer);
    req->pub.header.data_len = sizeof(buffer);
    req->stage_buf           = (void *)&buffer;
    req->pub.state |= PSCOM_REQ_STATE_ERROR;

    _pscom_unstage_buffer(req, /*copy=*/1);
    assert_true(req->stage_buf == NULL);
    assert_int_equal(req->pub.data, &buffer);
    int testval = 0xdeadbeef;
    assert_memory_equal(&buffer, &testval, 4);

    /* free the request */
    pscom_req_free(req);
}

/**
 * \brief Test _pscom_unstage_buffer() for device memory
 *
 * Given: a request with stage_buf != NULL
 * When: _pscom_unstage_buffer() is called with copy = 0
 * Then: req->pub.data remains unchanged
 */
void test_pscom_unstage_buffer_dev_mem_no_copy(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* create a pscom request */
    pscom_req_t *req         = pscom_req_create(0, 0);
    int buffer               = 0xdeadbeef;
    int *stage_buffer        = (int *)malloc(sizeof(int));
    *stage_buffer            = 42;
    req->pub.connection      = NULL;
    req->pub.data            = (void *)stage_buffer;
    req->pub.data_len        = sizeof(buffer);
    req->pub.header.data_len = sizeof(buffer);
    req->stage_buf           = (void *)&buffer;

    _pscom_unstage_buffer(req, 0);
    assert_true(req->stage_buf == NULL);
    assert_int_equal(req->pub.data, &buffer);
    int testval = 0xdeadbeef;
    assert_memory_equal(&buffer, &testval, 4);

    /* free the request */
    pscom_req_free(req);
}

/**
 * \brief Test _pscom_unstage_buffer() for host memory
 *
 * Given: a request with stage_buf == NULL
 * When: _pscom_unstage_buffer() is called
 * Then: req->pub.data remains untouched
 */
void test_pscom_unstage_buffer_host_mem(void **state)
{
    (void)state;

    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* create a pscom request */
    pscom_req_t *req         = pscom_req_create(0, 0);
    int buffer               = 42;
    req->pub.connection      = NULL;
    req->pub.data            = (void *)&buffer;
    req->pub.data_len        = sizeof(buffer);
    req->pub.header.data_len = sizeof(buffer);
    req->stage_buf           = NULL;

    _pscom_unstage_buffer(req, 1);
    assert_true(req->stage_buf == NULL);
    assert_int_equal(req->pub.data, &buffer);
    assert_int_equal(buffer, 42);

    _pscom_unstage_buffer(req, 0);
    assert_true(req->stage_buf == NULL);
    assert_int_equal(req->pub.data, &buffer);
    assert_int_equal(buffer, 42);

    /* free the request */
    pscom_req_free(req);

    /* disable CUDA support */
    pscom.env.cuda = 0;
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_post_recv()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_post_recv() for staging
 *
 * Given: CUDA-awareness is enabled and
 *        non-CUDA-aware connection
 * When: pscom_post_recv() is called
 * Then: buffer staging should not be called
 */
void test_cuda_post_recv_without_staging(void **state)
{
    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* obtain dummy connection from the test setup */
    pscom_con_t *recv_con = (pscom_con_t *)(*state);

    /* create non-CUDA-aware connection*/
    recv_con->is_gpu_aware = 0;

    /* create a pscom request */
    pscom_req_t *req         = pscom_req_create(0, 0);
    int buffer               = 42;
    req->pub.connection      = &recv_con->pub;
    req->pub.data            = (void *)&buffer;
    req->pub.data_len        = sizeof(buffer);
    req->pub.header.data_len = sizeof(buffer);
    req->stage_buf           = NULL;
    pscom_request_t *request = &req->pub;

    /* post a recv request (i.e., start reading) */
    pscom_post_recv(request);
    assert_int_equal(pscom.stat.gpu_staging, 0);
    assert_int_equal(pscom.stat.gpu_unstaging, 0);

    request->state |= PSCOM_REQ_STATE_DONE;
    /* free the request */
    pscom_req_free(req);

    /* disable CUDA support */
    pscom.env.cuda = 0;
}

////////////////////////////////////////////////////////////////////////////////
/// pscom_post_send()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_post_send() for staging
 *
 * Given: CUDA-awareness is enabled and
 *        non-CUDA-aware connection
 * When: pscom_post_send() is called
 * Then: buffer staging should not be called
 */
void test_cuda_post_send_without_staging(void **state)
{
    /* enable CUDA support */
    pscom.env.cuda = 1;

    /* obtain dummy connection from the test setup */
    pscom_con_t *send_con = (pscom_con_t *)(*state);

    /* create non-CUDA-aware connection*/
    send_con->is_gpu_aware = 0;

    /* create a pscom request */
    pscom_req_t *req         = pscom_req_create(0, 0);
    int buffer               = 42;
    req->pub.connection      = &send_con->pub;
    req->pub.data            = (void *)&buffer;
    req->pub.data_len        = sizeof(buffer);
    req->pub.header.data_len = sizeof(buffer);
    req->stage_buf           = NULL;
    pscom_request_t *request = &req->pub;

    /* post a send request (i.e., start writing) */
    pscom_post_send(request);
    assert_int_equal(pscom.stat.gpu_staging, 0);
    assert_int_equal(pscom.stat.gpu_unstaging, 0);


    request->state |= PSCOM_REQ_STATE_DONE;
    /* free the request */
    pscom_req_free(req);

    /* disable CUDA support */
    pscom.env.cuda = 1;
}
