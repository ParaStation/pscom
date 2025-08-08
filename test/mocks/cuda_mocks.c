/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
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

#include <cuda.h>
#include <stddef.h>
#include <stdio.h>

#include "mocks/misc_mocks.h"

#define CUDA_MAX_STR "999"
#define STRLEN(s)    (sizeof(s) / sizeof(s[0]))
static char cuda_error_string[STRLEN(CUDA_MAX_STR)] = "";

/**
 * \brief Mocking function for cuInit()
 */
CUresult __wrap_cuInit(unsigned int flags)
{
    /* currently flags have to be 0 (see CUDA documentation) */
    assert_int_equal(flags, 0);

    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuDeviceGetCount()
 */
CUresult __wrap_cuDeviceGetCount(int *count)
{
    *count = mock_type(int);
    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuDeviceGetAttribute()
 */
CUresult __wrap_cuDeviceGetAttribute(int *pi, CUdevice_attribute attrib,
                                     CUdevice dev)
{
    check_expected(attrib);
    check_expected(dev);

    *pi = mock_type(int);
    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuPointerGetAttributes()
 */
CUresult __wrap_cuPointerGetAttributes(unsigned int numAttributes,
                                       CUpointer_attribute *attributes,
                                       void **data, CUdeviceptr ptr)
{
    check_expected(numAttributes);
    check_expected_ptr(ptr);

    *(CUmemorytype *)data[0] = mock_type(CUmemorytype);
    *(unsigned int *)data[1] = mock_type(unsigned int);
    *(unsigned int *)data[2] = mock_type(unsigned int);

    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuPointerSetAttribute()
 */
CUresult __wrap_cuPointerSetAttribute(const void *value,
                                      CUpointer_attribute attribute,
                                      CUdeviceptr ptr)
{
    function_called();
    check_expected(value);
    check_expected_ptr(ptr);

    return mock_type(CUresult);
}


/**
 * \brief Generic mocking function for cuMemcpy derivates
 */
static inline CUresult cuMemcpy_generic(void *dst, CUdeviceptr src,
                                        size_t nbytes)
{
    function_called();
    check_expected_ptr(src);
    check_expected_ptr(dst);
    check_expected(nbytes);

    /* call standard memcpy() for verification */
    __real_memcpy(dst, (void *)src, nbytes);

    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuMemcpyAsync()
 */
CUresult __wrap_cuMemcpyAsync(void *dst, CUdeviceptr src, size_t nbytes,
                              CUstream hStream)
{
    return cuMemcpy_generic(dst, src, nbytes);
}

/**
 * \brief Mocking function for cuMemcpyDtoHAsync_v2()
 */
CUresult __wrap_cuMemcpyDtoHAsync_v2(void *dst, CUdeviceptr src, size_t nbytes,
                                     CUstream hStream)
{
    return cuMemcpy_generic(dst, src, nbytes);
}


/**
 * \brief Mocking function for cuMemcpyHtoDAsync_v2()
 */
CUresult __wrap_cuMemcpyHtoDAsync_v2(void *dst, CUdeviceptr src, size_t nbytes,
                                     CUstream hStream)
{
    return cuMemcpy_generic(dst, src, nbytes);
}


/**
 * \brief Mocking function for cuStreamSynchronize()
 */
CUresult __wrap_cuStreamSynchronize(CUstream hStream)
{
    function_called();
    return CUDA_SUCCESS;
}


/**
 * \brief Mocking function for cuMemcpyHtoD_v2()
 */
CUresult __wrap_cuMemcpyHtoD_v2(void *dst, CUdeviceptr src, size_t nbytes)
{
    return cuMemcpy_generic(dst, src, nbytes);
}


/**
 * \brief Mocking function for cuMemcpy()
 */
CUresult __wrap_cuMemcpy(void *dst, CUdeviceptr src, size_t nbytes)
{
    return cuMemcpy_generic(dst, src, nbytes);
}


/**
 * \brief Mocking function for cuGetErrorString()
 */
CUresult __wrap_cuGetErrorName(CUresult error, const char **pStr)
{
    CUresult ret = CUDA_SUCCESS;

    if (error > CUDA_ERROR_UNKNOWN) {
        ret   = CUDA_ERROR_INVALID_VALUE;
        *pStr = NULL;
    } else {
        snprintf(cuda_error_string, STRLEN(cuda_error_string), "%d", error);
        *pStr = cuda_error_string;
    }

    return ret;
}


/**
 * \brief Mocking function for cuCtxGetCurrent()
 */
CUresult __wrap_cuCtxGetCurrent(CUcontext *pctx)
{
    *pctx = mock_type(CUcontext);

    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuCtxGetDevice()
 */
CUresult __wrap_cuCtxGetDevice(CUdevice *device)
{
    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuCtxGetDevice()
 */
CUresult __wrap_cuDevicePrimaryCtxGetState(CUdevice dev, unsigned int *flags,
                                           int *active)
{
    *active = mock_type(int);

    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cuStreamDestroy()
 */
CUresult CUDAAPI __wrap_cuStreamDestroy_v2(CUstream hStream)
{
    function_called();

    return mock_type(CUresult);
}


/**
 * \brief Mocking function for cudaStreamCreateWithFlags()
 */
CUresult __wrap_cuStreamCreate(CUstream *phStream, unsigned int Flags)
{
    function_called();

    *phStream = mock_type(CUstream);

    return mock_type(CUresult);
}
