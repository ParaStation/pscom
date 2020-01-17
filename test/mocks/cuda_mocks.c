#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <cuda.h>
#include <driver_types.h>

#include "mocks/misc_mocks.h"

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
CUresult __wrap_cuDeviceGetCount(int* count)
{
	*count = mock_type(int);
	return mock_type(CUresult);
}

/**
 * \brief Mocking function for cuDeviceGetAttribute()
 */
CUresult __wrap_cuDeviceGetAttribute(int* pi, CUdevice_attribute attrib,
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
CUresult __wrap_cuPointerGetAttributes(unsigned int  numAttributes,
		CUpointer_attribute* attributes, void** data, CUdeviceptr ptr)
{
	check_expected(numAttributes);
	check_expected_ptr(ptr);

	*(CUmemorytype*)data[0] = mock_type(CUmemorytype);
	*(unsigned int*)data[1] = mock_type(unsigned int);
	*(unsigned int*)data[2] = mock_type(unsigned int);

	return mock_type(CUresult);
}

/**
 * \brief Mocking function for cuPointerSetAttribute()
 */
CUresult __wrap_cuPointerSetAttribute(const void* value,
		CUpointer_attribute attribute, CUdeviceptr ptr)
{
	function_called();
	check_expected(value);
	check_expected_ptr(ptr);

	return mock_type(CUresult);
}


/**
 * \brief Generic mocking function for cuMemcpy derivates
 */
static inline
CUresult cuMemcpy_generic(void* dst, CUdeviceptr src, size_t nbytes)
{
	function_called();
	check_expected_ptr(src);
	check_expected_ptr(dst);
	check_expected(nbytes);

	/* call standard memcpy() for verification */
	__real_memcpy(dst, (void*)src, nbytes);

	return mock_type(CUresult);
}

/**
 * \brief Mocking function for cuMemcpyDtoH_v2()
 */
CUresult __wrap_cuMemcpyDtoH_v2(void* dst, CUdeviceptr src, size_t nbytes)
{
	return cuMemcpy_generic(dst, src, nbytes);
}

/**
 * \brief Mocking function for cuMemcpyHtoD_v2()
 */
CUresult __wrap_cuMemcpyHtoD_v2(void* dst, CUdeviceptr src, size_t nbytes)
{
	return cuMemcpy_generic(dst, src, nbytes);
}

/**
 * \brief Mocking function for cuMemcpy()
 */
CUresult __wrap_cuMemcpy(void* dst, CUdeviceptr src, size_t nbytes)
{
	return cuMemcpy_generic(dst, src, nbytes);
}