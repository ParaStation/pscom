/*
 * ParaStation
 *
 * Copyright (C) 2019 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Simon Pickartz <pickartz@par-tec.com>
 */

#include <errno.h>

#include "pscom_cuda.h"
#include "pscom_priv.h"
#include "pscom_util.h"

PSCOM_API_EXPORT
int pscom_is_cuda_enabled(void)
{
	return PSCOM_IF_CUDA(pscom.env.cuda, 0);
}

#ifdef PSCOM_CUDA_AWARENESS

/**
 * \brief Prints a diagnostic string base on a CUresult
 *
 * This function can be used to print a diagnostic string from a
 * CUresult != CUDA_SUCCESS.
 *
 * \param [in] func The CUDA driver API call that failed
 * \param [in] err The CUDA error code
 */
static
void pscom_print_cuda_err(const char *func, CUresult err)
{
	const char *cuda_err_str;
	cuGetErrorName(err, &cuda_err_str);
	DPRINT(D_ERR, "CUDA driver call '%s' failed "
				  "[CUDA error code: '%s' (%d)]",
				  func, cuda_err_str, err);

	return;
}

/**
 * \brief Initializes the CUDA driver API
 *
 * This function initializes the CUDA driver API if CUDA awareness is enabled.
 * Since cuInit() fails if no CUDA device could be found, this function disables
 * the CUDA awareness to avoid further calls to the CUDA driver API.
 *
 * \return PSCOM_SUCCESS or PSCOM_ERR_STDERROR if cuInit() returns an error code
 *         other than CUDA_SUCCESS or CUDA_ERROR_NO_DEVICE; errno is set
 *         accordingly.
 */
static
pscom_err_t pscom_cuda_init_driver_api(void)
{
	pscom_err_t ret = PSCOM_SUCCESS;
	int cuda_ret;

	if (pscom.env.cuda) {
		cuda_ret = cuInit(0);

		switch(cuda_ret) {
		case CUDA_SUCCESS:
			break;
		case CUDA_ERROR_NO_DEVICE:
			/* disable CUDA awareness if no GPU is available */
			pscom.env.cuda = 0;

			DPRINT(D_INFO, "Could not find any CUDA devices");
			break;
		default:
			pscom_print_cuda_err("cuInit()", cuda_ret);
			errno = EFAULT;
			ret = PSCOM_ERR_STDERROR;
			break;
		}
	}

	return ret;
}

pscom_err_t pscom_cuda_init(void)
{
	CUresult ret;
	int dev_cnt, i, uva_support;
	const char *err_name;

	if (pscom_cuda_init_driver_api() != PSCOM_SUCCESS) goto err_out;

	if (pscom.env.cuda) {
		/* determine the number of  CUDA devices */
		ret = cuDeviceGetCount(&dev_cnt);
		if (ret != CUDA_SUCCESS) {
			pscom_print_cuda_err("cuDeviceGetCount()", ret);
			goto err_init;
		}

		if (dev_cnt == 0) DPRINT(D_INFO, "CUDA device count is zero");

		/* check if the devices share a unifed address space with the host */
		for (i=0; i<dev_cnt; ++i) {
			ret = cuDeviceGetAttribute(&uva_support, CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING, i);
			if (ret != CUDA_SUCCESS) {
				pscom_print_cuda_err("cuDeviceGetAttribute()", ret);
				goto err_init;
			}

			if (uva_support == 0) {
				DPRINT(D_ERR, "CUDA is missing support for Unified Virtual Addressing (UVA)");
				errno = ENOTSUP;
				goto err_out;
			}
		}
	}

	return PSCOM_SUCCESS;
	/* --- */
err_init:
	errno = EFAULT;
	/* --- */
err_out:
	return PSCOM_ERR_STDERROR;
}

/* simply map to internal _pscom_memcpy() */
PSCOM_API_EXPORT
void pscom_memcpy(void* dst, const void* src, size_t len)
{
	_pscom_memcpy_default(dst, src, len);
}

/* simply map to internal _pscom_is_gpu_ptr() */
PSCOM_API_EXPORT
int pscom_is_gpu_mem(const void* ptr)
{
	return _pscom_is_gpu_mem(ptr, 1);
}


/**
 * \brief GPU-safe memcpy from user to host memory
 *
 * For details see _pscom_memcpy_from_user().
 */
void pscom_memcpy_gpu_safe_from_user(void* dst, const void* src, size_t len)
{
	CUresult ret;

	if (_pscom_is_gpu_mem(src, len)) {
		ret = cuMemcpyDtoH(dst, (CUdeviceptr)src, len);
		assert(ret == CUDA_SUCCESS);
	} else {
		memcpy(dst, src, len);
	}
}

/**
 * \brief GPU-safe memcpy from host to user memory
 *
 * For details see _pscom_memcpy_from_user().
 */
void pscom_memcpy_gpu_safe_to_user(void* dst, const void* src, size_t len)
{
	CUresult ret;

	if (_pscom_is_gpu_mem(dst, len)) {
		ret = cuMemcpyHtoD((CUdeviceptr)dst, src, len);
		assert(ret == CUDA_SUCCESS);
	} else {
		memcpy(dst, src, len);
	}
}

/**
 * \brief GPU-safe memcpy
 *
 * For details see _pscom_memcpy_default().
 */
void pscom_memcpy_gpu_safe_default(void* dst, const void* src, size_t len)
{
	CUresult ret;

	if (_pscom_is_gpu_mem(dst, len) || _pscom_is_gpu_mem(src, len)) {
		ret = cuMemcpy((CUdeviceptr)dst, (CUdeviceptr)src, len);
		assert(ret == CUDA_SUCCESS);
	} else {
		memcpy(dst, src, len);
	}
}

/**
 * \brief Check for device memory and set memop synchronization if necessary
 *
 * \param [in] ptr The pointer to be checked
 * \param [in] length The length of the memory region (deprecated)
 *
 * This function checks if ptr resides on device memory and sets the CUDA
 * CU_POINTER_ATTRIBUTE_SYNC_MEMOPS attribute accordingly (if not already set).
 * This behavior can be influenced by using the environmen variable
 * PSP_CUDA_SYNC_MEMOPS (default: 1).
 */
int _pscom_is_gpu_mem(const void* ptr, size_t length)
{
	CUresult ret;

	if (!pscom.env.cuda || (ptr == NULL)) {
		return 0;
	}

	/* try to check via the CUDA driver API first */
	CUmemorytype mem_type = 0;
	unsigned int is_managed = 0;
	unsigned int is_gpu_mem = 0;
	unsigned int sync_memops = 0;
	void *drv_attr_data[] = {
		(void*)&mem_type,
		(void*)&is_managed,
		(void*)&sync_memops,
	};
	CUpointer_attribute drv_attrs[3] = {
		CU_POINTER_ATTRIBUTE_MEMORY_TYPE,
		CU_POINTER_ATTRIBUTE_IS_MANAGED,
		CU_POINTER_ATTRIBUTE_SYNC_MEMOPS
	};

	ret = cuPointerGetAttributes(3, drv_attrs, drv_attr_data, (CUdeviceptr)ptr);
	if (ret != CUDA_SUCCESS) {
		DPRINT(D_TRACE, "Cannot determine memory type. Assuming host memory!");
		return 0;
	}

	/* managed memory does not have to be specially treated */
	is_gpu_mem = (!is_managed && (mem_type == CU_MEMORYTYPE_DEVICE));

	/* synchronize memory operations on the device buffer; this can be
	 * necessary, e.g., when combining  cudaMemcpy() operations with
	 * GPUDirect TODO: what about managed memory? */
	if (pscom.env.cuda_sync_memops && is_gpu_mem && !sync_memops) {
		ret = cuPointerSetAttribute(&is_gpu_mem, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS, (CUdeviceptr)ptr);
		if (ret != CUDA_SUCCESS) pscom_print_cuda_err("cuPointerSetAttribute()", ret);
	}

	return is_gpu_mem;
}
#endif /* PSCOM_CUDA_AWARENESS */
