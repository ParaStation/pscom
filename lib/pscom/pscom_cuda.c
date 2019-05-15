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


#ifdef PSCOM_CUDA_AWARENESS

pscom_err_t pscom_cuda_init(void)
{
	int ret = PSCOM_SUCCESS;
	int device_count, i, uva_support;
	const char *err_name;
	CUresult cuda_res;

	if (pscom.env.cuda) {
		if ((cuda_res = cuInit(0)) != CUDA_SUCCESS) {
			cuGetErrorName(cuda_res, &err_name);
			DPRINT(D_ERR, "Could not initialize the CUDA driver API [CUDA error code: '%s' (%d)]",
					err_name, cuda_res);
			errno = EFAULT;
			goto err_out;
		}

		if ((cuda_res = cuDeviceGetCount(&device_count)) != CUDA_SUCCESS) {
			cuGetErrorName(cuda_res, &err_name);
			DPRINT(D_ERR, "Could not determine the number of CUDA devices [CUDA error code: '%s' (%d)]",
					err_name, cuda_res);
			errno = EFAULT;
			goto err_out;
		}

		if (device_count == 0) {
			DPRINT(D_WARN, "Could not find any CUDA devices");
			goto out;
		}

		/* check if the devices share a unifed address space with the host */
		for (i=0; i<device_count; ++i) {
			if ((cuda_res = cuDeviceGetAttribute(&uva_support, CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING, i)) != CUDA_SUCCESS) {
				cuGetErrorName(cuda_res, &err_name);
				DPRINT(D_ERR, "Could not query UVA support for device %d the number of CUDA devices [CUDA error code: '%s' (%d)]",
						i, err_name, cuda_res);
				errno = EFAULT;
				goto err_out;
			}

			if (uva_support == 0) {
				DPRINT(D_ERR, "CUDA is missing support for Unified Virtual Addressing (UVA)");
				errno = ENOTSUP;
				goto err_out;
			}
		}
	}

out:
	return ret;

err_out:
	ret = PSCOM_ERR_STDERROR;
	return ret;
}

/* simply map to internal _pscom_memcpy() */
void pscom_memcpy(void* dst, const void* src, size_t len)
{
	_pscom_memcpy_default(dst, src, len);
}

/* simply map to internal _pscom_is_gpu_ptr() */
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
	if (_pscom_is_gpu_mem(src, len)) {
		cuMemcpyDtoH(dst, (CUdeviceptr)src, len);
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
	if (_pscom_is_gpu_mem(dst, len)) {
		cuMemcpyHtoD((CUdeviceptr)dst, src, len);
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
	if (_pscom_is_gpu_mem(dst, len) || _pscom_is_gpu_mem(src, len)) {
		cuMemcpy((CUdeviceptr)dst, (CUdeviceptr)src, len);
	} else {
		memcpy(dst, src, len);
	}
}


int _pscom_is_gpu_mem(const void* ptr, size_t length)
{
	int ret;

	if (!pscom.env.cuda || (ptr == NULL)) {
		return 0;
	}

	/* try to check via the CUDA driver API first */
	CUmemorytype mem_type = 0;
	unsigned int is_managed = 0;
	void *drv_attr_data[] = {(void*)&mem_type, (void*)&is_managed};
	CUpointer_attribute drv_attrs[2] = {CU_POINTER_ATTRIBUTE_MEMORY_TYPE,
					    CU_POINTER_ATTRIBUTE_IS_MANAGED};

	ret = cuPointerGetAttributes(2, drv_attrs, drv_attr_data, (CUdeviceptr)ptr);

	/* managed memory does not have to be specially treated */
	if (ret == CUDA_SUCCESS) {
		return (!is_managed && (mem_type == CU_MEMORYTYPE_DEVICE));
	}

	// TODO: error handling
	return 0;
}
#endif /* PSCOM_CUDA_AWARENESS */
