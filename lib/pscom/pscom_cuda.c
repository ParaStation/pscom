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
	int device_count, i;
	struct cudaDeviceProp dev_props;
	cudaError_t cuda_err;

	if (pscom.env.cuda) {
		if (cudaGetDeviceCount(&device_count) != cudaSuccess) {
			cuda_err = cudaGetLastError();
			DPRINT(D_ERR, "Could not determine the number of CUDA devices [CUDA error code: '%s' (%d)]",
					cudaGetErrorName(cuda_err), cuda_err);
			errno = EFAULT;
			goto err_out;
		}

		if (device_count == 0) {
			DPRINT(D_WARN, "Could not find any CUDA devices");
			goto out;
		}

		/* check if the devices share a unifed address space with the host */
		for (i=0; i<device_count; ++i) {
			cudaGetDeviceProperties(&dev_props, i);

			if (dev_props.unifiedAddressing == 0) {
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
	_pscom_memcpy(dst, src, len);
}

/* simply map to internal _pscom_check_for_gpu_ptr() */
int pscom_is_gpu_mem(const void* ptr)
{
	return _pscom_is_gpu_mem(ptr, 1);
}

void pscom_memcpy_gpu_safe(void* dst, const void* src, size_t len)
{
	if (_pscom_is_gpu_mem(dst, len) || _pscom_is_gpu_mem(src, len)) {
		cudaMemcpy(dst, src, len, cudaMemcpyDefault);
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

	/* now, try to query the CUDA runtime API */
	struct cudaPointerAttributes rt_attrs;
	ret = cudaPointerGetAttributes(&rt_attrs, ptr);

	/* managed memory does not have to be specially treated */
	if (ret == cudaSuccess) {
#ifndef CUDART_VERSION
#error CUDART_VERSION Undefined!
#elif (CUDART_VERSION > 9020)
		return (!(rt_attrs.type == cudaMemoryTypeManaged) &&
			(rt_attrs.type == cudaMemoryTypeDevice));
#else
		return (!rt_attrs.isManaged &&
			(rt_attrs.memoryType == cudaMemoryTypeDevice));
#endif
	}

	return 0;
}
#endif /* PSCOM_CUDA_AWARENESS */
