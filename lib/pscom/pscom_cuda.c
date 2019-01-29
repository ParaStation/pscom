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

#include "pscom_cuda.h"
#include "pscom_priv.h"
#include "pscom_util.h"


#ifdef PSCOM_CUDA_AWARENESS
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
