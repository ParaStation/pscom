#ifndef _PSCOM_CUDA_H_
#define _PSCOM_CUDA_H_

#ifdef PSCOM_CUDA_AWARENESS
#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <driver_types.h>

static inline
int pscom_check_for_gpu_ptr(void* ptr)
{
	int ret, type;
	struct cudaPointerAttributes attr;

	/* Try to check via CUDA driver API: */
	ret = cuPointerGetAttribute(&type, CU_POINTER_ATTRIBUTE_MEMORY_TYPE, (CUdeviceptr)ptr);

	if(ret == CUDA_SUCCESS) {
		if(type == CU_MEMORYTYPE_DEVICE) {
			return 1;
		} else {
			assert(type == CU_MEMORYTYPE_HOST);
			return 0;
		}
	}

	if(ret != CUDA_ERROR_INVALID_VALUE) {

		/* Try to check via CUDA runtime API: */
		ret = cudaPointerGetAttributes(&attr, ptr);

		if(ret == cudaSuccess) {
			if(attr.memoryType == cudaMemoryTypeDevice) {
				return 1;
			} else {
				assert(attr.memoryType == cudaMemoryTypeDevice);
				return 0;
			}
		}

		assert(ret == cudaErrorInvalidValue);
	}
}

static inline
void pscom_memcpy_gpu_safe(void* dst, void* src, size_t len)
{
	cudaMemcpy(dst, src, len, cudaMemcpyDefault);
}

static inline
void pscom_memcpy(void* dst, void* src, size_t len)
{
	if(pscom.env.cuda) {
		pscom_memcpy_gpu_safe(dst, src, len);
	} else {
		memcpy(dst, src, len);
	}
}

#else

static inline
void pscom_memcpy(void* dst, void* src, size_t len)
{
	memcpy(dst, src, len);
}

#endif

#endif
