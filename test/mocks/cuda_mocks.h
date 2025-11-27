/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stddef.h>
#include <cuda.h>

CUresult __wrap_cuInit(unsigned int flags);
CUresult __wrap_cuDeviceGetCount(int *count);
CUresult __wrap_cuDeviceGetAttribute(int *pi, CUdevice_attribute attrib,
                                     CUdevice dev);
CUresult __wrap_cuPointerGetAttributes(unsigned int numAttributes,
                                       CUpointer_attribute *attributes,
                                       void **data, CUdeviceptr ptr);
CUresult __wrap_cuPointerSetAttribute(const void *value,
                                      CUpointer_attribute attribute,
                                      CUdeviceptr ptr);
CUresult __wrap_cuMemcpyAsync(void *dst, CUdeviceptr src, size_t nbytes,
                              CUstream hStream);
CUresult __wrap_cuMemcpyDtoHAsync_v2(void *dst, CUdeviceptr src, size_t nbytes,
                                     CUstream hStream);
CUresult __wrap_cuMemcpyHtoDAsync_v2(void *dst, CUdeviceptr src, size_t nbytes,
                                     CUstream hStream);
CUresult __wrap_cuStreamSynchronize(CUstream hStream);
CUresult __wrap_cuMemcpyHtoD_v2(void *dst, CUdeviceptr src, size_t nbytes);
CUresult __wrap_cuMemcpy(void *dst, CUdeviceptr src, size_t nbytes);
CUresult __wrap_cuGetErrorName(CUresult error, const char **pStr);
CUresult __wrap_cuCtxGetCurrent(CUcontext *pctx);
CUresult __wrap_cuCtxGetDevice(CUdevice *device);
CUresult __wrap_cuDevicePrimaryCtxGetState(CUdevice dev, unsigned int *flags,
                                           int *active);
CUresult CUDAAPI __wrap_cuStreamDestroy_v2(CUstream hStream);
CUresult __wrap_cuStreamCreate(CUstream *phStream, unsigned int Flags);
