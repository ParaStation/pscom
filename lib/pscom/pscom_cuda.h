#ifndef _PSCOM_CUDA_H_
#define _PSCOM_CUDA_H_

#include "pscom_priv.h"

#ifdef PSCOM_CUDA_AWARENESS

#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <driver_types.h>

#define MIN(a,b)      (((a)<(b))?(a):(b))

pscom_err_t pscom_cuda_init(void);
int _pscom_is_gpu_mem(const void* ptr, size_t length);

static inline
int _pscom_buffer_needs_staging(const void* ptr, pscom_con_t* con)
{
	/* CUDA-awareness enabled AND
	 * (No connection (=ANY recv) OR not gpu aware con) AND
	 * GPU mem */
	return pscom.env.cuda && ((con == NULL) || !con->is_gpu_aware) && _pscom_is_gpu_mem(ptr, 1 /* length */);
}

static inline
void _pscom_stage_buffer(pscom_req_t *req, unsigned copy)
{
	pscom_con_t *con = req->pub.connection? get_con(req->pub.connection) : NULL;

	if (_pscom_buffer_needs_staging(req->pub.data, con)) {
		req->stage_buf = req->pub.data;
		req->pub.data = malloc(req->pub.data_len);

		/* we only have to copy in case of send requests */
		if (copy) {
			cudaMemcpy(req->pub.data, req->stage_buf, req->pub.data_len, cudaMemcpyDeviceToHost);
		}
	}
}

static inline
void _pscom_unstage_buffer(pscom_req_t *req, unsigned copy)
{
	if (req->stage_buf != NULL) {

		/* we only have to copy in case of recv requests */
		if (copy) {
			size_t copy_len = MIN(req->pub.data_len, req->pub.header.data_len);
			cudaMemcpy(req->stage_buf, req->pub.data, copy_len, cudaMemcpyHostToDevice);
		}

		free(req->pub.data);
		req->pub.data = req->stage_buf;
		req->stage_buf = NULL;
	}
}

#else /* PSCOM_CUDA_AWARENESS */

static inline
void _pscom_stage_buffer(pscom_req_t *req, unsigned copy)
{
	return;
}

static inline
void _pscom_unstage_buffer(pscom_req_t *req, unsigned copy)
{
	return;
}

#endif /* PSCOM_CUDA_AWARENESS */
#endif /* _PSCOM_CUDA_H_ */
