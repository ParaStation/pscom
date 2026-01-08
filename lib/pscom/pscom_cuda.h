/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_CUDA_H_
#define _PSCOM_CUDA_H_

#include "pscom_priv.h"

#ifdef PSCOM_CUDA_AWARENESS

#include <stdlib.h>

#include "cuda.h"
#include "pscom.h"
#include "pscom_env.h"


#define CU_MEMORYTYPE_UNDEFINED ((CUmemorytype) - 1)
#define MIN(a, b)               (((a) < (b)) ? (a) : (b))

typedef enum PSCOM_copy_dir {
    PSCOM_COPY_ANY_DIR = 0,
    PSCOM_COPY_DEVICE2HOST,
    PSCOM_COPY_HOST2DEVICE,
    PSCOM_COPY_DIR_COUNT
} pscom_copy_dir_t;


pscom_err_t pscom_cuda_init(void);
pscom_err_t pscom_cuda_cleanup(void);
int _pscom_is_gpu_mem(const void *ptr, size_t length);


/**
 * @brief Synchronous device to host memcpy operation
 *
 * This operation utilizes the appropriate, pscom-internal CUDA stream
 * and performs basic error checking. The stream is created lazily if
 * approprate.
 *
 * @param [in] dst destination buffer
 * @param [in] src source buffer
 * @param [in] len bytes to be copied
 */
void pscom_memcpy_device2host(void *dst, const void *src, size_t len);


/**
 * @brief Synchronous host to device memcpy operation
 *
 * This operation utilizes the appropriate, pscom-internal CUDA stream
 * and performs basic error checking. The stream is created lazily if
 * approprate.
 *
 * @param [in] dst destination buffer
 * @param [in] src source buffer
 * @param [in] len bytes to be copied
 */
void pscom_memcpy_host2device(void *dst, const void *src, size_t len);


static inline int _pscom_buffer_needs_staging(const void *ptr, pscom_con_t *con)
{
    /* CUDA-awareness enabled AND
     * (No connection (=ANY recv) OR not gpu aware con) AND
     * GPU mem */
    return pscom.env.cuda && ((con == NULL) || !con->is_gpu_aware) &&
           _pscom_is_gpu_mem(ptr, 1 /* length */);
}

static inline void _pscom_stage_buffer(pscom_req_t *req, unsigned copy)
{
    pscom_con_t *con = req->pub.connection ? get_con(req->pub.connection)
                                           : NULL;

    if (_pscom_buffer_needs_staging(req->pub.data, con)) {
        req->stage_buf = req->pub.data;
        req->pub.data  = malloc(req->pub.data_len);

        /* we only have to copy in case of send requests */
        if (copy) {
            pscom_memcpy_device2host(req->pub.data, req->stage_buf,
                                     req->pub.data_len);
        }
        pscom.stat.gpu_staging++;
    }
}

static inline void _pscom_unstage_buffer(pscom_req_t *req, unsigned copy)
{
    if (req->stage_buf != NULL) {

        /* we only have to copy in case of (at least partly successful) recv
         * requests */
        if (copy && !(req->pub.state &
                      (PSCOM_REQ_STATE_ERROR | PSCOM_REQ_STATE_CANCELED))) {
            size_t copy_len = MIN(req->pub.data_len, req->pub.header.data_len);
            pscom_memcpy_host2device(req->stage_buf, req->pub.data, copy_len);
        }

        free(req->pub.data);
        req->pub.data  = req->stage_buf;
        req->stage_buf = NULL;
        pscom.stat.gpu_unstaging++;
    }
}

#else /* PSCOM_CUDA_AWARENESS */

static inline void _pscom_stage_buffer(pscom_req_t *req, unsigned copy)
{
    return;
}

static inline void _pscom_unstage_buffer(pscom_req_t *req, unsigned copy)
{
    return;
}

#endif /* PSCOM_CUDA_AWARENESS */
#endif /* _PSCOM_CUDA_H_ */
