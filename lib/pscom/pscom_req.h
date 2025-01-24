/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_REQ_H_
#define _PSCOM_REQ_H_

#include <stdlib.h>
#include "pscom_priv.h"

pscom_req_t *pscom_req_create(size_t max_xheader_len, size_t user_size);

void pscom_req_free(pscom_req_t *req);

size_t pscom_req_write(pscom_req_t *req, char *buf, size_t len);
size_t pscom_req_forward(pscom_req_t *req, size_t len);

/* append data on req. used for partial send requests with pending data. */
void pscom_req_append(pscom_req_t *req, char *buf, size_t len);

// #define USE_PSCOM_MALLOC 1

#if USE_PSCOM_MALLOC

#define PSCOM_MALLOC_SAFE_SIZE 0

void *pscom_malloc(size_t size);
void pscom_free(void *ptr);
void pscom_mverify(void *ptr);

#else

#define pscom_malloc malloc
#define pscom_free   free
#define pscom_mverify(x)                                                       \
    do {                                                                       \
    } while (0)

#endif

#endif /* _PSCOM_REQ_H_ */
