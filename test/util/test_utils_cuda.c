/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_cuda.h"

extern CUstream pscom_cuda_stream_set[PSCOM_COPY_DIR_COUNT];

int setup_dummy_streams(void **state)
{
	pscom_cuda_stream_set[PSCOM_COPY_ANY_DIR] = (CUstream)0x42;
	pscom_cuda_stream_set[PSCOM_COPY_HOST2DEVICE] = (CUstream)0xDEADBEEF;
	pscom_cuda_stream_set[PSCOM_COPY_DEVICE2HOST] = (CUstream)0xFEEBDAED;

	return 0;
}

int clear_dummy_streams(void **state)
{
	pscom_cuda_stream_set[PSCOM_COPY_ANY_DIR] = NULL;
	pscom_cuda_stream_set[PSCOM_COPY_HOST2DEVICE] = NULL;
	pscom_cuda_stream_set[PSCOM_COPY_DEVICE2HOST] = NULL;

	return 0;
}
