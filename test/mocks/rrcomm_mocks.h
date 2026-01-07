/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdint.h>
#include <sys/types.h>
#include "pstaskid.h"

int __wrap_RRC_init(void);
void __wrap_RRC_finalize(void);
PStask_ID_t __wrap_RRC_getJobID(void);
ssize_t __wrap_RRC_sendX(PStask_ID_t jobid, uint32_t dest, char *buf,
                         int buf_size);
ssize_t __wrap_RRC_recvX(PStask_ID_t *jobid, uint32_t *src, char *buf,
                         int buf_size);
