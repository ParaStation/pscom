/*
 * ParaStation
 *
 * Copyright (C) 2015 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _PSCOM_ASYNC_H_
#define _PSCOM_ASYNC_H_

#include "pscom_ufd.h"

typedef void async_cb_t(ufd_t *ufd, ufd_info_t *ufd_info);

void pscom_async_on_readable(int fd, async_cb_t *async_cb, void *priv);
void pscom_async_off_readable(int fd, async_cb_t *async_cb, void *priv);

#endif /* _PSCOM_ASYNC_H_ */
