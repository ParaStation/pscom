/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_SOCK_H_
#define _PSCOM_SOCK_H_

#include <stddef.h>
#include <stdint.h>

#include "pscom_priv.h"

void pscom_sock_unset_id(pscom_sock_t *sock);
void pscom_sock_close(pscom_sock_t *sock);
pscom_sock_t *pscom_sock_create(size_t userdata_size,
                                size_t connection_userdata_size, int local_rank,
                                uint64_t socket_flags);

#endif /* _PSCOM_SOCK_H_ */
