/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_TCP_H_
#define _PSCOM_TCP_H_

#include "pscom_plugin.h"
#include "pscom_ufd.h"

typedef struct tcp_conn_s {
    ufd_info_t ufd_info;
} tcp_conn_t;


extern pscom_plugin_t pscom_plugin_tcp;

#endif /* _PSCOM_TCP_H_ */
