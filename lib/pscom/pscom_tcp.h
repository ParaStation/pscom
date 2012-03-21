/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/*
 * psport_tcp.h: Header for tcp communication
 */

#ifndef _PSPORT_TCP_H_
#define _PSPORT_TCP_H_

#include "pscom_types.h"
#include "pscom_plugin.h"

typedef struct tcp_conn_s {
	ufd_info_t ufd_info;
} tcp_conn_t;


typedef struct tcp_sock_s {
} tcp_sock_t;


extern pscom_plugin_t pscom_plugin_tcp;

#endif /* _PSPORT_TCP_H_ */
