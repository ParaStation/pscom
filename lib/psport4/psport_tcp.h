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
 *
 * @author
 *         Jens Hauke <hauke@par-tec.de>
 *
 * @file
 ***********************************************************/

#ifndef _PSPORT_TCP_H_
#define _PSPORT_TCP_H_

#include "psport_types.h"

typedef struct PSP_ConnTCP_s {
    int	con_fd;
    int ufd_idx;
} PSP_ConnTCP_t;

int PSP_connect_tcp(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_accept_tcp(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);

void PSP_terminate_con_tcp(PSP_Port_t *port, PSP_Connection_t *con);

#endif /* _PSPORT_TCP_H_ */
