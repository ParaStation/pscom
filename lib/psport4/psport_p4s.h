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
/**
 * psport_p4s.h: Header for p4sock communication
 */

#ifndef _PSPORT_P4S_H_
#define _PSPORT_P4S_H_

#include "p4sockets.h"
#include "p4io.h"
#include "list.h"

typedef struct p4s_info_s {
    int p4s_con;
    struct list_head sendq;
} p4s_info_t;


void p4s_init(PSP_Port_t *port);

int PSP_connect_p4s(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_accept_p4s(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_do_sendrecv_p4s(PSP_Port_t *port);

void PSP_terminate_con_p4s(PSP_Port_t *port, PSP_Connection_t *con);

#endif /* _PSPORT_P4S_H_ */
