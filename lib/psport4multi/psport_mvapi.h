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
 * psport_mvapi.h: Header for MVAPI communication
 */

#ifndef _PSPORT_MVAPI_H_
#define _PSPORT_MVAPI_H_

#include <sys/ipc.h>
#include <sys/shm.h>

typedef struct psib_con_info_s psib_con_info_t;

typedef struct psib_info_s {
    struct list_head next;
    struct list_head next_send;
    psib_con_info_t *mcon;
} psib_info_t;

int PSP_connect_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_accept_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_do_sendrecv_mvapi(PSP_Port_t *port);

void PSP_mvapi_init(PSP_Port_t *port);

void PSP_terminate_con_mvapi(PSP_Port_t *port, PSP_Connection_t *con);

#endif /* _PSPORT_MVAPI_H_ */
