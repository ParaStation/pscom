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
 * psport_gm.h: Header for GM communication
 */

#ifndef _PSPORT_GM_H_
#define _PSPORT_GM_H_

typedef struct psgm_con_info_s psgm_con_info_t;

typedef struct psgm_info_s {
    struct list_head next;
    struct list_head next_send;
    psgm_con_info_t *gmcon;
} psgm_info_t;

int PSP_connect_gm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_accept_gm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_do_sendrecv_gm(PSP_Port_t *port);

void PSP_gm_init(PSP_Port_t *port);

void PSP_terminate_con_gm(PSP_Port_t *port, PSP_Connection_t *con);

#endif /* _PSPORT_GM_H_ */
