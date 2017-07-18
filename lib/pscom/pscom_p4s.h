/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_p4s.h: Header for p4sock communication
 */

#ifndef _PSPORT_P4S_H_
#define _PSPORT_P4S_H_

#include "p4sockets.h"
#include "p4io.h"
#include "list.h"

typedef struct p4s_conn_s {
	uint16_t		p4s_con;
	struct list_head	con_sendq_next; // used by list p4s_sock_t.con_sendq
	unsigned		reading : 1;
} p4s_conn_t;


typedef struct p4s_sock_s {
	int			users;
	int			readers;
	ufd_info_t		ufd_info;
	struct PSCOM_con	**p4s_conidx;
	uint16_t		p4s_conidx_cnt;
	struct sockaddr_p4	p4s_sockaddr;
	struct list_head	con_sendq;	// list of p4s_conn_t.con_sendq_next
	pscom_con_t		*recv_cur_con;
	uint16_t		recv_cur_con_idx;
} p4s_sock_t;


extern pscom_plugin_t pscom_plugin_p4s;

#endif /* _PSPORT_P4S_H_ */
