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
 * psp_shm.h: Header for sharedmem communication
 */

#ifndef _PSPORT_SHM_H_
#define _PSPORT_SHM_H_

#include <sys/ipc.h>
#include <sys/shm.h>


/*
 * Shared memory structs
 */

typedef struct shm_msg_s {
    uint32_t len;
    volatile uint32_t msg_type;
} shm_msg_t;

#define SHM_BUFS 8
#define SHM_BUFLEN (8192 - sizeof(shm_msg_t))

#define SHM_MSGTYPE_NONE 0
#define SHM_MSGTYPE_STD	 1

#define SHM_DATA(buf, len) ((char*)(&(buf)->header) - len)

typedef struct shm_buf_s {
    uint8_t _data[SHM_BUFLEN];
    shm_msg_t header;
} shm_buf_t;

typedef struct shm_ctrl_s {
    volatile uint8_t	used;
} shm_ctrl_t;

typedef struct shm_com_s {
    shm_buf_t	buf[SHM_BUFS];
    shm_ctrl_t	ctrl[SHM_BUFS];
} shm_com_t;

typedef struct shm_info_s {
    struct list_head next;
    struct list_head next_send;
    shm_com_t *local_com; /* local */
    shm_com_t *remote_com; /* remote */
    int local_id;
    int remote_id;
    int recv_cur;
    int send_cur;
} shm_info_t;


int PSP_connect_shm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_accept_shm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd);
int PSP_do_sendrecv_shm(PSP_Port_t *port);

void PSP_terminate_con_shm(PSP_Port_t *port, PSP_Connection_t *con);

#endif /* _PSPORT_SHM_H_ */
