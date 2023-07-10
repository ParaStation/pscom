/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_shm.h: Header for sharedmem communication
 */

#ifndef _PSPORT_SHM_H_
#define _PSPORT_SHM_H_

#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdint.h>
#include "list.h"
#include "pscom_types.h"
#include "pscom_poll.h"
#include "pscom_plugin.h"
/*
 * Shared memory structs
 */

typedef struct shm_msg_s {
    uint32_t len;
    volatile uint32_t msg_type;
} shm_msg_t;

#if !(defined(__KNC__) || defined(__MIC__))
#define SHM_BUFS   8
#define SHM_BUFLEN (8192 - sizeof(shm_msg_t))
#else
/* On KNC use more, but much smaller shm buffers. Using direct shm to archive a
 * good throughput. */
#define SHM_BUFS   16
#define SHM_BUFLEN ((1 * 1024) - sizeof(shm_msg_t))
#endif

#define SHM_MSGTYPE_NONE        0
#define SHM_MSGTYPE_STD         1
#define SHM_MSGTYPE_DIRECT      2
#define SHM_MSGTYPE_DIRECT_DONE 3

#define SHM_DATA(buf, len) ((char *)(&(buf)->header) - (((len) + 7) & ~7))

typedef struct shm_buf_s {
    uint8_t _data[SHM_BUFLEN];
    shm_msg_t header;
} shm_buf_t;

typedef struct shm_com_s {
    shm_buf_t buf[SHM_BUFS];
} shm_com_t;

typedef struct shm_conn_s {
    shm_com_t *local_com;  /* local */
    shm_com_t *remote_com; /* remote */
    int recv_cur;
    int send_cur;
    long direct_offset; /* base offset for shm direct */
    int local_id;
    int remote_id;
    void *direct_base; /* shm direct base */

    pscom_poll_t poll_write_pending_io; // Polled if this shm_conn_t has pending
                                        // io
    struct shm_pending *shm_pending;    /* first pending io request of this
                                           connection */
} shm_conn_t;


extern pscom_plugin_t pscom_plugin_shm;

#endif /* _PSPORT_SHM_H_ */
