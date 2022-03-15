/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSPORTALS_H_
#define _PSPORTALS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

/* some forward declarations */
typedef struct psptl_con_info psptl_con_info_t;
typedef struct psptl_hca_info psptl_hca_info_t;

typedef enum psptl_init_state {
    PSPORTALS_NOT_INITIALIZED = 1,
    PSPORTALS_INIT_DONE       = 0,
    PSPORTALS_INIT_FAILED     = -1
} psptl_init_state_t;


/*
 * Contact endpoint info
 */
typedef struct psptl_info_msg {
    uint64_t pid;
    uint32_t pti;
} psptl_info_msg_t;

/* lower level configuration */
typedef struct psptl {
    psptl_hca_info_t *hca_info;
    struct {
        int level;
        FILE *stream;
    } debug;
    uint32_t eq_size;
    struct {
        size_t bufsize;
        uint32_t sendq_size;
        uint32_t recvq_size;
    } con_params;
    struct {
        uint64_t retry_cnt;
        uint64_t outstanding_put_ops;
    } stats;
    psptl_init_state_t init_state;
    struct list_head cleanup_cons;
} psptl_t;


extern psptl_t psptl;


int psptl_init(void);
void psptl_finalize(void);

psptl_con_info_t *psptl_con_create(void);
int psptl_con_init(psptl_con_info_t *con_info, void *con_priv);
int psptl_con_connect(psptl_con_info_t *con_info, psptl_info_msg_t *info_msg);
void psptl_con_free(psptl_con_info_t *con_info);
void psptl_con_cleanup(psptl_con_info_t *con_info);

void psptl_con_get_info_msg(psptl_con_info_t *con_info,
                            psptl_info_msg_t *info_msg);

int psptl_progress(void);
ssize_t
psptl_sendv(psptl_con_info_t *con_info, struct iovec iov[2], size_t len);

void psptl_configure_debug(FILE *stream, int level);
void psptl_print_stats(void);

/* callbacks implemented by upper layer */
void pscom_portals_sendv_done(void);
void pscom_portals_recv_done(void *priv, void *buf, size_t len);

#endif /* _PSPORTALS_H_ */
