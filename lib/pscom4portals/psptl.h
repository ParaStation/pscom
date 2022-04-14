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
typedef struct psptl_ep psptl_ep_t;

typedef enum psptl_init_state {
    PSPORTALS_NOT_INITIALIZED = 1,
    PSPORTALS_INIT_DONE       = 0,
    PSPORTALS_INIT_FAILED     = -1
} psptl_init_state_t;


/*
 * Contact endpoint info
 */

typedef enum psptl_prot_type {
    PSPTL_PROT_EAGER,
    PSPTL_PROT_RNDV,
    PSPTL_PROT_COUNT,
} psptl_prot_type_t;


typedef struct psptl_info_msg {
    uint64_t pid;
    uint32_t pti[PSPTL_PROT_COUNT];
} psptl_info_msg_t;

/* lower level configuration */
typedef struct psptl {
    struct {
        int level;
        FILE *stream;
    } debug;
    uint32_t eq_size;
    struct {
        size_t bufsize;
        uint32_t sendq_size;
        uint32_t recvq_size;
        uint32_t max_rndv_reqs;
        uint32_t max_rndv_retry;
    } con_params;
    struct {
        uint64_t retry_cnt;
        uint64_t outstanding_put_ops;
        uint64_t rndv_write;
        uint64_t rndv_retry;
    } stats;
    psptl_init_state_t init_state;
    struct list_head cleanup_cons;
} psptl_t;


/* memory region for receiving RMA puts (i.e., PtlPut()) */
typedef struct psptl_rma_mreg {
    void *priv;
    uint64_t match_bits;
} psptl_rma_mreg_t;

typedef struct psptl_rma_req {
    void (*io_done)(void *priv, int err);
    void *priv;
    void *mdh;
    psptl_con_info_t *con_info;
    void *data;
    size_t data_len;
    uint64_t match_bits;
    uint8_t retry_cnt;
} psptl_rma_req_t;

extern psptl_t psptl;


int psptl_init(void);
void psptl_finalize(void);

int psptl_init_ep(void **ep_priv);
void psptl_cleanup_ep(void *ep_priv);

psptl_con_info_t *psptl_con_create(void);
int psptl_con_init(psptl_con_info_t *con_info, void *con_priv, void *ep_priv);
int psptl_con_connect(psptl_con_info_t *con_info, psptl_info_msg_t *info_msg);
void psptl_con_free(psptl_con_info_t *con_info);
void psptl_con_cleanup(psptl_con_info_t *con_info);

void psptl_con_get_info_msg(psptl_con_info_t *con_info,
                            psptl_info_msg_t *info_msg);

int psptl_progress(void *ep_priv);
ssize_t
psptl_sendv(psptl_con_info_t *con_info, struct iovec iov[2], size_t len);

void psptl_configure_debug(FILE *stream, int level);
void psptl_print_stats(void);

/* callbacks implemented by upper layer */
void pscom_portals_sendv_done(void *con_priv);
void pscom_portals_recv_done(void *priv, void *buf, size_t len);

/* rendezvous-related interface */
int psptl_rma_mem_register(psptl_con_info_t *con_info, void *buf, size_t len,
                           psptl_rma_mreg_t *rma_mreg);
void psptl_rma_mem_deregister(psptl_rma_mreg_t *rma_mreg);
int psptl_post_rma_put(psptl_rma_req_t *rma_req);

#endif /* _PSPORTALS_H_ */
