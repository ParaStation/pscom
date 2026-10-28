/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSUCP_H_
#define _PSUCP_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <sys/types.h>
#include "pscom.h"


typedef struct psucp_con_info psucp_con_info_t;
typedef struct psucp_hca_info psucp_hca_info_t;
typedef struct psucp_rma_module psucp_rma_module_t;
typedef struct psucp_con_rma_stat psucp_con_rma_stat_t;

struct psucp_con_rma_stat {
    size_t issued_op_count;
    size_t local_complete;
    int flush_local;
    int flush_remote;
};


typedef struct pscom_ucp_sock {
    unsigned flush_required; /**< flush tag */
} pscom_ucp_sock_t;


// contact endpoint info
typedef struct psucp_info_msg_s {
    uint64_t tag;
    uint32_t small_msg_len; /**< max length for small messages (= size of
                               "xheader" receive request) */
    uint16_t ucp_addr_size;
    char ucp_addr[0]; // ucp_addr_size bytes after this struct
} psucp_info_msg_t;


/* Initialise ucp. This must be called first. */
int psucp_init(void);

/* cleanup ucp. This should be called when ucp plugin is destroyed. */
void psucp_finalize(void);

/*
 * Connection handling:
 *
 * Live cycle of a connection is:
 * ci = psucp_con_create(void);
 * psucp_con_init(ci, hca_info);
 * psucp_con_get_info_msg(ci, my_info);
 * write(peer, my_info);
 * read(peer, info), peer called psucp_con_get_info_msg() a transmit the result
 * to us. psucp_con_connect(ci, info); // both sides have to call connect
 * (psucp_sendv()/psucp_recvlook and done)*
 * psucp_con_cleanup(ci);
 * psucp_con_free(ci);
 */

/* Create a con_info. usable for psucp_con_init().
 * return NULL on error */
psucp_con_info_t *psucp_con_create(void);
void psucp_con_free(psucp_con_info_t *con_info);


int psucp_con_init(psucp_con_info_t *con_info, psucp_hca_info_t *hca_info,
                   void *con_priv);
int psucp_con_connect(psucp_con_info_t *con_info, psucp_info_msg_t *info_msg);
void psucp_con_cleanup(psucp_con_info_t *con_info);

/* Caller has to call free() on result after usage. */
psucp_info_msg_t *psucp_con_get_info_msg(psucp_con_info_t *con_info,
                                         unsigned long tag);

static inline unsigned psucp_info_msg_length(psucp_info_msg_t *info_msg)
{
    return (unsigned)sizeof(*info_msg) + info_msg->ucp_addr_size;
}


/* returnvalue like write(), except on error errno is negative return
 * send through con_info. (iov[0].iov_len + iov[1].iov_len > 0)
 * return number of bytes send or:
 * -EAGAIN if ci is busy or
 * -EPIPE in case of a broken connection.
 */
ssize_t psucp_sendv(psucp_con_info_t *con_info, struct iovec iov[2],
                    void *req_priv);

/* Callback to be implemented by upper layer */
void pscom_psucp_sendv_done(void *req_priv);

/* Include ucp.h for psucp_msg_t */
#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>

typedef struct {
    ucp_tag_message_h msg_tag;
    ucp_tag_recv_info_t info_tag;
} psucp_msg_t;

// Probe for incoming message on any connection.
// In success: MUST call psucp_recv(msg) or psucp_irecv(msg) afterwards!
size_t psucp_probe(psucp_msg_t *msg);
ssize_t psucp_recv(psucp_msg_t *msg, void *buf, size_t size);

/* Flush the notification queue and make progress. */
void psucp_progress(void);


/* Suggest a value for psucp_pending_tokens. Result depends on psucp_recvq_size.
 */
unsigned psucp_pending_tokens_suggestion(void);


ssize_t psucp_irecv(psucp_con_info_t *con_info, psucp_msg_t *msg, void *buf,
                    size_t size);
/* Callback to be implemented by upper layer */
void pscom_psucp_read_done(void *con_priv, void *req_priv);

/* rma */
int psucp_rma_mem_register(void *addr, size_t length, void **rkeybuf,
                           uint16_t *bufsize, ucp_mem_h *memh);
int psucp_rma_mem_deregister(ucp_mem_h memh);
int psucp_rma_rkey_generate(psucp_con_info_t *con_info, void *rkeybuf,
                            ucp_rkey_h *rkey);
int psucp_rma_rkey_destroy(ucp_rkey_h rkey);
void psucp_rma_rkey_buf_free(void *rkey_buf);

int psucp_rma_put(psucp_con_info_t *ci, void *buffer, size_t length,
                  void *remote_addr, ucp_rkey_h ucp_rkey, void *req_priv);
int psucp_rma_get(psucp_con_info_t *ci, void *buffer, size_t length,
                  void *remote_addr, ucp_rkey_h ucp_rkey, void *req_priv);
int psucp_rma_native_check(pscom_rma_op_t rma_op);
int psucp_rma_atomics_check(pscom_rma_atomic_op_t atomic_op,
                            pscom_datatype_t data_type, size_t length,
                            pscom_rma_op_t rma_op);
int psucp_rma_atomic_op(psucp_con_info_t *ci, void *buffer, size_t length,
                        void *remote_addr, void *result_addr,
                        ucp_atomic_op_t ucp_opcode, ucp_rkey_h ucp_rkey,
                        void *req_priv);
int psucp_rma_atomic_op_segment(psucp_con_info_t *ci, void *buffer,
                                size_t length, pscom_datatype_t data_type,
                                void *remote_addr, void *result_addr,
                                ucp_atomic_op_t ucp_opcode, ucp_rkey_h ucp_rkey,
                                void *req_priv);
ucp_atomic_op_t psucp_rma_opcode_convert(pscom_rma_atomic_op_t rma_opcode);
int psucp_rma_worker_flush(void);
int psucp_rma_ep_flush(psucp_con_info_t *con_info);
int psucp_rma_ep_flush_local(psucp_con_info_t *con_info);
void pscom_psucp_rma_put_done(void *req_priv);
void pscom_psucp_rma_cs_done(void *req_priv);
void psucp_init_rma_masks(void);

/*
 * Configuration
 */
extern int psucp_debug;
extern FILE *psucp_debug_stream; /* Stream to use for debug output */
extern unsigned psucp_small_msg_len;
extern unsigned int psucp_sendq_size;  /* sendqueue size. Used when
                                          psucp_global_sendq == 0 */
extern unsigned int psucp_gsendq_size; /* Global sendqueue size. Used when
                                          psucp_global_sendq == 1 */
extern unsigned int psucp_recvq_size;
extern unsigned int psucp_pending_tokens;
extern int psucp_global_sendq; /* bool. Use one sendqueue for all connections?
                                */
extern int psucp_event_count;  /* bool. Be busy if outstanding_cq_entries is to
                                  high? */
extern unsigned int psucp_max_recv; /* Maximum number of concurrent receive
                                       requests */

/*
 * Information
 */
extern unsigned psucp_pending_global_sends; /* counter. Used only with
                                               psucp_global_sendq == 1 */

#endif /* _PSUCP_H_ */
