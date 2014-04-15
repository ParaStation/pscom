/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psoib.c: OPENIB/Infiniband communication
 */

#ifndef _PSOIB_H_
#define _PSOIB_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include "list.h"

typedef struct psoib_con_info psoib_con_info_t;
typedef struct hca_info hca_info_t;
typedef struct port_info port_info_t;

// contact endpoint info
typedef struct psoib_info_msg_s {
	uint16_t	lid;
	uint32_t	qp_num;  /* QP number */
	void		*remote_ptr; /* Info about receive buffers */
	uint32_t	remote_rkey;
} psoib_info_msg_t;


typedef struct {
    void *ptr;
    struct ibv_mr *mr;
} mem_info_t;

#define IB_USE_ZERO_COPY
#define IB_RNDV_THRESHOLD 1024
#define IB_USE_MREG_CACHE
#define IB_MREG_CACHE_SIZE 16

#if defined(IB_USE_ZERO_COPY) && defined(IB_DONT_USE_ZERO_COPY)
#undef IB_USE_ZERO_COPY
#endif

#if !defined(IB_USE_ZERO_COPY) && defined(IB_RMA_MREG_CACHE_SIZE)
#undef IB_RMA_MREG_CACHE_SIZE
#endif

/*
 * ++ RMA rendezvous
 */
#ifdef IB_USE_ZERO_COPY
/* registered memory region. (Opaque object for users of psoib_get_rma_mreg() and psoib_put_rma_mreg()) */
typedef struct psoib_rma_req psoib_rma_req_t;

typedef struct psoib_rma_mreg {
	mem_info_t      mem_info;
	uint32_t        key;
	size_t          size;
#ifdef IB_USE_MREG_CACHE
	struct psoib_mregion_cache* mreg_cache;
#endif
} psoib_rma_mreg_t;


/* rendezvous data for the rma get request */
struct psoib_rma_req {
	struct list_head next;
	size_t		 data_len;
	psoib_rma_mreg_t  mreg;
	psoib_con_info_t *ci;
	uint32_t        remote_key;
	uint64_t        remote_addr;
	void		(*io_done)(psoib_rma_req_t *req);
	void		*priv;
};

int psoib_acquire_rma_mreg(psoib_rma_mreg_t *mreg, void *buf, size_t size, psoib_con_info_t *ci);
int psoib_release_rma_mreg(psoib_rma_mreg_t *mreg);
int psoib_post_rma_get(psoib_rma_req_t *req);
#ifdef IB_USE_MREG_CACHE
void psoib_mregion_cache_cleanup(void);
void psoib_mregion_cache_init(void);
#endif

#endif
/*
 *  -- RMA rendezvous end
 */


int psoib_init(void);


// Connection handling:

psoib_con_info_t *psoib_con_create(void);
void	psoib_con_free(psoib_con_info_t *con_info);

int	psoib_con_init(psoib_con_info_t *con_info, hca_info_t *hca_info, port_info_t *port_info);
int	psoib_con_connect(psoib_con_info_t *con_info, psoib_info_msg_t *info_msg);
void	psoib_con_cleanup(psoib_con_info_t *con_info, hca_info_t *hca_info);

void	psoib_con_get_info_msg(psoib_con_info_t *con_info /* in */, psoib_info_msg_t *info /* out */);


/* returnvalue like read() , except on error errno is negative return */
int psoib_recvlook(psoib_con_info_t *con_info, void **buf);
void psoib_recvdone(psoib_con_info_t *con_info);


/* returnvalue like write(), except on error errno is negative return */
/* It's important, that the sending side is aligned to IB_MTU_SPEC,
   else we loose a lot of performance!!! */
int psoib_sendv(psoib_con_info_t *con_info, struct iovec *iov, int size);
void psoib_send_eof(psoib_con_info_t *con_info);

/* Handle outstanding cq events. */
void psoib_progress(void);

/* Suggest a value for psoib_pending_tokens. Result depends on psoib_recvq_size. */
unsigned psoib_pending_tokens_suggestion(void);

/*
 * Configuration
 */
extern int psoib_debug;
extern FILE *psoib_debug_stream; /* Stream to use for debug output */
extern char *psoib_hca; /* hca name to use. Default: first hca */
extern unsigned int psoib_port; /* port index to use. Default: 0 (means first active port) */
extern unsigned int psoib_path_mtu; /* path mtu to use. */
extern unsigned int psoib_sendq_size;
extern unsigned int psoib_recvq_size;
extern unsigned int psoib_compq_size;
extern unsigned int psoib_pending_tokens;
extern int psoib_global_sendq; /* bool. Use one sendqueue for all connections? */
extern int psoib_event_count; /* bool. Be busy if outstanding_cq_entries is to high? */
extern int psoib_ignore_wrong_opcodes; /* bool: ignore wrong cq opcodes */
extern int psoib_lid_offset; /* int: offset to base LID (adaptive routing) */

/*
 * Information
 */
extern unsigned psoib_outstanding_cq_entries; /* counter */

#endif /* _PSOIB_H_ */
