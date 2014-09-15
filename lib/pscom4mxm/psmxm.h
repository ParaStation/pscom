/*
 * ParaStation
 *
 * Copyright (C) 2014 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _PSMXM_H_
#define _PSMXM_H_

#include <sys/uio.h>
#include <mxm/api/mxm_api.h>
#include "list.h"

#define MXM_EP_ADDR_LEN       (256)
#define PSMXM_PROTOCOL_VERSION	(0x00000100)
#define PSMXM_MTU (16*1024)

typedef struct psmxm_con_info psmxm_con_info_t;
typedef struct {
	uint32_t	psmxm_protocol_version;
	uint64_t	tag;
	char		mxm_ep_addr[MXM_EP_ADDR_LEN];
} psmxm_info_msg_t;


extern int psmxm_debug;
extern FILE *psmxm_debug_stream;

int psmxm_init(void);
int psmxm_close_endpoint(void);

psmxm_con_info_t *psmxm_con_create(void);
int psmxm_con_init(psmxm_con_info_t *con_info);

void psmxm_con_get_info_msg(psmxm_con_info_t *con_info,
			    psmxm_info_msg_t *info_msg);

int psmxm_con_connect(psmxm_con_info_t *con_info, psmxm_info_msg_t *info_msg, void *ctx);

void psmxm_con_cleanup(psmxm_con_info_t *con_info);
void psmxm_con_free(psmxm_con_info_t *con_info);


/* IO */

typedef struct psmxm_recv_req {
	struct list_head next;
	mxm_recv_req_t	mxm_rreq;
	char		data[PSMXM_MTU];
} psmxm_recv_req_t;


typedef struct psmxm_send_req {
	mxm_send_req_t		mxm_sreq;
	mxm_req_buffer_t	iov[2];
} psmxm_send_req_t;


int psmxm_send_done(psmxm_con_info_t *con_info);

int psmxm_sendv(psmxm_con_info_t *con_info, struct iovec *iov, int size);

/* Progress requests from previous sendv's. Return proceeded bytes or 0 */
unsigned psmxm_send_progress(psmxm_con_info_t *con_info);


psmxm_recv_req_t *psmxm_recv_peek(void);
void psmxm_recv_release(psmxm_recv_req_t *rreq);


/* Make progress in psmxm */
void psmxm_progress(void);

/* return context of the connection where the data comes from. This
 * is the ctx from psmxm_con_connect(). */
static inline
void *psmxm_recv_req_ctx(psmxm_recv_req_t *rreq) {
	return mxm_conn_ctx_get(rreq->mxm_rreq.completion.source);
}


static inline
size_t psmxm_recv_req_length(psmxm_recv_req_t *rreq) {
	return rreq->mxm_rreq.completion.sender_len;
}

#endif /* _PSMXM_H_ */
