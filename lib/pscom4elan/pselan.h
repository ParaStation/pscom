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
 * pselan.c: ELAN communication
 */

#ifndef _PSELAN_H_
#define _PSELAN_H_

#include <stdint.h>
#include <sys/uio.h>
#include "elan/elan.h"

typedef struct pselan_con_info pselan_con_info_t;


/* Initialise libelan. This must be called first. */
void pselan_init(void);


/* Create a con_info usable for pselan_connect().
 * return NULL on error */
pselan_con_info_t *pselan_con_create(void);


u_int pselan_get_myvp(void);
void *pselan_get_r_ptr(pselan_con_info_t *ci);


/* Connect remote con */
void pselan_connect(pselan_con_info_t *ci, u_int destvp, void *remote_r_ptr);


/* Close connection ci and free resources */
void pselan_con_destroy(pselan_con_info_t *ci);


/* send size bytes from iov through ci. (size > 0)
 * return number of bytes send or:
 * -EAGAIN if ci is busy or
 * -EPIPE in case of a broken connection.
 */
int pselan_sendv(pselan_con_info_t *ci, struct iovec *iov, int size);


/* Start receiving.
 * return:
 * number of bytes received or
 * -EAGAIN nothing received or
 * -EPIPE broken connction.
 * (call pselan_recvdone after usage of *buf!)
 */
int pselan_recvlook(pselan_con_info_t *ci, void **buf);

/* End receiving. */
void pselan_recvdone(pselan_con_info_t *ci);

extern int pselan_debug;

#if 0
/*
 * RDMA calls
 */

typedef struct pselan_mregion_cache pselan_mregion_cache_t;

typedef struct pselan_rdma_req pselan_rdma_req_t;
struct pselan_rdma_req {
	pselan_con_info_t *ci;
	DAT_RMR_CONTEXT rmr_context;
	DAT_VADDR	rmr_vaddr;
	char		*lmr_buf;
	size_t		size;

	pselan_mregion_cache_t *mreg; /* set by pselan_post_rma_put() */

	void		(*io_done)(pselan_rdma_req_t *req);
	void		*priv;
};


/* get lmr and rmr Handles from mem region buf:size. from cache.
 * call pselan_put_mregion() after usage!
 * return NULL on error. */
pselan_mregion_cache_t *
pselan_get_mregion(void *buf, size_t size, pselan_con_info_t *ci);

void pselan_put_mregion(pselan_mregion_cache_t *mreg);

/* return -1 on error */
int pselan_post_rdma_put(pselan_rdma_req_t *req);

/* return -1 on error */
int pselan_post_rdma_get(pselan_rdma_req_t *req);


static inline
DAT_VADDR pselan_mem2vaddr(char *mem)
{
	return (DAT_VADDR)(long)mem;
}


static inline
DAT_VADDR pselan_get_rmr_vaddr(void *buf)
{
	return pselan_mem2vaddr(buf);
}


DAT_RMR_CONTEXT pselan_get_rmr_context(pselan_mregion_cache_t *mreg);

#endif

#endif /* _PSELAN_H_ */
