/*
 * ParaStation
 *
 * Copyright (C) 2016 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _PSUCP_H_
#define _PSUCP_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>


typedef struct psucp_con_info psucp_con_info_t;
typedef struct hca_info hca_info_t;

// contact endpoint info
typedef struct psucp_info_msg_s {
	uint64_t	tag;
	uint32_t	small_msg_len; /**< max length for small messages (= size of "xheader" receive request) */
	uint16_t	ucp_addr_size;
	char		ucp_addr[0]; // ucp_addr_size bytes after this struct
} psucp_info_msg_t;


/* Initialise ucp. This must be called first. */
int psucp_init(void);


/*
 * Connection handling:
 *
 * Live cycle of a connection is:
 * ci = psucp_con_create(void);
 * psucp_con_init(ci, hca_info);
 * psucp_con_get_info_msg(ci, my_info);
 * write(peer, my_info);
 * read(peer, info), peer called psucp_con_get_info_msg() a transmit the result to us.
 * psucp_con_connect(ci, info); // both sides have to call connect
 * (psucp_sendv()/psucp_recvlook and done)*
 * psucp_con_cleanup(ci);
 * psucp_con_free(ci);
 */

/* Create a con_info. usable for psucp_con_init().
 * return NULL on error */
psucp_con_info_t *psucp_con_create(void);
void	psucp_con_free(psucp_con_info_t *con_info);


int	psucp_con_init(psucp_con_info_t *con_info, hca_info_t *hca_info, void *con_priv);
int	psucp_con_connect(psucp_con_info_t *con_info, psucp_info_msg_t *info_msg);
void	psucp_con_cleanup(psucp_con_info_t *con_info);

/* Caller has to call free() on result after usage. */
psucp_info_msg_t *
psucp_con_get_info_msg(psucp_con_info_t *con_info, unsigned long tag);

static inline
unsigned psucp_info_msg_length(psucp_info_msg_t *info_msg) {
	return (unsigned)sizeof(*info_msg) + info_msg->ucp_addr_size;
}


/* returnvalue like write(), except on error errno is negative return
 * send through con_info. (iov[0].iov_len + iov[1].iov_len > 0)
 * return number of bytes send or:
 * -EAGAIN if ci is busy or
 * -EPIPE in case of a broken connection.
 */
ssize_t psucp_sendv(psucp_con_info_t *con_info, struct iovec iov[2], void *req_priv);

/* Callback to be implemented by upper layer */
void pscom_psucp_sendv_done(void *req_priv);

/* Include ucp.h for psucp_msg_t */
#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>

typedef struct {
	ucp_tag_message_h	msg_tag;
	ucp_tag_recv_info_t	info_tag;
} psucp_msg_t;

// Probe for incoming message on any connection.
// In success: MUST call psucp_recv(msg) or psucp_irecv(msg) afterwards!
size_t psucp_probe(psucp_msg_t *msg);
ssize_t psucp_recv(psucp_msg_t *msg, void *buf, size_t size);

/* Flush the notification queue and make progress. */
int psucp_progress(void);

/* Suggest a value for psucp_pending_tokens. Result depends on psucp_recvq_size. */
unsigned psucp_pending_tokens_suggestion(void);


ssize_t psucp_irecv(psucp_con_info_t *con_info, psucp_msg_t *msg, void *buf, size_t size);
/* Callback to be implemented by upper layer */
void pscom_psucp_read_done(void *con_priv, void *req_priv);

/*
 * Configuration
 */
extern int psucp_debug;
extern FILE *psucp_debug_stream; /* Stream to use for debug output */
extern unsigned psucp_small_msg_len;
extern unsigned int psucp_sendq_size; /* sendqueue size. Used when psucp_global_sendq == 0 */
extern unsigned int psucp_gsendq_size; /* Global sendqueue size. Used when psucp_global_sendq == 1 */
extern unsigned int psucp_recvq_size;
extern unsigned int psucp_pending_tokens;
extern int psucp_global_sendq; /* bool. Use one sendqueue for all connections? */
extern int psucp_event_count; /* bool. Be busy if outstanding_cq_entries is to high? */

/*
 * Information
 */
extern unsigned psucp_pending_global_sends; /* counter. Used only with psucp_global_sendq == 1 */

#endif /* _PSUCP_H_ */
