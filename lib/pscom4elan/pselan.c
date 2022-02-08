/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pselan.c: ELAN communication
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_util.h"
#include "pscom_env.h"
#include "pselan.h"

/* Size of the send and receive queue */
#define SIZE_SR_QUEUE	16

#define MAX_PENDING_TOKS (SIZE_SR_QUEUE - 6)

/* Used buffersize */
#define ELAN_BUFSIZE_PAYLOAD	(16*1024) /* must be < 65536, or change sizeof pselan_msgheader_t.payload */

#define PSELAN_MAGIC_UNUSED	0
#define PSELAN_MAGIC_IO		1


#define PSELAN_LEN(len) ((len + 7) & ~7)
//#define PSELAN_DATA_OFFSET(pos, pselanlen) ((pos) * ELAN_BUFSIZE + ELAN_BUFSIZE_PAYLOAD - (pselanlen))

int pselan_debug = 2;


typedef struct {
	uint16_t	token;
	uint16_t	payload;
	volatile uint32_t	magic;
} pselan_msgheader_t;


typedef struct {
	char __data[ELAN_BUFSIZE_PAYLOAD];
	char data[0];
	pselan_msgheader_t tail;
} pselan_msg_t;


struct pselan_con_info {
	pselan_msg_t	*remote_r_buf;
	u_int		remote_destvp;

	ELAN_EVENT	*event;

	unsigned	send_pos;
	unsigned	recv_pos;

	pselan_msg_t	send_bufs[SIZE_SR_QUEUE];
	pselan_msg_t	recv_bufs[SIZE_SR_QUEUE];

	/* higher level */
	int		n_send_toks;
	int		n_recv_toks;
	int		n_tosend_toks;
	int		con_broken;

#define PSELAN_CON_INFO_MAGIC 0x6a156e73
	unsigned int	magic;
};


#define pselan_dprint(level,fmt,arg... ) do {			\
	if ((level) <= pselan_debug) {				\
		fprintf(stderr, "<pselan:"fmt">\n",##arg);	\
		fflush(stderr);					\
	}							\
}while(0);


#define pselan_dprint_errno(level,_errno,fmt,arg... ) do {		\
	if ((level) <= pselan_debug) {					\
		pselan_dprint(level, fmt " : %s",##arg,			\
			      strerror(_errno));			\
	}								\
}while(0);


ELAN_STATE *pselan_base_state = NULL;
ELAN_BASE *pselan_base = NULL;


//#include "pselan_rdma.c"



u_int pselan_get_myvp(void)
{
	return pselan_base_state->vp;
}


void *pselan_get_r_ptr(pselan_con_info_t *ci)
{
	return ci->recv_bufs;
}


static
void pselan_init_buffers_local(pselan_con_info_t *ci)
{
	int i;

	ci->send_pos = 0;
	ci->recv_pos = 0;

	/* Clear all receive magics */
	for (i = 0; i < SIZE_SR_QUEUE; i++) {
		pselan_msg_t *msg = ci->recv_bufs + i;
		msg->tail.magic = PSELAN_MAGIC_UNUSED;
	}
}


/* Connect remote con */
void pselan_connect(pselan_con_info_t *ci, u_int destvp, void *remote_r_ptr)
{
	ci->remote_destvp = destvp;
	ci->remote_r_buf = remote_r_ptr;
}


static
void pselan_queue_event(pselan_con_info_t *ci, ELAN_EVENT *event)
{
	if (ci->event) {
		ci->event = elan_link(ci->event, event);
	} else {
		ci->event = event;
	}
}


static
void pselan_flush_event(pselan_con_info_t *ci)
{
	// Flush events:
	if (ci->event && elan_poll(ci->event, 0)) {
		ci->event = NULL;
	}
}


static inline
void pselan_flush_sendbuf(pselan_con_info_t *ci,
			  char *lmem /* ci->send_bufs.lmr_mem */,
			  char *rmem, unsigned size)
{
	ELAN_EVENT *event;

	event = elan_put(pselan_base_state,
			 lmem,
			 rmem,
			 size, ci->remote_destvp);

	pselan_queue_event(ci, event);
}


void pselan_con_destroy(pselan_con_info_t *ci)
{
	assert(ci->magic == PSELAN_CON_INFO_MAGIC);

	pselan_flush_event(ci);

	ci->con_broken = 1;

	ci->magic = 0;
	free(ci);
}


/* Create a con_info usable for pselan_connect().
 * return NULL on error */
pselan_con_info_t *pselan_con_create(void)
{
	pselan_con_info_t *ci = calloc(sizeof(*ci), 1);
	if (!ci) return NULL;

	ci->magic = PSELAN_CON_INFO_MAGIC;

	ci->event = NULL;

	pselan_init_buffers_local(ci);

	ci->n_send_toks = SIZE_SR_QUEUE;
	ci->n_recv_toks = 0;
	ci->n_tosend_toks = 0;

	ci->con_broken = 0;

	return ci;
}


static
void pselan_get_fresh_tokens(pselan_con_info_t *ci);


/* returnvalue like write(), except on error errno is negative return */
static
int _pselan_sendv(pselan_con_info_t *ci, struct iovec *iov, int size, unsigned int magic)
{
	int len;
	int pselanlen;
	pselan_msg_t *msg;

	if (ci->con_broken) goto err_broken;

	/* Its allowed to send, if
	   At least 2 tokens left or (1 token left AND n_tosend > 0)
	*/

	if ((ci->n_send_toks < 2) &&
	    ((ci->n_send_toks < 1) || (ci->n_tosend_toks == 0))) goto err_busy;

	len = (size <= (int)ELAN_BUFSIZE_PAYLOAD) ? size : (int)ELAN_BUFSIZE_PAYLOAD;
	pselanlen = PSELAN_LEN(len);

	msg = ci->send_bufs + ci->send_pos;

	msg->tail.token = ci->n_tosend_toks;
	msg->tail.payload = len;
	msg->tail.magic = magic;

	char *buf = msg->data - pselanlen;

	/* copy to registerd send buffer */
	pscom_memcpy_from_iov(buf, iov, len);

	pselan_flush_sendbuf(ci, buf,
			     ci->remote_r_buf[ci->send_pos].data - pselanlen,
			     pselanlen + sizeof(pselan_msgheader_t));

	pscom_forward_iov(iov, len);

	ci->n_tosend_toks = 0;
	ci->send_pos = (ci->send_pos + 1) % SIZE_SR_QUEUE;
	ci->n_send_toks--;

	pselan_flush_event(ci);

	return len;
err_busy:
	pselan_get_fresh_tokens(ci);
	pselan_flush_event(ci);

	return -EAGAIN;
err_broken:
	return -EPIPE;
}


int pselan_sendv(pselan_con_info_t *ci, struct iovec *iov, int size)
{
	return _pselan_sendv(ci, iov, size, PSELAN_MAGIC_IO);
}


void pselan_recvdone(pselan_con_info_t *ci)
{
	ci->n_tosend_toks++;
	ci->n_recv_toks--;
	ci->recv_pos = (ci->recv_pos + 1) % SIZE_SR_QUEUE;

	if (ci->n_tosend_toks >= MAX_PENDING_TOKS) {
		//while (pselan_sendv(con_info, NULL, 0) == -EAGAIN);
		pselan_sendv(ci, NULL, 0);
	}
}


/* returnvalue like read() , except on error errno is negative return */
int pselan_recvlook(pselan_con_info_t *ci, void **buf)
{
	// assert(con_info->n_recv_toks == 0) as long as we only poll!
	while (1) {
		pselan_msg_t *msg = ci->recv_bufs + ci->recv_pos;

		unsigned int magic = msg->tail.magic;
		if (!magic) { // Nothing received
			pselan_flush_event(ci);

			return (ci->con_broken) ? -EPIPE : -EAGAIN;
		}

		msg->tail.magic = PSELAN_MAGIC_UNUSED;

		/* Fresh tokens ? */
		ci->n_send_toks += msg->tail.token;
		ci->n_recv_toks++;

		unsigned len = msg->tail.payload;
		unsigned pselanlen = PSELAN_LEN(len);

		*buf = ci->recv_bufs[ci->recv_pos].data - pselanlen;
		if (len) {
			// receive data
			return len;
		}

		/* skip 0 payload packages (probably fresh tokens) */
		pselan_recvdone(ci);
	}
}


static
void pselan_get_fresh_tokens(pselan_con_info_t *ci)
{
	pselan_msg_t *msg = ci->recv_bufs + ci->recv_pos;
	unsigned int magic = msg->tail.magic;

	if ((magic == PSELAN_MAGIC_IO) &&
	    (msg->tail.payload == 0)) {
		// Fresh tokens
		msg->tail.magic = PSELAN_MAGIC_UNUSED;
		ci->n_send_toks += msg->tail.token;
		ci->n_recv_toks++;

		pselan_recvdone(ci);
	}
}


void pselan_init(void)
{
	if (pselan_base) return;

	pselan_dprint(3, "call elan_baseInit(0)");
	pselan_base = elan_baseInit(0);
	pselan_base_state = pselan_base->state;
}
