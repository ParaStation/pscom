/*
 * ParaStation
 *
 * Copyright (C) 2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psextoll.c: EXTOLL communication
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
#include "psextoll.h"

/* Size of the send, receive and completion queue */
#define _SIZE_SEND_QUEUE 16
#define _SIZE_RECV_QUEUE 16


/* Used buffersize */
#define PSEX_RMA2_MTU		(4*1024)
#define PSEX_RMA2_PAYLOAD	(PSEX_RMA2_MTU - sizeof(psex_msgheader_t)) /* must be < 65536, or change sizeof psex_msgheader_t.payload */

typedef struct {
	void *ptr;
	RMA2_Region	*mr;
} mem_info_t;


typedef struct {
	mem_info_t	bufs;
	unsigned	pos;	/* current position */
} ringbuf_t;


struct hca_info {
	RMA2_Port	port;	/* extoll port from rma_open(&port) */

	/* send */
	ringbuf_t	send;	/* global send queue */

	RMA2_Nodeid	nodeid;	/* local nodeid */
	RMA2_VPID	vpid;	/* local vpid */
};



/* Extoll specific information about one connection */
struct psex_con_info {
	RMA2_Port	port;	/* extoll port from rma2_open(&port) (copied from hca_info) */
	RMA2_Handle	handle; /* Connection handle from rma2_connect(..&handle); */

	/* low level */
	hca_info_t	*hca_info;

	/* send */
	unsigned int	remote_recv_pos; /* next to use receive buffer (= remote recv_pos) */

	RMA2_NLA		remote_rbuf_nla; /* from remote rma2_get_nla(con->recv.bufs.mr, 0, &remote_rbuf) */

	ringbuf_t	send;

	/* recv */
	ringbuf_t	recv;

	/* higher level */
	unsigned int n_send_toks;
	unsigned int n_recv_toks;
	unsigned int n_tosend_toks;

	int con_broken;
};


typedef struct {
	uint16_t		token;
	uint16_t		payload;
	volatile uint32_t	magic;
} psex_msgheader_t;


#define PSEX_MAGIC_UNUSED	0
#define PSEX_MAGIC_IO		1
#define PSEX_MAGIC_EOF		2


typedef struct {
    char __data[PSEX_RMA2_PAYLOAD];
    psex_msgheader_t tail;
} psex_msg_t;


// PSEXTOLL_LEN(len) + sizeof(header) must be a multiple of 64 bytes (cacheline)
#define PSEX_LEN(len) (((len) + sizeof(psex_msgheader_t) + 63) & ~63)
#define PSEX_DATA(buf, psexlen) ((buf) + sizeof(psex_msg_t) - (psexlen))


/*
 * static variables
 */

static hca_info_t  default_hca;
unsigned psex_pending_global_sends = 0; /* counting pending sends from global send ring */

char *psex_err_str = NULL; /* last error string */

int psex_debug = 2;
FILE *psex_debug_stream = NULL;

unsigned int psex_sendq_size = _SIZE_SEND_QUEUE;
unsigned int psex_recvq_size = _SIZE_RECV_QUEUE;
unsigned int psex_pending_tokens = _SIZE_RECV_QUEUE - 6;

int psex_global_sendq = 0;	/* bool. Use one sendqueue for all connections? */
int psex_event_count = 0;	/* bool. Be busy if psex_pending_global_sends is to high? */

struct psex_stat_s {
	unsigned busy_notokens;		// connection out of tokens for sending
	unsigned busy_global_cq;	// global completion queue busy.
	unsigned post_send_eagain;	// ibv_post_send() returned EAGAIN.
	unsigned post_send_error;	// ibv_port_send() returned with an error != EAGAIN.
	unsigned busy_token_refresh;	// sending tokens with nop message failed.
} psex_stat;


#define psex_dprint(level,fmt,arg... )					\
	do {								\
		if ((level) <= psex_debug) {				\
			fprintf(psex_debug_stream ? psex_debug_stream : stderr,	\
				"extoll:" fmt "\n",##arg);			\
		}							\
	} while(0);


static
void psex_err(char *str)
{
	if (psex_err_str) free(psex_err_str);

	psex_err_str = str ? strdup(str) : strdup("");
	return;
}


static
void psex_err_errno(char *str, int err_no)
{
	const char *err_str = strerror(err_no);
	int len = strlen(str) + strlen(err_str) + 10;
	char *msg = malloc(len);

	assert(msg);

	strcpy(msg, str);
	strcat(msg, " : ");
	strcat(msg, err_str);

	psex_err(msg);
	free(msg);
}


static
void psex_err_rma2_error(char *str, int rc)
{
	char rma2_err_str[100];
	int len;
	char *msg;

	rma2_serror(rc, rma2_err_str, sizeof(rma2_err_str));

	len = strlen(str) + strlen(rma2_err_str) + 10;
	msg = malloc(len);

	assert(msg);

	strcpy(msg, str);
	strcat(msg, " : ");
	strcat(msg, rma2_err_str);

	psex_err(msg);
	free(msg);
}


unsigned psex_pending_tokens_suggestion(void)
{
	unsigned res = 0;
	switch (psex_recvq_size) {
	default: return psex_recvq_size - 6;
	case 11:
	case 10: return 5;
	case 9:
	case 8: return 4;
	case 7:
	case 6: return 3;
	case 5:
	case 4:
	case 3:
	case 2: return 2;
	case 1:
	case 0: return 0;
	}
	return res;
}


static
void psex_rma2_free(hca_info_t *hca_info, mem_info_t *mem_info)
{
	rma2_unregister(hca_info->port, mem_info->mr);
	mem_info->mr = NULL;
	free(mem_info->ptr);
	mem_info->ptr = NULL;
}


static
void print_mlock_help(unsigned size)
{
	static int called = 0;
	struct rlimit rlim;

	if (called) return;
	called = 1;

	psex_dprint(0, "EXTOLL: rma2_register(%u) failed.", size);
	psex_dprint(0, "(Check memlock limit in /etc/security/limits.conf or try 'ulimit -l')");

	if (!getrlimit(RLIMIT_MEMLOCK, &rlim)) {
		psex_dprint(0, "Current RLIMIT_MEMLOCK: soft=%lu byte, hard=%lu byte", rlim.rlim_cur, rlim.rlim_max);
	}
}


static
int psex_rma2_alloc(hca_info_t *hca_info, int size, mem_info_t *mem_info)
{
	int rc;

	mem_info->mr = NULL;

	/* Region for buffers */
	mem_info->ptr = valloc(size);
	if (!mem_info->ptr) goto err_malloc;

	rc = rma2_register(hca_info->port, mem_info->ptr, size, &mem_info->mr);
	if (!mem_info->mr) goto err_reg_mr;

	return 0;
	/* --- */
err_reg_mr:
	free(mem_info->ptr);
	mem_info->ptr = NULL;
	psex_err_rma2_error("rma2_register()", rc);
	/*if (rc == RMA2_ERR_NO_MEM)*/ print_mlock_help(size);
	return -1;
err_malloc:
	psex_err_errno("malloc()", errno);
	return -1;
}


void psex_con_cleanup(psex_con_info_t *con_info)
{
	hca_info_t *hca_info = con_info->hca_info;

	if (con_info->send.bufs.mr) {
		usleep(20000); // Workaround: Wait for the completion of all rma2_post_put_bt()'s // ToDo: remove me!

		psex_rma2_free(hca_info, &con_info->send.bufs);
		con_info->send.bufs.mr = 0;
	}
	if (con_info->recv.bufs.mr) {
		psex_rma2_free(hca_info, &con_info->recv.bufs);
		con_info->recv.bufs.mr = 0;
	}
	if (con_info->handle) {
		rma2_disconnect(hca_info->port, con_info->handle);
		con_info->handle = NULL;
	}
}


int psex_con_init(psex_con_info_t *con_info, hca_info_t *hca_info)
{
	unsigned int i;

	if (!hca_info) hca_info = &default_hca;

	con_info->hca_info = hca_info;

	con_info->send.bufs.mr = NULL;
	con_info->recv.bufs.mr = NULL;
	con_info->con_broken = 0;

	/*
	 *  Memory for send and receive bufs
	 */

	if (!psex_global_sendq) {
		if (psex_rma2_alloc(hca_info, PSEX_RMA2_MTU * psex_sendq_size,
				   &con_info->send.bufs))
			goto err_alloc;
	}
	con_info->send.pos = 0;

	if (psex_rma2_alloc(hca_info, PSEX_RMA2_MTU * psex_recvq_size,
			    &con_info->recv.bufs))
		goto err_alloc;

	/* Clear all receive magics */
	for (i = 0; i < psex_recvq_size; i++) {
		psex_msg_t *msg = ((psex_msg_t *)con_info->recv.bufs.ptr) + i;
		msg->tail.magic = PSEX_MAGIC_UNUSED;
	}

	con_info->remote_recv_pos = 0;
	con_info->recv.pos = 0;

	// Initialize receive tokens
	con_info->n_recv_toks = 0;
	con_info->n_tosend_toks = 0;

	// Initialize send tokens
	con_info->n_send_toks = psex_recvq_size; // #tokens = length of _receive_ queue!

	return 0;
	/* --- */
err_alloc:
	psex_con_cleanup(con_info);
	psex_dprint(1, "psex_con_init() : %s", psex_err_str);
	return -1;
}


int psex_con_connect(psex_con_info_t *con_info, psex_info_msg_t *info_msg)
{
	hca_info_t *hca_info = con_info->hca_info;
	int rc;

	con_info->port = hca_info->port; // Copy port for faster access.

	con_info->remote_rbuf_nla = info_msg->rbuf_nla;


	rc = rma2_connect(con_info->port, info_msg->nodeid,
			  info_msg->vpid, RMA2_CONN_DEFAULT, &con_info->handle);
	if (rc) goto err_connect;

	return 0;
	/* --- */
err_connect:
	psex_err_rma2_error("rma2_connect()", rc);
	psex_dprint(1, "psex_con_connect() : %s", psex_err_str);
	return -1;
}


static
void psex_cleanup_hca(hca_info_t *hca_info)
{
	if (hca_info->send.bufs.mr) {
		usleep(20000); // Workaround: Wait for the completion of all rma2_post_put_bt()'s // ToDo: remove me!

		psex_rma2_free(hca_info, &hca_info->send.bufs);
		hca_info->send.bufs.mr = 0;
	}
	if (hca_info->port) {
		rma2_close(hca_info->port);
		hca_info->port = NULL;
	}
}


static
int psex_init_hca(hca_info_t *hca_info)
{
	int rc;

	hca_info->send.bufs.mr = NULL;

	if (psex_pending_tokens > psex_recvq_size) {
		psex_dprint(1, "warning: reset psex_pending_tokens from %u to %u\n",
			    psex_pending_tokens, psex_recvq_size);
		psex_pending_tokens = psex_recvq_size;
	}

	rc = rma2_open(&hca_info->port);
	if (rc != RMA2_SUCCESS) {
		psex_err_rma2_error("rma2_open()", rc);
		goto err_hca;
	}


	if (psex_global_sendq) {
		if (psex_rma2_alloc(hca_info, PSEX_RMA2_MTU * psex_sendq_size, &hca_info->send.bufs))
			goto err_alloc;
		hca_info->send.pos = 0;
	}

	hca_info->nodeid = rma2_get_nodeid(hca_info->port);
	hca_info->vpid = rma2_get_vpid(hca_info->port);

	return 0;
	/* --- */
err_alloc:
	psex_cleanup_hca(hca_info);
err_hca:
	return -1;
}


int psex_init(void)
{
	static int init_state = 1;
	assert(sizeof(psex_msg_t) == 4096);
	if (init_state == 1) {
		memset(&psex_stat, 0, sizeof(psex_stat));

		if (psex_init_hca(&default_hca)) goto err_hca;

		init_state = 0;
	}

	return init_state; /* 0 = success, -1 = error */
	/* --- */
err_hca:
	init_state = -1;
	psex_dprint(1, "EXTOLL disabled : %s", psex_err_str);
	return -1;
}


/* returnvalue like write(), except on error errno is negative return */
static
int _psex_sendv(psex_con_info_t *con_info, struct iovec *iov, int size, unsigned int magic)
{
	int len;
	int psex_len;
	psex_msg_t *_msg;
	int rc;
	psex_msgheader_t *tail;
	hca_info_t *hca_info = con_info->hca_info;

	if (con_info->con_broken) goto err_broken;

	/* Its allowed to send, if
	   At least 2 tokens left or (1 token left AND n_tosend > 0)
	*/

	if ((con_info->n_send_toks < 2) &&
	    ((con_info->n_send_toks < 1) || (con_info->n_tosend_toks == 0))) {
		psex_stat.busy_notokens++;
		goto err_busy;
	}

	if (psex_global_sendq && psex_pending_global_sends >= psex_sendq_size && psex_event_count) {
		// printf("Busy global\n"); usleep(10*1000);
		psex_stat.busy_global_cq++;
		goto err_busy;
	}

	len = (size <= (int)PSEX_RMA2_PAYLOAD) ? size : (int)PSEX_RMA2_PAYLOAD;
	psex_len = PSEX_LEN(len);

	ringbuf_t *send = (con_info->send.bufs.mr) ? &con_info->send : &hca_info->send;
	_msg = ((psex_msg_t *)send->bufs.ptr) + send->pos;

	tail = (psex_msgheader_t *)((char*)_msg + psex_len - sizeof(psex_msgheader_t));

	tail->token = con_info->n_tosend_toks;
	tail->payload = len;
	tail->magic = magic;

	/* copy to registerd send buffer */
	pscom_memcpy_from_iov((void *)_msg, iov, len);
	rc = rma2_post_put_bt(con_info->port, con_info->handle, send->bufs.mr,
			     ((char*)_msg - (char *)send->bufs.ptr), psex_len,
			     PSEX_DATA(con_info->remote_rbuf_nla +
				       con_info->remote_recv_pos * sizeof(psex_msg_t), psex_len),
			      0, 0);
	if (rc != 0) goto err_rma2_post_cl;

	psex_pending_global_sends++; // ToDo: Decrease the counter somewhere!

	pscom_forward_iov(iov, len);

	con_info->n_tosend_toks = 0;
	con_info->remote_recv_pos = (con_info->remote_recv_pos + 1) % psex_recvq_size;
	send->pos = (send->pos + 1) % psex_sendq_size;
	con_info->n_send_toks--;

	return len;
	/* --- */
err_busy:
	return -EAGAIN;
	/* --- */
err_rma2_post_cl:
    if (0 /*rc == ???EAGAIN  Too many posted work requests ? */) {
	psex_stat.post_send_eagain++;
	return -EAGAIN;
    } else {
	psex_stat.post_send_error++;
	psex_err_rma2_error("rma2_post_put_cl()", rc);
	con_info->con_broken = 1;
	return -EPIPE;
    }
    /* --- */
 err_broken:
    return -EPIPE;
}


int psex_sendv(psex_con_info_t *con_info, struct iovec *iov, int size)
{
	return _psex_sendv(con_info, iov, size, PSEX_MAGIC_IO);
}


void psex_send_eof(psex_con_info_t *con_info)
{
	_psex_sendv(con_info, NULL, 0, PSEX_MAGIC_EOF);
	con_info->con_broken = 1; // Do not send more
}


static
void _psex_send_tokens(psex_con_info_t *con_info)
{
	if (con_info->n_tosend_toks >= psex_pending_tokens) {
		if (psex_sendv(con_info, NULL, 0) == -EAGAIN) {
			psex_stat.busy_token_refresh++;
		}
	}
}


void psex_recvdone(psex_con_info_t *con_info)
{
	con_info->n_tosend_toks++;
	con_info->n_recv_toks--;
	con_info->recv.pos = (con_info->recv.pos + 1) % psex_recvq_size;

	// if send_tokens() fail, we will retry it in psex_recvlook.
	_psex_send_tokens(con_info);
}


/* returnvalue like read() , except on error errno is negative return */
int psex_recvlook(psex_con_info_t *con_info, void **buf)
{
#if 1 // Simpler loop because:
	// assert(con_info->n_recv_toks == 0) as long as we only poll!
	while (1) {
		psex_msg_t *msg =
			((psex_msg_t *)con_info->recv.bufs.ptr) + con_info->recv.pos;

		unsigned int magic = msg->tail.magic;

		if (!magic) { // Nothing received
			*buf = NULL;
			// Maybe we have to send tokens before we can receive more:
			_psex_send_tokens(con_info);
			return (con_info->con_broken) ? -EPIPE : -EAGAIN;
		}

		msg->tail.magic = PSEX_MAGIC_UNUSED;

		/* Fresh tokens ? */
		con_info->n_send_toks += msg->tail.token;
		con_info->n_recv_toks++;

		unsigned int len = msg->tail.payload;

		*buf = PSEX_DATA((char*)msg, PSEX_LEN(len));
		if (len || (magic == PSEX_MAGIC_EOF)) {
			// receive data or EOF
			return len;
		}

		/* skip 0 payload packages (probably fresh tokens) */
		psex_recvdone(con_info);
	}
#else
	unsigned int magic;
	/* Check for new packages */
	{
		psex_con_info_t *con = con_info;
		psex_msg_t *msg = ((psex_msg_t *)con->recv_bufs.ptr) +
			((con->recv_pos + con->n_recv_toks) % SIZE_SR_QUEUE);
		magic = msg->tail.magic;

		if (magic) {
//			printf("receive magic %08x\n", msg->tail.magic);
			msg->tail.magic = PSEX_MAGIC_UNUSED;

			/* Fresh tokens ? */
			con->n_send_toks += msg->tail.token;
			con->n_recv_toks++;
		}
	}

	while (con_info->n_recv_toks > 0) {
		psex_msg_t *msg = ((psex_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;
		int len = msg->tail.payload;

		*buf = PSEX_DATA(msg, PSEX_LEN(len));
		if (len || (magic == PSEX_MAGIC_EOF)) {
			// ToDo: This could be the wrong magic!!!
			return len;
		}
		/* skip 0 payload packages */
		psex_recvdone(con_info);
	}

	if (con_info->con_broken) {
		return -EPIPE;
	} else {
		// Maybe we have to send tokens before we ca receive more:
		_psex_send_tokens(con_info);
		return -EAGAIN;
	}
#endif
}


psex_con_info_t *psex_con_create(void)
{
	psex_con_info_t *con_info = malloc(sizeof(*con_info));
	return con_info;
}


void psex_con_free(psex_con_info_t *con_info)
{
	free(con_info);
}


void psex_con_get_info_msg(psex_con_info_t *con_info /* in */, psex_info_msg_t *info_msg /* out */)
{
	int rc;
	hca_info_t *hca_info = con_info->hca_info;

	info_msg->nodeid	= hca_info->nodeid;
	info_msg->vpid		= hca_info->vpid;
	rc = rma2_get_nla(con_info->recv.bufs.mr, 0, &info_msg->rbuf_nla);
	assert(rc == RMA2_SUCCESS);
}
