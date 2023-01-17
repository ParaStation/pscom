/*
 * ParaStation
 *
 * Copyright (C) 2014-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "psmxm.h"
#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int psmxm_debug = 2;
FILE *psmxm_debug_stream = NULL;
unsigned psmxm_devcheck = 1;

static char *psmxm_err_str = NULL; /* last error string */

#define MXM_TAG_ANY (31)
#define MXM_TAG_FIRST_CON  (MXM_TAG_ANY + 1)

#define PSMXM_RECV_BUFFER_COUNT (1024)

/*
 * Use one global mxm endpoint per process:
 * mxm_h, mxm_ep_h and mxm_mq_h
 */

typedef struct mxm_socket{
	mxm_h		mxm_mxmh;
	mxm_ep_h        mxm_ep;
	mxm_mq_h	mxm_mq;
	char		mxm_ep_addr[MXM_EP_ADDR_LEN];
	struct list_head recvq; /* list of posted recv requests : psmxm_recv_req_t.next */

	psmxm_recv_req_t rreqs[PSMXM_RECV_BUFFER_COUNT];
} mxm_socket_t;


struct psmxm_con_info {
	mxm_conn_h      mxm_conn;
	int		con_broken;
	unsigned	sending; // Send sending bytes in progress. 0 = not sending

	uint64_t	send_tag; // Used for direct sends (= recv_tag of the remote peer)
	uint64_t	recv_tag; // local identification tag for this connection

	psmxm_send_req_t	sreq; // One prepared send request

	char		mxm_remote_ep_addr[MXM_EP_ADDR_LEN];
};


static
mxm_socket_t mxm_socket;

/*
 * Parameters
 */
struct {
	int flag_no_optimization : 1; // if true: Don't configure MXM for maximal performance, be more portable.
} psmxm_params = {
	.flag_no_optimization = 0,
};


#define psmxm_dprint(level,fmt,arg... )					\
	do {								\
		if ((level) <= psmxm_debug) {				\
			fprintf(psmxm_debug_stream ? psmxm_debug_stream : stderr,	\
				"mxm:" fmt "\n",##arg);			\
		}							\
	} while(0);


static
void psmxm_err(const char *str)
{
	if (psmxm_err_str) free(psmxm_err_str);

	if (str) {
		psmxm_err_str = strdup(str);
	} else {
		psmxm_err_str = strdup("");
	}
	return;
}

static
void psmxm_msg_err(const char *msg, mxm_error_t err)
{
	char buf[400];
	snprintf(buf, sizeof(buf), "%s : %s", msg, mxm_error_string(err));
	psmxm_err(buf);
}


void psmxm_con_get_info_msg(psmxm_con_info_t *con_info,
			    psmxm_info_msg_t *info_msg)
{
	info_msg->psmxm_protocol_version = PSMXM_PROTOCOL_VERSION;
	info_msg->tag = con_info->recv_tag;

	memcpy(info_msg->mxm_ep_addr, mxm_socket.mxm_ep_addr,
	       sizeof(info_msg->mxm_ep_addr));
}


/* return 0 if the mxm device is there, -1 else. */
static
int psmxm_check_dev(void)
{
	struct stat s;
	const char **df;
	const char *devfiles[] = {
		"/sys/class/infiniband/mlx5_0", "/sys/class/infiniband/mlx5_1", "/sys/class/infiniband/mlx5_2",
		NULL
	};
	if (!psmxm_devcheck) return 0;

	for (df = devfiles; *df; df++) {
		if (!stat(*df, &s)) {
			return 0;
		}
	}

	return -1;
}


static
void psmxm_init_req_buffer(mxm_req_base_t *req, mxm_socket_t *mxm_socket, mxm_conn_h mxm_conn,
			   void *data, unsigned data_len)
{
	/* Initialize request fields */
	req->state        = MXM_REQ_NEW;
	req->mq           = mxm_socket->mxm_mq;
	req->conn         = mxm_conn; // might be NULL for ANY_SOURCE
	req->completed_cb = NULL;
	req->data_type    = MXM_REQ_DATA_BUFFER; /* or for pscom use MXM_REQ_DATA_IOV */
	req->error        = MXM_OK;
	req->data.buffer.ptr    = data;
	req->data.buffer.length = data_len;
}


static
void psmxm_init_req_iov(mxm_req_base_t *req, mxm_socket_t *mxm_socket, mxm_conn_h mxm_conn,
			mxm_req_buffer_t *data_iov, unsigned data_iov_count)
{
	/* Initialize request fields */
	req->state        = MXM_REQ_NEW;
	req->mq           = mxm_socket->mxm_mq;
	req->conn         = mxm_conn; // might be NULL for ANY_SOURCE
	req->completed_cb = NULL;
	req->data_type    = MXM_REQ_DATA_IOV; /* no iov[2]? Use: MXM_REQ_DATA_BUFFER */
	req->error        = MXM_OK;
	req->data.iov.count = data_iov_count;
	req->data.iov.vector = data_iov;
}


static
void psmxm_init_mxm_recv_req(mxm_recv_req_t *rreq, mxm_socket_t *mxm_socket, mxm_conn_h mxm_conn,
			     void *data, unsigned data_len)
{
	psmxm_init_req_buffer(&rreq->base, mxm_socket, mxm_conn, data, data_len);
	rreq->tag      = MXM_TAG_ANY;
	rreq->tag_mask = -1;
}


static
void psmxm_init_mxm_send_req(mxm_send_req_t *sreq, mxm_socket_t *mxm_socket, mxm_conn_h mxm_conn,
			     mxm_req_buffer_t *data_iov, unsigned data_iov_count)
{
	psmxm_init_req_iov(&sreq->base, mxm_socket, mxm_conn, data_iov, data_iov_count);
	sreq->flags   = 0;

	// sreq->flags |= MXM_REQ_SEND_FLAG_BLOCKING;
	// sreq->flags |= MXM_REQ_SEND_FLAG_LAZY;

	sreq->opcode = MXM_REQ_OP_SEND; // MXM_REQ_OP_SEND_SYNC
	sreq->op.send.tag = MXM_TAG_ANY;
}


static
void psmxm_init_recv_req(psmxm_recv_req_t *rreq, mxm_socket_t *mxm_socket)
{
	psmxm_init_mxm_recv_req(&rreq->mxm_rreq, mxm_socket, NULL,
				rreq->data, PSMXM_MTU);
}


static
void psmxm_init_send_req(psmxm_send_req_t *sreq, mxm_socket_t *mxm_socket, psmxm_con_info_t *con_info)
{
	psmxm_init_mxm_send_req(&sreq->mxm_sreq, mxm_socket, con_info->mxm_conn, sreq->iov, 2);
}


static
void psmxm_recv_req_post(psmxm_recv_req_t *rreq)
{
	mxm_error_t error;

	error = mxm_req_recv(&rreq->mxm_rreq);
	assert(error == MXM_OK);
}


static
psmxm_recv_req_t *psmxm_recvq_head(void)
{
	return list_entry(mxm_socket.recvq.next, psmxm_recv_req_t, next);
}


static
void psmxm_recvq_append(psmxm_recv_req_t *rreq)
{
	list_add_tail(&rreq->next, &mxm_socket.recvq);
}



static
void psmxm_init_endpoint(mxm_socket_t *mxm_socket)
{
	memset(mxm_socket, 0, sizeof(*mxm_socket));
	INIT_LIST_HEAD(&mxm_socket->recvq);
}


static
void psmxm_post_recv_buffers(mxm_socket_t *mxm_socket)
{
	int i;

	if (!list_empty(&mxm_socket->recvq)) return; // Already posted

	for (i = 0; i < PSMXM_RECV_BUFFER_COUNT; i++) {
		psmxm_recv_req_t *rreq = &mxm_socket->rreqs[i];
		psmxm_init_recv_req(rreq, mxm_socket);
		psmxm_recv_req_post(rreq);
		psmxm_recvq_append(rreq);
	}
}


static
int psmxm_open_endpoint(mxm_socket_t *mxm_socket)
{
	mxm_context_opts_t *mxm_opts = NULL;
	mxm_ep_opts_t *ep_opts = NULL;
	mxm_error_t error;
	size_t mxm_ep_addr_len = sizeof(mxm_socket->mxm_ep_addr);

	error = mxm_config_read_opts(&mxm_opts, &ep_opts, NULL, NULL, 0);
	if (error != MXM_OK) goto err_mxm_config_read_opts;

	if (psmxm_params.flag_no_optimization) {
		// Fast mode. Might be not portable.
		ep_opts->ud.ib.rx.queue_len = 1024;
		mxm_opts->async_mode     = MXM_ASYNC_MODE_SIGNAL;
	}

	error = mxm_init(mxm_opts, &mxm_socket->mxm_mxmh);
	if (error != MXM_OK) goto err_mxm_init;

	error = mxm_ep_create(mxm_socket->mxm_mxmh, ep_opts, &mxm_socket->mxm_ep);
	if (error != MXM_OK) goto err_mxm_ep_create;

	error = mxm_ep_get_address(mxm_socket->mxm_ep, mxm_socket->mxm_ep_addr,
				   &mxm_ep_addr_len);
	if (error != MXM_OK) goto err_mxm_ep_get_address;


	/* Initialize the mq */
	error = mxm_mq_create(mxm_socket->mxm_mxmh, 0x5115, &mxm_socket->mxm_mq);
	if (error != MXM_OK) goto err_mxm_mq_create;

	mxm_config_free_context_opts(mxm_opts);
	mxm_config_free_ep_opts(ep_opts);

	psmxm_post_recv_buffers(mxm_socket);

	return 0;
err_mxm_mq_create:
	psmxm_msg_err("mxm_mq_create()", error);
	goto err_common;
err_mxm_ep_get_address:
	psmxm_msg_err("mxm_ep_get_address()", error);
	goto err_common;
err_mxm_ep_create:
	psmxm_msg_err("mxm_ep_create()", error);
	goto err_common;
err_mxm_init:
	psmxm_msg_err("mxm_init()", error);
	goto err_common;
err_mxm_config_read_opts:
	psmxm_msg_err("mxm_config_read_opts()", error);
	goto err_common;
err_common:
	if (mxm_opts) mxm_config_free_context_opts(mxm_opts);
	if (ep_opts) mxm_config_free_ep_opts(ep_opts);

	psmxm_dprint(1, "psmxm_open_endpoint: %s", psmxm_err_str);
	return -1;
}


int psmxm_close_endpoint(void)
{
#if 1
	/* ToDo: Implement close endpoint! */

	return 0;
#else
	mxm_error_t ret;

	if (psmxm_ep){
		ret = mxm_ep_close(psmxm_ep, MXM_EP_CLOSE_GRACEFUL, 0);
		psmxm_ep = NULL;
		if (ret != MXM_OK) goto err;

		if (sendbuf) free(sendbuf);

		psmxm_dprint(2, "psmxm_close_endpoint: OK");
	}
	return 0;

err:
	psmxm_err(mxm_error_get_string(ret));
	psmxm_dprint(1, "psmxm_close_endpoint: %s", psmxm_err_str);
	return -1;
#endif
}


int psmxm_con_init(psmxm_con_info_t *con_info)
{
	static uint64_t tag = MXM_TAG_FIRST_CON;

	con_info->con_broken = 0;
	con_info->sending = 0;

	con_info->recv_tag = tag++;

	psmxm_dprint(2, "psmxm_con_init: OK");
	return 0;
}


int psmxm_con_connect(psmxm_con_info_t *con_info, psmxm_info_msg_t *info_msg, void *ctx)
{
	mxm_error_t error;

	if (info_msg->psmxm_protocol_version != PSMXM_PROTOCOL_VERSION) {
		goto err_protocol;
	}

	con_info->send_tag = info_msg->tag;

	error = mxm_ep_connect(mxm_socket.mxm_ep, info_msg->mxm_ep_addr, &con_info->mxm_conn);
	if (error != MXM_OK) goto err_mxm_ep_connect;

	error = mxm_ep_wireup(mxm_socket.mxm_ep);
	if (error != MXM_OK) goto err_mxm_ep_wireup;

	mxm_conn_ctx_set(con_info->mxm_conn, ctx); // set upper layer context

	/* Prepare one send request */
	psmxm_init_send_req(&con_info->sreq, &mxm_socket, con_info);

	return 0;
err_mxm_ep_wireup:
	psmxm_msg_err("mxm_ep_wireup()", error);
	goto err_common;
err_mxm_ep_connect:
	psmxm_msg_err("mxm_ep_connect()", error);
	goto err_common;
err_protocol:
	{
		char str[80];
		snprintf(str, sizeof(str), "protocol error : '%04x' != '%04x'",
			 info_msg->psmxm_protocol_version, PSMXM_PROTOCOL_VERSION);
		psmxm_err(str);
	}
	goto err_common;
err_common:
	psmxm_dprint(1, "psmxm_con_connect: %s", psmxm_err_str);
	return -1;
}


int psmxm_init(void)
{
	static int init_state = 1;
	int ret;

	if (init_state == 1) {
		/* Check for an available mxm device */
		ret = psmxm_check_dev();
		if (ret != 0) {
			goto err_dev_knem;
		}

		psmxm_init_endpoint(&mxm_socket);
		if (psmxm_open_endpoint(&mxm_socket)) goto err_open;

		psmxm_dprint(2, "psmxm_init: OK");
		init_state = 0;
	}
	return init_state; /* 0 = success, -1 = error */
err_dev_knem:
	psmxm_dprint(2, "psmxm_init: No \"/dev/knem\" found. Arch mxm is disabled.");
	goto err_exit;
err_open:
err_exit:
	init_state = -1;
	return init_state; /* 0 = success, -1 = error */
}


#if 0
static
void psmxm_iov_print(const struct iovec *iov, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			psmxm_dprint(2, "SENDV %p %zu", iov->iov_base, iov->iov_len);
			len -= iov->iov_len;
		}
		iov++;
	}
}
#endif


int psmxm_send_done(psmxm_con_info_t *con_info) {
	return !con_info->sending;
}


int psmxm_sendv(psmxm_con_info_t *con_info, struct iovec *iov, size_t size)
{
	unsigned data_len, length;
	mxm_error_t error;

	if (con_info->sending) goto err_busy;

	if (con_info->con_broken) goto err_broken;

	length = (size <= PSMXM_MTU) ? (unsigned)size : PSMXM_MTU;
	con_info->sending = length;
	data_len = length - (unsigned)iov[0].iov_len;

	assert(data_len <= iov[1].iov_len);
	assert(iov[0].iov_len <= PSMXM_MTU);

	con_info->sreq.iov[0].ptr = iov[0].iov_base;
	con_info->sreq.iov[0].length = iov[0].iov_len;
	con_info->sreq.iov[1].ptr = iov[1].iov_base;
	con_info->sreq.iov[1].length = data_len;

	error = mxm_req_send(&con_info->sreq.mxm_sreq);
	if (error != MXM_OK) goto err_sendv;

	assert(length > 0);

	return length;
err_busy:
	return -EAGAIN;
err_broken:
	return -EPIPE;
err_sendv:
	psmxm_msg_err("mxm_req_send()", error);
	psmxm_dprint(0, "psmxm_sendv: %s", psmxm_err_str);
	return -EPIPE;
}


unsigned psmxm_send_progress(psmxm_con_info_t *con_info)
{
	unsigned sending = con_info->sending;
	if (sending && mxm_req_test(&con_info->sreq.mxm_sreq.base)) {
		con_info->sending = 0;
		return sending;
	}
	return 0;
}


void psmxm_progress(void)
{
	mxm_progress(mxm_socket.mxm_mxmh);
}


psmxm_recv_req_t *psmxm_recv_peek(void)
{
	psmxm_recv_req_t *rreq = psmxm_recvq_head();

	if (mxm_req_test(&rreq->mxm_rreq.base)) {
		return rreq;
	} else {
		return NULL;
	}
}


void psmxm_recv_release(psmxm_recv_req_t *rreq)
{
	list_del(&rreq->next);
	psmxm_recv_req_post(rreq);
	psmxm_recvq_append(rreq);
}


psmxm_con_info_t *psmxm_con_create(void)
{
	psmxm_con_info_t *con_info = malloc(sizeof(*con_info));
	return con_info;
}


void psmxm_con_free(psmxm_con_info_t *con_info)
{
	free(con_info);
}


void psmxm_con_cleanup(psmxm_con_info_t *con_info)
{
	/* FIXME: implement */
}
