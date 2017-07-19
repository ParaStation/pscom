/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_openib.c: OPENIB/Infiniband communication
 */

#include "psoib.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <malloc.h>
#include <infiniband/verbs.h>

#include "pscom_priv.h"
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_io.h"
#include "pscom_openib.h"
#include "pscom_req.h"
#include "pscom_util.h"


static
struct pscom_poll_reader pscom_cq_poll;

int pscom_poll_cq(pscom_poll_reader_t *reader)
{
	psoib_progress();

	if (!psoib_outstanding_cq_entries) {
		/* Stop polling on cq */
		/* it's save to dequeue more then once */
		list_del_init(&reader->next);
	}

	return 0;
}

static inline
void pscom_check_cq_poll(void)
{
	if (psoib_outstanding_cq_entries &&
	    list_empty(&pscom_cq_poll.next)) {
		// There are outstanding cq events and
		// we do not already poll the cq

		// Start polling:
		list_add_tail(&pscom_cq_poll.next, &pscom.poll_reader);
	}
}


static
int _pscom_openib_do_read(pscom_con_t *con, psoib_con_info_t *mcon)
{
	void *buf;
	ssize_t size;

	size = psoib_recvlook(mcon, &buf);

	if (size >= 0) {
		perf_add("openib_do_read");
		pscom_read_done(con, buf, size);

		psoib_recvdone(mcon);
		return 1;
	} else if ((size == -EINTR) || (size == -EAGAIN)) {
		// Nothing received
		return 0;
	} else {
		// Error
		errno = (int)-size;
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
		return 1;
	}
}


static
int pscom_openib_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	psoib_con_info_t *mcon = con->arch.openib.mcon;

	return _pscom_openib_do_read(con, mcon);
}


static
void pscom_openib_do_write(pscom_con_t *con)
{
	size_t len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psoib_con_info_t *mcon = con->arch.openib.mcon;
		len = iov[0].iov_len + iov[1].iov_len;

		perf_add("openib_sendv");
		ssize_t rlen = psoib_sendv(mcon, iov, len);

		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
			pscom_check_cq_poll();
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Maybe out of tokens? try to read more tokens:
			_pscom_openib_do_read(con, mcon);
		} else {
			// Error
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}


/*
 * ++ RMA rendezvous begin
 */
#ifdef IB_USE_RNDV

typedef struct pscom_rendezvous_data_openib {
	struct psoib_rma_req	rma_req;
	pscom_req_t		*rendezvous_req; // Receiving side: users receive request (or generated request)
	pscom_con_t		*con;
	void			(*io_done)(void *priv);
	void			*priv;
} pscom_rendezvous_data_openib_t;


static inline
pscom_rendezvous_data_openib_t *get_req_data(pscom_rendezvous_data_t *rd)
{
	_pscom_rendezvous_data_openib_t *data = &rd->arch.openib;
	pscom_rendezvous_data_openib_t *res = (pscom_rendezvous_data_openib_t *) data;
	assert(sizeof(*res) <= sizeof(*data));
	return res;
}

static
int pscom_openib_rma_mem_register_check(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_openib_t *openib_rd = get_req_data(rd);
	psoib_con_info_t *ci = con->arch.openib.mcon;
	psoib_rma_mreg_t *mreg = &openib_rd->rma_req.mreg;

	return psoib_check_rma_mreg(mreg, rd->msg.data, rd->msg.data_len, ci);
}

static
unsigned int pscom_openib_rma_mem_register(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	int err = 0;
	pscom_rendezvous_data_openib_t *openib_rd = get_req_data(rd);
	psoib_con_info_t *ci = con->arch.openib.mcon;
	psoib_rma_mreg_t *mreg = &openib_rd->rma_req.mreg;

	if (rd->msg.data_len > IB_MAX_RDMA_MSG_SIZE) goto err_size;

#ifdef IB_RNDV_USE_PADDING
#ifdef   IB_RNDV_RDMA_WRITE
#error   IB_RNDV_USE_PADDING and IB_RNDV_RDMA_WRITE are mutually exclusive!
#endif

	rd->msg.arch.openib.padding_size = (IB_RNDV_PADDING_SIZE - ((long long int)rd->msg.data) % IB_RNDV_PADDING_SIZE) % IB_RNDV_PADDING_SIZE;

	memcpy(rd->msg.arch.openib.padding_data, rd->msg.data, rd->msg.arch.openib.padding_size);

	/* get mem region */
	perf_add("openib_acquire_rma_mreg");
	err = psoib_acquire_rma_mreg(mreg, rd->msg.data + rd->msg.arch.openib.padding_size, rd->msg.data_len - rd->msg.arch.openib.padding_size, ci);

	if (err) goto err_get_region;

	rd->msg.arch.openib.mr_key  = mreg->mem_info.mr->rkey;
	rd->msg.arch.openib.mr_addr = (uint64_t)mreg->mem_info.ptr;

	return sizeof(rd->msg.arch.openib) - sizeof(rd->msg.arch.openib.padding_data) + rd->msg.arch.openib.padding_size;
#else

	/* get mem region */
	perf_add("openib_acquire_rma_mreg2");
	err = psoib_acquire_rma_mreg(mreg, rd->msg.data, rd->msg.data_len, ci);

	if (err) goto err_get_region;

	rd->msg.arch.openib.mr_key  = mreg->mem_info.mr->rkey;
	rd->msg.arch.openib.mr_addr = (uint64_t)mreg->mem_info.ptr;

	return sizeof(rd->msg.arch.openib) - sizeof(rd->msg.arch.openib.padding_data);
#endif

err_get_region:
err_size:
	// return len_arch=0 in the error case:
	return 0;
}


static
void pscom_openib_rma_mem_deregister(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_openib_t *openib_rd = get_req_data(rd);
	psoib_rma_mreg_t *mreg = &openib_rd->rma_req.mreg;

	perf_add("openib_release_rma_mreg");
	psoib_release_rma_mreg(mreg);
}


static
void pscom_openib_rma_read_io_done(void *priv, int err)
{
	psoib_rma_req_t *dreq = (psoib_rma_req_t *)priv;
	pscom_rendezvous_data_openib_t *psopenib_rd =
		(pscom_rendezvous_data_openib_t *)dreq->priv;

	pscom_req_t *rendezvous_req = psopenib_rd->rendezvous_req;
	psoib_rma_mreg_t *mreg = &psopenib_rd->rma_req.mreg;

	psoib_release_rma_mreg(mreg);

	if (unlikely(err)) {
		rendezvous_req->pub.state |= PSCOM_REQ_STATE_ERROR;
	}
	_pscom_recv_req_done(rendezvous_req);
}


static
int pscom_openib_rma_read(pscom_req_t *rendezvous_req, pscom_rendezvous_data_t *rd)
{
	int err, ret;
	pscom_rendezvous_data_openib_t *psopenib_rd = get_req_data(rd);
	psoib_rma_req_t *dreq = &psopenib_rd->rma_req;
	pscom_con_t *con = get_con(rendezvous_req->pub.connection);
	psoib_con_info_t *ci = con->arch.openib.mcon;

	perf_add("openib_rma_read");

	if (con->rma_mem_register_check && !con->rma_mem_register_check(con, rd)) goto err_register;

#ifdef IB_RNDV_USE_PADDING
	memcpy(rendezvous_req->pub.data, rd->msg.arch.openib.padding_data, rd->msg.arch.openib.padding_size);
	rendezvous_req->pub.data += rd->msg.arch.openib.padding_size;
	rendezvous_req->pub.data_len -= rd->msg.arch.openib.padding_size;
#endif

	err = psoib_acquire_rma_mreg(&dreq->mreg, rendezvous_req->pub.data, rendezvous_req->pub.data_len, ci);
	if(err) goto err_register;

	dreq->remote_addr = rd->msg.arch.openib.mr_addr;
	dreq->remote_key  = rd->msg.arch.openib.mr_key;
	dreq->data_len = rendezvous_req->pub.data_len;
	dreq->ci = ci;
	dreq->io_done = pscom_openib_rma_read_io_done;
	dreq->priv = psopenib_rd;

	psopenib_rd->rendezvous_req = rendezvous_req;

	err = psoib_post_rma_get(dreq);
	assert(!err); // ToDo: Catch error

	return 0;

err_register:
	return -1;
}


static
void pscom_openib_rma_write_io_done(void *priv, int err)
{
	pscom_rendezvous_data_t *rd_data = (pscom_rendezvous_data_t *)priv;
	pscom_rendezvous_data_openib_t *rd_data_openib = get_req_data(rd_data);

	// ToDo: Error propagation
	rd_data_openib->io_done(rd_data_openib->priv);

	pscom_openib_rma_mem_deregister(rd_data_openib->con, rd_data);
	pscom_free(rd_data);
}


/* Send from:
 *   rd_src = (pscom_rendezvous_data_t *)req->pub.user
 *   (rd_src->msg.data, rd_src->msg.data_len)
 *   rd_src->msg.arch.openib.{mr_key, mr_addr}
 * To:
 *   (rd_des->msg.data, rd_des->msg.data_len)
 *   rd_des->msg.arch.openib.{mr_key, mr_addr}
 */

static
int pscom_openib_rma_write(pscom_con_t *con, void *src, pscom_rendezvous_msg_t *des,
			   void (*io_done)(void *priv), void *priv)
{
	pscom_rendezvous_data_t *rd_data = (pscom_rendezvous_data_t *)pscom_malloc(sizeof(*rd_data));
	pscom_rendezvous_data_openib_t *rd_data_openib = get_req_data(rd_data);
	psoib_con_info_t *mcon = con->arch.openib.mcon;

	psoib_rma_req_t *dreq = &rd_data_openib->rma_req;
	size_t len;
	int err;

	rd_data->msg.id = (void*)42;
	rd_data->msg.data = src;
	rd_data->msg.data_len = des->data_len;

	len = pscom_openib_rma_mem_register(con, rd_data);
       if(!len) goto err_register;
/*
	dreq->mreg.mem_info.ptr = xxx;
	dreq->mreg.size = xxx;
	dreq->mreg.mem_ingo.mr->lkey = xxx;
*/
	perf_add("openib_rma_write");

	dreq->remote_addr = des->arch.openib.mr_addr;
	dreq->remote_key  = des->arch.openib.mr_key;
	dreq->data_len = des->data_len;
	dreq->ci = mcon;
	dreq->io_done = pscom_openib_rma_write_io_done;
	dreq->priv = rd_data;

	rd_data_openib->con = con;
	rd_data_openib->io_done = io_done;
	rd_data_openib->priv = priv;

	err = psoib_post_rma_put(dreq);
	assert(!err); // ToDo: Catch error
	rd_data = NULL; /* Do not use rd_data after psoib_post_rma_put()!
			   io_done might already be called and freed rd_data. */

	return 0;

err_register:
       return -1;
}
#endif /* IB_USE_RNDV */
/*
 * -- RMA rendezvous end
 */


static
void pscom_openib_con_cleanup(pscom_con_t *con)
{
	psoib_con_info_t *mcon = con->arch.openib.mcon;

	if (mcon) {
		psoib_con_cleanup(mcon, NULL);
		psoib_con_free(mcon);
	}
	con->arch.openib.mcon = NULL;
}


static
void pscom_openib_con_close(pscom_con_t *con)
{
	psoib_con_info_t *mcon = con->arch.openib.mcon;

	if (!mcon) return;

	pscom_openib_con_cleanup(con);
}


static
void pscom_openib_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_OPENIB;

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = pscom_openib_do_read;
	con->do_write = pscom_openib_do_write;
	con->close = pscom_openib_con_close;

#ifdef IB_USE_RNDV
	con->rma_mem_register = pscom_openib_rma_mem_register;
	con->rma_mem_deregister = pscom_openib_rma_mem_deregister;

	if(psoib_rndv_fallbacks) {
		con->rma_mem_register_check = pscom_openib_rma_mem_register_check;
	} else {
		con->rma_mem_register_check = NULL;
	}
#ifdef IB_RNDV_RDMA_WRITE
	con->rma_write = pscom_openib_rma_write;
#else
	con->rma_read = pscom_openib_rma_read;
#endif

	con->rendezvous_size = pscom.env.rendezvous_size_openib;

#endif /* IB_USE_RNDV */

	pscom_con_setup_ok(con);
}

/*********************************************************************/
static
void pscom_openib_init(void)
{
	psoib_debug = pscom.env.debug;
	psoib_debug_stream = pscom_debug_stream();
	pscom_env_get_str(&psoib_hca, ENV_OPENIB_HCA);
	pscom_env_get_uint(&psoib_port, ENV_OPENIB_PORT);
	pscom_env_get_uint(&psoib_path_mtu, ENV_OPENIB_PATH_MTU);

	pscom_env_get_uint(&psoib_recvq_size, ENV_OPENIB_RECVQ_SIZE);

	pscom_env_get_int(&psoib_global_sendq, ENV_OPENIB_GLOBAL_SENDQ);
	pscom_env_get_uint(&psoib_compq_size, ENV_OPENIB_COMPQ_SIZE);
	if (psoib_global_sendq) {
		// One sendq for all connection. limit sendq to compq size.
		psoib_sendq_size = psoib_compq_size;
	} else {
		// One sendq for each connection. limit sendq to recvq size.
		psoib_sendq_size = pscom_min(psoib_sendq_size, psoib_recvq_size);
	}
	pscom_env_get_uint(&psoib_sendq_size, ENV_OPENIB_SENDQ_SIZE);

	psoib_pending_tokens = psoib_pending_tokens_suggestion();
	pscom_env_get_uint(&psoib_pending_tokens, ENV_OPENIB_PENDING_TOKENS);

//	if (!psoib_global_sendq && psoib_sendq_size == psoib_recvq_size) {
//		// Disable event counting:
//		psoib_event_count = 0;
//	}
	pscom_env_get_int(&psoib_event_count, ENV_OPENIB_EVENT_CNT);
	pscom_env_get_int(&psoib_ignore_wrong_opcodes, ENV_OPENIB_IGNORE_WRONG_OPCODES);
	pscom_env_get_int(&psoib_lid_offset, ENV_OPENIB_LID_OFFSET);

#if PSOIB_USE_MREGION_CACHE
	pscom_env_get_uint(&psoib_mregion_cache_max_size, ENV_OPENIB_MCACHE_SIZE);
#endif
	pscom_env_get_int(&psoib_rndv_fallbacks, ENV_OPENIB_RNDV_FALLBACKS);

	INIT_LIST_HEAD(&pscom_cq_poll.next);
	pscom_cq_poll.do_read = pscom_poll_cq;

}


#define PSCOM_INFO_OIB_ID PSCOM_INFO_ARCH_STEP1


static
int pscom_openib_con_init(pscom_con_t *con)
{
	return psoib_init();
}


static
void pscom_openib_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		psoib_con_info_t *mcon = psoib_con_create();
		con->arch.openib.mcon = mcon;
		if (!mcon) goto error_con_create;

		if (psoib_con_init(mcon, NULL, NULL)) goto error_con_init;

		psoib_info_msg_t msg;
		psoib_con_get_info_msg(mcon, &msg);

		pscom_precon_send(con->precon, PSCOM_INFO_OIB_ID, &msg, sizeof(msg));

		break; /* Next is OIB_ID or ARCH_NEXT */
	}
	case PSCOM_INFO_OIB_ID: {
		psoib_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		if (psoib_con_connect(con->arch.openib.mcon, msg)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_OK:
		pscom_con_guard_start(con);
		break;
	case PSCOM_INFO_ARCH_NEXT:
		/* Cleanup con */
		pscom_openib_con_cleanup(con);
		break; /* Done (this one failed) */
	case PSCOM_INFO_EOF:
		pscom_openib_init_con(con);
		break; /* Done (use this one) */
	}


	return;
	/* --- */
error_con_create:
error_con_init:
error_con_connect:
	pscom_openib_con_cleanup(con);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


pscom_plugin_t pscom_plugin = {
	.name		= "openib",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_OPENIB,
	.priority	= PSCOM_OPENIB_PRIO,

	.init		= pscom_openib_init,
	.destroy	= NULL,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_init	= pscom_openib_con_init,
	.con_handshake	= pscom_openib_handshake,
};
