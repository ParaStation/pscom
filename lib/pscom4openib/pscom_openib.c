/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
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

static pscom_err_t
pscom_openib_env_parser_set_pending_tokens(void *buf,
					   const char *config_val)
{
	const char *set_val =
		config_val ? config_val : psoib_pending_tokens_suggestion_str();

	return pscom_env_parser_set_config_uint(buf, set_val);
}


static pscom_err_t
pscom_openib_env_parser_set_sendq_size(void *buf, const char *config_val)
{
	pscom_err_t ret;
	ret = pscom_env_parser_set_config_uint(buf, config_val);

	if (psoib_global_sendq) {
		/* one sendq for all connection. limit sendq to compq size */
		psoib_sendq_size = psoib_compq_size;
	} else {
		/* One sendq for each connection. limit sendq to recvq size */
		psoib_sendq_size = pscom_min(psoib_sendq_size, psoib_recvq_size);
	}

	return ret;
}


#define PSCOM_OPENIB_ENV_PARSER_PENDING_TOKENS {pscom_openib_env_parser_set_pending_tokens, \
					        pscom_env_parser_get_config_int}

#define PSCOM_OPENIB_ENV_PARSER_SENDQ_SIZE {pscom_openib_env_parser_set_sendq_size, \
					    pscom_env_parser_get_config_uint}


pscom_env_table_entry_t pscom_env_table_openib [] = {
	{"HCA", NULL,
	 "Name of the hca to use. (default to the name of the first active "
	 "hca).",
	 &psoib_hca, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_STR},

	{"PORT", "0",
	 "Port to use (default is first active port).",
	 &psoib_port, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"PATH_MTU", "3",
	 "MTU of the IB packets. (1:256, 2:512, 3:1024)",
	 &psoib_path_mtu, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RECVQ_SIZE", "16",
	 "Number of receive buffers per connection.",
	 &psoib_recvq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"GLOBAL_SENDQ", "0",
	 "Enable/disable global send queue.",
	 &psoib_global_sendq, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"COMPQ_SIZE", "128",
	 "Size of the completion queue. This likewise corresponds to the size "
	 "of the global send queue (if enabled).",
	 &psoib_compq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"SENDQ_SIZE", "16",
	 "Number of send buffers per connection.",
	 &psoib_sendq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_OPENIB_ENV_PARSER_SENDQ_SIZE},

	{"EVENT_CNT", "1",
	 "Enable/disable busy polling if outstanding_cq_entries is to high.",
	 &psoib_event_count, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"IGNORE_WRONG_OPCODES", "0",
	 "If enabled, terminate all IB connections when receiving a wrong CQ "
	 "opcode",
	 &psoib_ignore_wrong_opcodes, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"LID_OFFSET", "0",
	 "Offset to base LID (adaptive routing).",
	 &psoib_lid_offset, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"RENDEZVOUS", "40000",
	 "The rendezvous threshold for pscom4openib.",
	 &pscom.env.rendezvous_size_openib, PSCOM_ENV_ENTRY_HAS_PARENT,
	 PSCOM_ENV_PARSER_UINT},

	{"RNDV_FALLBACKS", "1",
	 "Enable/disable usage of eager/sw-rndv if memory cannot be registered "
	 "for rendezvous communication.",
	 &psoib_rndv_fallbacks, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"PENDING_TOKENS", NULL,
	 "Number of tokens for incoming packets.",
	 &psoib_pending_tokens, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_OPENIB_ENV_PARSER_PENDING_TOKENS},

#if PSOIB_USE_MREGION_CACHE
	{"MCACHE_SIZE", "8",
	 "Maximum number of entries in the memory registration cache. Disables "
	 "the cache if set to 0.",
	 &psoib_mregion_cache_max_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"MALLOC_OPTS", "1",
	 "Enable/disable the usage of mallopt() in the pscom4open RNDV case.",
	 &psoib_mregion_malloc_options, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},
#endif
	{NULL},
};

static
pscom_poll_t pscom_poll_cq;

__attribute__((visibility("hidden")))
int pscom_do_poll_cq(pscom_poll_t *poll)
{
	psoib_progress();

	if (!psoib_outstanding_cq_entries) {
		/* Stop polling on cq */
		pscom_poll_stop(poll);
	}

	return 0;
}

static inline
void pscom_check_cq_poll(void)
{
	if (psoib_outstanding_cq_entries) {
		// There are outstanding cq events

		// Start polling:
		 // ToDo: Should we prefer &pscom.poll_write here?
		pscom_poll_start(&pscom_poll_cq, pscom_do_poll_cq, &pscom.poll_read);
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
		pscom_con_check_read_stop(con);
		return 0;
	} else {
		// Error
		errno = (int)-size;
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
		return 1;
	}
}


static
int pscom_openib_do_read(pscom_poll_t *poll)
{
	pscom_con_t *con = list_entry(poll, pscom_con_t, poll_read);
	psoib_con_info_t *mcon = con->arch.openib.mcon;

	return _pscom_openib_do_read(con, mcon);
}


static
int pscom_openib_do_write(pscom_poll_t *poll)
{
	pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);
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
	return 0;
}


/*
 * ++ RMA rendezvous begin
 */
#ifdef IB_USE_RNDV

typedef struct pscom_rendezvous_data_openib {
	struct psoib_rma_req	rma_req;
	pscom_req_t		*rendezvous_req; // Receiving side: users receive request (or generated request)
	pscom_con_t		*con;
	void			(*io_done)(void *priv, int err);
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

	memcpy(rd->msg.arch.openib.padding_data, rd->msg.data, rd->msg.arch.openib.padding_size); // ToDo: _pscom_memcpy?

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


#ifndef IB_RNDV_RDMA_WRITE
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
	int err;
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

	pscom_check_cq_poll();

	return 0;

err_register:
	return -1;
}
#endif


static
void pscom_openib_rma_write_io_done(void *priv, int err)
{
	pscom_rendezvous_data_t *rd_data = (pscom_rendezvous_data_t *)priv;
	pscom_rendezvous_data_openib_t *rd_data_openib = get_req_data(rd_data);

	rd_data_openib->io_done(rd_data_openib->priv, err);

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
			   void (*io_done)(void *priv, int err), void *priv)
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

	pscom_check_cq_poll();

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
void pscom_poll_read_start_openib(pscom_con_t *con) {
	pscom_poll_read_start(con, pscom_openib_do_read);
}


static
void pscom_poll_write_start_openib(pscom_con_t *con) {
	pscom_poll_write_start(con, pscom_openib_do_write);
}


static
void pscom_openib_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_OPENIB;

#ifdef PSCOM_CUDA_AWARENESS
	con->is_gpu_aware = pscom.env.cuda && pscom.env.cuda_aware_openib;
#endif

	// Only Polling:
	con->read_start = pscom_poll_read_start_openib;
	con->read_stop = pscom_poll_read_stop;

	con->write_start = pscom_poll_write_start_openib;
	con->write_stop = pscom_poll_write_stop;

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

	/* register the environment configuration table */
	pscom_env_table_register_and_parse("pscom OPENIB", "OPENIB_",
					   pscom_env_table_openib);

#if PSOIB_USE_MREGION_CACHE
	psoib_mregion_cache_init();
#endif

	pscom_poll_init(&pscom_poll_cq);
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


#ifndef PSCOM_ALLIN_OPENIB
PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin =
#else
pscom_plugin_t pscom_plugin_openib =
#endif
{
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
