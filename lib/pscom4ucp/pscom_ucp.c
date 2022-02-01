/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_ucp.c: UCP communication
 */

#include "psucp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_priv.h"
#include "pscom_io.h"
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_ucp.h"

pscom_env_table_entry_t pscom_env_table_ucp [] = {
	{"MAX_RECV", PSCOM_ENV_UINT_INF_STR,
	 "Limit the number of outstanding receive requests that are handled by "
	 "the pscom4ucp plugin concurrently.",
	 &psucp_max_recv, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"FASTINIT", "1",
	 "If enabled, ucp_init() is called from within pscom4ucp plugin init, "
	 "otherwise on first usage of a pscom4ucp connection.",
	 &pscom.env.ucp_fastinit, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RENDEZVOUS", PSCOM_ENV_UINT_INF_STR,
	 "The rendezvous threshold for pscom4ucp.",
	 &pscom.env.rendezvous_size_ucp,
	 (PSCOM_ENV_ENTRY_HAS_PARENT | PSCOM_ENV_ENTRY_HIDDEN),
	 PSCOM_ENV_PARSER_UINT},

	{"SMALL_MSG_LEN", "350",
	 "The threshold for buffered sending of small messages.",
	 &psucp_small_msg_len, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{NULL},
};


static struct {
	pscom_poll_t poll_read; // pscom_ucp_do_read
	unsigned reader_user;
} pscom_ucp;


static
int pscom_ucp_do_read(pscom_poll_t *poll);


static
void reader_inc(void)
{
	if (!pscom_ucp.reader_user) {
		// enqueue to polling reader
		pscom_poll_start(&pscom_ucp.poll_read, pscom_ucp_do_read, &pscom.poll_read);
	}
	pscom_ucp.reader_user++;
}


static
void reader_dec(void)
{
	pscom_ucp.reader_user--;
	if (!pscom_ucp.reader_user) {
		// dequeue from polling reader
		pscom_poll_stop(&pscom_ucp.poll_read);
	}
}


static
void pscom_ucp_read_start(pscom_con_t *con)
{
	if (!con->arch.ucp.reading) {
		con->arch.ucp.reading = 1;
		reader_inc();
	}
}


static
void pscom_ucp_read_stop(pscom_con_t *con)
{
	if (con->arch.ucp.reading) {
		con->arch.ucp.reading = 0;
		reader_dec();
	}
}

static
int pscom_ucp_do_read(pscom_poll_t *poll)
{
	psucp_msg_t msg;
	ssize_t rc;

	rc = psucp_probe(&msg);

	if (rc > 0) {
		pscom_con_t *con = (pscom_con_t *)msg.info_tag.sender_tag;
		psucp_con_info_t *ci = con->arch.ucp.ci;
		char *buf;
		size_t len;
		ssize_t rlen;

		assert(con->magic == MAGIC_CONNECTION);

		pscom_read_get_buf(con, &buf, &len);

		rlen = psucp_irecv(ci, &msg, buf, len);

		if (rlen < 0) {
			// error receive
			errno = -(int)rlen;
			pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
			return 1;
		}

//		printf("%s:%u:%s  recv len:%u rlen:%u buf:%s\n", __FILE__, __LINE__, __func__,
//		       (unsigned)len, (unsigned)rlen, pscom_dumpstr(buf, rlen));
//		pscom_read_done(con, buf, rlen);
	}

	return rc > 0;
}


void pscom_psucp_sendv_done(void *req_priv)
{
	pscom_req_t *req = (pscom_req_t *)req_priv;
	assert(req != NULL);
	assert(req->magic == MAGIC_REQUEST);

	reader_dec();

	pscom_write_pending_done(get_con(req->pub.connection), req);
}


static
int pscom_ucp_do_write(pscom_poll_t *poll)
{
	size_t len;
	struct iovec iov[2];
	pscom_req_t *req;
	pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psucp_con_info_t *ci = con->arch.ucp.ci;
		len = iov[0].iov_len + iov[1].iov_len;

		pscom_write_pending(con, req, len);

		ssize_t rlen = psucp_sendv(ci, iov, req);

		if (rlen >= 0) {
			assert((size_t)rlen == len);
			reader_inc();
			// pscom_write_done(con, req, rlen);
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Retry later.
			// ToDo: revert the call to pscom_write_pending. For now, fail:
			assert(0);
		} else {
			// Error
			pscom_write_pending_error(con, req);
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
	return 0;
}


static
void pscom_ucp_con_cleanup(pscom_con_t *con)
{
	psucp_con_info_t *ci = con->arch.ucp.ci;
	if (!ci) return;

	psucp_con_cleanup(ci);
	psucp_con_free(ci);

	con->arch.ucp.ci = NULL;
}


static
void pscom_ucp_con_close(pscom_con_t *con)
{
	psucp_con_info_t *ci = con->arch.ucp.ci;
	if (!ci) return;

	pscom_ucp_con_cleanup(con);
	reader_dec();
}


static
void pscom_poll_write_start_ucp(pscom_con_t *con) {
	pscom_poll_write_start(con, pscom_ucp_do_write);
}


static
void pscom_ucp_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_UCP;

#ifdef PSCOM_CUDA_AWARENESS
	con->is_gpu_aware = pscom.env.cuda && pscom.env.cuda_aware_ucp;
#endif

	// Only Polling:
	con->read_start = pscom_ucp_read_start;
	con->read_stop = pscom_ucp_read_stop;

	con->write_start = pscom_poll_write_start_ucp;
	con->write_stop = pscom_poll_write_stop;

	con->close = pscom_ucp_con_close;

//	con->rma_mem_register = pscom_ucp_rma_mem_register;
//	con->rma_mem_deregister = pscom_ucp_rma_mem_deregister;
//	con->rma_read = pscom_ucp_rma_read;

	con->rendezvous_size = pscom.env.rendezvous_size_ucp;

	reader_inc();
	pscom_con_setup_ok(con);
}


/*********************************************************************/
static
void pscom_ucp_init(void)
{
	psucp_debug = pscom.env.debug;
	psucp_debug_stream = pscom_debug_stream();

	/* set the rendezvous threshold based on the global configuration */
	if (pscom.env.rendezvous_size != (unsigned)~0)
		pscom.env.rendezvous_size_ucp = pscom.env.rendezvous_size;

	/* register the environment configuration table */
	pscom_env_table_register_and_parse("pscom UCP", "UCP_",
					   pscom_env_table_ucp);

	pscom_poll_init(&pscom_ucp.poll_read);
	pscom_ucp.reader_user = 0;

	/* ensure the initialization of the UCP memory cache */
	if (pscom.env.ucp_fastinit) psucp_init();
}


static
void pscom_ucp_destroy(void)
{
}

#define PSCOM_INFO_UCP_ID PSCOM_INFO_ARCH_STEP1


static
int pscom_ucp_con_init(pscom_con_t *con)
{
	return psucp_init();
}


static
void pscom_ucp_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		psucp_info_msg_t *msg;
		psucp_con_info_t *ci = psucp_con_create();

		con->arch.ucp.ci = ci;
		con->arch.ucp.reading = 0;

		if (psucp_con_init(ci, NULL, con)) goto error_con_init;

		/* send my connection id's */
		msg = psucp_con_get_info_msg(ci, (unsigned long)con);

		pscom_precon_send(con->precon, PSCOM_INFO_UCP_ID, msg, psucp_info_msg_length(msg));
		free(msg);

		break; /* Next is PSCOM_INFO_UCP_ID or PSCOM_INFO_ARCH_NEXT */
	}
	case PSCOM_INFO_UCP_ID: {
		psucp_info_msg_t *msg = data;
		assert(sizeof(*msg) <= size);
		assert(psucp_info_msg_length(msg) <= size);

		if (psucp_con_connect(con->arch.ucp.ci, msg)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Something failed. Cleanup. */
		pscom_ucp_con_cleanup(con);
		break; /* Done. Ucp failed */
	case PSCOM_INFO_ARCH_OK:
		pscom_con_guard_start(con);
		break;
	case PSCOM_INFO_EOF:
		pscom_ucp_init_con(con);
		break; /* Done. Use Ucp */
	}
	return;
	/* --- */
error_con_connect:
error_con_init:
	pscom_ucp_con_cleanup(con);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


#ifndef PSCOM_ALLIN_UCP
PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin = {
#else
pscom_plugin_t pscom_plugin_ucp = {
#endif
	.name		= "ucp",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_UCP,
	.priority	= PSCOM_UCP_PRIO,

	.init		= pscom_ucp_init,
	.destroy	= pscom_ucp_destroy,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_init	= pscom_ucp_con_init,
	.con_handshake	= pscom_ucp_handshake,
};
