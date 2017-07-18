/*
 * ParaStation
 *
 * Copyright (C) 2016 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
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

static struct {
	struct pscom_poll_reader reader; // pscom_ucp_do_read
	unsigned reader_user;
} pscom_ucp;


static
void reader_inc(void)
{
	if (!pscom_ucp.reader_user) {
		// enqueue to polling reader
		list_add_tail(&pscom_ucp.reader.next, &pscom.poll_reader);
	}
	pscom_ucp.reader_user++;
}


static
void reader_dec(void)
{
	pscom_ucp.reader_user--;
	if (!pscom_ucp.reader_user) {
		// dequeue from polling reader
		list_del_init(&pscom_ucp.reader.next);
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
int pscom_ucp_do_read(pscom_poll_reader_t *reader)
{
	psucp_msg_t msg;
	ssize_t rc;

	rc = psucp_probe(&msg);

	if (rc > 0) {
		pscom_con_t *con = (pscom_con_t *)msg.info_tag.sender_tag;
		char *buf;
		size_t len;
		ssize_t rlen;

		assert(con->magic == MAGIC_CONNECTION);

		pscom_read_get_buf(con, &buf, &len);

		rlen = psucp_recv(&msg, buf, len);

//		printf("%s:%u:%s  recv len:%u rlen:%u buf:%s\n", __FILE__, __LINE__, __func__,
//		       (unsigned)len, (unsigned)rlen, pscom_dumpstr(buf, rlen));
		pscom_read_done(con, buf, rlen);
	} else {
		psucp_progress();
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
void pscom_ucp_do_write(pscom_con_t *con)
{
	size_t len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psucp_con_info_t *ci = con->arch.ucp.ci;
		len = iov[0].iov_len + iov[1].iov_len;

		pscom_write_pending(con, req, len);

		ssize_t rlen = psucp_sendv(ci, iov, len,
				       pscom_psucp_sendv_done, req);

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
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
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
void pscom_ucp_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_UCP;

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_ucp_read_start;
	con->read_stop = pscom_ucp_read_stop;

	con->do_write = pscom_ucp_do_write;
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

	// pscom_env_get_uint(&psucp_recvq_size, ENV_UCP_RECVQ_SIZE);
	// pscom_env_get_int(&psucp_global_sendq, ENV_UCP_GLOBAL_SENDQ);
	// pscom_env_get_uint(&psucp_sendq_size, ENV_UCP_SENDQ_SIZE);


	INIT_LIST_HEAD(&pscom_ucp.reader.next);
	pscom_ucp.reader.do_read = pscom_ucp_do_read;
	pscom_ucp.reader_user = 0;
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
		psucp_info_msg_t msg;
		psucp_con_info_t *ci = psucp_con_create();

		con->arch.ucp.ci = ci;
		con->arch.ucp.reading = 0;

		if (psucp_con_init(ci, NULL, con)) goto error_con_init;

		/* send my connection id's */
		psucp_con_get_info_msg(ci, (unsigned long)con, &msg);

		pscom_precon_send(con->precon, PSCOM_INFO_UCP_ID, &msg, sizeof(msg));
		break; /* Next is PSCOM_INFO_UCP_ID or PSCOM_INFO_ARCH_NEXT */
	}
	case PSCOM_INFO_UCP_ID: {
		psucp_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		if (psucp_con_connect(con->arch.ucp.ci, msg)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Something failed. Cleanup. */
		pscom_ucp_con_cleanup(con);
		break; /* Done. Ucp failed */
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


pscom_plugin_t pscom_plugin = {
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
