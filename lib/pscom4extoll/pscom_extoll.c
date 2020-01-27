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
 * pscom_extoll.c: EXTOLL communication
 */

#include "psextoll.h"

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
#include "pscom_extoll.h"

static struct {
	struct pscom_poll_reader reader; // pscom_extoll_make_progress
	unsigned reader_user;
} pscom_extoll;


static
void reader_inc(void)
{
	if (!pscom_extoll.reader_user) {
		// enqueue to polling reader
		list_add_tail(&pscom_extoll.reader.next, &pscom.poll_reader);
	}
	pscom_extoll.reader_user++;
}


static
void reader_dec(void)
{
	pscom_extoll.reader_user--;
	if (!pscom_extoll.reader_user) {
		// dequeue from polling reader
		list_del_init(&pscom_extoll.reader.next);
	}
}

static
int pscom_extoll_make_progress(pscom_poll_reader_t *reader)
{
	psex_progress();
	return 0; // Nothing received
}



static
int _pscom_extoll_rma2_do_read(pscom_con_t *con, psex_con_info_t *ci)
{
	void *buf;
	int size;

	size = psex_recvlook(ci, &buf);

	if (size >= 0) {
		pscom_read_done(con, buf, size);

		psex_recvdone(ci);
		return 1;
	} else if ((size == -EINTR) || (size == -EAGAIN)) {
		// Nothing received
		pscom_con_check_read_stop(con);
		return 0;
	} else {
		// Error
		errno = -size;
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
		return 1;
	}
}


static
int pscom_extoll_rma2_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	psex_con_info_t *ci = con->arch.extoll.ci;

	return _pscom_extoll_rma2_do_read(con, ci);
}


static
void pscom_extoll_rma2_do_write(pscom_con_t *con)
{
	size_t len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psex_con_info_t *ci = con->arch.extoll.ci;
		len = iov[0].iov_len + iov[1].iov_len;

		ssize_t rlen = psex_sendv(ci, iov, len);

		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Maybe out of tokens? try to read more tokens:
			_pscom_extoll_rma2_do_read(con, ci);
		} else {
			// Error
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}


static
void pscom_extoll_con_cleanup(pscom_con_t *con)
{
	psex_con_info_t *ci = con->arch.extoll.ci;
	if (!ci) return;

	psex_con_cleanup(ci);
	psex_con_free(ci);

	con->arch.extoll.ci = NULL;
}


static
void pscom_extoll_con_close(pscom_con_t *con)
{
	psex_con_info_t *ci = con->arch.extoll.ci;
	if (!ci) return;

	pscom_extoll_con_cleanup(con);
	reader_dec();
}


static
void pscom_extoll_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_EXTOLL;

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = pscom_extoll_rma2_do_read;
	con->do_write = pscom_extoll_rma2_do_write;
	con->close = pscom_extoll_con_close;

//	con->rma_mem_register = pscom_extoll_rma_mem_register;
//	con->rma_mem_deregister = pscom_extoll_rma_mem_deregister;
//	con->rma_read = pscom_extoll_rma_read;

	con->rendezvous_size = pscom.env.rendezvous_size_extoll;

	reader_inc();
	pscom_con_setup_ok(con);
}


/*********************************************************************/
static
void pscom_extoll_init(void)
{
	psex_debug = pscom.env.debug;
	psex_debug_stream = pscom_debug_stream();

	pscom_env_get_uint(&psex_recvq_size, ENV_EXTOLL_RECVQ_SIZE);

	pscom_env_get_int(&psex_global_sendq, ENV_EXTOLL_GLOBAL_SENDQ);

	if (psex_global_sendq) {
		// One sendq for all connection. Allocate buffers for 1024 connections
		psex_sendq_size = 1024 * pscom_min(psex_sendq_size, psex_recvq_size);
	} else {
		// One sendq for each connection. limit sendq to recvq size.
		psex_sendq_size = pscom_min(psex_sendq_size, psex_recvq_size);
	}
	pscom_env_get_uint(&psex_sendq_size, ENV_EXTOLL_SENDQ_SIZE);

	psex_pending_tokens = psex_pending_tokens_suggestion();
	pscom_env_get_uint(&psex_pending_tokens, ENV_EXTOLL_PENDING_TOKENS);

//	if (!psex_global_sendq && psex_sendq_size == psex_recvq_size) {
//		// Disable event counting:
//		psex_event_count = 0;
//	}
	pscom_env_get_int(&psex_event_count, ENV_EXTOLL_EVENT_CNT);

	INIT_LIST_HEAD(&pscom_extoll.reader.next);
	pscom_extoll.reader.do_read = pscom_extoll_make_progress;
	pscom_extoll.reader_user = 0;
}


static
void pscom_extoll_destroy(void)
{
}

#define PSCOM_INFO_EXTOLL_ID PSCOM_INFO_ARCH_STEP1


static
int pscom_extoll_con_init(pscom_con_t *con)
{
	return psex_init();
}


static
void pscom_extoll_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		psex_info_msg_t msg;
		psex_con_info_t *ci = psex_con_create();

		con->arch.extoll.ci = ci;
		con->arch.extoll.reading = 0;

		if (psex_con_init(ci, NULL, con)) goto error_con_init;

		/* send my connection id's */
		psex_con_get_info_msg(ci, &msg);

		pscom_precon_send(con->precon, PSCOM_INFO_EXTOLL_ID, &msg, sizeof(msg));
		break; /* Next is PSCOM_INFO_EXTOLL_ID or PSCOM_INFO_ARCH_NEXT */
	}
	case PSCOM_INFO_EXTOLL_ID: {
		psex_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		if (psex_con_connect(con->arch.extoll.ci, msg)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Something failed. Cleanup. */
		pscom_extoll_con_cleanup(con);
		break; /* Done. Extoll failed */
	case PSCOM_INFO_EOF:
		pscom_extoll_init_con(con);
		break; /* Done. Use Extoll */
	}
	return;
	/* --- */
error_con_connect:
error_con_init:
	pscom_extoll_con_cleanup(con);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


pscom_plugin_t pscom_plugin = {
	.name		= "extoll",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_EXTOLL,
	.priority	= PSCOM_EXTOLL_PRIO,

	.init		= pscom_extoll_init,
	.destroy	= pscom_extoll_destroy,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_init	= pscom_extoll_con_init,
	.con_handshake	= pscom_extoll_handshake,
};
