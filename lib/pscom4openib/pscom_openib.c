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

#include "pscom_priv.h"
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_openib.h"


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
	int size;

	size = psoib_recvlook(mcon, &buf);

	if (size >= 0) {
		pscom_read_done(con, buf, size);

		psoib_recvdone(mcon);
		return 1;
	} else if ((size == -EINTR) || (size == -EAGAIN)) {
		// Nothing received
		return 0;
	} else {
		// Error
		errno = -size;
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
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psoib_con_info_t *mcon = con->arch.openib.mcon;
		len = iov[0].iov_len + iov[1].iov_len;

		int rlen = psoib_sendv(mcon, iov, len);

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

	psoib_send_eof(mcon);
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
