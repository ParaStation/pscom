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
#include "pscom_extoll.h"


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
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psex_con_info_t *ci = con->arch.extoll.ci;
		len = iov[0].iov_len + iov[1].iov_len;

		int rlen = psex_sendv(ci, iov, len);

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
void pscom_extoll_close(pscom_con_t *con)
{
	psex_con_info_t *ci = con->arch.extoll.ci;

	if (!ci) return;

	psex_send_eof(ci);

	psex_con_cleanup(ci);
	psex_con_free(ci);

	con->arch.extoll.ci = NULL;
}


static
void pscom_extoll_con_init(pscom_con_t *con, int con_fd,
			   psex_con_info_t *ci)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_EXTOLL;

	close(con_fd);

	con->arch.extoll.ci = ci;
	con->arch.extoll.reading = 0;

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = pscom_extoll_rma2_do_read;
	con->do_write = pscom_extoll_rma2_do_write;
	con->close = pscom_extoll_close;

//	con->rma_mem_register = pscom_extoll_rma_mem_register;
//	con->rma_mem_deregister = pscom_extoll_rma_mem_deregister;
//	con->rma_read = pscom_extoll_rma_read;

	con->rendezvous_size = pscom.env.rendezvous_size_extoll;
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
}


static
void pscom_extoll_destroy(void)
{
}


static
int pscom_extoll_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_EXTOLL;
	psex_con_info_t *ci = psex_con_create();
	psex_info_msg_t msg;
	psex_info_msg_t my_msg;

	if (!ci) goto err_no_ci;
	if (psex_init()) goto dont_use;  /* Dont use extoll */

	if (psex_con_init(ci, NULL, con)) goto dont_use; /* Initialize connection */

	/* We want talk extoll */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_EXTOLL))
		goto err_remote;

	/* step 2 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	/* step 3: send my connection id's */
	psex_con_get_info_msg(ci, &my_msg);
	pscom_writeall(con_fd, &my_msg, sizeof(my_msg));


	/* Connect */
	if (psex_con_connect(ci, &msg)) {
		/* ToDo: bad! How to inform the peer about the error? */
		DPRINT(0, "Extoll psex_con_connect() failed!");
		goto err_local;
	}

	pscom_extoll_con_init(con, con_fd, ci);

	return 1;
	/* --- */
err_local:
err_remote:
	psex_con_cleanup(ci);
dont_use:
	psex_con_free(ci);
err_no_ci:
	return 0;
}


static
int pscom_extoll_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_EXTOLL;
	psex_con_info_t *ci = psex_con_create();
	psex_info_msg_t msg;

	if (!ci) goto err_no_ci;
	if (psex_init()) goto out_noextoll;

	if (psex_con_init(ci, NULL, con)) goto dont_use; /* Initialize connection */

	/* step 1:  Yes, we talk extoll. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's */
	psex_con_get_info_msg(ci, &msg);
	pscom_writeall(con_fd, &msg, sizeof(msg));

	/* step 3 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	/* Connect */
	if (psex_con_connect(ci, &msg)) {
		/* ToDo: bad! How to inform the peer about the error? */
		DPRINT(0, "Extoll psex_con_connect() failed!");
		goto err_local;
	}

	pscom_extoll_con_init(con, con_fd, ci);

	return 1;
	/* --- */
err_local:
err_remote:
	if (ci) psex_con_cleanup(ci);
	if (ci) psex_con_free(ci);
	return 0;
	/* --- */
dont_use:
out_noextoll:
	psex_con_free(ci);
err_no_ci:
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use extoll */
	/* --- */
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
	.con_connect	= pscom_extoll_connect,
	.con_accept	= pscom_extoll_accept,
};
