/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_ofed.c: OFED/Infiniband communication (in UD mode)
 */

#include "psofed.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_priv.h"
#include "pscom_ofed.h"

static struct {
	struct pscom_poll_reader reader;
	unsigned reader_user;
} pscom_ofed;


static
void reader_inc(void)
{
	if (!pscom_ofed.reader_user) {
		// enqueue to polling reader
		list_add_tail(&pscom_ofed.reader.next, &pscom.poll_reader);
	}
	pscom_ofed.reader_user++;
}


static
void reader_dec(void)
{
	pscom_ofed.reader_user--;
	if (!pscom_ofed.reader_user) {
		// dequeue from polling reader
		list_del_init(&pscom_ofed.reader.next);
	}
}


static
void pscom_ofed_read_start(pscom_con_t *con)
{
	if (!con->arch.ofed.reading) {
		con->arch.ofed.reading = 1;
		reader_inc();
	}
}


static
void pscom_ofed_read_stop(pscom_con_t *con)
{
	if (con->arch.ofed.reading) {
		con->arch.ofed.reading = 0;
		reader_dec();
	}
}


static
int pscom_ofed_do_read(pscom_poll_reader_t *reader)
{
	psofed_recv_t *msg = psofed_recv(NULL);

	if (msg) {
		pscom_con_t *con = msg->priv;

		if (msg->len >= 0) {
			// Got data
			pscom_read_done(con, msg->data, msg->len);
			psofed_recvdone(NULL);
		} else {
			// Error
			errno = -msg->len;
			pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
		}
		return 1;
	} else {
		// Nothing received
		return 0;
	}
}


static
void pscom_ofed_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psofed_con_info_t *mcon = con->arch.ofed.mcon;
		len = iov[0].iov_len + iov[1].iov_len;

		int rlen = psofed_sendv(mcon, iov, len);

		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
			// psofed_progress();
			// Make progress with cq events:
			pscom_ofed_do_read(NULL);
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Maybe out of tokens? try to read more tokens:
			pscom_ofed_do_read(NULL);
		} else {
			// Error
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}


static
void pscom_ofed_close(pscom_con_t *con)
{
	psofed_con_info_t *mcon = con->arch.ofed.mcon;

	if (!mcon) return;

	psofed_send_eof(mcon);

	psofed_con_cleanup(mcon);
	psofed_con_free(mcon);

	con->arch.ofed.mcon = NULL;
}


static
void pscom_ofed_con_init(pscom_con_t *con, int con_fd,
			   psofed_con_info_t *mcon)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_OFED;

	close(con_fd);

	con->arch.ofed.mcon = mcon;
	con->arch.ofed.reading = 0;
	psofed_con_set_priv(mcon, con);

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_ofed_read_start;
	con->read_stop = pscom_ofed_read_stop;

	con->do_write = pscom_ofed_do_write;
	con->close = pscom_ofed_close;
}

/*********************************************************************/
static
void pscom_ofed_init(void)
{
	psofed_debug = pscom.env.debug;
	psofed_debug_stream = pscom_debug_stream();
	pscom_env_get_str(&psofed_hca, ENV_OFED_HCA);
	pscom_env_get_uint(&psofed_port, ENV_OFED_PORT);
	pscom_env_get_uint(&psofed_path_mtu, ENV_OFED_PATH_MTU);

	pscom_env_get_uint(&psofed_compq_size, ENV_OFED_COMPQ_SIZE);
	pscom_env_get_uint(&psofed_sendq_size, ENV_OFED_SENDQ_SIZE);
	pscom_env_get_uint(&psofed_recvq_size, ENV_OFED_RECVQ_SIZE);

	psofed_pending_tokens = psofed_pending_tokens_suggestion();
	pscom_env_get_uint(&psofed_pending_tokens, ENV_OFED_PENDING_TOKENS);

	pscom_env_get_uint(&psofed_winsize, ENV_OFED_WINSIZE);

	{
		unsigned int auint;
		auint = psofed_resend_timeout;
		pscom_env_get_uint(&auint, ENV_OFED_RESEND_TIMEOUT);
		psofed_resend_timeout = auint;
	}

	pscom_env_get_uint(&psofed_resend_timeout_shift, ENV_OFED_RESEND_TIMEOUT_SHIFT);
	pscom_env_get_int(&psofed_event_count, ENV_OFED_EVENT_CNT);

	INIT_LIST_HEAD(&pscom_ofed.reader.next);
	pscom_ofed.reader.do_read = pscom_ofed_do_read;
	pscom_ofed.reader_user = 0;
}


static
int pscom_ofed_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_OFED;
	psofed_con_info_t *mcon = psofed_con_create();
	psofed_info_msg_t msg;
	int call_cleanup_con = 0;
	int err;

	if (psofed_init() || !mcon)
		goto dont_use;  /* Dont use ofed */

	/* We want talk ofed */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_OFED))
		goto err_remote;

	/* step 2 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	err = psofed_con_init(mcon, NULL);
	if (!err) {
		call_cleanup_con = 1;
		err = psofed_con_connect(mcon, &msg);
	}

	/* step 3 : send connection id's (or error) */
	if (!err) {
		psofed_con_get_info_msg(mcon, &msg);
	} else {
		msg.lid = 0xffff; // send error
	}

	pscom_writeall(con_fd, &msg, sizeof(msg));

	if (err) goto err_connect;

	/* step 4: ofed initialized. Recv final ACK. */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.lid == 0xffff)) goto err_ack;

	pscom_ofed_con_init(con, con_fd, mcon);

	return 1;
	/* --- */
err_ack:
err_connect:
	if (call_cleanup_con) psofed_con_cleanup(mcon);
err_remote:
dont_use:
	if (mcon) psofed_con_free(mcon);
	return 0;
}


static
int pscom_ofed_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_OFED;
	psofed_con_info_t *mcon = NULL;
	psofed_info_msg_t msg;

	if (psofed_init())
		goto out_noofed;

	mcon = psofed_con_create();
	if (!mcon)
		goto out_noofed;

	if (psofed_con_init(mcon, NULL))
		goto err_con_init;

	/* step 1:  Yes, we talk ofed. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's */
	psofed_con_get_info_msg(mcon, &msg);

	pscom_writeall(con_fd, &msg, sizeof(msg));

	/* step 3 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.lid == 0xffff))
		goto err_remote;

	if (psofed_con_connect(mcon, &msg))
		goto err_connect_con;

	/* step 4: OFED mem initialized. Send final ACK. */
	msg.lid = 0;
	pscom_writeall(con_fd, &msg, sizeof(msg));

	pscom_ofed_con_init(con, con_fd, mcon);

	return 1;
	/* --- */
err_connect_con:
	/* Send NACK */
	msg.lid = 0xffff;
	pscom_writeall(con_fd, &msg, sizeof(msg));
err_remote:
	psofed_con_cleanup(mcon);
err_con_init:
out_noofed:
	if (mcon) psofed_con_free(mcon);
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use ofed */
	/* --- */
}


pscom_plugin_t pscom_plugin = {
	.name		= "ofed",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_OFED,
	.priority	= PSCOM_OFED_PRIO,

	.init		= pscom_ofed_init,
	.destroy	= NULL,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_connect	= pscom_ofed_connect,
	.con_accept	= pscom_ofed_accept,
};
