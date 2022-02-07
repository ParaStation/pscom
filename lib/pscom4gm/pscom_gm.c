/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psport_gm.c: GM Myrinet communication
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>


#include "pscom_priv.h"
#include "pscom_gm.h"

#include "psgm.h"

static
int _pscom_gm_do_read(psgm_sock_t *sock)
{
	void *con_id;
	void *buf;
	unsigned int size;

	void *handle = psgm_recvlook(&con_id, &buf, &size);

	if (handle) {
		pscom_con_t *con = con_id;

		assert(con->magic == MAGIC_CONNECTION);
		pscom_read_done(con, buf, size);

		psgm_recvdone(handle);

		return 1;
	}
	return 0;
// Cant detect errors here?
//	pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
}


static
int pscom_gm_do_read(pscom_poll_t *poll)
{
	psgm_sock_t *sock = list_entry(poll, psgm_sock_t, poll_read);
	return _pscom_gm_do_read(sock);
}


static
void pscom_gm_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psgm_con_info_t *gmcon = con->arch.gm.gmcon;

		len = iov[0].iov_len + iov[1].iov_len;

		int rlen = psgm_sendv(gmcon, iov, len);

		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Maybe out of tokens? try to read more tokens:
			psgm_sock_t *sock = &get_sock(con->pub.socket)->gm;
			_pscom_gm_do_read(sock);
		} else {
			// Error
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}


static
void pscom_gm_read_start(pscom_con_t *con)
{
	if (!con->arch.gm.reading) {
		psgm_sock_t *sock = &get_sock(con->pub.socket)->gm;

		con->arch.gm.reading = 1;
		if (!sock->readers) {
			// enqueue to polling reader
			list_add_tail(&sock->poll_reader.next, &pscom.poll_reader);
		}
		sock->readers++;
	}
}


static
void pscom_gm_read_stop(pscom_con_t *con)
{
	if (con->arch.gm.reading) {
		psgm_sock_t *sock = &get_sock(con->pub.socket)->gm;

		con->arch.gm.reading = 0;
		sock->readers--;
		if (sock->readers <= 0) {
			// deque from polling reader
			list_del_init(&sock->poll_reader.next);
			sock->readers = 0; // should be useless
		}
	}
}


static
void pscom_gm_close(pscom_con_t *con)
{
	psgm_con_info_t *gmcon = con->arch.gm.gmcon;

	if (!gmcon) return;

	psgm_con_cleanup(gmcon);
	psgm_con_free(gmcon);

	con->arch.gm.gmcon = NULL;
}


static
void pscom_gm_con_init(pscom_con_t *con, int con_fd,
		       psgm_con_info_t *gmcon)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_GM;

	close(con_fd);

	con->arch.gm.gmcon = gmcon;
	con->arch.gm.reading = 0;

	// Send: polling on all connections
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->do_write = pscom_gm_do_write;

	// Recv: polling on socket
	con->read_start = pscom_gm_read_start;
	con->read_stop = pscom_gm_read_stop;

	con->close = pscom_gm_close;
}

/*********************************************************************/
static
void pscom_gm_init(void)
{
	psgm_debug = pscom.env.debug;
}


static
void pscom_gm_sock_init(pscom_sock_t *sock)
{
	sock->gm.readers = 0;
	psgm_sock_t *gsock = &sock->gm;

	INIT_LIST_HEAD(&gsock->poll_reader.next);
	gsock->poll_reader.do_read = pscom_gm_do_read;
}


static
int pscom_gm_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_GM;
	psgm_con_info_t *gmcon = psgm_con_create();
	psgm_info_msg_t msg;
	int call_cleanup_con = 0;
	int err;

	if (psgm_init() || !gmcon)
		goto dont_use; /* Dont use gm */

	/* We want talk gm */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_GM))
		goto err_remote;

	/* step 2 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	err = psgm_con_init(gmcon, NULL);
	if (!err) {
		call_cleanup_con = 1;
		err = psgm_con_connect(gmcon, NULL, &msg);
	}

	/* step 3 : send connection id's (or error) */
	psgm_con_get_info_msg(gmcon, NULL, con, &msg);
	msg.error = err;

	pscom_writeall(con_fd, &msg, sizeof(msg));

	if (err) goto err_connect;

	/* step 4: gm initialized. Recv final ACK. */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.error)) goto err_ack;

	pscom_gm_con_init(con, con_fd, gmcon);

	return 1;
	/* --- */
err_ack:
err_connect:
	if (call_cleanup_con) psgm_con_cleanup(gmcon);
err_remote:
dont_use:
	if (gmcon) psgm_con_free(gmcon);
	return 0;
}


static
int pscom_gm_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_GM;
	psgm_con_info_t *gmcon = NULL;
	psgm_info_msg_t msg;

	if (psgm_init())
		goto out_nogm;

	gmcon = psgm_con_create();
	if (!gmcon)
		goto out_nogm;

	if (psgm_con_init(gmcon, NULL))
		goto err_con_init;

	/* step 1:  Yes, we talk gm. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's */
	psgm_con_get_info_msg(gmcon, NULL, con, &msg);

	pscom_writeall(con_fd, &msg, sizeof(msg));

	/* step 3 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.error))
		goto err_remote;

	if (psgm_con_connect(gmcon, NULL, &msg))
		goto err_connect_con;

	/* step 4: GM initialized. Send final ACK. */
	msg.error = 0;
	pscom_writeall(con_fd, &msg, sizeof(msg));

	pscom_gm_con_init(con, con_fd, gmcon);

	return 1;
	/* --- */
err_connect_con:
	/* Send NACK */
	msg.error = 1;
	pscom_writeall(con_fd, &msg, sizeof(msg));
err_remote:
	psgm_con_cleanup(gmcon);
err_con_init:
out_nogm:
	if (gmcon) psgm_con_free(gmcon);
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use gm */
}

PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin = {
	.name		= "gm",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_GM,
	.priority	= PSCOM_GM_PRIO,

	.init		= pscom_gm_init,
	.destroy	= NULL,
	.sock_init	= pscom_gm_sock_init,
	.sock_destroy	= NULL,
	.con_connect	= pscom_gm_connect,
	.con_accept	= pscom_gm_accept,
};
