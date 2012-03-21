/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_dapl.c: DAPL communication
 */

#include "psdapl.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_priv.h"
#include "pscom_io.h"
#include "pscom_dapl.h"

typedef struct psdapl_info_msg {
	DAT_SOCK_ADDR sock_addr;
	DAT_CONN_QUAL conn_qual;
} psdapl_info_msg_t;


static
int _pscom_dapl_do_read(pscom_con_t *con, psdapl_con_info_t *ci)
{
	void *buf;
	int size;

	size = psdapl_recvlook(ci, &buf);

	if (size >= 0) {
		pscom_read_done(con, buf, size);

		psdapl_recvdone(ci);
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
int pscom_dapl_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	psdapl_con_info_t *ci = con->arch.dapl.ci;

	return _pscom_dapl_do_read(con, ci);
}


static
void pscom_dapl_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psdapl_con_info_t *ci = con->arch.dapl.ci;
		len = iov[0].iov_len + iov[1].iov_len;

		int rlen = psdapl_sendv(ci, iov, len);

		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
		} else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
			// Busy: Maybe out of tokens? try to read more tokens:
			_pscom_dapl_do_read(con, ci);
		} else {
			// Error
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}


/*
 * RMA
 */

typedef struct pscom_rendezvous_data_dapl {
	struct psdapl_rdma_req	rma_req;
	pscom_req_t		*rendezvous_req;
} pscom_rendezvous_data_dapl_t;


static inline
pscom_rendezvous_data_dapl_t *get_req_data(pscom_rendezvous_data_t *rd)
{
	_pscom_rendezvous_data_dapl_t *data = &rd->arch.dapl;
	pscom_rendezvous_data_dapl_t *res = (pscom_rendezvous_data_dapl_t *) data;
	assert(sizeof(*res) <= sizeof(*data));
	return res;
}


static
unsigned int pscom_dapl_rma_mem_register(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_dapl_t *dapl_rd = get_req_data(rd);
	psdapl_con_info_t *ci = con->arch.dapl.ci;

	/* get mem region */
	psdapl_mregion_cache_t *mreg =
		psdapl_get_mregion(rd->msg.data, rd->msg.data_len, ci);
	if (!mreg)
		goto err_get_region;

	dapl_rd->rma_req.mreg = mreg;

	rd->msg.arch.dapl.rmr_context = psdapl_get_rmr_context(mreg);
	rd->msg.arch.dapl.rmr_vaddr = psdapl_get_rmr_vaddr(rd->msg.data);

	return sizeof(rd->msg.arch.dapl);
err_get_region:
	// ToDo: Count get_mregion errors!
	dapl_rd->rma_req.mreg = NULL;
	return 0;
}


static
void pscom_dapl_rma_mem_deregister(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_dapl_t *dapl_rd = get_req_data(rd);

	if (dapl_rd->rma_req.mreg) {
		psdapl_put_mregion(dapl_rd->rma_req.mreg);
		dapl_rd->rma_req.mreg = NULL;
	}
}


static
void pscom_dapl_rma_read_io_done(psdapl_rdma_req_t *dreq)
{
	pscom_rendezvous_data_dapl_t *dapl_rd =
		(pscom_rendezvous_data_dapl_t *)dreq->priv;

	pscom_req_t *rendezvous_req = dapl_rd->rendezvous_req;

	/* called via
	   _psdapl_sendv() -> psdapl_flush_evd() ->
	   do_DTO_COMPLETION_EVENT() -> io_done.

	   we have the global lock!
	   Use locked version of req_done: */

	_pscom_recv_req_done(rendezvous_req);
}


static
int pscom_dapl_rma_read(pscom_req_t *rendezvous_req, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_dapl_t *dapl_rd = get_req_data(rd);
	psdapl_rdma_req_t *dreq = &dapl_rd->rma_req;
	pscom_con_t *con = get_con(rendezvous_req->pub.connection);
	psdapl_con_info_t *ci = con->arch.dapl.ci;


	dreq->ci = ci;
	dreq->rmr_context = rd->msg.arch.dapl.rmr_context;
	dreq->rmr_vaddr = rd->msg.arch.dapl.rmr_vaddr;
	dreq->lmr_buf = rendezvous_req->pub.data;
	dreq->size = rendezvous_req->pub.data_len;

	dreq->io_done = pscom_dapl_rma_read_io_done;
	dreq->priv = dapl_rd;

	dapl_rd->rendezvous_req = rendezvous_req;

	return psdapl_post_rdma_get(dreq);
}


/* RMA end */

static
void pscom_dapl_close(pscom_con_t *con)
{
	psdapl_con_info_t *ci = con->arch.dapl.ci;

	if (!ci) return;

	psdapl_send_eof(ci);

	psdapl_con_destroy(ci);

	con->arch.dapl.ci = NULL;
}


static
void pscom_dapl_con_init(pscom_con_t *con, int con_fd,
			 psdapl_con_info_t *ci)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_DAPL;

	close(con_fd);

	con->arch.dapl.ci = ci;

	// Only Polling:
	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = pscom_dapl_do_read;
	con->do_write = pscom_dapl_do_write;
	con->close = pscom_dapl_close;

	con->rma_mem_register = pscom_dapl_rma_mem_register;
	con->rma_mem_deregister = pscom_dapl_rma_mem_deregister;
	con->rma_read = pscom_dapl_rma_read;

	con->rendezvous_size = pscom.env.rendezvous_size_dapl;
}

/*********************************************************************/
static
void pscom_dapl_init(void)
{
	psdapl_debug = pscom.env.debug;
	psdapl_debug_stream = pscom_debug_stream();
}


static
psdapl_socket_t *glob_sock = NULL;


static
void pscom_dapl_destroy(void)
{
	if (!glob_sock) return;

	psdapl_socket_put(glob_sock);
	glob_sock = NULL;
}


static
psdapl_socket_t *pscom_dapl_get_sock(void)
{
	if (glob_sock) return glob_sock;

	glob_sock = psdapl_socket_create();
	if (glob_sock) psdapl_socket_hold(glob_sock);

	return glob_sock;
}


static
int pscom_dapl_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_DAPL;
	psdapl_con_info_t *ci = psdapl_con_create(pscom_dapl_get_sock());
	psdapl_info_msg_t msg;
	int err;

	if (!ci) goto dont_use;  /* Dont use dapl */

	/* We want talk dapl */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_DAPL))
		goto err_remote;

	/* step 2 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
		goto err_remote;

	err = psdapl_connect(ci, &msg.sock_addr, msg.conn_qual);
	if (err) goto err_connect;

	pscom_dapl_con_init(con, con_fd, ci);

	return 1;
	/* --- */
err_connect:
err_remote:
dont_use:
	if (ci) {
		psdapl_con_destroy(ci);
	}
	return 0;
}


static
int pscom_dapl_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_DAPL;
	psdapl_socket_t *sock = pscom_dapl_get_sock();
	psdapl_con_info_t *ci = psdapl_con_create(sock);
	psdapl_info_msg_t msg;

	if (!ci) goto out_nodapl;

	if (psdapl_listen(sock))
		goto err_listen;

	/* step 1:  Yes, we talk dapl. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's */
	memcpy(&msg.sock_addr, psdapl_socket_get_addr(sock), sizeof(msg.sock_addr));
	msg.conn_qual = psdapl_socket_get_conn_qual(sock);

	pscom_writeall(con_fd, &msg, sizeof(msg));

	if (psdapl_accept_wait(ci))
		goto err_accept;

	pscom_dapl_con_init(con, con_fd, ci);

	return 1;
	/* --- */
err_accept:
err_listen:
	if (ci) {
		psdapl_con_destroy(ci);
	}
out_nodapl:
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use dapl */
	/* --- */
}


pscom_plugin_t pscom_plugin = {
	.name		= "dapl",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_DAPL,
	.priority	= PSCOM_DAPL_PRIO,

	.init		= pscom_dapl_init,
	.destroy	= pscom_dapl_destroy,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_connect	= pscom_dapl_connect,
	.con_accept	= pscom_dapl_accept,
};
