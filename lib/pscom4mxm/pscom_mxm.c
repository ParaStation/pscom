/*
 * ParaStation
 *
 * Copyright (C) 2014 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author: Jens Hauke <hauke@par-tec.com>
 */

#include "pscom_mxm.h"
#include "psmxm.h"
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_priv.h"

#include <errno.h>


typedef struct {
	struct pscom_poll_reader poll;
	unsigned poll_user; // count the users which wait for progress
} psmxm_poll_t;


static psmxm_poll_t psmxm_poll;

static
void poll_user_inc(void)
{
	if (!psmxm_poll.poll_user) {
		/* enqueue to polling reader */
		list_add_tail(&psmxm_poll.poll.next, &pscom.poll_reader);
	}
	psmxm_poll.poll_user++;
}


static
void poll_user_dec(void)
{
	psmxm_poll.poll_user--;
	if (!psmxm_poll.poll_user) {
		/* dequeue from polling reader */
		list_del_init(&psmxm_poll.poll.next);
	}
}


static
void pscom_mxm_read_start(pscom_con_t *con)
{
	if (!con->arch.mxm.reading) {
		con->arch.mxm.reading = 1;
		poll_user_inc();
	}
}


static
void pscom_mxm_read_stop(pscom_con_t *con)
{
	if (con->arch.mxm.reading) {
		con->arch.mxm.reading = 0;
		poll_user_dec();
	}
}


static
void pscom_process_rreq(psmxm_recv_req_t *rreq)
{
	pscom_con_t *con = (pscom_con_t *)psmxm_recv_req_ctx(rreq);
	size_t length = psmxm_recv_req_length(rreq);

	pscom_read_done(con, rreq->data, length);
	psmxm_recv_release(rreq);
}


static
int pscom_mxm_make_progress(pscom_poll_reader_t *reader)
{
	psmxm_recv_req_t *rreq;
	rreq = psmxm_recv_peek();
	if (rreq) {
		pscom_process_rreq(rreq);
		return 1;
	} else {
		psmxm_progress();
		return 0;
	}
}


static
void pscom_mxm_do_write(pscom_con_t *con)
{
	struct iovec iov[2];
	psmxm_con_info_t *ci = con->arch.mxm.ci;
	pscom_req_t *req = con->arch.mxm.sreq;
	int polling = 0;

	if (req) {
		// proceed with the send from the last iteration.
		polling = 1;
		unsigned sent = psmxm_send_progress(ci);
		if (sent) {
			pscom_write_done(con, req, sent);
		} else {
			/* FIXME: we might want to send more than one message at a
			   time. */
			/* send in progress. wait for completion before
			   transmitting the next message. */
			return;
		}
	}

	/* get and post a new write request */
	req = pscom_write_get_iov(con, iov);
	if (req) {
		int ret = psmxm_sendv(ci, iov, iov[0].iov_len + iov[1].iov_len);
		if (ret > 0){
			/* sending ret bytes. Complete this request in the next iteration. */
			if (!polling) poll_user_inc();
		} else if (ret == -EAGAIN){
			/* Try again later. */
			req = NULL;
		} else {
			assert(ret == -EPIPE);
			errno = -ret;
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
			req = NULL;
		}
	}
	if (!req && polling) poll_user_dec();
	// Remember the current request or NULL in the case of EAGAIN.
	con->arch.mxm.sreq = req;
}


static
void pscom_mxm_con_cleanup(pscom_con_t *con)
{
	psmxm_con_info_t *ci = con->arch.mxm.ci;
	if (!ci) return;

	psmxm_con_cleanup(ci);
	psmxm_con_free(ci);

	con->arch.mxm.ci = NULL;
}


static
void pscom_mxm_con_close(pscom_con_t *con)
{
	psmxm_con_info_t *ci = con->arch.mxm.ci;
	if (!ci) return;

	pscom_mxm_con_cleanup(con);
}


static
void pscom_mxm_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_MXM;

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_mxm_read_start;
	con->read_stop = pscom_mxm_read_stop;

	con->do_write = pscom_mxm_do_write;
	con->close = pscom_mxm_con_close;

	pscom_con_setup_ok(con);
}


static
void pscom_mxm_init(void)
{
	psmxm_debug = pscom.env.debug;
	psmxm_debug_stream = pscom_debug_stream();

	INIT_LIST_HEAD(&psmxm_poll.poll.next);
	psmxm_poll.poll.do_read = pscom_mxm_make_progress;

	pscom_env_get_uint(&psmxm_devcheck, ENV_MXM_DEVCHECK);

/*
  Disabled. Init will be called with the first connect.
	// Preinitialize psmxm. Ignore errors. pscom_mxm_connect will see the error again.
	psmxm_init();
*/
}


#define PSCOM_INFO_MXM_ID PSCOM_INFO_ARCH_STEP1


static
int pscom_mxm_con_init(pscom_con_t *con)
{
	return psmxm_init();
}


static
void pscom_mxm_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		psmxm_info_msg_t msg;
		psmxm_con_info_t *ci = psmxm_con_create();

		con->arch.mxm.ci = ci;
		con->arch.mxm.reading = 0;
		con->arch.mxm.sreq = NULL;

		if (psmxm_con_init(ci)) goto error_con_init;

		/* send my connection id's */
		psmxm_con_get_info_msg(ci, &msg);

		pscom_precon_send(con->precon, PSCOM_INFO_MXM_ID, &msg, sizeof(msg));
		break; /* Next is PSCOM_INFO_MXM_ID or PSCOM_INFO_ARCH_NEXT */
	}
	case PSCOM_INFO_MXM_ID: {
		psmxm_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		if (psmxm_con_connect(con->arch.mxm.ci, msg, con)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Something failed. Cleanup. */
		pscom_mxm_con_cleanup(con);
		break; /* Done. Mxm failed */
	case PSCOM_INFO_EOF:
		pscom_mxm_init_con(con);
		break; /* Done. Use Mxm */
	}
	return;
	/* --- */
error_con_connect:
error_con_init:
	pscom_mxm_con_cleanup(con);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


static
void pscom_mxm_finalize(void){
	if (psmxm_close_endpoint() == -1) goto err;
	return;
 err:
	DPRINT(1, "psmxm_mxm_finalize not successful");
}


pscom_plugin_t pscom_plugin = {
	.name		= "mxm",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_MXM,
	.priority	= PSCOM_MXM_PRIO,
	.init		= pscom_mxm_init,
	.destroy	= pscom_mxm_finalize,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_init	= pscom_mxm_con_init,
	.con_handshake	= pscom_mxm_handshake,
};
