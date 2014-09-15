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
void pscom_mxm_close(pscom_con_t *con)
{
	psmxm_con_info_t *ci = con->arch.mxm.ci;

	if (!ci) return;

	// ToDo: implement psmxm_send_eof() and send EOF.

	psmxm_con_cleanup(ci);
	psmxm_con_free(ci);

	con->arch.mxm.ci = NULL;
}


static
void pscom_mxm_con_init(pscom_con_t *con, int con_fd,
			psmxm_con_info_t *ci)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_MXM;

	close(con_fd);

	con->arch.mxm.ci = ci;
	con->arch.mxm.reading = 0;
	con->arch.mxm.sreq = NULL;

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_mxm_read_start;
	con->read_stop = pscom_mxm_read_stop;

	con->do_write = pscom_mxm_do_write;
	con->close = pscom_mxm_close;
}


static
void pscom_mxm_init(void)
{
	psmxm_debug = pscom.env.debug;
	psmxm_debug_stream = pscom_debug_stream();

	INIT_LIST_HEAD(&psmxm_poll.poll.next);
	psmxm_poll.poll.do_read = pscom_mxm_make_progress;
/*
  Disabled. Init will be called with the first connect.
	// Preinitialize psmxm. Ignore errors. pscom_mxm_connect will see the error again.
	psmxm_init();
*/
}


static
int pscom_mxm_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_MXM;
	psmxm_con_info_t *ci = psmxm_con_create();
	psmxm_info_msg_t msg;
	psmxm_info_msg_t my_msg;

	if (psmxm_init() || !ci) goto dont_use;
	if (psmxm_con_init(ci)) goto dont_use;

	/* We want talk mxm */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_MXM)) {
		goto err_remote;
	}

	/* step 2 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg))) {
		goto err_remote;
	}

	/* step 3: send my connection id's */
	psmxm_con_get_info_msg(ci, &my_msg);
	pscom_writeall(con_fd, &my_msg, sizeof(my_msg));

	/* Connect */
	if (psmxm_con_connect(ci, &msg, con)) {
		/* ToDo: bad! How to inform the peer about the error? */
		DPRINT(0, "Mxm psmxm_con_connect() failed!");
		goto err_local;
	}

	pscom_mxm_con_init(con, con_fd, ci);

	return 1;
	/* --- */
 err_local:
 err_remote:
 dont_use:
	if (ci) {
		psmxm_con_cleanup(ci);
		psmxm_con_free(ci);
	}
	return 0;
}


static
int pscom_mxm_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_MXM;
	psmxm_con_info_t *ci = psmxm_con_create();
	psmxm_info_msg_t msg;

	if (psmxm_init() || !ci) goto out_nomxm;
	if (psmxm_con_init(ci)) goto dont_use;

	/* step 1:  Yes, we talk mxm. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send Connection id's */
	psmxm_con_get_info_msg(ci, &msg);
	pscom_writeall(con_fd, &msg, sizeof(msg));

	/* step 3 : recv connection id's */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg))) {
		goto err_remote;
	}

	/* Connect */
	if (psmxm_con_connect(ci, &msg, con)) {
		/* ToDo: bad! How to inform the peer about the error? */
		DPRINT(0, "Mxm psmxm_con_connect() failed!");
		goto err_local;
	}

	pscom_mxm_con_init(con, con_fd, ci);

	return 1;
	/* --- */
 err_local:
 err_remote:
	if (ci) psmxm_con_cleanup(ci);
 dont_use:
	if (ci) psmxm_con_free(ci);
	return 0;
	/* --- */
 out_nomxm:
	arch = PSCOM_ARCH_ERROR;
	pscom_writeall(con_fd, &arch, sizeof(arch));
	return 0;
	/* --- */
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
	.con_connect	= pscom_mxm_connect,
	.con_accept	= pscom_mxm_accept,
};
