/*
 * ParaStation
 *
 * Copyright (C) 2011 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author: Thomas Moschny <moschny@par-tec.com>
 */
/**
 * pscom_psm.c: PSM communication
 */

#include "pscom_psm.h"
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_async.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pspsm.h"


typedef struct {
	struct pscom_poll_reader poll;
	unsigned poll_user; // count the users which wait for progress
} pspsm_poll_t;

static pspsm_poll_t pspsm_poll;


static
void poll_user_inc(void)
{
	if (!pspsm_poll.poll_user) {
		/* enqueue to polling reader */
		list_add_tail(&pspsm_poll.poll.next, &pscom.poll_reader);
	}
	pspsm_poll.poll_user++;
}


static
void poll_user_dec(void)
{
	pspsm_poll.poll_user--;
	if (!pspsm_poll.poll_user) {
		/* dequeue from polling reader */
		list_del_init(&pspsm_poll.poll.next);
	}
}


static
void pscom_psm_read_start(pscom_con_t *con)
{
	if (!con->arch.psm.reading) {
		con->arch.psm.reading = 1;
		poll_user_inc();
	}
	/* post a receive */
	pscom_psm_do_read(con);
}


static
void pscom_psm_read_stop(pscom_con_t *con)
{
	if (con->arch.psm.reading) {
		con->arch.psm.reading = 0;
		poll_user_dec();
	}
}


static
int pscom_psm_make_progress(pscom_poll_reader_t *reader)
{
	return pspsm_progress();
}


static
int pscom_psm_do_read(pscom_con_t *con)
{
	pspsm_con_info_t *ci = con->arch.psm.ci;
	char *rbuf;             /**< buffer to be used for next receive */
	size_t rbuflen;         /**< size of buffer */

	/* old request outstanding? */
	if (pspsm_recv_pending(ci)) return 0;

	/* post a new request */
	pscom_read_get_buf_locked(con, &rbuf, &rbuflen);
	int ret = pspsm_recv_start(ci, rbuf, rbuflen);

	if (ret) goto err;
	return 0;
err:
	errno = -ret;
	pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
	return 1;
}


static
void pscom_psm_do_read_check(pscom_con_t *con)
{
	if (con->arch.psm.reading) {
		/* There is more to read. Post the next receive request */
		pscom_psm_do_read(con);
	}
}


static
void pscom_psm_do_write(pscom_con_t *con)
{
	pspsm_con_info_t *ci = con->arch.psm.ci;
	struct iovec iov[2];

	if (pspsm_send_pending(ci)) {
		/* send in progress. wait for completion before
		   transmiting the next message. */
		return;
	}

	/* FIXME: we might want to send more than one message at a
	   time. */

	/* get and post a new write request */
	pscom_req_t *req = pscom_write_get_iov(con, iov);
	if (req) {
		int ret = pspsm_sendv(ci, iov, req);
		if (ret == 0){
			/* was a direct send */
			size_t size = iov[0].iov_len + iov[1].iov_len;
			pscom_write_done(con, req, size);
		}
		else if (ret == -EAGAIN){
			/* pspsm_sendv was successful, send is pending. */
		}
		else if (ret == -EPIPE){
			errno = -ret;
			pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
		}
	}
}


static
volatile unsigned cleanup_wait_count = 0;

static
void pscom_psm_con_cleanup_delayed(void *ci_priv)
{
	pspsm_con_info_t *ci = ci_priv;
	pspsm_progress();
	pspsm_con_cleanup(ci);
	pspsm_con_free(ci);
	cleanup_wait_count--;
}


static
void pscom_psm_con_cleanup(pscom_con_t *con)
{
	pspsm_con_info_t *ci = con->arch.psm.ci;
	if (!ci) return;

	cleanup_wait_count++;

	if (pscom.env.psm_close_delay) {
		pspsm_progress();
		pscom_timer(pscom.env.psm_close_delay, pscom_psm_con_cleanup_delayed, ci);
	} else {
		pscom_psm_con_cleanup_delayed(ci);
	}

	con->arch.psm.ci = NULL;
}


static
void pscom_psm_con_close(pscom_con_t *con)
{
	pspsm_con_info_t *ci = con->arch.psm.ci;
	if (!ci) return;

	pscom_psm_con_cleanup(con);
}


static
void pscom_psm_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_PSM;

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_psm_read_start;
	con->read_stop = pscom_psm_read_stop;

	con->do_write = pscom_psm_do_write;
	con->close = pscom_psm_con_close;

	pscom_con_setup_ok(con);
}


static
void pscom_psm_init(void)
{
	pspsm_debug = pscom.env.debug;
	pspsm_debug_stream = pscom_debug_stream();

	/* see comment in pspsm_init() */
	pscom_env_get_uint(&pscom.env.psm_uniq_id, ENV_PSM_UNIQ_ID);
	if (!pscom.env.psm_uniq_id) {
		pscom_env_get_uint(&pscom.env.psm_uniq_id, ENV_PMI_ID);
	}
	pscom_env_get_uint(&pspsm_devcheck, ENV_PSM_DEVCHECK);

	INIT_LIST_HEAD(&pspsm_poll.poll.next);
	pspsm_poll.poll.do_read = pscom_psm_make_progress;

	// Preinitialize pspsm. Ignore errors. pscom_psm_connect will see the error again.

	pscom_env_get_uint(&pscom.env.psm_fastinit, ENV_PSM_FASTINIT);
	if (pscom.env.psm_fastinit) pspsm_init();

	pscom_env_get_uint(&pscom.env.psm_close_delay, ENV_PSM_CLOSE_DELAY);
}


#define PSCOM_INFO_PSM_ID PSCOM_INFO_ARCH_STEP1


static
int pscom_psm_con_init(pscom_con_t *con)
{
	return pspsm_init();
}


static
void pscom_psm_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		pspsm_info_msg_t msg;
		pspsm_con_info_t *ci = pspsm_con_create();

		con->arch.psm.ci = ci;
		con->arch.psm.reading = 0;

		if (pspsm_con_init(ci, con)) goto error_con_init;

		/* send my connection id's */
		pspsm_con_get_info_msg(ci, &msg);

		pscom_precon_send(con->precon, PSCOM_INFO_PSM_ID, &msg, sizeof(msg));
		break; /* Next is PSCOM_INFO_PSM_ID or PSCOM_INFO_ARCH_NEXT */
	}
	case PSCOM_INFO_PSM_ID: {
		pspsm_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		if (pspsm_con_connect(con->arch.psm.ci, msg)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Something failed. Cleanup. */
		pscom_psm_con_cleanup(con);
		break; /* Done. Psm failed */
	case PSCOM_INFO_EOF:
		pscom_psm_init_con(con);
		break; /* Done. Use Psm */
	}
	return;
	/* --- */
error_con_connect:
error_con_init:
	pscom_psm_con_cleanup(con);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


static
void pscom_psm_finalize(void){
	pspsm_dprint(D_DBG_V, "pspsm_psm_finalize wait for close (%u)", cleanup_wait_count);
	while (cleanup_wait_count) {
		pscom_progress(pscom.ufd_timeout != -1 ? pscom.ufd_timeout : 100);
	}
	pspsm_dprint(D_DBG_V, "pspsm_psm_finalize done");

	if (pspsm_close_endpoint() == -1) goto err;
	if (pspsm_finalize_mq() == -1) goto err;
	return;
 err:
	pspsm_dprint(D_WARN, "pspsm_psm_finalize not successful");
}


/* ToDo: Clean Separation of pscom_psm_* and pspsm_* */
#include "pspsm.c"

#ifndef PSCOM_ALLIN_PSM2
pscom_plugin_t pscom_plugin =
#else
pscom_plugin_t pscom_plugin_psm =
#endif
{
	.name		= "psm",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_PSM,
	.priority	= PSCOM_PSM_PRIO,
	.init		= pscom_psm_init,
	.destroy	= pscom_psm_finalize,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_init	= pscom_psm_con_init,
	.con_handshake	= pscom_psm_handshake,
};
