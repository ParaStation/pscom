/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
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

pscom_env_table_entry_t pscom_env_table_psm [] = {
	{"FASTINIT", "1",
	 "If enabled, psm2_init() is called from within pscom4psm plugin init, "
	 "otherwise on first usage of a pscom4psm connection.",
	 &pscom.env.psm_fastinit, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"CLOSE_DELAY", "1000",
	 "Delayed call to psm2_ep_disconnect2() in milliseconds.",
	 &pscom.env.psm_close_delay, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"PSM_UNIQ_ID", "0",
	 "Unsigned integer used to seed the PSM UUID. If unset or zero, PMI_ID "
	 "is checked. If also unset or zero, a constant seed is used.",
	 &pscom.env.psm_uniq_id, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"DEVCHECK", "1",
	 "Enable/disable checking for any of the following device files:"
	 "/dev/ipath{,0,1},/dev/hfi{1,2}{,_0,_1,_2}",
	 &pspsm_devcheck, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{NULL},
};

typedef struct {
	pscom_poll_t	poll_read;
	unsigned poll_user; // count the users which wait for progress
} pspsm_poll_t;

static pspsm_poll_t pspsm_poll;


static
int pscom_psm_make_progress(pscom_poll_t *poll);


static
void poll_user_inc(void)
{
	if (!pspsm_poll.poll_user) {
		/* enqueue to polling reader */
		pscom_poll_start(&pspsm_poll.poll_read, pscom_psm_make_progress, &pscom.poll_read);
	}
	pspsm_poll.poll_user++;
}


static
void poll_user_dec(void)
{
	pspsm_poll.poll_user--;
	if (!pspsm_poll.poll_user) {
		/* dequeue from polling reader */
		pscom_poll_stop(&pspsm_poll.poll_read);
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
	pscom_psm_post_recv(con);
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
int pscom_psm_make_progress(pscom_poll_t *poll)
{
	return pspsm_progress();
}


static
int pscom_psm_post_recv(pscom_con_t *con)
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
void pscom_psm_post_recv_check(pscom_con_t *con)
{
	if (con->arch.psm.reading) {
		/* There is more to read. Post the next receive request */
		pscom_psm_post_recv(con);
	}
}


static
int pscom_psm_do_write(pscom_poll_t *poll)
{
	pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);
	pspsm_con_info_t *ci = con->arch.psm.ci;
	struct iovec iov[2];

	if (pspsm_send_pending(ci)) {
		/* send in progress. wait for completion before
		   transmiting the next message. */
		return 0;
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
	return 0;
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
void pscom_poll_write_start_psm(pscom_con_t *con) {
	pscom_poll_write_start(con, pscom_psm_do_write);
}


static
void pscom_psm_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_PSM;

	con->write_start = pscom_poll_write_start_psm;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_psm_read_start;
	con->read_stop = pscom_psm_read_stop;

	con->close = pscom_psm_con_close;

	pscom_con_setup_ok(con);
}


static
void pscom_psm_init(void)
{
	pspsm_debug = pscom.env.debug;
	pspsm_debug_stream = pscom_debug_stream();

	/* register the environment configuration table */
	pscom_env_table_register_and_parse("pscom PSM", "PSM_",
					   pscom_env_table_psm);

	/* see comment in pspsm_init() */
	if (!pscom.env.psm_uniq_id) {
		/* TODO: Support overwrites with different name */
		pscom_env_get_uint(&pscom.env.psm_uniq_id, ENV_PMI_ID);
	}

	pscom_poll_init(&pspsm_poll.poll_read);
	pspsm_poll.poll_user = 0;

	// Preinitialize pspsm. Ignore errors. pspsm_connect will see the error again.

	if (pscom.env.psm_fastinit) pspsm_init();
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
PSCOM_PLUGIN_API_EXPORT
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
