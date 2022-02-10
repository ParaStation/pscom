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
#include "pscom_con.h"
#include "pscom_precon.h"
#include "pscom_ofed.h"

static pscom_err_t
pscom_ofed_env_parser_set_pending_tokens(void *buf,
					 const char *config_val)
{
	const char *set_val =
		config_val ? config_val : psofed_pending_tokens_suggestion_str();

	return pscom_env_parser_set_config_uint(buf, set_val);
}


#define PSCOM_OFED_ENV_PARSER_PENDING_TOKENS {pscom_ofed_env_parser_set_pending_tokens, \
					      pscom_env_parser_get_config_int}


static pscom_env_table_entry_t pscom_env_table_ofed [] = {
	{"HCA", NULL,
	 "Name of the hca to use. (default to the name of the first active "
	 "hca).",
	 &psofed_hca, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_STR},

	{"PORT", NULL,
	 "Port to use (default is first active port).",
	 &psofed_port, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"PATH_MTU", "3",
	 "MTU of the IB packets. (1:256, 2:512, 3:1024.",
	 &psofed_path_mtu, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"COMPQ_SIZE", "2048",
	 "Size of the completion queue queue.",
	 &psofed_compq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RECVQ_SIZE", "1024",
	 "Number of receive buffers per connection.",
	 &psofed_recvq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"SENDQ_SIZE", "1024",
	 "Number of send buffers per connection.",
	 &psofed_sendq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"PENDING_TOKENS", NULL,
	 "Number of tokens for incoming packets.",
	 &psofed_pending_tokens, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_OFED_ENV_PARSER_PENDING_TOKENS},

	{"WINSIZE", "512",
	 "Maximum number of unacked packets.",
	 &psofed_winsize, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RESEND_TIMEOUT", "10000",
	 "Resend in usec. 4 times the timeout on each resend starting with "
	 "psofed_resend_timeout maximal wait: 10000 << 11 =  20.48 sec.",
	 &psofed_resend_timeout, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"RESEND_TIMEOUT_SHIFT", "11",
	 "Never wait longer than: "
	 "psofed_resend_timeout << psofed_resend_timeout_shift",
	 &psofed_resend_timeout_shift, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_UINT},

	{"EVENT_CNT", "1",
	 "Enable/disable busy polling if outstanding_cq_entries is to high.",
	 &psofed_event_count, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{"LID_OFFSET", "0",
	 "Offset to base LID (adaptive routing).",
	 &psofed_lid_offset, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
	 PSCOM_ENV_PARSER_INT},

	{0},
};


static struct {
	pscom_poll_t	poll_read;
	unsigned	reader_user;
} pscom_ofed;


static
int pscom_ofed_do_read(pscom_poll_t *poll);


static
void reader_inc(void)
{
	if (!pscom_ofed.reader_user) {
		// enqueue to polling reader
		pscom_poll_start(&pscom_ofed.poll_read, pscom_ofed_do_read, &pscom.poll_read);
	}
	pscom_ofed.reader_user++;
}


static
void reader_dec(void)
{
	pscom_ofed.reader_user--;
	if (!pscom_ofed.reader_user) {
		// dequeue from polling reader
		pscom_poll_stop(&pscom_ofed.poll_read);
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
int pscom_ofed_do_read(pscom_poll_t *poll)
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
int pscom_ofed_do_write(pscom_poll_t *poll)
{
	struct iovec iov[2];
	pscom_req_t *req;
	pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psofed_con_info_t *mcon = con->arch.ofed.mcon;
		size_t len = iov[0].iov_len + iov[1].iov_len;

		ssize_t rlen = psofed_sendv(mcon, iov, len);

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
	return 0;
}


static
void pscom_ofed_con_cleanup(pscom_con_t *con)
{
	psofed_con_info_t *mcon = con->arch.ofed.mcon;
	if (!mcon) return;

	psofed_con_cleanup(mcon);
	psofed_con_free(mcon);

	con->arch.ofed.mcon = NULL;
}


static
void pscom_ofed_con_close(pscom_con_t *con)
{
	psofed_con_info_t *mcon = con->arch.ofed.mcon;
	if (!mcon) return;

	pscom_ofed_con_cleanup(con);
}


static
void pscom_poll_write_start_ofed(pscom_con_t *con) {
	pscom_poll_write_start(con, pscom_ofed_do_write);
}


static
void pscom_ofed_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_OFED;

	// Only Polling:
	con->read_start = pscom_ofed_read_start;
	con->read_stop = pscom_ofed_read_stop;

	con->write_start = pscom_poll_write_start_ofed;
	con->write_stop = pscom_poll_write_stop;

	con->close = pscom_ofed_con_close;

	pscom_con_setup_ok(con);
}

/*********************************************************************/
static
void pscom_ofed_init(void)
{
	psofed_debug = pscom.env.debug;
	psofed_debug_stream = pscom_debug_stream();

	/* register the environment configuration table */
	pscom_env_table_register_and_parse("pscom OFED", "OFED_",
					   pscom_env_table_ofed);

	pscom_poll_init(&pscom_ofed.poll_read);
	pscom_ofed.reader_user = 0;
}

#define PSCOM_INFO_OFED_ID PSCOM_INFO_ARCH_STEP1


static
int pscom_ofed_con_init(pscom_con_t *con)
{
	return psofed_init();
}


static
void pscom_ofed_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		psofed_info_msg_t msg;
		psofed_con_info_t *mcon = psofed_con_create();

		con->arch.ofed.mcon = mcon;
		con->arch.ofed.reading = 0;

		if (psofed_con_init(mcon, NULL, con)) goto error_con_init;

		/* send my connection id's */
		psofed_con_get_info_msg(mcon, &msg);

		pscom_precon_send(con->precon, PSCOM_INFO_OFED_ID, &msg, sizeof(msg));
		break; /* Next is PSCOM_INFO_OFED_ID or PSCOM_INFO_ARCH_NEXT */
	}
	case PSCOM_INFO_OFED_ID: {
		psofed_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		if (psofed_con_connect(con->arch.ofed.mcon, msg)) goto error_con_connect;

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		break; /* Next is EOF or ARCH_NEXT */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Something failed. Cleanup. */
		pscom_ofed_con_cleanup(con);
		break; /* Done. Ofed failed */
	case PSCOM_INFO_EOF:
		pscom_ofed_init_con(con);
		break; /* Done. Use Ofed */
	}
	return;
	/* --- */
error_con_connect:
error_con_init:
	pscom_ofed_con_cleanup(con);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin_ofed = {
	.name		= "ofed",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_OFED,
	.priority	= PSCOM_OFED_PRIO,

	.init		= pscom_ofed_init,
	.destroy	= NULL,
	.sock_init	= NULL,
	.sock_destroy	= NULL,
	.con_init	= pscom_ofed_con_init,
	.con_handshake	= pscom_ofed_handshake,
};
