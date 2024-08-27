/*
 * ParaStation
 *
 * Copyright (C) 2010-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_extoll.c: EXTOLL communication
 */

#include "pscom_extoll.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/uio.h>

#include "list.h"
#include "pscom.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_io.h"
#include "pscom_plugin.h"
#include "pscom_poll.h"
#include "pscom_precon.h"
#include "pscom_priv.h"
#include "psextoll.h"


static pscom_env_table_entry_t pscom_env_table_velo[] = {
    {"RENDEZVOUS", "1024", "The rendezvous threshold for pscom4velo.",
     &pscom.env.rendezvous_size_velo, PSCOM_ENV_ENTRY_HAS_PARENT,
     PSCOM_ENV_PARSER_UINT},

#ifdef PSEX_USE_MREGION_CACHE
    {"MCACHE_SIZE", "6",
     "Maximum number of entries in the memory registration cache. Minimum "
     "1, i.e., cannot be disabled at runtime.",
     &psex_mregion_cache_max_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},
#endif
    {0},
};


static struct {
    pscom_poll_t poll_read; // pscom_extoll_velo2_do_read
    unsigned reader_user;
} pscom_extoll;


static int pscom_extoll_velo2_do_read(pscom_poll_t *poll);


static void reader_inc(void)
{
    if (!pscom_extoll.reader_user) {
        // enqueue to polling reader
        pscom_poll_start(&pscom_extoll.poll_read, pscom_extoll_velo2_do_read,
                         &pscom.poll_read);
    }
    pscom_extoll.reader_user++;
}


static void reader_dec(void)
{
    pscom_extoll.reader_user--;
    if (!pscom_extoll.reader_user) {
        // dequeue from polling reader
        pscom_poll_stop(&pscom_extoll.poll_read);
    }
}


static void pscom_extoll_velo2_read_start(pscom_con_t *con)
{
    if (!con->arch.extoll.reading) {
        con->arch.extoll.reading = 1;
        reader_inc();
    }
}


static void pscom_extoll_velo2_read_stop(pscom_con_t *con)
{
    if (con->arch.extoll.reading) {
        con->arch.extoll.reading = 0;
        reader_dec();
    }
}


static int pscom_extoll_velo2_do_read(pscom_poll_t *poll)
{
    char msg[PSEX_VELO2_MTU];
    pscom_con_t *con = NULL;
    int msg_len      = psex_velo2_recv(NULL, (void **)&con, msg, sizeof(msg));

    if (con) {
        if (msg_len >= 0) {
            // Got data
            pscom_read_done(con, msg, msg_len);
        } else {
            // Error
            // msglen == -EAGAIN implies con==NULL and is handled below
            // in "Nothing received".
            errno = -msg_len;
            pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
        }
        return 1;
    } else {
        // Nothing received
        return 0;
    }
}


static int pscom_extoll_velo2_do_write(pscom_poll_t *poll)
{
    pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;

    req = pscom_write_get_iov(con, iov);

    if (req) {
        psex_con_info_t *ci = con->arch.extoll.ci;
        len                 = iov[0].iov_len + iov[1].iov_len;

        int rlen = psex_velo2_sendv(ci, iov, len);

        if (rlen >= 0) {
            pscom_write_done(con, req, rlen);
        } else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
            // Busy. Try again later
        } else {
            // Error
            errno = -rlen;
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }
    return 0;
}


/*
 * RMA rendezvous
 */

typedef struct pscom_rendezvous_data_extoll {
    struct psex_rma_req rma_req;
    pscom_req_t *rendezvous_req; // Receiving side: users receive request (or
                                 // generated request)
} pscom_rendezvous_data_extoll_t;


static inline pscom_rendezvous_data_extoll_t *
get_req_data(pscom_rendezvous_data_t *rd)
{
    _pscom_rendezvous_data_extoll_t *data = &rd->arch.extoll;
    pscom_rendezvous_data_extoll_t *res = (pscom_rendezvous_data_extoll_t *)data;
    assert(sizeof(*res) <= sizeof(*data));
    return res;
}


static unsigned int pscom_extoll_rma_mem_register(pscom_con_t *con,
                                                  pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_extoll_t *extoll_rd = get_req_data(rd);
    psex_con_info_t *ci                       = con->arch.extoll.ci;
    psex_mregion_t *mreg                      = &extoll_rd->rma_req.mreg;
    /* get mem region */
    int err = psex_get_mregion(mreg, rd->msg.data, rd->msg.data_len, ci);
    if (err) { goto err_get_region; }

    rd->msg.arch.extoll.rma2_nla = mreg->rma2_nla;

    return sizeof(rd->msg.arch.extoll);
err_get_region:
    // ToDo: Count get_mregion errors!
    return 0;
}


static void pscom_extoll_rma_mem_deregister(pscom_con_t *con,
                                            pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_extoll_t *extoll_rd = get_req_data(rd);
    psex_mregion_t *mreg                      = &extoll_rd->rma_req.mreg;
    psex_con_info_t *ci                       = con->arch.extoll.ci;

    psex_put_mregion(mreg, ci);
}


static void pscom_extoll_rma_read_io_done(psex_rma_req_t *dreq)
{
    pscom_rendezvous_data_extoll_t *extoll_rd =
        (pscom_rendezvous_data_extoll_t *)dreq->priv;
    pscom_req_t *rendezvous_req = extoll_rd->rendezvous_req;
    psex_mregion_t *mreg        = &extoll_rd->rma_req.mreg;
    psex_con_info_t *ci         = dreq->ci;

    psex_put_mregion(mreg, ci);

    /* called via
       psex_handle_notification() -> io_done.

       we have the global lock!
       Use locked version of req_done: */

    _pscom_recv_req_done(rendezvous_req);
}


static int pscom_extoll_rma_read(pscom_req_t *rendezvous_req,
                                 pscom_rendezvous_data_t *rd)
{
    pscom_rendezvous_data_extoll_t *extoll_rd = get_req_data(rd);
    psex_rma_req_t *dreq                      = &extoll_rd->rma_req;
    pscom_con_t *con    = get_con(rendezvous_req->pub.connection);
    psex_con_info_t *ci = con->arch.extoll.ci;
    int err;

    err = psex_get_mregion(&dreq->mreg, rendezvous_req->pub.data,
                           rendezvous_req->pub.data_len, ci);
    assert(!err); // ToDo: Catch error

    dreq->rma2_nla = rd->msg.arch.extoll.rma2_nla; // nla of the sender
    dreq->data_len = rendezvous_req->pub.data_len;
    dreq->ci       = ci;
    dreq->io_done  = pscom_extoll_rma_read_io_done;
    dreq->priv     = extoll_rd;

    extoll_rd->rendezvous_req = rendezvous_req;

    return psex_post_rma_gets(dreq);
}

/* RMA rendezvous end */

#if 0
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
		pscom_con_check_read_stop(con);
		return 0;
	} else {
		// Error
		errno = -size;
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
		return 1;
	}
}


static
int pscom_extoll_rma2_do_read(pscom_poll_t *poll)
{
	pscom_con_t *con = list_entry(poll, pscom_con_t, poll_read);
	psex_con_info_t *ci = con->arch.extoll.ci;

	return _pscom_extoll_rma2_do_read(con, ci);
}


static
void pscom_extoll_rma_do_write(pscom_con_t *con)
{
	size_t len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		psex_con_info_t *ci = con->arch.extoll.ci;
		len = iov[0].iov_len + iov[1].iov_len;

		ssize_t rlen = psex_sendv(ci, iov, len);

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
#endif // #if 0

static void pscom_extoll_con_cleanup(pscom_con_t *con)
{
    psex_con_info_t *ci = con->arch.extoll.ci;
    if (!ci) { return; }

    psex_con_cleanup(ci);
    psex_con_free(ci);

    con->arch.extoll.ci = NULL;
}


static void pscom_extoll_con_close(pscom_con_t *con)
{
    psex_con_info_t *ci = con->arch.extoll.ci;
    if (!ci) { return; }

    pscom_extoll_con_cleanup(con);
}


static void pscom_poll_write_start_extoll(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_extoll_velo2_do_write);
}


static void pscom_extoll_init_con(pscom_con_t *con)
{
    con->pub.type = PSCOM_CON_TYPE_VELO;

#ifdef PSCOM_CUDA_AWARENESS
    con->is_gpu_aware = pscom.env.cuda && pscom.env.cuda_aware_velo;
#endif

    // Read
    con->read_start = pscom_extoll_velo2_read_start;
    con->read_stop  = pscom_extoll_velo2_read_stop;

    // Write with polling:
    con->write_start = pscom_poll_write_start_extoll;
    con->write_stop  = pscom_poll_write_stop;

    con->close = pscom_extoll_con_close;

    con->rndv.mem_register   = pscom_extoll_rma_mem_register;
    con->rndv.mem_deregister = pscom_extoll_rma_mem_deregister;
    con->rndv.rma_read       = pscom_extoll_rma_read;

    con->rendezvous_size = pscom.env.rendezvous_size_velo;

    pscom_con_setup_ok(con);
}

/*********************************************************************/
static void pscom_extoll_init(void)
{
    psex_debug        = pscom.env.debug;
    psex_debug_stream = pscom_debug_stream();

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom VELO", "VELO_",
                                       pscom_env_table_velo);

#ifndef DISABLE_RMA2
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
#endif

#ifdef PSEX_USE_MREGION_CACHE
    if (!psex_mregion_cache_max_size) {
        psex_mregion_cache_max_size = 1; // 0 not allowed.
    }
#endif

    pscom_poll_init(&pscom_extoll.poll_read);
    pscom_extoll.reader_user = 0;
}


static void pscom_extoll_destroy(void)
{
}


#define PSCOM_INFO_EXTOLL_ID PSCOM_INFO_ARCH_STEP1


static int pscom_extoll_con_init(pscom_con_t *con)
{
    return psex_init();
}


static void pscom_extoll_handshake(pscom_con_t *con, int type, void *data,
                                   unsigned size)
{
    switch (type) {
    case PSCOM_INFO_ARCH_REQ: {
        psex_info_msg_t msg;
        psex_con_info_t *ci = psex_con_create();

        con->arch.extoll.ci      = ci;
        con->arch.extoll.reading = 0;

        if (psex_con_init(ci, NULL, con)) { goto error_con_init; }

        /* send my connection id's */
        psex_con_get_info_msg(ci, &msg);

        pscom_precon_send(con->precon, PSCOM_INFO_EXTOLL_ID, &msg, sizeof(msg));
        break; /* Next is PSCOM_INFO_EXTOLL_ID or PSCOM_INFO_ARCH_NEXT */
    }
    case PSCOM_INFO_EXTOLL_ID: {
        psex_info_msg_t *msg = data;
        assert(sizeof(*msg) == size);

        if (psex_con_connect(con->arch.extoll.ci, msg)) {
            goto error_con_connect;
        }

        pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
        break; /* Next is EOF or ARCH_NEXT */
    }
    case PSCOM_INFO_ARCH_NEXT:
        /* Something failed. Cleanup. */
        pscom_extoll_con_cleanup(con);
        break; /* Done. Extoll failed */
    case PSCOM_INFO_EOF:
        pscom_extoll_init_con(con);
        break; /* Done. Use Extoll */
    }
    return;
    /* --- */
error_con_connect:
error_con_init:
    pscom_extoll_con_cleanup(con);
    pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin_velo = {
    .name     = "velo",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_VELO,
    .priority = PSCOM_EXTOLL_PRIO,

    .init          = pscom_extoll_init,
    .destroy       = pscom_extoll_destroy,
    .sock_init     = NULL,
    .sock_destroy  = NULL,
    .con_init      = pscom_extoll_con_init,
    .con_handshake = pscom_extoll_handshake,
};
