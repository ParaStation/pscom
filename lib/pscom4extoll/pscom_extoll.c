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
#include <sys/types.h>
#include <sys/uio.h>

#include "list.h"
#include "pscom.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_plugin.h"
#include "pscom_poll.h"
#include "pscom_precon.h"
#include "pscom_priv.h"
#include "psextoll.h"


static pscom_err_t pscom_extoll_parser_set_pending_tokens(void *buf,
                                                          const char *config_val)
{
    const char *set_val = config_val ? config_val
                                     : psex_pending_tokens_suggestion_str();

    return pscom_env_parser_set_config_uint(buf, set_val);
}


static pscom_err_t pscom_extoll_parser_set_sendq_size(void *buf,
                                                      const char *config_val)
{
    pscom_err_t ret;
    ret = pscom_env_parser_set_config_uint(buf, config_val);

    if (psex_global_sendq) {
        /* one sendq for all connection; buffers for 1024 connections */
        psex_sendq_size = 1024 * pscom_min(psex_sendq_size, psex_recvq_size);
    } else {
        /* one sendq for each connection. limit sendq to recvq size */
        psex_sendq_size = pscom_min(psex_sendq_size, psex_recvq_size);
    }

    return ret;
}


#define PSCOM_EXTOLL_PARSER_PENDING_TOKENS                                     \
    {                                                                          \
        pscom_extoll_parser_set_pending_tokens,                                \
            pscom_env_parser_get_config_int                                    \
    }

#define PSCOM_EXTOLL_PARSER_SENDQ_SIZE                                         \
    {                                                                          \
        pscom_extoll_parser_set_sendq_size, pscom_env_parser_get_config_uint   \
    }


static pscom_env_table_entry_t pscom_env_table_extoll[] = {
    {"RENDEZVOUS", PSCOM_ENV_UINT_INF_STR,
     "The rendezvous threshold for pscom4extoll.",
     &pscom.env.rendezvous_size_extoll, PSCOM_ENV_ENTRY_HAS_PARENT,
     PSCOM_ENV_PARSER_UINT},

    {"RECVQ_SIZE", "16", "Number of receive buffers per connection.",
     &psex_recvq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_UINT},

    {"GLOBAL_SENDQ", "0", "Enable/disable global send queue.",
     &psex_global_sendq, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_INT},

    {"SENDQ_SIZE", "16", "Number of send buffers per connection.",
     &psex_sendq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_EXTOLL_PARSER_SENDQ_SIZE},

    {"EVENT_CNT", "0",
     "Enable/disable busy polling if psex_pending_global_sends is to high.",
     &psex_event_count, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_INT},

    {"PENDING_TOKENS", NULL, "Number of tokens for incoming packets.",
     &psex_pending_tokens, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_EXTOLL_PARSER_PENDING_TOKENS},

    {0},
};


static struct {
    pscom_poll_t poll_read; // pscom_extoll_make_progress
    unsigned reader_user;
} pscom_extoll;


static int pscom_extoll_make_progress(pscom_poll_t *poll);


static void reader_inc(void)
{
    if (!pscom_extoll.reader_user) {
        // enqueue to polling reader
        pscom_poll_start(&pscom_extoll.poll_read, pscom_extoll_make_progress,
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

static int pscom_extoll_make_progress(pscom_poll_t *poll)
{
    psex_progress();
    return 0; // Nothing received
}


static int _pscom_extoll_rma2_do_read(pscom_con_t *con, psex_con_info_t *ci)
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


static int pscom_extoll_rma2_do_read(pscom_poll_t *poll)
{
    pscom_con_t *con    = list_entry(poll, pscom_con_t, poll_read);
    psex_con_info_t *ci = con->arch.extoll.ci;

    return _pscom_extoll_rma2_do_read(con, ci);
}


static int pscom_extoll_rma2_do_write(pscom_poll_t *poll)
{
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;
    pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);

    req = pscom_write_get_iov(con, iov);

    if (req) {
        psex_con_info_t *ci = con->arch.extoll.ci;
        len                 = iov[0].iov_len + iov[1].iov_len;

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
    return 0;
}


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
    reader_dec();
}


static void pscom_poll_read_start_extoll(pscom_con_t *con)
{
    pscom_poll_read_start(con, pscom_extoll_rma2_do_read);
}


static void pscom_poll_write_start_extoll(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_extoll_rma2_do_write);
}


static void pscom_extoll_init_con(pscom_con_t *con)
{
    con->pub.type = PSCOM_CON_TYPE_EXTOLL;

#ifdef PSCOM_CUDA_AWARENESS
    con->is_gpu_aware = pscom.env.cuda && pscom.env.cuda_aware_extoll;
#endif

    // Only Polling:
    con->read_start = pscom_poll_read_start_extoll;
    con->read_stop  = pscom_poll_read_stop;

    con->write_start = pscom_poll_write_start_extoll;
    con->write_stop  = pscom_poll_write_stop;

    con->close = pscom_extoll_con_close;

    //	con->rndv.mem_register = pscom_extoll_rma_mem_register;
    //	con->rndv.mem_deregister = pscom_extoll_rma_mem_deregister;
    //	con->rndv.rma_read = pscom_extoll_rma_read;

    con->rendezvous_size = pscom.env.rendezvous_size_extoll;

    reader_inc();
    pscom_con_setup_ok(con);
}


/*********************************************************************/
static void pscom_extoll_init(void)
{
    psex_debug        = pscom.env.debug;
    psex_debug_stream = pscom_debug_stream();

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom EXTOLL", "EXTOLL_",
                                       pscom_env_table_extoll);

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
pscom_plugin_t pscom_plugin_extoll = {
    .name     = "extoll",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_EXTOLL,
    .priority = PSCOM_EXTOLL_PRIO,

    .init          = pscom_extoll_init,
    .destroy       = pscom_extoll_destroy,
    .sock_init     = NULL,
    .sock_destroy  = NULL,
    .con_init      = pscom_extoll_con_init,
    .con_handshake = pscom_extoll_handshake,
};
