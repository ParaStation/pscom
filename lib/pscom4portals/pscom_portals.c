/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_portals.h"
#include "pscom_async.h"
#include "pscom_con.h"
#include "pscom_precon.h"

#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "psptl.h"

pscom_env_table_entry_t pscom_env_table_portals[] = {
    {"BUFFER_SIZE", "8192", "The size of the buffers in the send/recv queues.",
     &psptl.con_params.bufsize, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"RECVQ_SIZE", "16", "Number of receive buffers per connection.",
     &psptl.con_params.recvq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"SENDQ_SIZE", "16", "Number of send buffers per connection.",
     &psptl.con_params.sendq_size, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"EQ_SIZE", "65536", "Size of the event queue.", &psptl.eq_size,
     PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_UINT},

    {0},
};

/*
 * maintain a plugin-wide reader counter, i.e., there is ony one reader for all
 * portals connections
 */
static struct {
    pscom_poll_t poll_read;
    unsigned reader_user;
} pscom_portals_poll;

static int pscom_portals_make_progress(pscom_poll_t *poll);

static void poll_reader_inc(void)
{
    /* enqueue to polling reader if not enqueued yet */
    if (!pscom_portals_poll.reader_user) {
        pscom_poll_start(&pscom_portals_poll.poll_read,
                         pscom_portals_make_progress, &pscom.poll_read);
    }

    /* increase the reader counter */
    pscom_portals_poll.reader_user++;
}

static void poll_reader_dec(void)
{
    /* decrease the reader counter */
    pscom_portals_poll.reader_user--;

    /* dequeue from polling reader if there are no readers left */
    if (!pscom_portals_poll.reader_user) {
        pscom_poll_stop(&pscom_portals_poll.poll_read);
    }
}

static void pscom_portals_read_start(pscom_con_t *con)
{
    /* increment the reader counter if not yet reading */
    if (!con->arch.portals.reading) {
        con->arch.portals.reading = 1;
        poll_reader_inc();
    }
}

static void pscom_portals_read_stop(pscom_con_t *con)
{
    /* decrement the reader counter if this connection is still reading */
    if (con->arch.portals.reading) {
        con->arch.portals.reading = 0;
        poll_reader_dec();
    }
}

static int pscom_portals_make_progress(pscom_poll_t *poll)
{
    return psptl_progress();
}

void pscom_portals_sendv_done(void)
{
    poll_reader_dec();
}

void pscom_portals_recv_done(void *priv, void *buf, size_t len)
{
    pscom_con_t *con = (pscom_con_t *)priv;
    assert(con->magic == MAGIC_CONNECTION);

    pscom_read_done(con, buf, len);
}

static int pscom_portals_do_write(pscom_poll_t *poll)
{
    size_t len;
    struct iovec iov[2];
    pscom_req_t *req;
    pscom_con_t *con = list_entry(poll, pscom_con_t, poll_write);

    /* get a new iov for sending */
    req = pscom_write_get_iov(con, iov);

    if (req) {
        psptl_con_info_t *ci = con->arch.portals.ci;
        len                  = iov[0].iov_len + iov[1].iov_len;

        ssize_t slen = psptl_sendv(ci, iov, len);

        if (slen >= 0) {
            /* ensure execution of the psptl progress engine */
            poll_reader_inc();

            pscom_write_done(con, req, slen);
        } else if (slen != -EAGAIN) {
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }

    return 0;
}

static void pscom_portals_con_cleanup(pscom_con_t *con)
{
    psptl_con_info_t *ci = con->arch.portals.ci;
    if (!ci) return;

    psptl_con_cleanup(ci);
    psptl_con_free(ci);

    con->arch.portals.ci = NULL;
}

static void pscom_portals_con_close(pscom_con_t *con)
{
    psptl_con_info_t *ci = con->arch.portals.ci;
    if (!ci) return;

    pscom_portals_con_cleanup(con);
}

static void pscom_poll_write_start_portals(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_portals_do_write);
}

static void pscom_portals_init_con(pscom_con_t *con)
{
    con->pub.type = PSCOM_CON_TYPE_PORTALS;

    con->write_start = pscom_poll_write_start_portals;
    con->write_stop  = pscom_poll_write_stop;

    con->read_start = pscom_portals_read_start;
    con->read_stop  = pscom_portals_read_stop;

    con->close = pscom_portals_con_close;

    pscom_con_setup_ok(con);
}

static void pscom_portals_init(void)
{
    psptl_configure_debug(pscom_debug_stream(), pscom.env.debug);

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom PORTALS", "PORTALS_",
                                       pscom_env_table_portals);

    pscom_poll_init(&pscom_portals_poll.poll_read);
    pscom_portals_poll.reader_user = 0;
}


static int pscom_portals_con_init(pscom_con_t *con)
{
    return psptl_init();
}

#define PSCOM_INFO_PORTALS_ID PSCOM_INFO_ARCH_STEP1

static void
pscom_portals_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
    switch (type) {
    case PSCOM_INFO_ARCH_REQ: {
        psptl_info_msg_t msg = {0};
        psptl_con_info_t *ci = psptl_con_create();

        con->arch.portals.ci      = ci;
        con->arch.portals.reading = 0;

        if (psptl_con_init(ci, con)) goto error_con_init;

        /* send my connection id's */
        psptl_con_get_info_msg(ci, &msg);

        pscom_precon_send(con->precon, PSCOM_INFO_PORTALS_ID, &msg,
                          sizeof(msg));
        break; /* Next: PSCOM_INFO_PORTALS_ID or PSCOM_INFO_ARCH_NEXT */
    }
    case PSCOM_INFO_PORTALS_ID: {
        psptl_info_msg_t *msg = data;
        assert(sizeof(*msg) == size);

        if (psptl_con_connect(con->arch.portals.ci, msg)) {
            goto error_con_connect;
        }

        pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
        break; /* Next: EOF or ARCH_NEXT */
    }
    case PSCOM_INFO_ARCH_NEXT: {
        /* Something failed. Cleanup. */
        pscom_portals_con_cleanup(con);
        break; /* Done. Portals failed */
    }
    case PSCOM_INFO_ARCH_OK: {
        pscom_con_guard_start(con);
        break;
    }
    case PSCOM_INFO_EOF:
        pscom_portals_init_con(con);
        break; /* Done. Use Portals */
    }
    return;
/* --- */
error_con_connect:
error_con_init:
    pscom_portals_con_cleanup(con);
    pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}

static void pscom_portals_destroy(void)
{
    if (pscom_portals_poll.reader_user) {
        DPRINT(
            D_WARN,
            "Closing the pscom4portals plugin but there are still %u readers!",
            pscom_portals_poll.reader_user);
    }

    /* we do not want to make further progress on the Portals4 layer */
    pscom_poll_stop(&pscom_portals_poll.poll_read);

    psptl_finalize();
}

PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin_portals = {
    .name     = "portals",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_PORTALS,
    .priority = PSCOM_PORTALS_PRIO,

    .init          = pscom_portals_init,
    .destroy       = pscom_portals_destroy,
    .sock_init     = NULL,
    .sock_destroy  = NULL,
    .con_init      = pscom_portals_con_init,
    .con_handshake = pscom_portals_handshake,
};
