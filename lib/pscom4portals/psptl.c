/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <assert.h>
#include <errno.h>
#include <portals4.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pscom_debug.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include "psptl.h"

/* define some ME-related flags */
#define PSPTL_PUT_FLAGS                                                        \
    (PTL_ME_EVENT_LINK_DISABLE | PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_OP_PUT)
#define PSPTL_USE_ONCE (PTL_ME_USE_ONCE)
#define PSPTL_RMA_WRITE_FLAGS                                                  \
    (PSPTL_PUT_FLAGS | PTL_ME_EVENT_COMM_DISABLE | PTL_ME_USE_ONCE)

#define psptl_dprint(debug_level, fmt, arg...)                                 \
    do {                                                                       \
        if ((debug_level) <= psptl.debug.level) {                              \
            fprintf(psptl.debug.stream ? psptl.debug.stream : stderr,          \
                    "portals:" fmt "\n", ##arg);                               \
        }                                                                      \
    } while (0);

typedef struct psptl_bucket psptl_bucket_t;

struct psptl_hca_info {
    ptl_handle_ni_t nih;
    ptl_handle_eq_t eqh[PSPTL_PROT_COUNT];
    ptl_handle_md_t mdh[PSPTL_PROT_COUNT];
    ptl_pt_index_t pti[PSPTL_PROT_COUNT];
    union {
        ptl_process_t ptl_pid;
        uint64_t raw;
    } pid;
};

typedef struct psptl_remote_con_info {
    union {
        ptl_process_t ptl_pid;
        uint64_t raw;
    } pid;
    ptl_pt_index_t pti[PSPTL_PROT_COUNT];
} psptl_remote_con_info_t;

struct psptl_con_info {
    psptl_hca_info_t *hca_info;
    psptl_remote_con_info_t remote_ci;
    uint64_t send_seq_id;
    uint64_t recv_seq_id;
    uint64_t rndv_seq_id;
    uint64_t outstanding_put_ops;
    uint32_t outstanding_rndv_reqs;
    struct {
        void *mem;
        psptl_bucket_t *buckets;
        uint32_t cur;
    } send_buffers;
    struct {
        void *mem;
        psptl_bucket_t *buckets;
    } recv_buffers;

    void *con_priv; /**< the pscom_con_t object */
    struct list_head pending_recvs;
    struct list_head next;
};

typedef struct psptl_bucket {
    psptl_con_info_t *con_info;
    void *buf;
    size_t len;
    uint64_t seq_id;
    uint64_t match_bits;
    uint64_t ignore_bits;
    uint8_t in_use;
    ptl_handle_me_t meh;
    struct list_head next;
} psptl_bucket_t;

psptl_hca_info_t default_hca;

psptl_t psptl = {
    .hca_info = &default_hca,
    .debug =
        {
            .level  = 2,
            .stream = NULL,
        },
    .stats =
        {
            .retry_cnt           = 0,
            .outstanding_put_ops = 0,
            .rndv_write          = 0,
            .rndv_retry          = 0,
        },
    .init_state   = PSPORTALS_NOT_INITIALIZED,
    .cleanup_cons = LIST_HEAD_INIT(psptl.cleanup_cons),
};

/**
 * @brief Remove a receive bucket from the list of pending buckets
 *
 * @param bucket The bucket to be removed from the list of pending buckets of
 *               this connection.
 */
static inline void psptl_pending_bucket_remove(psptl_bucket_t *bucket)
{
    list_del_init(&bucket->next);
}


/**
 * @brief Insert a receive bucket with new data into the list of pending buckets
 *
 * This is only necessary if the sequence number of this bucket does not match
 * the expected sequence number on the receiving side. In this case, its
 * processing is postponed until all preceding buckets have been received.
 *
 * @param bucket The bucket to be inserted in the pending list of buckets of
 *               this connection.
 */
static inline void psptl_pending_bucket_insert(psptl_bucket_t *bucket)
{
    struct list_head *pos;
    psptl_con_info_t *con_info = bucket->con_info;

    /* find the correct position according to the sequence number */
    list_for_each (pos, &con_info->pending_recvs) {
        psptl_bucket_t *cur_recv_bucket = list_entry(pos, psptl_bucket_t, next);

        if (bucket->seq_id < cur_recv_bucket->seq_id) break;
    }

    /* insert the bucket */
    list_add_tail(&bucket->next, pos);
}


static const char *psptl_prot_str(psptl_prot_type_t protocol)
{
    static char buf[100];

    switch (protocol) {
    case PSPTL_PROT_EAGER: return "PSPTL_PROT_EAGER";
    case PSPTL_PROT_RNDV: return "PSPTL_PROT_RNDV";
    default: {
        snprintf(buf, sizeof(buf), "unknown protocol (%d)", protocol);
        return buf;
    }
    }
}


static const char *psptl_err_str(int error)
{
    static char buf[100];

    switch (error) {
    case PTL_ARG_INVALID: return "Invalid argument passed";
    case PTL_CT_NONE_REACHED: {
        return "Timeout reached before any counting event reached the "
               "test";
    }
    case PTL_EQ_DROPPED: return "At least one event has been dropped";
    case PTL_EQ_EMPTY: return "No events available in an event queue";
    case PTL_FAIL: return "Error during initialization";
    case PTL_IGNORED: return "Logical map set failed";
    case PTL_IN_USE: return "MD, ME, or LE has pending operations";
    case PTL_INTERRUPTED: return "wait/get operation was interrupted";
    case PTL_LIST_TOO_LONG: return "List too long";
    case PTL_NO_INIT: return "Uninitialized API";
    case PTL_NO_SPACE: return "Insufficient memory";
    case PTL_OK: return "Success";
    case PTL_PID_IN_USE: return "Pid is in use";
    case PTL_PT_EQ_NEEDED: {
        return "EQ must be attached when flow control is enabled";
    }
    case PTL_PT_FULL: return "Portal table is full";
    case PTL_PT_IN_USE: return "Portal table index is busy";
    }

    snprintf(buf, sizeof(buf), "error %d", error);
    return buf;
}


static const char *psptl_event_str(ptl_event_t event)
{
    static char buf[100];

    switch (event.type) {
    case PTL_EVENT_GET: return "PTL_EVENT_GET";
    case PTL_EVENT_GET_OVERFLOW: return "PTL_EVENT_GET_OVERFLOW";

    case PTL_EVENT_PUT: return "PTL_EVENT_PUT";
    case PTL_EVENT_PUT_OVERFLOW: return "PTL_EVENT_PUT_OVERFLOW";

    case PTL_EVENT_ATOMIC: return "PTL_EVENT_ATOMIC";
    case PTL_EVENT_ATOMIC_OVERFLOW: return "PTL_EVENT_ATOMIC_OVERFLOW";

    case PTL_EVENT_FETCH_ATOMIC: return "PTL_EVENT_FETCH_ATOMIC";
    case PTL_EVENT_FETCH_ATOMIC_OVERFLOW: {
        return "PTL_EVENT_FETCH_ATOMIC_OVERFLOW";
    }
    case PTL_EVENT_REPLY: return "PTL_EVENT_REPLY";
    case PTL_EVENT_SEND: return "PTL_EVENT_SEND";
    case PTL_EVENT_ACK: return "PTL_EVENT_ACK";

    case PTL_EVENT_PT_DISABLED: return "PTL_EVENT_PT_DISABLED";
    case PTL_EVENT_LINK: return "PTL_EVENT_LINK";
    case PTL_EVENT_AUTO_UNLINK: return "PTL_EVENT_AUTO_UNLINK";
    case PTL_EVENT_AUTO_FREE: return "PTL_EVENT_AUTO_FREE";
    case PTL_EVENT_SEARCH: return "PTL_EVENT_SEARCH";
    }

    snprintf(buf, sizeof(buf), "event %d", event.type);
    return buf;
}


static int psptl_register_recv_buffer(psptl_bucket_t *recv_bucket,
                                      uint32_t options, int32_t list,
                                      ptl_pt_index_t pti, size_t len)
{
    int ret;
    psptl_hca_info_t *hca_info = psptl.hca_info;
    psptl_con_info_t *con_info = recv_bucket->con_info;

    /* create a list entry for the receive buffer */
    ptl_me_t me = {
        .start      = recv_bucket->buf,        /* start address */
        .length     = len,                     /* size of the mem region*/
        .uid        = PTL_UID_ANY,             /* any usage ID */
        .options    = options,                 /* ME-related flags */
        .match_bits = recv_bucket->match_bits, /* bits to be matched */
        .match_id =
            con_info->remote_ci.pid.ptl_pid, /* only messages from the peer */
        .ignore_bits = recv_bucket->ignore_bits, /* bits to be ignored */
    };

    /* append it to the matching list */
    ret = PtlMEAppend(hca_info->nih, pti, &me, list, recv_bucket,
                      &recv_bucket->meh);
    if (ret != PTL_OK) goto err_out;

    psptl_dprint(D_TRACE, "PtlMEAppend (%p; %p; %p)\n", recv_bucket,
                 recv_bucket->con_info, recv_bucket->buf);

    return 0;
    /* --- */
err_out:
    psptl_dprint(D_ERR, "PtlMEAppend() failed: '%s'", psptl_err_str(ret));
    return -1;
}


static void psptl_deregister_recv_buffer(psptl_bucket_t *recv_bucket)
{
    int ret;

    ret = PtlMEUnlink(recv_bucket->meh);
    if (ret != PTL_OK) goto err_out;

    psptl_dprint(D_TRACE, "PtlMEUnlink (%p; %p; %p)\n", recv_bucket,
                 recv_bucket->con_info, recv_bucket->buf);

    return;
    /* --- */
err_out:
    psptl_dprint(D_ERR, "PtlMEUnlink() failed: '%s'", psptl_err_str(ret));
    return;
}


static int psptl_create_recv_queue(uint32_t num_bufs, size_t buf_len,
                                   psptl_con_info_t *con_info)
{
    uint32_t i;
    ssize_t ret;
    psptl_hca_info_t *hca_info = con_info->hca_info;

    /* allocate memory for the receive buffers */
    con_info->recv_buffers.mem = malloc(num_bufs * buf_len);
    assert(con_info->recv_buffers.mem);

    /* allocate memory for the buckets of the receive buffers */
    con_info->recv_buffers.buckets = (psptl_bucket_t *)
        calloc(num_bufs, sizeof(psptl_bucket_t));

    /* initialize the buckets and register for receiving data */
    for (i = 0; i < num_bufs; ++i) {
        void *buf                  = con_info->recv_buffers.mem + buf_len * i;
        psptl_bucket_t *cur_bucket = &con_info->recv_buffers.buckets[i];
        uint32_t flags             = (PSPTL_PUT_FLAGS | PSPTL_USE_ONCE);

        cur_bucket->buf         = buf;
        cur_bucket->con_info    = con_info;
        cur_bucket->match_bits  = 0;
        cur_bucket->ignore_bits = ~0;
        INIT_LIST_HEAD(&cur_bucket->next);

        /* register the memory region */
        ret = psptl_register_recv_buffer(cur_bucket, flags, PTL_PRIORITY_LIST,
                                         hca_info->pti[PSPTL_PROT_EAGER],
                                         buf_len);
        if (ret < 0) goto err_out;
    }

    return 0;
    /* --- */
err_out:
    psptl_dprint(D_ERR, "Failed to register overflow buffer %u/%u\n", i,
                 num_bufs);
    return -1;
}


static void
psptl_destroy_recv_queue(psptl_con_info_t *con_info, uint32_t num_bufs)
{
    if (con_info->recv_buffers.buckets) {
        /* deregister the buckets */
        for (uint32_t i = 0; i < num_bufs; ++i) {
            psptl_bucket_t *cur_bucket = &con_info->recv_buffers.buckets[i];

            psptl_deregister_recv_buffer(cur_bucket);
        }

        /* free queue-related memory */
        free(con_info->recv_buffers.buckets);
        con_info->recv_buffers.buckets = NULL;
    }


    if (con_info->recv_buffers.mem) {
        free(con_info->recv_buffers.mem);
        con_info->recv_buffers.mem = NULL;
    }
}


static void psptl_create_send_queue(uint32_t num_bufs, size_t buf_len,
                                    psptl_con_info_t *con_info)
{
    /* allocate memory for the send buffers */
    con_info->send_buffers.mem = malloc(num_bufs * buf_len);
    assert(con_info->send_buffers.mem);

    /* allocate memory for the buckets of the send buffers */
    con_info->send_buffers.buckets = (psptl_bucket_t *)malloc(
        sizeof(psptl_bucket_t) * num_bufs);
    assert(con_info->send_buffers.buckets);

    /* initialize the indices */
    con_info->send_buffers.cur = 0;

    /* initialize the buckets */
    for (uint32_t i = 0; i < num_bufs; ++i) {
        void *buf = con_info->send_buffers.mem + buf_len * i;

        con_info->send_buffers.buckets[i].con_info = con_info;
        con_info->send_buffers.buckets[i].buf      = buf;
        con_info->send_buffers.buckets[i].in_use   = 0;
    }

    return;
}


static void psptl_destroy_send_queue(psptl_con_info_t *con_info)
{
    if (con_info->send_buffers.buckets) {
        free(con_info->send_buffers.buckets);
        con_info->send_buffers.buckets = NULL;
    }

    if (con_info->send_buffers.mem) {
        free(con_info->send_buffers.mem);
        con_info->send_buffers.mem = NULL;
    }
}


void psptl_configure_debug(FILE *stream, int level)
{
    psptl.debug.stream = stream;
    psptl.debug.level  = level;
}


int psptl_con_init(psptl_con_info_t *con_info, void *con_priv)
{
    con_info->hca_info = psptl.hca_info;
    con_info->con_priv = con_priv;

    return 0;
}


int psptl_con_connect(psptl_con_info_t *con_info, psptl_info_msg_t *info_msg)
{
    int ret;

    /* set the remote connection information */
    con_info->remote_ci.pid.raw = info_msg->pid;
    memcpy(con_info->remote_ci.pti, info_msg->pti,
           PSPTL_PROT_COUNT * sizeof(uint32_t));

    /* initialize the sequence IDs */
    con_info->send_seq_id = 0;
    con_info->recv_seq_id = 0;
    con_info->rndv_seq_id = 0;

    /* initialize the counter for pending put operations */
    con_info->outstanding_put_ops   = 0;
    con_info->outstanding_rndv_reqs = 0;

    psptl_dprint(D_DBG_V, "Remote con_info (pid: %lu, ptis: [%u,%u])",
                 con_info->remote_ci.pid.raw,
                 con_info->remote_ci.pti[PSPTL_PROT_EAGER],
                 con_info->remote_ci.pti[PSPTL_PROT_RNDV]);

    /* create the send and receive queue */
    ret = psptl_create_recv_queue(psptl.con_params.recvq_size,
                                  psptl.con_params.bufsize, con_info);
    if (ret < 0) goto err_out;

    psptl_create_send_queue(psptl.con_params.sendq_size,
                            psptl.con_params.bufsize, con_info);

    return 0;
    /* --- */
err_out:
    return -1;
}


void psptl_con_cleanup(psptl_con_info_t *con_info)
{
    if (!list_empty(&con_info->next)) {
        goto out; /* cleanup has already been deferred */
    } else if (con_info->outstanding_put_ops) {
        list_add_tail(&con_info->next, &psptl.cleanup_cons);
        goto out; /* we need to defer the cleanup */
    }

    /* destroy the send and receive queue */
    psptl_destroy_send_queue(con_info);
    psptl_destroy_recv_queue(con_info, psptl.con_params.recvq_size);

out:
    return;
}


static void psptl_cleanup_hca(psptl_hca_info_t *hca_info)
{
    int ret;
    psptl_prot_type_t prot;

    /* now cleanup the connections that had pending put operations */
    struct list_head *pos, *next;

    list_for_each_safe (pos, next, &psptl.cleanup_cons) {
        psptl_con_info_t *con_info = list_entry(pos, psptl_con_info_t, next);

        /* remove from list */
        list_del_init(&con_info->next);

        /* reset counter for outstanding put operations */
        psptl.stats.outstanding_put_ops += con_info->outstanding_put_ops;
        psptl_dprint(D_DBG_V, "con: %p; outstanding put operations: %lu",
                     con_info, con_info->outstanding_put_ops);
        con_info->outstanding_put_ops = 0;

        /* release connection-related resources */
        psptl_con_cleanup(con_info);

        psptl_con_free(con_info);
    }

    for (prot = 0; prot < PSPTL_PROT_COUNT; ++prot) {
        /* free the PT handle */
        ret = PtlPTFree(hca_info->nih, hca_info->pti[prot]);
        if (ret != PTL_OK) goto err_pt_free;

        /* release the MD handle */
        ret = PtlMDRelease(hca_info->mdh[prot]);
        if (ret != PTL_OK) goto err_md_release;

        /* free the event queue */
        ret = PtlEQFree(hca_info->eqh[prot]);
        if (ret != PTL_OK) goto err_eq_free;
    }

    /* release NI resources */
    ret = PtlNIFini(hca_info->nih);
    if (ret != PTL_OK) goto err_ni_fini;

    return;
    /* --- */
err_pt_free:
    psptl_dprint(D_ERR, "PtlPTFree() failed (prot: %s): '%s'",
                 psptl_prot_str(prot), psptl_err_str(ret));
    goto err_out;
    /* --- */
err_md_release:
    psptl_dprint(D_ERR, "PtlMDRelease() failed (prot: %s): '%s'",
                 psptl_prot_str(prot), psptl_err_str(ret));
    goto err_out;
    /* --- */
err_eq_free:
    psptl_dprint(D_ERR, "PtlEQFree() failed (prot: %s): '%s'",
                 psptl_prot_str(prot), psptl_err_str(ret));
    goto err_out;
    /* --- */
err_ni_fini:
    psptl_dprint(D_ERR, "PtlEQFree() failed: '%s'", psptl_err_str(ret));
    goto err_out;
    /* --- */
err_out:
    return;
}


static int psptl_init_hca(psptl_hca_info_t *hca_info)
{
    int ret;
    psptl_prot_type_t prot;

    /* initialize the network interface */
    int init_opts = (PTL_NI_MATCHING | PTL_NI_PHYSICAL);
    ret           = PtlNIInit(PTL_IFACE_DEFAULT, /* use the default interface */
                              init_opts,         /* NI-related options */
                              PTL_PID_ANY, /* let portals4 choose the pid */
                              NULL,        /* do not impose resource limits */
                              NULL,        /* do not retrieve resource limits */
                              &hca_info->nih); /* handle to the network interface */
    if (ret != PTL_OK) goto err_init;

    /* retrieve the portals process ID */
    ret = PtlGetPhysId(hca_info->nih, &hca_info->pid.ptl_pid);
    if (ret != PTL_OK) goto err_get_id;

    /* build the event queues */
    for (prot = 0; prot < PSPTL_PROT_COUNT; ++prot) {
        ret = PtlEQAlloc(hca_info->nih, psptl.eq_size, &hca_info->eqh[prot]);
        if (ret != PTL_OK) goto err_eq_alloc;

        /* bind the whole VA to avoid regular calls to PtlMDBind */
        ptl_md_t md = {
            .start     = 0,
            .length    = PTL_SIZE_MAX,
            .options   = (PTL_MD_EVENT_SEND_DISABLE | PTL_MD_VOLATILE),
            .eq_handle = hca_info->eqh[prot],
            .ct_handle = PTL_CT_NONE,
        };
        ret = PtlMDBind(hca_info->nih, &md, &hca_info->mdh[prot]);
        if (ret != PTL_OK) goto err_md_bind;

        /* request a portals index for the respective communication protocol */
        ret = PtlPTAlloc(hca_info->nih,         /* interface handle */
                         0,                     /* disable flow control */
                         hca_info->eqh[prot],   /* event queue handle */
                         PTL_PT_ANY,            /* no specific PTI */
                         &hca_info->pti[prot]); /* the assigned PTI */
        if (ret != PTL_OK) goto err_pt_alloc;
    }

    psptl_dprint(D_DBG_V, "HCA initialized!");

    return 0;
    /* --- */
err_pt_alloc:
    psptl_dprint(D_ERR, "PtlPTAlloc() failed (prot: %s): '%s'",
                 psptl_prot_str(prot), psptl_err_str(ret));
    goto err_out;
    /* --- */
err_md_bind:
    psptl_dprint(D_ERR, "PtlMDBind() failed (prot: %s): '%s'",
                 psptl_prot_str(prot), psptl_err_str(ret));
    goto err_out;
    /* --- */
err_get_id:
    psptl_dprint(D_ERR, "PtlGetPhysId() failed: '%s'", psptl_err_str(ret));
    goto err_out;
    /* --- */
err_eq_alloc:
    psptl_dprint(D_ERR, "PtlEQAlloc() failed (prot: %s): '%s'",
                 psptl_prot_str(prot), psptl_err_str(ret));
    /* --- */
err_out:
    psptl_cleanup_hca(hca_info);
    return -1;
    /* --- */
err_init:
    psptl_dprint(D_ERR, "PtlNIInit() failed: '%s'", psptl_err_str(ret));
    return -1;
}


int psptl_init(void)
{
    int ret;

    /* only initialize once */
    if (psptl.init_state == PSPORTALS_NOT_INITIALIZED) {
        /* initialize the portals4 library */
        if ((ret = PtlInit()) != PTL_OK) goto err_init;

        if (psptl_init_hca(psptl.hca_info)) goto err_hca;

        psptl.init_state = PSPORTALS_INIT_DONE;
    }

    return psptl.init_state;
    /* --- */
err_init:
    psptl_dprint(D_ERR, "PtlInit() failed: '%s'", psptl_err_str(ret));
err_hca:
    psptl.init_state = PSPORTALS_INIT_FAILED;
    psptl_dprint(D_INFO, "PORTALS disabled");

    return psptl.init_state; /* 0 = success, -1 = error */
}


void psptl_finalize(void)
{
    if (psptl.init_state == PSPORTALS_INIT_DONE) {
        /* cleanup HCA-related resources */
        psptl_cleanup_hca(psptl.hca_info);

        /* print statistics */
        psptl_print_stats();

        /* cleanup the portals4 library */
        PtlFini();
    }

    return;
}


static void psptl_bucket_send_done(psptl_bucket_t *send_bucket)
{
    /* the bucket is free to be reused */
    send_bucket->in_use = 0;

    /* tell the upper layer the request is done */
    pscom_portals_sendv_done(send_bucket->con_info->con_priv);

    return;
}


static void psptl_req_recv_done(psptl_bucket_t *recv_bucket)
{
    psptl_con_info_t *con_info = recv_bucket->con_info;
    psptl_hca_info_t *hca_info = con_info->hca_info;
    size_t len                 = recv_bucket->len;

    /* tell the upper layer that some IO was done */
    pscom_portals_recv_done(con_info->con_priv, recv_bucket->buf, len);

    /* re-register the buffer */
    psptl_register_recv_buffer(recv_bucket, (PSPTL_PUT_FLAGS | PSPTL_USE_ONCE),
                               PTL_PRIORITY_LIST,
                               hca_info->pti[PSPTL_PROT_EAGER],
                               psptl.con_params.bufsize);

    con_info->recv_seq_id++;

    return;
}


static void psptl_progress_pending_recvs(psptl_con_info_t *con_info)
{
    struct list_head *pos, *next;

    list_for_each_safe (pos, next, &con_info->pending_recvs) {
        psptl_bucket_t *cur_recv_bucket = list_entry(pos, psptl_bucket_t, next);

        if (cur_recv_bucket->seq_id > con_info->recv_seq_id) {
            break;
        } else {
            assert(cur_recv_bucket->seq_id == con_info->recv_seq_id);
            psptl_pending_bucket_remove(cur_recv_bucket);
            psptl_req_recv_done(cur_recv_bucket);
        }
    }
}


static void psptl_handle_put_event(ptl_event_t event)
{
    psptl_bucket_t *recv_bucket = event.user_ptr;
    psptl_con_info_t *con_info  = recv_bucket->con_info;

    recv_bucket->len = event.mlength;

    /* check whether there have been retries on the sending side */
    if (event.hdr_data == con_info->recv_seq_id) {
        psptl_req_recv_done((psptl_bucket_t *)event.user_ptr);
    } else {

        recv_bucket->seq_id = event.hdr_data;

        psptl_pending_bucket_insert(recv_bucket);
    }

    /* now try to progress on the pending packets */
    psptl_progress_pending_recvs(con_info);
}


static void psptl_bucket_send_retry(psptl_bucket_t *send_bucket)
{
    int ret;
    psptl_con_info_t *con_info         = send_bucket->con_info;
    psptl_hca_info_t *hca_info         = con_info->hca_info;
    psptl_remote_con_info_t *remote_ci = &con_info->remote_ci;
    size_t len                         = send_bucket->len;

    void *send_buf = send_bucket->buf;

    /* Transmit the messages via put operation */
    ret = PtlPut(hca_info->mdh[PSPTL_PROT_EAGER], /* local memory handle */
                 (uint64_t)send_buf,              /* local offset */
                 len,                    /* amount of bytes to be sent */
                 PTL_ACK_REQ,            /* request a full event */
                 remote_ci->pid.ptl_pid, /* peer process ID */
                 remote_ci->pti[PSPTL_PROT_EAGER], /* remote portals index */
                 0,                                /* match bits */
                 0,                                /* remote offset */
                 send_bucket,                      /* local user pointer */
                 send_bucket->seq_id);             /* no header */
    if (ret != PTL_OK) goto err_put;

    /* increase some counters */
    psptl.stats.retry_cnt++;
    con_info->outstanding_put_ops++;

    return;
    /* --- */
err_put:
    psptl_dprint(D_ERR, "PtlPut() failed: '%s'", psptl_err_str(ret));
    return;
}

static void psptl_handle_eager_ack(psptl_bucket_t *send_bucket, uint8_t done)
{
    psptl_con_info_t *con_info = send_bucket->con_info;

    /* decrease the pending put counter */
    con_info->outstanding_put_ops--;

    if (done) {
        psptl_bucket_send_done(send_bucket);
    } else {
        psptl_bucket_send_retry(send_bucket);
    }
}


static void psptl_handle_rndv_ack(psptl_rma_req_t *rma_req, int err)
{
    if (err && (rma_req->retry_cnt < psptl.con_params.max_rndv_retry)) {
        psptl_post_rma_put(rma_req);

        /* increase the retry counter */
        rma_req->retry_cnt++;

        /* take statistics */
        psptl.stats.rndv_retry++;
    } else {
        rma_req->io_done(rma_req->priv, err);
    }
}


int psptl_progress(void)
{
    int ret;
    unsigned int eqh_idx;
    ptl_event_t event;
    psptl_hca_info_t *hca_info = psptl.hca_info;

    ret = PtlEQPoll(hca_info->eqh, 2, 0, &event, &eqh_idx);

    /* no progress */
    if (ret == PTL_EQ_EMPTY) {
        return 0;
    } else if (ret != PTL_OK) {
        goto err_out;
    }

    switch (event.type) {
    case PTL_EVENT_ACK: {
        if (eqh_idx == PSPTL_PROT_EAGER) {
            psptl_handle_eager_ack((psptl_bucket_t *)(event.user_ptr),
                                   (event.ni_fail_type == PTL_NI_OK));
        } else {
            psptl_handle_rndv_ack((psptl_rma_req_t *)(event.user_ptr),
                                  (event.ni_fail_type != PTL_NI_OK));
        }
        break;
    }
    case PTL_EVENT_PUT: {
        /* PUT events are only generated for eager messages */
        assert(event.pt_index == hca_info->pti[PSPTL_PROT_EAGER]);

        psptl_handle_put_event(event);
        break;
    }
    case PTL_EVENT_SEND: break;
    default:
        psptl_dprint(D_ERR, "Unhandled event: %s (eqh: %d)!",
                     psptl_event_str(event), eqh_idx);

        break;
    }

    return 1;
    /* --- */
err_out:
    psptl_dprint(D_ERR, "PtlEQGet() failed: '%s'", psptl_err_str(ret));
    return 0;
}


ssize_t psptl_sendv(psptl_con_info_t *con_info, struct iovec iov[2], size_t len)
{
    int ret;
    psptl_bucket_t *send_bucket;
    psptl_hca_info_t *hca_info         = con_info->hca_info;
    psptl_remote_con_info_t *remote_ci = &con_info->remote_ci;
    uint32_t cur_send_bucket           = con_info->send_buffers.cur;

    /* check if the current send bucket is free */
    if (con_info->send_buffers.buckets[cur_send_bucket].in_use) {
        goto err_busy;
    }

    /* limit send length to the buffer size */
    len = (len <= psptl.con_params.bufsize) ? len : psptl.con_params.bufsize;

    send_bucket         = &(con_info->send_buffers.buckets[cur_send_bucket]);
    send_bucket->in_use = 1;
    send_bucket->len    = len;
    send_bucket->seq_id = con_info->send_seq_id++;

    void *send_buf = send_bucket->buf;

    /* copy the iovec (header+payload) to the send buffer */
    pscom_memcpy_from_iov(send_buf, iov, len);

    /* transmit the messages via put operation */
    ret = PtlPut(hca_info->mdh[PSPTL_PROT_EAGER], /* local memory handle */
                 (uint64_t)send_buf,              /* local offset */
                 len,                    /* amount of bytes to be sent */
                 PTL_ACK_REQ,            /* request a full event */
                 remote_ci->pid.ptl_pid, /* peer process ID */
                 remote_ci->pti[PSPTL_PROT_EAGER], /* remote portals index */
                 0,                                /* match bits */
                 0,                                /* remote offset */
                 send_bucket,                      /* local user pointer */
                 send_bucket->seq_id);             /* sequence number */
    if (ret != PTL_OK) goto err_put;

    /* increase the pending put counter */
    con_info->outstanding_put_ops++;

    con_info->send_buffers.cur = (uint32_t)((cur_send_bucket + 1) %
                                            psptl.con_params.sendq_size);

    return len;
    /* --- */
err_busy:
    return -EAGAIN;
err_put:
    psptl_dprint(D_ERR, "PtlPut() failed: '%s'", psptl_err_str(ret));
    return -EPIPE;
}


psptl_con_info_t *psptl_con_create(void)
{
    psptl_con_info_t *con_info = calloc(1, sizeof(*con_info));
    INIT_LIST_HEAD(&con_info->pending_recvs);
    INIT_LIST_HEAD(&con_info->next);

    return con_info;
}


void psptl_con_free(psptl_con_info_t *con_info)
{
    /* only free the connection information if the cleanup is *not* deferred */
    if (list_empty(&con_info->next)) free(con_info);
}


void psptl_con_get_info_msg(psptl_con_info_t *con_info,
                            psptl_info_msg_t *info_msg)
{
    info_msg->pid = (uint64_t)(con_info->hca_info->pid.raw);
    memcpy(info_msg->pti, con_info->hca_info->pti,
           PSPTL_PROT_COUNT * sizeof(uint32_t));

    psptl_dprint(D_DBG_V, "Local con_info (pid: %lu, ptis: [%u,%u])",
                 info_msg->pid, info_msg->pti[PSPTL_PROT_EAGER],
                 info_msg->pti[PSPTL_PROT_RNDV]);
}


void psptl_print_stats(void)
{
    psptl_dprint(D_STATS, "retry_cnt           : %8lu", psptl.stats.retry_cnt);
    psptl_dprint(D_STATS, "outstanding_put_ops : %8lu",
                 psptl.stats.outstanding_put_ops);
    psptl_dprint(D_STATS, "rndv_write          : %8lu", psptl.stats.rndv_write);
    psptl_dprint(D_STATS, "rndv_retry          : %8lu", psptl.stats.rndv_retry);
}


int psptl_rma_mem_register(psptl_con_info_t *con_info, void *buf, size_t len,
                           psptl_rma_mreg_t *rma_mreg)
{
    int ret;
    psptl_hca_info_t *hca_info = con_info->hca_info;

    if (con_info->outstanding_rndv_reqs >= psptl.con_params.max_rndv_reqs) {
        goto err_out;
    }

    psptl_bucket_t *rndv_bucket = (psptl_bucket_t *)malloc(
        sizeof(*rndv_bucket));

    rndv_bucket->buf         = buf;
    rndv_bucket->con_info    = con_info;
    rndv_bucket->match_bits  = con_info->rndv_seq_id++; /* con-local seq ID */
    rndv_bucket->ignore_bits = 0;

    /* update the RMA request */
    rma_mreg->match_bits = rndv_bucket->match_bits;
    rma_mreg->priv       = rndv_bucket;

    ret = psptl_register_recv_buffer(rndv_bucket, PSPTL_RMA_WRITE_FLAGS,
                                     PTL_PRIORITY_LIST,
                                     hca_info->pti[PSPTL_PROT_RNDV], len);
    if (ret < 0) goto err_mem_register;

    con_info->outstanding_rndv_reqs++;

    return 0;
    /* --- */
err_mem_register:
    psptl_dprint(D_ERR, "Failed to register rendezvous buffer %p\n", buf);
err_out:
    return -1;
}


void psptl_rma_mem_deregister(psptl_rma_mreg_t *rma_mreg)
{
    psptl_bucket_t *rndv_bucket = (psptl_bucket_t *)(rma_mreg->priv);
    psptl_con_info_t *con_info  = rndv_bucket->con_info;

    /* PtlMEUnlink not required due to PSPTL_USE_ONCE */
    con_info->outstanding_rndv_reqs--;

    /* free the corresponding bucket */
    free(rma_mreg->priv);
}


int psptl_post_rma_put(psptl_rma_req_t *rma_req)
{
    int ret;
    void *data                         = rma_req->data;
    size_t data_len                    = rma_req->data_len;
    psptl_con_info_t *con_info         = rma_req->con_info;
    psptl_hca_info_t *hca_info         = con_info->hca_info;
    psptl_remote_con_info_t *remote_ci = &con_info->remote_ci;

    /* Transmit the messages via put operation */
    ret = PtlPut(hca_info->mdh[PSPTL_PROT_RNDV], /* local memory handle */
                 (uint64_t)data,                 /* local offset */
                 data_len,               /* amount of bytes to be sent */
                 PTL_ACK_REQ,            /* request a full event */
                 remote_ci->pid.ptl_pid, /* peer process ID */
                 remote_ci->pti[PSPTL_PROT_RNDV], /* remote portals index */
                 rma_req->match_bits,             /* match bits */
                 0,                               /* do not ignore any bit */
                 rma_req,                         /* local user pointer */
                 0);                              /* no header */
    if (ret != PTL_OK) goto err_put;

    /* take some statistics */
    psptl.stats.rndv_write++;
    // TODO: Do we need to increase `outstanding_put_ops`?

    return 0;
    /* --- */
err_put:
    psptl_dprint(D_ERR, "PtlPut() failed: '%s'", psptl_err_str(ret));
    goto err_out;
    /* --- */
err_out:
    return -1;
}
