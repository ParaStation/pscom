/*
 * ParaStation
 *
 * Copyright (C) 2010-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psextoll.c: EXTOLL communication
 */

#include "psextoll.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <rma2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <velo2.h>
#include <velo2_mod.h>

#include "pscom_priv.h"
#include "pscom_poll.h"
#include "pscom_util.h"


/* Size of the send, receive and completion queue */
#define _SIZE_SEND_QUEUE 16
#define _SIZE_RECV_QUEUE 16


/* Used buffersize */
#define PSEX_RMA2_MTU (4 * 1024)
#define PSEX_RMA2_PAYLOAD                                                      \
    (PSEX_RMA2_MTU - sizeof(psex_msgheader_t)) /* must be < 65536, or change   \
                                                  sizeof                       \
                                                  psex_msgheader_t.payload */
#define PSEX_RMA2_GET_MAX 0x800000

#ifndef DISABLE_RMA2
typedef struct {
    void *ptr;
    RMA2_Region *mr;
} mem_info_t;


typedef struct {
    mem_info_t bufs;
    unsigned pos; /* current position */
} ringbuf_t;
#endif

struct hca_info {
    velo2_port_t velo2_port; /* velo2 port from velo2_open(&velo2_port) */
    RMA2_Port rma2_port;     /* rma2 port from rma2_open(&rma2_port) */

#ifndef DISABLE_RMA2
    /* RMA2 */
    /* send */
    ringbuf_t send; /* global send queue */
#endif

    RMA2_Nodeid rma2_nodeid; /* local rma2 nodeid */
    RMA2_VPID rma2_vpid;     /* local rma2 vpid */

    /* rma2 rendezvous */
    struct list_head rma2_reqs;  /* list of active RMA requests :
                                    psex_rma_req_t.next */
    pscom_poll_t rma2_reqs_read; // calling psex_progress(). Used if
                                 // !list_empty(rma2_reqs)

    /* VELO2 */
    velo2_nodeid_t velo2_nodeid; /* local velo2 nodeid */
    velo2_vpid_t velo2_vpid;     /* local velo2 vpid */
};


/* Extoll specific information about one connection */
struct psex_con_info {
    /* low level */
    hca_info_t *hca_info;

    RMA2_Port rma2_port; /* extoll port from rma2_open(&rma2_port) (copied from
                            hca_info) */
    RMA2_Handle rma2_handle; /* Connection handle from
                                rma2_connect(..&rma2_handle); */

#ifndef DISABLE_RMA2
    /* send */
    unsigned int remote_recv_pos; /* next to use receive buffer (= remote
                                     recv_pos) */

    RMA2_NLA remote_rbuf_nla; /* from remote rma2_get_nla(con->recv.bufs.mr, 0,
                                 &remote_rbuf) */

    ringbuf_t send;

    /* recv */
    ringbuf_t recv;
#endif

    /* misc */
    void *priv; /* priv data from psex_con_init() */

#ifndef DISABLE_RMA2
    /* higher level */
    unsigned int n_send_toks;
    unsigned int n_recv_toks;
    unsigned int n_tosend_toks;
#endif

    velo2_connection_t velo2_con; /* velo connection from velo2_connect() */
    uint32_t velo2_srcid; /* srcid which could be compared against srcid from
                             velo2_recv().*/
    psex_con_info_t *map_next; /* next usef by map<srcid, psex_con_info_t> */
    int con_broken;
};


typedef struct {
    uint16_t token;
    uint16_t payload;
    volatile uint32_t magic;
} psex_msgheader_t;


#define PSEX_MAGIC_UNUSED 0
#define PSEX_MAGIC_IO     1


typedef struct {
    char __data[PSEX_RMA2_PAYLOAD];
    psex_msgheader_t tail;
} psex_msg_t;


// PSEXTOLL_LEN(len) + sizeof(header) must be a multiple of 64 bytes (cacheline)
#define PSEX_LEN(len)           (((len) + sizeof(psex_msgheader_t) + 63) & ~63)
#define PSEX_DATA(buf, psexlen) ((buf) + sizeof(psex_msg_t) - (psexlen))


/*
 * static variables
 */

static hca_info_t default_hca;
unsigned psex_pending_global_sends = 0; /* counting pending sends from global
                                           send ring */

char *psex_err_str = NULL; /* last error string */

int psex_debug          = 2;
FILE *psex_debug_stream = NULL;

#ifndef DISABLE_RMA2
unsigned int psex_sendq_size     = _SIZE_SEND_QUEUE;
unsigned int psex_recvq_size     = _SIZE_RECV_QUEUE;
unsigned int psex_pending_tokens = _SIZE_RECV_QUEUE - 6;

int psex_global_sendq = 0; /* bool. Use one sendqueue for all connections? */
int psex_event_count  = 0; /* bool. Be busy if psex_pending_global_sends is to
                              high? */
#endif

struct psex_stat_s {
    unsigned busy_notokens;      // connection out of tokens for sending
    unsigned busy_global_cq;     // global completion queue busy.
    unsigned post_send_eagain;   // ibv_post_send() returned EAGAIN.
    unsigned post_send_error;    // ibv_port_send() returned with an error !=
                                 // EAGAIN.
    unsigned busy_token_refresh; // sending tokens with nop message failed.
} psex_stat;


#define psex_map_size 8192
psex_con_info_t *psex_map[psex_map_size] = {NULL};

static int psex_rma2_reqs_progress(pscom_poll_t *poll);


#define psex_dprint(level, fmt, arg...)                                        \
    do {                                                                       \
        if ((level) <= psex_debug) {                                           \
            fprintf(psex_debug_stream ? psex_debug_stream : stderr,            \
                    "extoll:" fmt "\n", ##arg);                                \
        }                                                                      \
    } while (0);


static void psex_err(char *str)
{
    if (psex_err_str) { free(psex_err_str); }

    psex_err_str = str ? strdup(str) : strdup("");
    return;
}


#ifndef DISABLE_RMA2
static void psex_err_errno(char *str, int err_no)
{
    const char *err_str = strerror(err_no);
    size_t len          = strlen(str) + strlen(err_str) + 10;
    char *msg           = malloc(len);

    assert(msg);

    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, err_str);

    psex_err(msg);
    free(msg);
}
#endif


static void psex_err_rma2_error(char *str, int rc)
{
    char rma2_err_str[100];
    size_t len;
    char *msg;

    rma2_serror(rc, rma2_err_str, sizeof(rma2_err_str));

    len = strlen(str) + strlen(rma2_err_str) + 10;
    msg = malloc(len);

    assert(msg);

    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, rma2_err_str);

    psex_err(msg);
    free(msg);
}


static void psex_err_velo2_error(char *msg, velo2_ret_t vrc)
{
    char errmsg[200];
    const char *fmt = NULL;

    if (vrc == VELO2_RET_SUCCESS) { return; }

    switch (vrc) {
    case VELO2_RET_SUCCESS: fmt = "%s : operation was successful"; break;
    case VELO2_RET_INV_MSG: fmt = "%s : invalid message"; break;
    case VELO2_RET_ERROR: fmt = "%s : an error occured"; break;
    case VELO2_RET_NO_MSG: fmt = "%s : no valid message"; break;
    case VELO2_RET_NO_MATCH: fmt = "%s : no valid message match"; break;
    case VELO2_RET_ERR_FDOPEN: fmt = "%s : error during open operation"; break;
    case VELO2_RET_ERR_MMAP: fmt = "%s : error during mmap operation"; break;
    case VELO2_RET_INVALID_MBOX: fmt = "%s : mailbox id not valid"; break;
    case VELO2_RET_INVALID_NODE: fmt = "%s : node id not valid"; break;
    case VELO2_RET_TRY_AGAIN:
        fmt = "%s : no credit available for sending (flow-control)";
        break;
    case VELO2_RET_INV_MTT: fmt = "%s : invalid MTT used for sending"; break;
    }

    if (fmt) {
        snprintf(errmsg, sizeof(errmsg), fmt, msg);
    } else {
        snprintf(errmsg, sizeof(errmsg), "%s : Unknown velo2 error %d", msg,
                 vrc);
    }
    psex_err(errmsg);
}


#ifndef DISABLE_RMA2
unsigned psex_pending_tokens_suggestion(void)
{
    unsigned res = 0;
    switch (psex_recvq_size) {
    default: return psex_recvq_size - 6;
    case 11:
    case 10: return 5;
    case 9:
    case 8: return 4;
    case 7:
    case 6: return 3;
    case 5:
    case 4:
    case 3:
    case 2: return 2;
    case 1:
    case 0: return 0;
    }
    return res;
}


static void psex_rma2_free(hca_info_t *hca_info, mem_info_t *mem_info)
{
    rma2_unregister(hca_info->rma2_port, mem_info->mr);
    mem_info->mr = NULL;
    free(mem_info->ptr);
    mem_info->ptr = NULL;
}
#endif


#ifndef DISABLE_RMA2
static void print_mlock_help(unsigned size)
{
    static int called = 0;
    struct rlimit rlim;

    if (called) { return; }
    called = 1;

    psex_dprint(0, "EXTOLL: rma2_register(%u) failed.", size);
    psex_dprint(0, "(Check memlock limit in /etc/security/limits.conf or try "
                   "'ulimit -l')");

    if (!getrlimit(RLIMIT_MEMLOCK, &rlim)) {
        psex_dprint(0, "Current RLIMIT_MEMLOCK: soft=%lu byte, hard=%lu byte",
                    rlim.rlim_cur, rlim.rlim_max);
    }
}


static int psex_rma2_alloc(hca_info_t *hca_info, int size, mem_info_t *mem_info)
{
    int rc;

    mem_info->mr = NULL;

    /* Region for buffers */
    mem_info->ptr = valloc(size);
    if (!mem_info->ptr) { goto err_malloc; }

    rc = rma2_register(hca_info->rma2_port, mem_info->ptr, size, &mem_info->mr);
    if (!mem_info->mr) { goto err_reg_mr; }

    return 0;
    /* --- */
err_reg_mr:
    free(mem_info->ptr);
    mem_info->ptr = NULL;
    psex_err_rma2_error("rma2_register()", rc);
    /*if (rc == RMA2_ERR_NO_MEM)*/ print_mlock_help(size);
    return -1;
err_malloc:
    psex_err_errno("malloc()", errno);
    return -1;
}
#endif

/*
 * RMA2 rendezvous
 */

static int psex_mregion_register(RMA2_Region *rma2_region, RMA2_Port rma2_port,
                                 void *buf, size_t size)
{
    RMA2_ERROR rma2_error;

    rma2_error = rma2_register_nomalloc(rma2_port, buf, size, rma2_region);
    assert(rma2_error == RMA2_SUCCESS); // ToDo: catch error

    // printf("%s:%u:%s  buf:%p nla:%lx size:%lu\n", __FILE__, __LINE__,
    // __func__, buf, mreg->rma2_nla, size);
    return 0; /* success */
}


static int psex_mregion_deregister(RMA2_Region *rma2_region, RMA2_Port rma2_port)
{
    RMA2_ERROR rma2_error;

    rma2_error = rma2_unregister_nofree(rma2_port, rma2_region);
    assert(rma2_error == RMA2_SUCCESS); // ToDo: catch error

    return 0; /* success */
}


static RMA2_NLA psex_mregion_nla(RMA2_Region *rma2_region, void *buf)
{
    return rma2_region->nla +
           (RMA2_NLA)((char *)buf - (char *)rma2_region->start);
}

#ifdef PSEX_USE_MREGION_CACHE
/* Use mregion cache */

#include "psextoll_mregion_cache.c"

#else
/* No mregion cache */

int psex_get_mregion(psex_mregion_t *mreg, void *buf, size_t size,
                     psex_con_info_t *ci)
{
    int err;
    err = psex_mregion_register(&mreg->rma2_region, ci->rma2_port, buf, size);
    mreg->rma2_nla = psex_mregion_nla(&mreg->rma2_region, buf);
    return err;
}


void psex_put_mregion(psex_mregion_t *mreg, psex_con_info_t *ci)
{
    if (!mreg->rma2_nla) { return; }
    psex_mregion_deregister(&mreg->rma2_region, ci->rma2_port);
    mreg->rma2_nla = 0;
}

#endif /* ! PSEX_USE_MREGION_CACHE */

/*
RMA2_ERROR rma2_register(RMA2_Port port, void* address, size_t size,
RMA2_Region** region); RMA2_ERROR rma2_unregister(RMA2_Port port, RMA2_Region*
region); RMA2_ERROR rma2_get_nla(RMA2_Region* region, size_t offset, RMA2_NLA*
nla); RMA2_ERROR rma2_post_get_bt(RMA2_Port port,RMA2_Handle handle,
RMA2_Region* src_region, uint32_t src_offset, uint32_t size, RMA2_NLA
dest_address, RMA2_Notification_Spec spec, RMA2_Command_Modifier modifier);
RMA2_ERROR rma2_post_get_bt_direct(RMA2_Port port,RMA2_Handle handle, RMA2_NLA
src,  uint32_t size, RMA2_NLA dest_address, RMA2_Notification_Spec spec,
RMA2_Command_Modifier modifier);*/

static void psex_rma2_reqs_enq(psex_rma_req_t *req)
{
    hca_info_t *hca_info = req->ci->hca_info;
    int first            = list_empty(&hca_info->rma2_reqs);

    list_add_tail(&req->next, &hca_info->rma2_reqs);

    if (first) {
        // Start polling for completer notifications
        pscom_poll_start(&hca_info->rma2_reqs_read, psex_rma2_reqs_progress,
                         &pscom.poll_read);
    }
}


static void psex_rma2_reqs_deq(psex_rma_req_t *req)
{
    hca_info_t *hca_info = req->ci->hca_info;

    list_del(&req->next);

    if (list_empty(&hca_info->rma2_reqs)) {
        // Stop polling for completer notifications
        pscom_poll_stop(&hca_info->rma2_reqs_read);
    }
}


static void psex_rma_get_continue(psex_rma_req_t *req)
{
    RMA2_ERROR rma2_error;
    psex_con_info_t *ci = req->ci;
    // printf("%s:%u:%s nla_src:%lx nla_dest:%lx size:%lu pos:%lu\n", __FILE__,
    // __LINE__, __func__,
    //        req->rma2_nla, req->mreg.rma2_nla, req->data_len, req->pos);
    size_t len          = req->data_len - req->pos;
    if (len > PSEX_RMA2_GET_MAX) { len = PSEX_RMA2_GET_MAX; }

    rma2_error = rma2_post_get_bt_direct(ci->rma2_port, ci->rma2_handle,
                                         req->mreg.rma2_nla + req->pos,
                                         (uint32_t)len,
                                         req->rma2_nla + req->pos,
                                         RMA2_COMPLETER_NOTIFICATION,
                                         RMA2_CMD_DEFAULT);
    assert(rma2_error == RMA2_SUCCESS); // ToDo: catch error
    req->pos += len;
}


int psex_post_rma_gets(psex_rma_req_t *req)
{
    req->pos = 0;
    // Post step 0;
    psex_rma_get_continue(req);

    // Queue this request and wait for completer notification.
    psex_rma2_reqs_enq(req);

    return 0;
}


static void psex_handle_notification(hca_info_t *hca_info,
                                     RMA2_Notification *notification)
{
    // rma2_noti_dump(notification);
    // RMA2_Command rma2_noti_get_cmd(RMA2_Notification* noti);
    // RMA2_Notification_Spec rma2_noti_get_notification_type(RMA2_Notification*
    // noti); RMA2_Notification_Modifier rma2_noti_get_mode(RMA2_Notification
    // *noti); uint64_t rma2_noti_get_local_address(RMA2_Notification* noti);

    struct list_head *pos;
    list_for_each (pos, &hca_info->rma2_reqs) {
        psex_rma_req_t *req = list_entry(pos, psex_rma_req_t, next);

        /*
        printf("req:( nla_src:%lx nla_dest:%lx data_len:%zu) noti:(notiaddr:%lx
        len:%u)\n", req->rma2_nla, req->mreg.rma2_nla, req->data_len,
               rma2_noti_get_local_address(notification),
               rma2_noti_get_size(notification));
        */
        if (req->mreg.rma2_nla + req->pos ==
            notification->word0.value /* NLA */ +
                (notification->word1.value & 0x7fffffl) + 1 /* payload*/) {
            if (req->data_len - req->pos) {
                psex_rma_get_continue(req);
            } else {
                psex_rma2_reqs_deq(req);
                req->io_done(req);
            }
            return;
        }
    }

    /* Probably we will leak a request if we where here */
    psex_dprint(0,
                "rma2_noti_probe() : Unknown RMA2_Notification (nla: 0x%lx, "
                "len:%lu)",
                notification->word0.value /* NLA */,
                (notification->word1.value & 0x7fffffl) + 1 /* payload*/);
}


static int psex_rma2_reqs_progress(pscom_poll_t *poll)
{
    hca_info_t *hca_info = list_entry(poll, hca_info_t, rma2_reqs_read);
    RMA2_Notification *notification;
    RMA2_ERROR rc;
    RMA2_Port rma2_port = hca_info->rma2_port;

    rc = rma2_noti_probe(rma2_port, &notification);
    if (rc == RMA2_SUCCESS) {
        psex_handle_notification(hca_info, notification);
        rma2_noti_free(rma2_port, notification);
    }

    return 0;
}


/*
 * RMA2 rendezvous end
 */


static unsigned psex_map_hashfunc(uint32_t srcid)
{
    return (srcid * 17 + ((srcid >> 16) * 29)) % psex_map_size;
}


static void psex_map_del_con(psex_con_info_t *con_info)
{
    unsigned idx          = psex_map_hashfunc(con_info->velo2_srcid);
    psex_con_info_t **pos = &psex_map[idx];
    while (*pos) {
        if ((*pos) == con_info) {
            *pos = con_info->map_next;
            return;
        }
        pos = &(*pos)->map_next;
    }
}


static void psex_map_add_con(psex_con_info_t *con_info)
{
    unsigned idx       = psex_map_hashfunc(con_info->velo2_srcid);
    con_info->map_next = psex_map[idx];
    psex_map[idx]      = con_info;
}


static psex_con_info_t *psex_map_get_con(uint32_t srcid)
{
    unsigned idx = psex_map_hashfunc(srcid);
    psex_con_info_t *pos;
    for (pos = psex_map[idx]; pos; pos = pos->map_next) {
        if (pos->velo2_srcid == srcid) { return pos; }
    }
    return NULL;
}


void psex_con_cleanup(psex_con_info_t *con_info)
{
    hca_info_t *hca_info = con_info->hca_info;

#ifndef DISABLE_RMA2
    if (con_info->send.bufs.mr) {
        usleep(100000); // Workaround: Wait for the completion of all
                        // rma2_post_put_bt()'s // ToDo: remove me!

        psex_rma2_free(hca_info, &con_info->send.bufs);
        con_info->send.bufs.mr = 0;
    }
    if (con_info->recv.bufs.mr) {
        psex_rma2_free(hca_info, &con_info->recv.bufs);
        con_info->recv.bufs.mr = 0;
    }
#endif
    if (con_info->rma2_handle) {
        rma2_disconnect(hca_info->rma2_port, con_info->rma2_handle);
        con_info->rma2_handle = NULL;
    }
    if (con_info->velo2_con.dest.raw || con_info->velo2_con.state_map) {
        velo2_disconnect(&hca_info->velo2_port, &con_info->velo2_con);
        con_info->velo2_con.dest.raw  = 0;
        con_info->velo2_con.state_map = NULL;

        psex_map_del_con(con_info);
    }
}


int psex_con_init(psex_con_info_t *con_info, hca_info_t *hca_info, void *priv)
{
#ifndef DISABLE_RMA2
    unsigned int i;
#endif

    if (!hca_info) { hca_info = &default_hca; }
    memset(con_info, 0, sizeof(*con_info));

    con_info->hca_info = hca_info;

#ifndef DISABLE_RMA2
    con_info->send.bufs.mr = NULL;
    con_info->recv.bufs.mr = NULL;
#endif
    con_info->priv       = priv;
    con_info->con_broken = 0;

    /*
     *  Memory for send and receive bufs
     */

#ifndef DISABLE_RMA2
    if (!psex_global_sendq) {
        if (psex_rma2_alloc(hca_info, PSEX_RMA2_MTU * psex_sendq_size,
                            &con_info->send.bufs)) {
            goto err_alloc;
        }
    }
    con_info->send.pos = 0;

    if (psex_rma2_alloc(hca_info, PSEX_RMA2_MTU * psex_recvq_size,
                        &con_info->recv.bufs)) {
        goto err_alloc;
    }

    /* Clear all receive magics */
    for (i = 0; i < psex_recvq_size; i++) {
        psex_msg_t *msg = ((psex_msg_t *)con_info->recv.bufs.ptr) + i;
        msg->tail.magic = PSEX_MAGIC_UNUSED;
    }

    con_info->remote_recv_pos = 0;
    con_info->recv.pos        = 0;

    // Initialize receive tokens
    con_info->n_recv_toks   = 0;
    con_info->n_tosend_toks = 0;

    // Initialize send tokens
    con_info->n_send_toks = psex_recvq_size; // #tokens = length of _receive_
                                             // queue!
#endif

    return 0;
    /* --- */
#ifndef DISABLE_RMA2
err_alloc:
    psex_con_cleanup(con_info);
    psex_dprint(1, "psex_con_init() : %s", psex_err_str);
    return -1;
#endif
}


int psex_con_connect(psex_con_info_t *con_info, psex_info_msg_t *info_msg)
{
    hca_info_t *hca_info = con_info->hca_info;
    int rc;
    velo2_ret_t vrc;

    con_info->rma2_port = hca_info->rma2_port; // Copy port for faster access.

#ifndef DISABLE_RMA2
    con_info->remote_rbuf_nla = info_msg->rbuf_nla;


#endif
    rc = rma2_connect(con_info->rma2_port, info_msg->rma2_nodeid,
                      info_msg->rma2_vpid, RMA2_CONN_DEFAULT,
                      &con_info->rma2_handle);
    if (rc) { goto err_rma2_connect; }

    vrc = velo2_connect(&hca_info->velo2_port, &con_info->velo2_con,
                        info_msg->velo2_nodeid, info_msg->velo2_vpid);
    if (vrc != VELO2_RET_SUCCESS) { goto err_velo2_connect; }

    con_info->velo2_srcid = (uint32_t)VELO2_ADDR_PACK(info_msg->velo2_nodeid,
                                                      info_msg->velo2_vpid);
    psex_map_add_con(con_info);

    return 0;
    /* --- */
err_rma2_connect:
    psex_err_rma2_error("rma2_connect()", rc);
    psex_dprint(1, "psex_con_connect() : %s", psex_err_str);
    return -1;
err_velo2_connect:
    psex_err_velo2_error("velo2_connect()", vrc);
    psex_dprint(1, "psex_con_connect() : %s", psex_err_str);
    return -1;
}


static void psex_cleanup_hca(hca_info_t *hca_info)
{
#ifndef DISABLE_RMA2
    if (hca_info->send.bufs.mr) {
        usleep(20000); // Workaround: Wait for the completion of all
                       // rma2_post_put_bt()'s // ToDo: remove me!

        psex_rma2_free(hca_info, &hca_info->send.bufs);
        hca_info->send.bufs.mr = 0;
    }
#endif
#ifdef PSEX_USE_MREGION_CACHE
    psex_mregion_cache_cleanup();
#endif
    if (hca_info->rma2_port) {
        rma2_close(hca_info->rma2_port);
        hca_info->rma2_port = NULL;
    }
    if (hca_info->velo2_port.map) {
        velo2_close(&hca_info->velo2_port);
        hca_info->velo2_port.map = NULL;
    }
}


static int psex_init_hca(hca_info_t *hca_info)
{
    int rc;
    velo2_ret_t vrc;

    memset(hca_info, 0, sizeof(*hca_info));

#ifndef DISABLE_RMA2
    /*
     * RMA2
     */
    hca_info->send.bufs.mr = NULL;

    if (psex_pending_tokens > psex_recvq_size) {
        psex_dprint(1, "warning: reset psex_pending_tokens from %u to %u\n",
                    psex_pending_tokens, psex_recvq_size);
        psex_pending_tokens = psex_recvq_size;
    }
#endif

    rc = rma2_open(&hca_info->rma2_port);
    if (rc != RMA2_SUCCESS) {
        psex_err_rma2_error("rma2_open()", rc);
        goto err_hca;
    }


#ifndef DISABLE_RMA2
    if (psex_global_sendq) {
        if (psex_rma2_alloc(hca_info, PSEX_RMA2_MTU * psex_sendq_size,
                            &hca_info->send.bufs)) {
            goto err_alloc;
        }
        hca_info->send.pos = 0;
    }

#endif
    hca_info->rma2_nodeid = rma2_get_nodeid(hca_info->rma2_port);
    hca_info->rma2_vpid   = rma2_get_vpid(hca_info->rma2_port);

    INIT_LIST_HEAD(&hca_info->rma2_reqs);
    pscom_poll_init(&hca_info->rma2_reqs_read);

    /*
     * VELO2
     */
    vrc = velo2_open(&hca_info->velo2_port);
    if (vrc != VELO2_RET_SUCCESS) {
        psex_err_velo2_error("velo2_open()", vrc);
        goto err_velo2_open;
    }

    hca_info->velo2_nodeid = velo2_get_nodeid(&hca_info->velo2_port);
    hca_info->velo2_vpid   = velo2_get_vpid(&hca_info->velo2_port);

    psex_dprint(2, "nodeid:%5u VELO vpid:%5u RMA vpid:%5u",
                hca_info->velo2_nodeid, hca_info->velo2_vpid,
                hca_info->rma2_vpid);

    return 0;
    /* --- */
err_velo2_open:
#ifndef DISABLE_RMA2
err_alloc:
#endif
    psex_cleanup_hca(hca_info);
err_hca:
    return -1;
}


int psex_init(void)
{
    static int init_state = 1;
    assert(sizeof(psex_msg_t) == 4096);
    if (init_state == 1) {
        memset(&psex_stat, 0, sizeof(psex_stat));

        if (psex_init_hca(&default_hca)) { goto err_hca; }

        init_state = 0;
    }

    return init_state; /* 0 = success, -1 = error */
                       /* --- */
err_hca:
    init_state = -1;
    psex_dprint(1, "EXTOLL disabled : %s", psex_err_str);
    return -1;
}


#ifndef DISABLE_RMA2
/* returnvalue like write(), except on error errno is negative return */
static ssize_t _psex_sendv(psex_con_info_t *con_info, struct iovec *iov,
                           size_t size, unsigned int magic)
{
    int len;
    int psex_len;
    psex_msg_t *_msg;
    int rc;
    psex_msgheader_t *tail;
    hca_info_t *hca_info = con_info->hca_info;

    if (con_info->con_broken) { goto err_broken; }

    /* Its allowed to send, if
       At least 2 tokens left or (1 token left AND n_tosend > 0)
    */

    if ((con_info->n_send_toks < 2) &&
        ((con_info->n_send_toks < 1) || (con_info->n_tosend_toks == 0))) {
        psex_stat.busy_notokens++;
        goto err_busy;
    }

    if (psex_global_sendq && psex_pending_global_sends >= psex_sendq_size &&
        psex_event_count) {
        // printf("Busy global\n"); usleep(10*1000);
        psex_stat.busy_global_cq++;
        goto err_busy;
    }

    len      = (size <= (int)PSEX_RMA2_PAYLOAD) ? size : (int)PSEX_RMA2_PAYLOAD;
    psex_len = PSEX_LEN(len);

    ringbuf_t *send = (con_info->send.bufs.mr) ? &con_info->send
                                               : &hca_info->send;
    _msg            = ((psex_msg_t *)send->bufs.ptr) + send->pos;

    tail = (psex_msgheader_t *)((char *)_msg + psex_len -
                                sizeof(psex_msgheader_t));

    tail->token   = con_info->n_tosend_toks;
    tail->payload = len;
    tail->magic   = magic;

    /* copy to registerd send buffer */
    pscom_memcpy_from_iov((void *)_msg, iov, len);
    rc = rma2_post_put_bt(con_info->rma2_port, con_info->rma2_handle,
                          send->bufs.mr,
                          ((char *)_msg - (char *)send->bufs.ptr), psex_len,
                          PSEX_DATA(con_info->remote_rbuf_nla +
                                        con_info->remote_recv_pos *
                                            sizeof(psex_msg_t),
                                    psex_len),
                          0, 0);
    if (rc != 0) { goto err_rma2_post_cl; }

    psex_pending_global_sends++; // ToDo: Decrease the counter somewhere!

    pscom_forward_iov(iov, len);

    con_info->n_tosend_toks   = 0;
    con_info->remote_recv_pos = (con_info->remote_recv_pos + 1) %
                                psex_recvq_size;
    send->pos = (send->pos + 1) % psex_sendq_size;
    con_info->n_send_toks--;

    return len;
    /* --- */
err_busy:
    return -EAGAIN;
    /* --- */
err_rma2_post_cl:
    if (0 /*rc == ???EAGAIN  Too many posted work requests ? */) {
        psex_stat.post_send_eagain++;
        return -EAGAIN;
    } else {
        psex_stat.post_send_error++;
        psex_err_rma2_error("rma2_post_put_cl()", rc);
        con_info->con_broken = 1;
        return -EPIPE;
    }
    /* --- */
err_broken:
    return -EPIPE;
}


ssize_t psex_sendv(psex_con_info_t *con_info, struct iovec *iov, size_t size)
{
    return _psex_sendv(con_info, iov, size, PSEX_MAGIC_IO);
}


static void _psex_send_tokens(psex_con_info_t *con_info)
{
    if (con_info->n_tosend_toks >= psex_pending_tokens) {
        if (psex_sendv(con_info, NULL, 0) == -EAGAIN) {
            psex_stat.busy_token_refresh++;
        }
    }
}


void psex_recvdone(psex_con_info_t *con_info)
{
    con_info->n_tosend_toks++;
    con_info->n_recv_toks--;
    con_info->recv.pos = (con_info->recv.pos + 1) % psex_recvq_size;

    // if send_tokens() fail, we will retry it in psex_recvlook.
    _psex_send_tokens(con_info);
}


static void psex_progress(psex_con_info_t *con_info)
{
    RMA2_Notification *notification;
    RMA2_ERROR rc;
    RMA2_Port rma2_port = con_info->rma2_port;

    rc = rma2_noti_probe(rma2_port, &notification);
    if (rc == RMA2_SUCCESS) {
        psex_handle_notification(notification);
        rma2_noti_free(rma2_port, notification);
    }
}


/* returnvalue like read() , except on error errno is negative return */
int psex_recvlook(psex_con_info_t *con_info, void **buf)
{
#if 1 // Simpler loop because:
      // assert(con_info->n_recv_toks == 0) as long as we only poll!
    while (1) {
        psex_msg_t *msg = ((psex_msg_t *)con_info->recv.bufs.ptr) +
                          con_info->recv.pos;

        unsigned int magic = msg->tail.magic;

        if (!magic) { // Nothing received
            *buf = NULL;
            // Maybe we have to send tokens before we can receive more:
            _psex_send_tokens(con_info);
            psex_progress(con_info);
            return (con_info->con_broken) ? -EPIPE : -EAGAIN;
        }

        msg->tail.magic = PSEX_MAGIC_UNUSED;

        /* Fresh tokens ? */
        con_info->n_send_toks += msg->tail.token;
        con_info->n_recv_toks++;

        unsigned int len = msg->tail.payload;

        *buf = PSEX_DATA((char *)msg, PSEX_LEN(len));
        if (len) {
            // receive data
            return len;
        }

        /* skip 0 payload packages (probably fresh tokens) */
        psex_recvdone(con_info);
    }
#else
    unsigned int magic;
    /* Check for new packages */
    {
        psex_con_info_t *con = con_info;
        psex_msg_t *msg      = ((psex_msg_t *)con->recv_bufs.ptr) +
                          ((con->recv_pos + con->n_recv_toks) % SIZE_SR_QUEUE);
        magic = msg->tail.magic;

        if (magic) {
            //			printf("receive magic %08x\n", msg->tail.magic);
            msg->tail.magic = PSEX_MAGIC_UNUSED;

            /* Fresh tokens ? */
            con->n_send_toks += msg->tail.token;
            con->n_recv_toks++;
        }
    }

    while (con_info->n_recv_toks > 0) {
        psex_msg_t *msg = ((psex_msg_t *)con_info->recv_bufs.ptr) +
                          con_info->recv_pos;
        int len = msg->tail.payload;

        *buf = PSEX_DATA(msg, PSEX_LEN(len));
        if (len) {
            // ToDo: This could be the wrong magic!!!
            return len;
        }
        /* skip 0 payload packages */
        psex_recvdone(con_info);
    }

    if (con_info->con_broken) {
        return -EPIPE;
    } else {
        // Maybe we have to send tokens before we ca receive more:
        _psex_send_tokens(con_info);
        return -EAGAIN;
    }
#endif
}
#endif


/* returnvalue like write(), except on error errno is negative return */
int psex_velo2_sendv(psex_con_info_t *con_info, struct iovec *iov, size_t size)
{
    unsigned len;
    velo2_ret_t vrc;

    if (con_info->con_broken) { goto err_broken; }

    len = (size <= PSEX_VELO2_MTU) ? (unsigned)size : PSEX_VELO2_MTU;
    if (0 /* iov[0].iov_len == 0 && iov[1].iov_len >= len */) {
        // direct copy
        char *msg = iov[1].iov_base;
        vrc       = velo2_send(&con_info->velo2_con, msg, len, 0x00, 0);
    } else {
        // copy to intermediate buffer
        char msg[PSEX_VELO2_MTU];
        pscom_memcpy_from_iov(msg, iov, len);
        vrc = velo2_send(&con_info->velo2_con, msg, len, 0x00, 0);
    }

    if (vrc != VELO2_RET_SUCCESS) { goto err_velo2_send; }

    pscom_forward_iov(iov, len);

    return len;
    /* --- */
err_velo2_send:
    psex_stat.post_send_error++;
    psex_err_velo2_error("velo2_send()", vrc);
    psex_dprint(1, "psex_velo2_sendv() : %s", psex_err_str);
    con_info->con_broken = 1;
    return -EPIPE;
    /* --- */
err_broken:
    return -EPIPE;
}


int psex_velo2_recv(hca_info_t *hca_info, void **priv, void *msg, size_t msglen)
{
    if (!hca_info) { hca_info = &default_hca; }

    uint32_t mlen;
    uint32_t srcid;
    uint8_t tag, mtt;
    velo2_ret_t vrc;

    if (msglen >= INT_MAX) { msglen = INT_MAX; }

    vrc = velo2_probe_recv(&hca_info->velo2_port, msg, (unsigned)msglen, &mlen,
                           &srcid, &tag, &mtt);

    if (vrc == VELO2_RET_SUCCESS) {
        psex_con_info_t *con = psex_map_get_con(srcid);
        if (con) {
            *priv = con->priv;
            return mlen;
        } else {
            // Receive message with wrong srcid
            psex_dprint(1,
                        "psex_velo2_recv() : received a message with unknown "
                        "srcid 0x%x",
                        srcid);
            return -EAGAIN;
        }
    } else if (vrc == VELO2_RET_NO_MSG) {
        return -EAGAIN;
    } else {
        psex_err_velo2_error("velo2_recv()", vrc);
        psex_dprint(1, "psex_velo2_recv() : %s", psex_err_str);
        return -EPIPE;
    }
}


psex_con_info_t *psex_con_create(void)
{
    psex_con_info_t *con_info = malloc(sizeof(*con_info));
    memset(con_info, 0, sizeof(*con_info));
    return con_info;
}


void psex_con_free(psex_con_info_t *con_info)
{
    free(con_info);
}


void psex_con_get_info_msg(psex_con_info_t *con_info /* in */,
                           psex_info_msg_t *info_msg /* out */)
{
    hca_info_t *hca_info = con_info->hca_info;

    info_msg->rma2_nodeid = hca_info->rma2_nodeid;
    info_msg->rma2_vpid   = hca_info->rma2_vpid;
#ifndef DISABLE_RMA2
    {
        int rc;
        rc = rma2_get_nla(con_info->recv.bufs.mr, 0, &info_msg->rbuf_nla);
        assert(rc == RMA2_SUCCESS);
    }
#endif
    info_msg->velo2_nodeid = hca_info->velo2_nodeid;
    info_msg->velo2_vpid   = hca_info->velo2_vpid;
}
