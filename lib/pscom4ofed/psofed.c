/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psofed.c: OFED/Infiniband communication (in UD mode)
 */

#include "psofed.h"

#include <assert.h>
#include <errno.h>
#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "list.h"
#include "pscom_util.h"

/* Size of the send, receive and completion queue */
#define _SIZE_SEND_QUEUE 1024
#define _SIZE_RECV_QUEUE 1024
#define _SIZE_COMP_QUEUE (_SIZE_SEND_QUEUE + _SIZE_RECV_QUEUE)


/* MTU on infiniband */
#define IB_MTU_SPEC IBV_MTU_2048 /* unused with UD? */

#define IB_MTU                                                                 \
    (2 * 1024) /* must be <= 2048 (IB UD MTU limit), should be a power of 2 */

#define IB_UD_OFFSET 40 /* UD global routing header (GRH) */

#define IB_MTU_PAYLOAD                                                         \
    (IB_MTU - ((unsigned)sizeof(psofed_msgheader_t) + IB_UD_OFFSET))
#define IB_MAX_INLINE 64

// #define TRACE(cmd) cmd
#define TRACE(cmd)

typedef struct {
    void *ptr;
    struct ibv_mr *mr;
} mem_info_t;


typedef struct {
    mem_info_t bufs;
    unsigned pos; /* current position */
} ringbuf_t;


typedef uint16_t psofed_seqno_t;


typedef struct {
    uint32_t src; // src id

    psofed_seqno_t seq; // sequence number
    psofed_seqno_t ack; // ack until (including)

    uint16_t len; // data len

    uint16_t _reserved1_; /* allign */
    uint32_t _reserved2_; /* 128 bit msgheader */
} psofed_msgheader_t;


#define PSOFED_MAGIC_UNUSED 0
#define PSOFED_MAGIC_IO     1

typedef struct {
    psofed_msgheader_t header;
    /* IB_MTU_PAYLOAD is 40 bytes smaller than sizeof(data)!
     * There is also room for the GRH at the receiver! */
    char data[IB_MTU - sizeof(psofed_msgheader_t)];
} psofed_msg_t;


typedef struct psofed_send_buffer {
    struct list_head next; /* General purpose next. Used by:
                              - list context_info.sbuf_pool
                              - list psofed_con_info.resendq
                           */
    psofed_msg_t *msg;   /* pointer inside context_info.send_buffers.bufs.ptr */
    unsigned psofed_len; /* len to use in ibv_post_send(). (alligned) */
    unsigned state;      /* state of this buffer */

    struct psofed_con_info *con_info; /* connection this buffer is used by */
} psofed_send_buffer_t;


#define SBUF_INIT    0x00
#define SBUF_UNUSED  0x01 /* sbuf is in sbuf_pool */
#define SBUF_SENDING 0x02 /* send posted, waiting for completion */
#define SBUF_ACKED   0x04 /* ack received for this sbuf */


/* Context: Information shared between multiple connections. */
struct context_info {
    /* ib */
    struct ibv_context *ctx;
    struct ibv_cq *cq; /* handle to cq */
    struct ibv_pd *pd; /* Protection domain */
    struct ibv_qp *qp;

    /* protocol */
    mem_info_t send_buffers;      /* IB_MTU * psofed_sendq_size bytes registered
                                     (pinned) and used for sending */
    struct list_head sbuf_pool;   /* List of psofed_send_buffer_t.next
                                     pool of unused sendbuffers */
    struct list_head con_resendq; /* psofed_con_info.next_resend
                                     List of connections with scheduled resends.
                                     Most urgent con first. */
    ringbuf_t recvq;
    unsigned sends_uncomplete; // count send WRs in progress
    unsigned int recv_posted;  // count posted receives
    unsigned int recv_done;    // count receives which are waiting for further
                               // processing.

    /* connections */
    psofed_con_info_t **connections; // list of all connections (indexed by
                                     // "src")
    unsigned connections_count;
    unsigned connections_firstfree_hint; /* hint for the first free place
                                          * There is never a free place before!
                                          */

    uint8_t port_num; // Used port
    uint16_t lid;     // my lid
    psofed_recv_t last_recv;

    /* Buffers */
    psofed_send_buffer_t *sbuffers; // send buffer meta data
};


/* OFED specific information about one connection */
struct psofed_con_info {
    /* low level */
    context_info_t *context;
    struct ibv_ah *ah;
    uint32_t qp_num; // remote qp numper

    /* send */
    uint32_t src;           // src id
    psofed_seqno_t s_seq;   // Next to use sequence number (send)
    psofed_seqno_t s_acked; // highest acked sequence number (send)
    psofed_seqno_t r_ack;   // last send ack (send)

    /* recv */
    psofed_seqno_t r_seq; // Next expected sequence number (receive)

    void *priv; // Private to the psofed user.

    struct list_head resendq; // List of psofed_send_buffer_t.next

    unsigned sending_count;       // Count unfinished send work request
    struct list_head next_resend; // - used by list context_info.con_resendq
    unsigned long last_send;
    unsigned resend_count; // Count the resends. Reset after receive of an ACK.

    int con_broken;
};


// msg length for payload len
#define PSOFED_LEN(len)                                                        \
    (((len + (unsigned)sizeof(psofed_msgheader_t)) + 7) & ~7)

/*
 * static variables
 */

static context_info_t default_context;
unsigned psofed_outstanding_cq_entries = 0;

static char *psofed_err_str = NULL;

int psofed_debug             = 2;
FILE *psofed_debug_stream    = NULL;
char *psofed_hca             = NULL;        /* hca name to use. */
unsigned int psofed_port     = 0;           /* port index to use. (0 = scan) */
unsigned int psofed_path_mtu = IB_MTU_SPEC; /* path mtu (unused with UD?)*/

unsigned int psofed_sendq_size     = _SIZE_SEND_QUEUE;
unsigned int psofed_recvq_size     = _SIZE_RECV_QUEUE;
unsigned int psofed_compq_size     = _SIZE_COMP_QUEUE;
unsigned int psofed_pending_tokens = _SIZE_RECV_QUEUE / 3; // Send ACK if
                                                           // pending_tokens are
                                                           // outstanding
unsigned int psofed_winsize = _SIZE_RECV_QUEUE / 2; // Do not send more then
                                                    // winsize unacked messsages

unsigned long psofed_resend_timeout      = 10000; // resend in usec. 4 times the
                                             // timeout on each resend starting
                                             // with psofed_resend_timeout
/* maximal wait: 10000 << 11 =  20.48 sec */
unsigned int psofed_resend_timeout_shift = 11; // Never wait longer then
                                               // psofed_resend_timeout <<
                                               // psofed_resend_timeout_shift

int psofed_event_count = 1; /* bool. Be busy if outstanding_cq_entries is to
                               high? */
int psofed_lid_offset  = 0; /* int: offset to base LID (adaptive routing) */


struct psofed_stat_s {
    unsigned busy_notokens; // connection out of tokens for sending (win closed)
    unsigned busy_nosbuffers; // No sendbuffers left
    //	unsigned busy_local_cq;	// connection sendqueue busy. (outstanding ev's)
    //	unsigned busy_global_cq;	// global completion queue busy.
    unsigned post_send_eagain; // ibv_post_send() returned EAGAIN.
    unsigned post_send_error;  // ibv_port_send() returned with an error !=
                               // EAGAIN.
    //	unsigned busy_token_refresh;// sending tokens with nop message failed.
    unsigned recv_ack;     // Received explicit ACKs (not comming piggyback)
    unsigned send_ack;     // explicit sent ACKs (not sent piggyback)
    unsigned send_resends; // explicit resends, not counting regular sends.
} psofed_stat;


#define psofed_dprint(level, fmt, arg...)                                      \
    do {                                                                       \
        if ((level) <= psofed_debug) {                                         \
            fprintf(psofed_debug_stream ? psofed_debug_stream : stderr,        \
                    "ib:" fmt "\n", ##arg);                                    \
        }                                                                      \
    } while (0);


static void psofed_err(char *str)
{
    if (psofed_err_str) { free(psofed_err_str); }

    psofed_err_str = str ? strdup(str) : strdup("");
    return;
}

static void psofed_err_errno(char *str, int err_no)
{
    const char *vapi_err = strerror(err_no);
    size_t len           = strlen(str) + strlen(vapi_err) + 20;
    char *msg            = malloc(len);

    assert(msg);

    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, vapi_err);

    psofed_err(msg);
    free(msg);
}


static inline int psofed_seqcmp(psofed_seqno_t a, psofed_seqno_t b)
{
    return (int16_t)(a - b);
}


static inline int timestamp_expired(unsigned long timestamp, unsigned long now,
                                    unsigned resendcnt)
{
    unsigned long delta = now - timestamp;
    unsigned shift      = resendcnt * 2;
    unsigned long expire_delta =
        psofed_resend_timeout
        << ((shift < psofed_resend_timeout_shift)
                ? shift
                : psofed_resend_timeout_shift); // doubling
                                                // timeout
                                                // each
                                                // resend.

    return delta >= expire_delta;
}


unsigned psofed_pending_tokens_suggestion(void)
{
    return psofed_recvq_size / 2;
}


char *psofed_pending_tokens_suggestion_str(void)
{
    static char res[16];

    snprintf(res, sizeof(res) - 1, "%u", psofed_pending_tokens_suggestion());

    return res;
}


static const char *port_state_str(enum ibv_port_state port_state)
{
    switch (port_state) {
    case IBV_PORT_DOWN: return "DOWN";
    case IBV_PORT_INIT: return "INIT";
    case IBV_PORT_ARMED: return "ARMED";
    case IBV_PORT_ACTIVE: return "ACTIVE";
    default: return "UNKNOWN";
    }
}

static char *port_name(const char *hca_name, int port)
{
    static char res[50];
    if (!hca_name && port == -1) { return "<first active>"; }
    if (!hca_name) { hca_name = "<first active>"; }
    if (port != -1) {
        snprintf(res, sizeof(res), "%s:%d", hca_name, port);
    } else {
        snprintf(res, sizeof(res), "%s:<first active>", hca_name);
    }
    return res;
}


static void psofed_scan_hca_ports(struct ibv_device *ib_dev)
{
    struct ibv_context *ctx;
    struct ibv_device_attr device_attr;
    int rc;
    uint8_t port_cnt;
    uint8_t port;
    const char *dev_name;

    dev_name = ibv_get_device_name(ib_dev);
    if (!dev_name) { dev_name = "unknown"; }

    ctx = ibv_open_device(ib_dev);
    if (!ctx) { goto err_open_dev; }

    rc = ibv_query_device(ctx, &device_attr);
    if (!rc) {
        port_cnt = device_attr.phys_port_cnt;
        if (port_cnt > 128) { port_cnt = 128; }
    } else {
        // Query failed. Assume 2 ports.
        port_cnt = 2;
    }

    for (port = 1; port <= port_cnt; port++) {
        struct ibv_port_attr port_attr;
        enum ibv_port_state port_state;
        const char *marker;

        rc         = ibv_query_port(ctx, port, &port_attr);
        port_state = (enum ibv_port_state)(!rc ? port_attr.state
                                               : 999 /* unknown */);

        marker = "";
        if (port_state == IBV_PORT_ACTIVE &&
            (!psofed_hca || !strcmp(dev_name, psofed_hca)) &&
            (!psofed_port || psofed_port == port)) {
            // use this port for the communication:

            if (!psofed_hca) { psofed_hca = strdup(dev_name); }
            if (!psofed_port) { psofed_port = port; }
            marker = "*";
        }

        psofed_dprint(3, "IB port <%s:%u>: %s%s", dev_name, port,
                      port_state_str(port_state), marker);
    }

    if (ctx) { ibv_close_device(ctx); }

err_open_dev:
    return;
}


static void psofed_scan_all_ports(void)
{
    struct ibv_device **dev_list;
    struct ibv_device *ib_dev = NULL;
    int dev_list_count;
    int i;

    // psofed_dprint(3, "configured port <%s>", port_name(psofed_hca,
    // psofed_port));

    dev_list = ibv_get_device_list(&dev_list_count);
    if (!dev_list) { goto err_no_dev_list; }

    for (i = 0; i < dev_list_count; i++) {
        ib_dev = dev_list[i];
        if (!ib_dev) { continue; }

        psofed_scan_hca_ports(ib_dev);
    }

    ibv_free_device_list(dev_list);
err_no_dev_list:
    if (!psofed_port) { psofed_port = 1; }
    psofed_dprint(2, "using port <%s>", port_name(psofed_hca, psofed_port));
}


static struct ibv_device *psofed_get_dev_by_hca_name(const char *in_hca_name)
{
    /* new method with ibv_get_device_list() */
    struct ibv_device **dev_list;
    struct ibv_device *ib_dev = NULL;
    int dev_list_count;

    dev_list = ibv_get_device_list(&dev_list_count);
    if (!dev_list) { goto err_no_dev; }
    if (!in_hca_name) {
        // const char *tmp;
        ib_dev = dev_list[0];

        // tmp = ibv_get_device_name(ib_dev);

        // psofed_dprint(2, "Got IB device \"%s\"", tmp);

        if (!ib_dev) { goto err_no_dev2; }
    } else {
        int i;
        for (i = 0; i < dev_list_count; i++) {
            ib_dev = dev_list[i];
            if (!ib_dev) { break; }
            const char *tmp = ibv_get_device_name(ib_dev);
            if (!strcmp(tmp, in_hca_name)) {
                // psofed_dprint(2, "Got IB device \"%s\"", tmp);
                break;
            }
            ib_dev = NULL;
        }
        if (!ib_dev) { goto err_no_dev_name; }
    }
    ibv_free_device_list(dev_list);

    return ib_dev;
    /* --- */
err_no_dev:
    psofed_err_errno("ibv_get_devices() failed : No IB dev found", errno);
    return 0;
    /* --- */
err_no_dev2:
    psofed_err_errno("ibv_get_devices() failed : IB dev list empty", errno);
    ibv_free_device_list(dev_list);
    return 0;
    /* --- */
err_no_dev_name : {
    static char err_str[50];
    snprintf(err_str, sizeof(err_str), "IB device \"%s\"", in_hca_name);
    psofed_err_errno(err_str, ENODEV);
    ibv_free_device_list(dev_list);
    return 0;
}
}


/* if hca_name == NULL choose first HCA */
static struct ibv_context *psofed_open_hca(char *hca_name)
{
    struct ibv_device *ib_dev;
    struct ibv_context *ctx;

    ib_dev = psofed_get_dev_by_hca_name(hca_name);
    if (!ib_dev) { goto err_no_hca; }

    ctx = ibv_open_device(ib_dev);
    if (!ctx) { goto err_open_device; }

    return ctx;
    /* --- */
err_open_device:
    psofed_err_errno("ibv_open_device() failed", errno);
    return NULL;
    /* --- */
err_no_hca:
    return NULL;
}

static struct ibv_cq *psofed_open_cq(struct ibv_context *ctx, int cqe_num)
{
    /* create completion queue - used for both send and receive queues */
    struct ibv_cq *cq;

    errno = 0;
    cq    = ibv_create_cq(ctx, cqe_num, NULL, NULL, 0);

    if (!cq) { psofed_err_errno("ibv_create_cq() failed", errno); }

    return cq;
}

static struct ibv_pd *psofed_open_pd(struct ibv_context *ctx)
{
    /* allocate a protection domain to be associated with QP */
    struct ibv_pd *pd;

    pd = ibv_alloc_pd(ctx);

    if (!pd) { psofed_err_errno("ibv_alloc_pd() failed", errno); }

    return pd;
}


static uint16_t psofed_get_lid(struct ibv_context *ctx, uint8_t port_num)
{
    struct ibv_port_attr attr;
    if (ibv_query_port(ctx, port_num, &attr)) { goto err_query_port; }

    if (attr.state != IBV_PORT_ACTIVE) { goto err_port_down; }

    if (attr.lid == 0) { goto err_no_lid; }

    return (uint16_t)(attr.lid + psofed_lid_offset);
    /* --- */
err_query_port:
    if (errno != EINVAL) {
        psofed_err_errno("ibv_query_port() failed", errno);
    } else {
        psofed_err("init_port failed : No ACTIVE port.");
    }
    return 0;
err_port_down:
    psofed_err("Port not in state ACTIVE");
    return 0;
err_no_lid:
    psofed_err("Port has no lid (subnet manager running?)");
    return 0;
}


struct ibv_qp *psofed_open_qp(context_info_t *context)
{
    /* open UD queue pair */
    struct ibv_qp *qp;
    int rc;
    struct ibv_qp_init_attr iattr = {
        .send_cq = context->cq,
        .recv_cq = context->cq,
        .cap     = {.max_send_wr  = psofed_sendq_size,
                    .max_recv_wr  = psofed_recvq_size,
                    .max_send_sge = 1,
                    .max_recv_sge = 1},
        .qp_type = IBV_QPT_UD,
    };
    struct ibv_qp_attr attr = {.qp_state   = IBV_QPS_INIT,
                               .pkey_index = 0,
                               .port_num   = context->port_num,
                               .qkey       = 0x11111111};

    qp = ibv_create_qp(context->pd, &iattr);
    if (!qp) { goto err_create_qp; }

    rc = ibv_modify_qp(qp, &attr,
                       IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT |
                           IBV_QP_QKEY);
    if (rc) { goto err_mod_qp; }

    return qp;
err_mod_qp:
    ibv_destroy_qp(qp);
    psofed_err("ibv_modify_qp(IBV_QPS_INIT) failed");
    return NULL;
err_create_qp:
    psofed_err("ibv_create_qp(IBV_QPT_UD) failed");
    return NULL;
}


static int psofed_start_qp(struct ibv_qp *qp)
{
    int rc;
    /* init -> rtr */
    {
        struct ibv_qp_attr attr = {.qp_state = IBV_QPS_RTR};

        rc = ibv_modify_qp(qp, &attr, IBV_QP_STATE);
        if (rc) {
            psofed_err("ibv_modify_qp(IBV_QPS_RTR)");
            return -1;
        }
    }
    /* rtr -> rts */
    {
        struct ibv_qp_attr attr = {
            .qp_state = IBV_QPS_RTS, .sq_psn = 0 /* my packet seqno */
        };

        rc = ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN);
        if (rc) {
            psofed_err("ibv_modify_qp(IBV_QPS_RTS)");
            return -1;
        }
    }
    return 0;
}


static void psofed_fix_compq_size(struct ibv_context *ctx)
{
    struct ibv_device_attr device_attr;

    if (!ibv_query_device(ctx, &device_attr)) {
        if ((device_attr.max_cqe >= 4) &&
            ((unsigned)device_attr.max_cqe < psofed_compq_size)) {
            psofed_compq_size = device_attr.max_cqe;
            psofed_dprint(1, "reset psofed_compq_size to hca limit %u\n",
                          psofed_compq_size);
        }
    } else {
        psofed_dprint(1, "ibv_query_device() : failed");
    }
}


static void psofed_vapi_free(context_info_t *context, mem_info_t *mem_info)
{
    ibv_dereg_mr(/*context->ctx,*/ mem_info->mr);
    mem_info->mr = NULL;
    free(mem_info->ptr);
    mem_info->ptr = NULL;
}


static void print_mlock_help(unsigned size)
{
    static int called = 0;
    struct rlimit rlim;

    if (called) { return; }
    called = 1;

    if (size) {
        psofed_dprint(0, "OFED: memlock(%u) failed.", size);
    } else {
        psofed_dprint(0, "OFED: memlock failed.");
    }
    psofed_dprint(0, "(Check memlock limit in /etc/security/limits.conf or try "
                     "'ulimit -l')");

    if (!getrlimit(RLIMIT_MEMLOCK, &rlim)) {
        psofed_dprint(0, "Current RLIMIT_MEMLOCK: soft=%lu byte, hard=%lu byte",
                      rlim.rlim_cur, rlim.rlim_max);
    }
}

static int psofed_vapi_alloc(context_info_t *context, int size, int access_perm,
                             mem_info_t *mem_info)
{
    mem_info->mr = NULL;

    /* Region for buffers */
    mem_info->ptr = valloc(size);
    if (!mem_info->ptr) { goto err_malloc; }

    // printf("ibv_reg_mr(pd = %p, ptr = %p, size = %d, access_perm = 0x%x)\n",
    //        context->pd, mem_info->ptr, size, access_perm);

    mem_info->mr = ibv_reg_mr(context->pd, mem_info->ptr, size, access_perm);
    if (!mem_info->mr) { goto err_reg_mr; }

    return 0;
    /* --- */
err_reg_mr:
    free(mem_info->ptr);
    mem_info->ptr = NULL;
    psofed_err_errno("ibv_reg_mr() failed", errno);
    if (errno == ENOMEM) { print_mlock_help(size); }
    return -1;
err_malloc:
    psofed_err_errno("malloc() failed!", errno);
    return -1;
}


static void _psofed_post_recv(context_info_t *context)
{
    psofed_msg_t *msg = ((psofed_msg_t *)context->recvq.bufs.ptr) +
                        (context->recvq.pos + context->recv_posted) %
                            psofed_recvq_size;

    //	printf("post receive at pos %d\n", context->recvq.pos +
    //	       context->recv_posted);
    struct ibv_sge list   = {.addr   = (uintptr_t)msg,
                             .length = IB_MTU,
                             .lkey   = context->recvq.bufs.mr->lkey};
    struct ibv_recv_wr wr = {
        .wr_id   = 0x6731, // ID only
        .sg_list = &list,
        .num_sge = 1,
    };
    struct ibv_recv_wr *bad_wr;
    int rc;

    assert(context->recv_posted < psofed_recvq_size);

    rc = ibv_post_recv(context->qp, &wr, &bad_wr);
    if (rc) { psofed_dprint(0, "ibv_post_recv() failed!"); }

    context->recv_posted++;
}


static void psofed_post_recvs(context_info_t *context)
{
    unsigned i;
    for (i = context->recv_posted; i < psofed_recvq_size; i++) {
        _psofed_post_recv(context);
    }
}


static int psofed_con_assign_src(psofed_con_info_t *con_info)
{
    unsigned idx;
    context_info_t *context = con_info->context;
    psofed_con_info_t **nconnections;

    // search for a free place in context_connections.
    for (idx = context->connections_firstfree_hint;
         idx < context->connections_count; idx++) {
        if (!(context->connections[idx])) { goto got_idx; }
    }
    // No free place. Increase connections array:
    idx = context->connections_count;
    context->connections_count++;
    nconnections = realloc(context->connections,
                           context->connections_count *
                               sizeof(context->connections[0]));
    if (!nconnections) { goto err_nomem; }
    context->connections = nconnections;

got_idx:
    context->connections[idx]           = con_info;
    context->connections_firstfree_hint = idx + 1;
    return 0;
    /* --- */
err_nomem:
    context->connections_count--;
    psofed_err_errno("realloc()", errno);
    return -1;
}


/* Find position of con_info in con_info->context->connections.
 * return -1 on error */
static int psofed_con2src(psofed_con_info_t *con_info)
{
    unsigned idx;
    context_info_t *context = con_info->context;

    for (idx = 0; idx < context->connections_count; idx++) {
        if (context->connections[idx] == con_info) { return idx; }
    }
    return -1;
}


static void psofed_con_unassign_src(psofed_con_info_t *con_info)
{
    int idx;
    context_info_t *context = con_info->context;

    idx = psofed_con2src(con_info);
    assert(idx >= 0);

    context->connections[idx] = NULL;
    if (idx < (int)context->connections_firstfree_hint) {
        context->connections_firstfree_hint = idx;
    }
}


void psofed_con_cleanup(psofed_con_info_t *con_info)
{
    if (con_info->ah) {
        ibv_destroy_ah(con_info->ah);
        con_info->ah = NULL;
    }
    psofed_con_unassign_src(con_info);
}


int psofed_con_init(psofed_con_info_t *con_info, context_info_t *context,
                    void *priv)
{
    int rc;

    if (!context) { context = &default_context; }

    con_info->context    = context;
    con_info->ah         = NULL;
    con_info->qp_num     = 0;
    con_info->priv       = priv;
    con_info->con_broken = 0;

    con_info->sending_count = 0;
    INIT_LIST_HEAD(&con_info->resendq);
    INIT_LIST_HEAD(&con_info->next_resend);
    con_info->resend_count = 0;

    rc = psofed_con_assign_src(con_info);
    if (rc) { goto err_assign_src; }

    return 0;
    /* --- */
err_assign_src:
    psofed_dprint(1, "psofed_con_init() : %s", psofed_err_str);
    return -1;
}


int psofed_con_connect(psofed_con_info_t *con_info, psofed_info_msg_t *info_msg)
{
    struct ibv_ah_attr ah_attr = {.is_global     = 0,
                                  .dlid          = info_msg->lid,
                                  .sl            = 0, // service level
                                  .src_path_bits = 0,
                                  .port_num      = con_info->context->port_num};

    if (info_msg->version != PSOFED_INFO_VERSION) { goto err_version; }

    con_info->src = info_msg->use_src;

    // Initialize receive tokens
    con_info->s_seq   = 0x80;
    con_info->s_acked = (psofed_seqno_t)(con_info->s_seq - 1);
    con_info->r_seq   = 0x80;

    con_info->qp_num = info_msg->qp_num;

    con_info->ah = ibv_create_ah(con_info->context->pd, &ah_attr);
    if (!con_info->ah) { goto err_ah; }

    return 0;
    /* --- */
err_ah:
    psofed_dprint(1, "psofed_con_connect() : ibv_create_ah() failed");
    return -1;
    /* --- */
err_version:
    psofed_dprint(1,
                  "psofed_con_connect() : version handshake failed (%03x "
                  "expect %03x)",
                  info_msg->version, PSOFED_INFO_VERSION);
    return -1;
}


static psofed_send_buffer_t *get_send_buffer(context_info_t *context)
{
    psofed_send_buffer_t *sbuf;

    if (list_empty(&context->sbuf_pool)) {
        if (!psofed_progress(context) || list_empty(&context->sbuf_pool)) {
            return NULL;
        }
    }

    // Get one buffer from the sbuf_pool
    // assert(!list_empty(&context->sbuf_pool));
    sbuf = list_entry(context->sbuf_pool.next, psofed_send_buffer_t, next);
    list_del(&sbuf->next);
    sbuf->state = SBUF_INIT;

    return sbuf;
}


static void put_send_buffer(context_info_t *context, psofed_send_buffer_t *sbuf)
{
    // send buffer back to pool of unused buffers
    if (unlikely(sbuf->state == SBUF_UNUSED)) { goto err_double_free; }

    sbuf->state = SBUF_UNUSED;
    list_add_tail(&sbuf->next, &context->sbuf_pool);

    return;
err_double_free:
    psofed_dprint(0, "OFED stack bug: ibv_poll_cq(cq, 1, &wc)"
                     " return opcode IBV_WC_SEND with same work request "
                     "twice.");
}


static void psofed_cleanup_context(context_info_t *context)
{
    unsigned i;
    // ToDo: Cancel all posted receices
    // ToDo: Wait for unfinished sends?

    // Cleanup all connetions
    for (i = 0; i < context->connections_count; i++) {
        if (context->connections[i]) {
            psofed_con_cleanup(context->connections[i]);
            psofed_con_free(context->connections[i]);
            context->connections[i] = NULL;
        }
    }
    if (context->connections) {
        free(context->connections);
        context->connections = NULL;
    }
    if (context->recvq.bufs.mr) {
        psofed_vapi_free(context, &context->recvq.bufs);
        context->recvq.bufs.mr = 0;
    }
    if (context->send_buffers.mr) {
        psofed_vapi_free(context, &context->send_buffers);
        context->send_buffers.mr = 0;
    }
    if (context->sbuffers) {
        free(context->sbuffers);
        context->sbuffers = NULL;
    }
    if (context->qp) {
        ibv_destroy_qp(context->qp);
        context->qp = NULL;
    }
    if (context->pd) {
        ibv_dealloc_pd(context->pd);
        context->pd = NULL;
    }
    if (context->cq) {
        ibv_destroy_cq(context->cq);
        context->cq = NULL;
    }
    if (context->ctx) {
        ibv_close_device(context->ctx);
        context->ctx = NULL;
    }
}


static int psofed_init_context(context_info_t *context)
{
    int rc;
    unsigned i;

    context->ctx             = NULL;
    context->cq              = NULL;
    context->pd              = NULL;
    context->qp              = NULL;
    context->send_buffers.mr = NULL;
    INIT_LIST_HEAD(&context->sbuf_pool);
    INIT_LIST_HEAD(&context->con_resendq);
    context->sbuffers      = NULL;
    context->recvq.pos     = 0;
    context->recvq.bufs.mr = NULL;
    context->recv_posted   = 0;
    context->recv_done     = 0;

    context->connections                = NULL;
    context->connections_count          = 0;
    context->connections_firstfree_hint = 0;
    context->last_recv.con_info         = NULL;

    if (psofed_pending_tokens > psofed_recvq_size) {
        psofed_dprint(1, "warning: reset psofed_pending_tokens from %u to %u\n",
                      psofed_pending_tokens, psofed_recvq_size);
        psofed_pending_tokens = psofed_recvq_size;
    }

    context->ctx = psofed_open_hca(psofed_hca);
    if (!context->ctx) { goto err_hca; }

    psofed_fix_compq_size(context->ctx);
    context->cq = psofed_open_cq(context->ctx, psofed_compq_size);
    if (!context->cq) { goto err_cq; }

    context->pd = psofed_open_pd(context->ctx);
    if (!context->pd) { goto err_pd; }

    context->port_num = (uint8_t)psofed_port;
    context->lid      = psofed_get_lid(context->ctx, context->port_num);
    if (!context->lid) { goto err_lid; }

    context->qp = psofed_open_qp(context);
    if (!context->qp) { goto err_qp; }


    /* Send buffers pinned mem */
    rc = psofed_vapi_alloc(context, IB_MTU * psofed_sendq_size, 0,
                           &context->send_buffers);
    if (rc) { goto err_alloc_sq; }

    /* Send buffer meta data */
    context->sbuffers = malloc(sizeof(*context->sbuffers) * psofed_sendq_size);
    if (!context->sbuffers) { goto err_alloc_sbuffers; }

    /* Send buffer pool */
    for (i = 0; i < psofed_sendq_size; i++) {
        psofed_send_buffer_t *sbuf = context->sbuffers + i;
        sbuf->msg   = ((psofed_msg_t *)context->send_buffers.ptr) + i;
        sbuf->state = SBUF_INIT;
        put_send_buffer(context, sbuf);
    }

    /* Receive buffers */
    rc = psofed_vapi_alloc(context, IB_MTU * psofed_recvq_size,
                           IBV_ACCESS_LOCAL_WRITE, &context->recvq.bufs);
    if (rc) { goto err_alloc_rq; }

    /* Post receive requests before moving to rtr and rts */
    psofed_post_recvs(context);

    rc = psofed_start_qp(context->qp);
    if (rc) { goto err_start_qp; }

    return 0;
    /* --- */
err_start_qp:
err_alloc_rq:
err_alloc_sbuffers:
err_alloc_sq:
err_qp:
err_lid:
err_pd:
err_cq:
err_hca:
    psofed_cleanup_context(context);
    return -1;
}


int psofed_init(void)
{
    static int init_state = 1;
    if (init_state == 1) {
        memset(&psofed_stat, 0, sizeof(psofed_stat));
        psofed_scan_all_ports();

        if (psofed_init_context(&default_context)) { goto err_context; }
        init_state = 0;
    }

    return init_state; /* 0 = success, -1 = error */
                       /* --- */
err_context:
    init_state = -1;
    psofed_dprint(1, "OFED disabled : %s", psofed_err_str);
    return -1;
}


static inline int send_send_buffer(psofed_con_info_t *con_info,
                                   psofed_send_buffer_t *sbuf)
{
    int rc;
    context_info_t *context = con_info->context;

    // Update header.ack
    sbuf->msg->header.ack = (psofed_seqno_t)(con_info->r_seq - 1);

    struct ibv_sge list   = {.addr   = (uintptr_t)sbuf->msg,
                             .length = sbuf->psofed_len,
                             .lkey   = context->send_buffers.mr->lkey};
    struct ibv_send_wr wr = {.wr_id      = (uint64_t)(unsigned long)sbuf,
                             .sg_list    = &list,
                             .num_sge    = 1,
                             .opcode     = IBV_WR_SEND,
                             .send_flags = IBV_SEND_SIGNALED,
                             .wr         = {.ud = {.ah          = con_info->ah,
                                                   .remote_qpn  = con_info->qp_num,
                                                   .remote_qkey = 0x11111111}}};
    struct ibv_send_wr *bad_wr;

    TRACE(psofed_dprint(0, "SEND%d Seq:%u Ack:%u len:%u\n",
                        con_info->resend_count, sbuf->msg->header.seq,
                        sbuf->msg->header.ack, sbuf->msg->header.len));
    rc = ibv_post_send(context->qp, &wr, &bad_wr);

    if (!rc) {
        sbuf->state |= SBUF_SENDING;
        con_info->sending_count++;

        con_info->r_ack = (psofed_seqno_t)(con_info->r_seq - 1);
    }
    return rc;
}


static void sched_resend_send_buffer(psofed_con_info_t *con_info,
                                     psofed_send_buffer_t *sbuf)
{
    list_add_tail(&sbuf->next, &con_info->resendq);
}


static void resend_con_sendbuffers(psofed_con_info_t *con_info,
                                   unsigned long now)
{
    struct list_head *pos;

    if (!timestamp_expired(con_info->last_send, now, con_info->resend_count)) {
        return;
    }

    assert(!list_empty(&con_info->resendq));

    con_info->resend_count++;

    /* Send all message not in state SBUF_SENDING again. Sending all messages,
       create much traffic. But if one message is lost, we know for shure, that
       also all following messages need a resend, until we implement an out of
       order receive queue.

       Improvement 1: Implement NACKs and send last messsage instead of first.
       If the receiver detect a lost message, he can request the lost message
       and all messages afterwards with one NACK.

       Improvement 2: Additional implement an out ouf order receive queue. The
       receiver than can request only the lost messages (instead of all messages
       starting from the lost one) with one NACK.

     */
    list_for_each (pos, &con_info->resendq) {
        psofed_send_buffer_t *sbuf = list_entry(pos, psofed_send_buffer_t, next);

        if (sbuf->state & SBUF_SENDING) {
            continue; // already sending
        }

        send_send_buffer(con_info, sbuf); /* error ignored. In case of an error,
                                             SBUF_SENDING will not be set and
                                             send_send() will be called again in
                                             the next loop. */
        psofed_stat.send_resends++;
    }

    con_info->last_send = now; // update the timestamp. Even if we didnt send
                               // anything.
}


static void resend(context_info_t *context)
{
    struct list_head *pos;
    unsigned long now;
    if (list_empty(&context->con_resendq)) { return; }

    now = pscom_wtime_usec();

    list_for_each (pos, &context->con_resendq) {
        psofed_con_info_t *con_info = list_entry(pos, psofed_con_info_t,
                                                 next_resend);
        resend_con_sendbuffers(con_info, now);
    }
}


/* returnvalue like writev(), except on error errno is negative return */
static int _psofed_sendv(psofed_con_info_t *con_info, struct iovec *iov,
                         size_t size)
{
    context_info_t *context = con_info->context;
    psofed_send_buffer_t *sbuf;
    psofed_msg_t *msg;
    unsigned len;
    int rc = 0;

    if (psofed_seqcmp(con_info->s_seq, (psofed_seqno_t)(con_info->s_acked +
                                                        psofed_winsize)) > 0) {
        goto err_winclosed;
    }

    sbuf = get_send_buffer(context);
    if (!sbuf) { goto err_getsbuf; }

    len = (size <= IB_MTU_PAYLOAD) ? (unsigned)size : IB_MTU_PAYLOAD;
    sbuf->psofed_len = PSOFED_LEN(len);
    sbuf->con_info   = con_info;
    /* ToDo: send more than one fragment with one ibv_post_send,
       if size > MTU. (Use multiple ibv_send_wr at once) */

    msg             = sbuf->msg;
    msg->header.src = con_info->src;
    msg->header.seq = con_info->s_seq++;
    msg->header.len = (uint16_t)len;

    pscom_memcpy_from_iov(msg->data, iov, len);

    rc = send_send_buffer(con_info, sbuf);
    if (rc) { goto err_send; }

    sched_resend_send_buffer(con_info, sbuf);

    pscom_forward_iov(iov, len);

    return len;
    /* --- */
err_send:
    con_info->s_seq--;              // Reuse this sequence number!
    put_send_buffer(context, sbuf); // sbuf back to pool of unused buffers
    psofed_stat.post_send_error++;
    // ToDo: error recovery from send failure
    psofed_dprint(0, "ibv_post_send() failed.");
    con_info->con_broken = 1;

    return -EPIPE;
err_winclosed:
    psofed_stat.busy_notokens++;
    return -EAGAIN;
err_getsbuf:
    psofed_stat.busy_nosbuffers++;
    return -EAGAIN;
}


int psofed_sendv(psofed_con_info_t *con_info, struct iovec *iov, size_t size)
{
    return _psofed_sendv(con_info, iov, size); //, PSOFED_MAGIC_IO);
}


static void psofed_send_ack(psofed_con_info_t *con_info)
{
    context_info_t *context = con_info->context;
    psofed_send_buffer_t *sbuf;
    psofed_msg_t *msg;

    sbuf = get_send_buffer(context);
    if (!sbuf) { goto err_getsbuf; }

    sbuf->psofed_len = PSOFED_LEN(0);
    sbuf->con_info   = con_info;

    msg             = sbuf->msg;
    msg->header.src = con_info->src;
    msg->header.seq = con_info->s_acked; // Use an already acked seqno with
                                         // len==0 as the ACK
    msg->header.len = 0;

    send_send_buffer(con_info, sbuf); /* Ignore errors here. We automatically
                                         recover from lost ACKs. */
    sbuf->state |= SBUF_ACKED;

    psofed_stat.send_ack++;

    return;
    /* --- */
err_getsbuf:
    psofed_stat.busy_nosbuffers++;
    return;
}


static void psofed_cond_send_ack(psofed_con_info_t *con_info)
{
    // Conditional send ack.
    if ((unsigned)psofed_seqcmp((psofed_seqno_t)(con_info->r_seq - 1),
                                con_info->r_ack) >= psofed_pending_tokens) {
        psofed_send_ack(con_info);
    }
}


static void ack_send_buffers(psofed_con_info_t *con_info, psofed_seqno_t ack)
{
    if (psofed_seqcmp(con_info->s_acked, ack) >= 0) {
        // Already acked. Nothing to do.
        return;
    }

    con_info->s_acked      = ack;
    con_info->resend_count = 0;

    while (!list_empty(&con_info->resendq)) {
        psofed_send_buffer_t *sbuf = list_entry(con_info->resendq.next,
                                                psofed_send_buffer_t, next);

        if (psofed_seqcmp(sbuf->msg->header.seq, ack) <= 0) {
            list_del(&sbuf->next);
            sbuf->state |= SBUF_ACKED;
            if (!(sbuf->state & SBUF_SENDING)) {
                put_send_buffer(con_info->context, sbuf);
            }
        } else {
            break;
        }
    }
    if (list_empty(&con_info->resendq)) {
        list_del_init(&con_info->next_resend);
    }
}


psofed_recv_t *psofed_recv(context_info_t *context)
{
    if (!context) { context = &default_context; }

    //	printf("Check for a receive\n"); sleep(2);
    psofed_post_recvs(context);
retry:
    // Check for receives, or make progress and check again.
    if (!context->recv_done) {
        psofed_progress(context);
        if (!context->recv_done) {
            // Nothing received
            return NULL;
        }
    }

    psofed_msg_t *msg = ((psofed_msg_t *)((char *)context->recvq.bufs.ptr +
                                          IB_UD_OFFSET)) +
                        context->recvq.pos;

    // Check the receive:
    unsigned src = msg->header.src;
    psofed_con_info_t *con_info;

    //	printf("Got the message: (on pos %d)\n"
    //	       "head: %s\n"
    //	       "data: %s\n",
    //	       context->recvq.pos,
    //	       dumpstr(msg, sizeof(msg->header)),
    //	       dumpstr(msg->data, MIN(msg->header.len, 16)));

    if (src >= context->connections_count ||
        !(con_info = context->connections[src])) {
        // drop message. Unknown src!
        psofed_dprint(3,
                      "psofed_recv(): drop msg with unkown src = %d (count = "
                      "%u)",
                      src, context->connections_count);
        psofed_recvdone(context);
        goto retry;
    }

    // Having a message from con_info.
    TRACE(psofed_dprint(0, "RECV%s Seq:%u Ack:%u len:%u\n",
                        (msg->header.seq == con_info->r_seq)
                            ? ""
                            : (msg->header.len ? "(dup)" : " ACK"),
                        msg->header.seq, msg->header.ack, msg->header.len));

    if (psofed_seqcmp(msg->header.seq, con_info->r_seq) <= 0) {
        ack_send_buffers(con_info, msg->header.ack);
    }

    // Check SeqNo:
    if (msg->header.seq != con_info->r_seq) {
        // Out of order
        // drop message
        // ToDo: Implement NACK

        if (msg->header.len) {
            if (psofed_seqcmp(msg->header.seq, con_info->r_seq) < 0) {
                // Old message = this is a resend. Send ACK now:
                TRACE(psofed_dprint(0, "Send urgent ack\n"));
                psofed_send_ack(con_info);
            } else {
                // Message lose detected.
                // ToDo: Send NACK
                TRACE(psofed_dprint(1,
                                    "psofed_recv(): recv out of order msg : "
                                    "seq = %u (expect %u)",
                                    (unsigned)msg->header.seq,
                                    (unsigned)con_info->r_seq));
            }
        } else {
            // Acks are old messages with len == 0;
            psofed_stat.recv_ack++;
        }
        psofed_recvdone(context);
        goto retry;
    }

    con_info->r_seq++;

    psofed_cond_send_ack(con_info);

    context->last_recv.data     = msg->data;
    context->last_recv.len      = msg->header.len;
    context->last_recv.con_info = con_info;
    context->last_recv.priv     = con_info->priv;

    return &context->last_recv;
}


void psofed_recvdone(context_info_t *context)
{
    if (!context) { context = &default_context; }

    // Ack the receive:
    context->recv_done--;
    context->recv_posted--;
    context->recvq.pos = (context->recvq.pos + 1) % psofed_recvq_size;

    // ToDo: Send ack
}


static void check_resend(psofed_con_info_t *con_info)
{
    if (!con_info->sending_count && !list_empty(&con_info->resendq)) {
        /* No pending send workrequests
           and send buffers waiting for an ACK
           -> Move connection to the tail of the con_resendq */
        list_del(&con_info->next_resend);
        list_add_tail(&con_info->next_resend, &con_info->context->con_resendq);
        con_info->last_send = pscom_wtime_usec();
    }
}


static int psofed_check_cq(context_info_t *context)
{
    struct ibv_wc wc;
    int rc;

    rc = ibv_poll_cq(context->cq, 1, &wc);

    if (rc == 1) {
        // handle IBV_WC_RECV with a fast "if", other wc.opcode with "switch".
        if (wc.opcode == IBV_WC_RECV) {
            if (wc.status == IBV_WC_SUCCESS) {
                context->recv_done++;
            } else {
                psofed_dprint(0, "ibv_poll_cq() : IBV_WC_RECV with status %d",
                              wc.status);
            }
        } else {
            switch (wc.opcode) {
            case IBV_WC_SEND:
                if (wc.status != IBV_WC_SUCCESS) {
                    psofed_dprint(0,
                                  "ibv_poll_cq() : IBV_WC_SEND with status %d",
                                  wc.status);
                    // ToDo: terminate corresponding connection with error
                }
                psofed_send_buffer_t *sbuf =
                    (psofed_send_buffer_t *)(unsigned long)wc.wr_id;

                psofed_con_info_t *con_info = sbuf->con_info;

                sbuf->state &= ~SBUF_SENDING;
                con_info->sending_count--;

                if (unlikely(sbuf->state & SBUF_ACKED)) {
                    put_send_buffer(context, sbuf);
                }

                check_resend(con_info);
                break;
            default:
                psofed_dprint(0, "ibv_poll_cq() : Unknown opcode: %d",
                              wc.opcode);
            }
        }
    }
    return rc;
}


static int psofed_poll(context_info_t *context, int blocking)
{
    int rc;

    do {
        rc = psofed_check_cq(context);
    } while (blocking && (rc != 0 /*VAPI_CQ_EMPTY*/));

    return (rc == 0 /*VAPI_CQ_EMPTY*/);
}


int psofed_progress(context_info_t *context)
{
    resend(context);
    return psofed_poll(context ? context : &default_context, 0);
}


psofed_con_info_t *psofed_con_create(void)
{
    psofed_con_info_t *con_info = malloc(sizeof(*con_info));
    return con_info;
}


void psofed_con_free(psofed_con_info_t *con_info)
{
    free(con_info);
}


void psofed_con_get_info_msg(psofed_con_info_t *con_info /* in */,
                             psofed_info_msg_t *info_msg /* out */)
{
    info_msg->version = PSOFED_INFO_VERSION;
    info_msg->lid     = con_info->context->lid;
    info_msg->qp_num  = con_info->context->qp->qp_num;
    info_msg->use_src = psofed_con2src(con_info);
}
