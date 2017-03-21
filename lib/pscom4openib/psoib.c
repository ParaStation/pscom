/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psoib.c: OPENIB/Infiniband communication
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/resource.h> // getrlimit
#include <syslog.h>

/* #include <sysfs/libsysfs.h> */
#include <infiniband/verbs.h>

#include "list.h"
#ifndef IB_DONT_USE_ZERO_COPY
#include "pscom_priv.h"
#endif
#include "pscom_util.h"
#include "perf.h"
#include "psoib.h"

/* Size of the send, receive and completion queue */
#define _SIZE_SEND_QUEUE 16
#define _SIZE_RECV_QUEUE 16
#define _SIZE_COMP_QUEUE (2500 * 16)


/* MTU on infiniband */
#define IB_MTU_SPEC	IBV_MTU_1024
#define IB_MTU	(16*1024) /* must be < 65536, or change sizeof psoib_msgheader_t.payload,
			     and should be a power of IB_MTU_SPEC */

#define IB_MTU_PAYLOAD	(IB_MTU - (unsigned)sizeof(psoib_msgheader_t))
#define IB_MAX_INLINE	64

/* I got the error
   THH(4): THHUL_qpm_post_send_req: Send queue is full (128 requests outstanding).
   if SEND_NOTIFICATION is disabled */
#define ENABLE_SEND_NOTIFICATION 1

typedef struct {
    mem_info_t	bufs;
    unsigned	pos; /* current position */
} ringbuf_t;


struct hca_info {
    struct ibv_context *ctx;
    struct ibv_cq      *cq; /* handle to cq */
    struct ibv_pd      *pd; /* Protection domain */

    /* send */
    ringbuf_t	send; /* global send queue */

    /* misc */
    struct list_head list_con_info; /* list of all psoib_con_info.next_con_info */

#ifdef IB_USE_RNDV
    /* RMA */
    struct list_head rma_reqs; /* list of active RMA requests : psiob_rma_req_t.next */
    struct pscom_poll_reader rma_reqs_reader; /* calling psoib_progress(). Used if !list_empty(rma_reqs) */
#endif
};

#ifdef IB_USE_RNDV
static int psoib_rma_reqs_progress(pscom_poll_reader_t *reader);
static void psoib_rma_reqs_deq(psoib_rma_req_t *dreq);
#endif

struct port_info {
    unsigned int port_num;
    uint16_t	 lid;
    hca_info_t *hca_info;
};


/* Openib specific information about one connection */
#define MAGIC_PSOIB_CONNECTION 0x24e41a21
struct psoib_con_info {
    unsigned long magic;
    /* low level */
    struct ibv_qp *qp;
    struct ibv_context *ctx; // <- copy from hca_info_t
    port_info_t *port_info;
    hca_info_t *hca_info;

    /* send */
    unsigned int remote_recv_pos; /* next to use receive buffer (= remote recv_pos) */

    void	*remote_ptr;
    uint32_t	remote_rkey;

    ringbuf_t	send;

    /* recv */
    ringbuf_t	recv;

    unsigned	outstanding_cq_entries;

    /* higher level */
    unsigned int n_send_toks;
    unsigned int n_recv_toks;
    unsigned int n_tosend_toks;

    int con_broken;

    /* misc */
    struct list_head next_con_info;
};


typedef struct {
    uint16_t	token;
    uint16_t	payload;
    volatile uint32_t	magic;
} psoib_msgheader_t;

#define PSOIB_MAGIC_UNUSED	0
#define PSOIB_MAGIC_IO		1
#define PSOIB_MAGIC_EOF		2

typedef struct {
    char __data[IB_MTU_PAYLOAD];
    psoib_msgheader_t tail;
} psoib_msg_t;

#define PSOIB_LEN(len) ((len + 7) & ~7)
#define PSOIB_DATA(buf, psoiblen) ((char*)(&(buf)->tail) - psoiblen)

/*
 * static variables
 */

static hca_info_t  default_hca;
static port_info_t default_port;
unsigned psoib_outstanding_cq_entries = 0;

static char *psoib_err_str = NULL;

int psoib_debug = 2;
FILE *psoib_debug_stream = NULL;
char *psoib_hca = NULL; /* hca name to use. */
unsigned int psoib_port = 0; /* port index to use. (0 = scan) */
unsigned int psoib_path_mtu = IB_MTU_SPEC; /* path mtu */

unsigned int psoib_sendq_size = _SIZE_SEND_QUEUE;
unsigned int psoib_recvq_size = _SIZE_RECV_QUEUE;
unsigned int psoib_compq_size = _SIZE_COMP_QUEUE;
unsigned int psoib_pending_tokens = _SIZE_RECV_QUEUE - 6;

int psoib_global_sendq = 0; /* bool. Use one sendqueue for all connections? */
int psoib_event_count = 1; /* bool. Be busy if outstanding_cq_entries is to high? */
int psoib_ignore_wrong_opcodes = 0; /* bool: ignore wrong cq opcodes */
int psoib_lid_offset; /* int: offset to base LID (adaptive routing) */
int psoib_use_mcache = 1; /* bool. Use the mcache. */

struct psoib_stat_s {
    unsigned busy_notokens;	// connection out of tokens for sending
    unsigned busy_local_cq;	// connection sendqueue busy. (outstanding ev's)
    unsigned busy_global_cq;	// global completion queue busy.
    unsigned post_send_eagain;	// ibv_post_send() returned EAGAIN.
    unsigned post_send_error;	// ibv_port_send() returned with an error != EAGAIN.
    unsigned busy_token_refresh;// sending tokens with nop message failed.
} psoib_stat;


#define psoib_dprint(level,fmt,arg... )					\
    do {								\
	if ((level) <= psoib_debug) {					\
	    fprintf(psoib_debug_stream ? psoib_debug_stream : stderr,	\
		    "ib:" fmt "\n",##arg);				\
	}								\
    } while(0);

#if defined(HAS_ibv_wc_status_str) && !HAS_ibv_wc_status_str
/* Older OFED Stacks do not define ibv_wc_status_str() */
const char *ibv_wc_status_str(enum ibv_wc_status status)
{
    return "?";
}
#endif

static
void psoib_err(char *str)
{
    if (psoib_err_str) free(psoib_err_str);

    psoib_err_str = str ? strdup(str) : strdup("");
    return;
}

static
void psoib_err_errno(char *str, int err_no)
{
    const char *vapi_err = strerror(err_no);
    int len = strlen(str) + strlen(vapi_err) + 20;
    char *msg = malloc(len);

    assert(msg);

    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, vapi_err);

    psoib_err(msg);
    free(msg);
}


unsigned psoib_pending_tokens_suggestion(void)
{
    unsigned res = 0;
    switch (psoib_recvq_size) {
    default: return psoib_recvq_size - 6;
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


static
const char *port_state_str(enum ibv_port_state port_state)
{
    switch (port_state) {
    case IBV_PORT_DOWN:   return "DOWN";
    case IBV_PORT_INIT:   return "INIT";
    case IBV_PORT_ARMED:  return "ARMED";
    case IBV_PORT_ACTIVE: return "ACTIVE";
    default:              return "UNKNOWN";
    }
}

static
char *port_name(const char *hca_name, int port)
{
    static char res[50];
    if (!hca_name && port == -1)
	return "<first active>";
    if (!hca_name) hca_name = "<first active>";
    if (port != -1) {
	snprintf(res, sizeof(res), "%s:%d", hca_name, port);
    } else {
	snprintf(res, sizeof(res), "%s:<first active>", hca_name);
    }
    return res;
}


static
void psoib_scan_hca_ports(struct ibv_device *ib_dev)
{
    struct ibv_context *ctx;
    struct ibv_device_attr device_attr;
    int rc;
    unsigned port_cnt;
    unsigned port;
    const char *dev_name;

    dev_name =ibv_get_device_name(ib_dev);
    if (!dev_name) dev_name = "unknown";

    ctx = ibv_open_device(ib_dev);
    if (!ctx) goto err_open_dev;

    rc = ibv_query_device(ctx, &device_attr);
    if (!rc) {
	port_cnt = device_attr.phys_port_cnt;
	if (port_cnt > 128) port_cnt = 128;
    } else {
	// Query failed. Assume 2 ports.
	port_cnt = 2;
    }

    for (port = 1; port <= port_cnt; port++) {
	struct ibv_port_attr port_attr;
	enum ibv_port_state port_state;
	const char *marker;

	rc = ibv_query_port(ctx, port, &port_attr);
	port_state = !rc ? port_attr.state : 999 /* unknown */;

	marker = "";
	if (port_state == IBV_PORT_ACTIVE &&
	    (!psoib_hca || !strcmp(dev_name, psoib_hca)) &&
	    (!psoib_port || psoib_port == port)) {
	    // use this port for the communication:

	    if (!psoib_hca) psoib_hca = strdup(dev_name);
	    if (!psoib_port) psoib_port = port;
	    marker = "*";
	}

	psoib_dprint(3, "IB port <%s:%u>: %s%s",
		     dev_name, port, port_state_str(port_state), marker);
    }

    if (ctx) ibv_close_device(ctx);

err_open_dev:
    return;
}


static
void psoib_scan_all_ports(void)
{
    struct ibv_device **dev_list;
    struct ibv_device *ib_dev = NULL;
    int dev_list_count;
    int i;

    // psoib_dprint(3, "configured port <%s>", port_name(psoib_hca, psoib_port));

    dev_list = ibv_get_device_list(&dev_list_count);
    if (!dev_list) goto err_no_dev_list;

    for (i = 0; i < dev_list_count; i++) {
	ib_dev = dev_list[i];
	if (!ib_dev) continue;

	psoib_scan_hca_ports(ib_dev);
    }

    ibv_free_device_list(dev_list);
err_no_dev_list:
    if (!psoib_port) psoib_port = 1;
    psoib_dprint(2, "using port <%s>", port_name(psoib_hca, psoib_port));
}


static
struct ibv_device *psoib_get_dev_by_hca_name(const char *in_hca_name)
{
    /* new method with ibv_get_device_list() */
    struct ibv_device **dev_list;
    struct ibv_device *ib_dev = NULL;
    int dev_list_count;

    dev_list = ibv_get_device_list(&dev_list_count);
    if (!dev_list) goto err_no_dev;
    if (!in_hca_name) {
	// const char *tmp;
	ib_dev = dev_list[0];

	// tmp = ibv_get_device_name(ib_dev);

	// psoib_dprint(2, "Got IB device \"%s\"", tmp);

	if (!ib_dev) goto err_no_dev2;
    } else {
	int i;
	for (i = 0; i < dev_list_count; i++) {
	    ib_dev = dev_list[i];
	    if (!ib_dev) break;
	    const char *tmp = ibv_get_device_name(ib_dev);
	    if (!strcmp(tmp, in_hca_name)) {
		// psoib_dprint(2, "Got IB device \"%s\"", tmp);
		break;
	    }
	    ib_dev = NULL;
	}
	if (!ib_dev) goto err_no_dev_name;
    }
    ibv_free_device_list(dev_list);

    return ib_dev;
    /* --- */
 err_no_dev:
    psoib_err_errno("ibv_get_devices() failed : No IB dev found", errno);
    return 0;
    /* --- */
 err_no_dev2:
    psoib_err_errno("ibv_get_devices() failed : IB dev list empty", errno);
    ibv_free_device_list(dev_list);
    return 0;
    /* --- */
 err_no_dev_name:
    {
	static char err_str[50];
	snprintf(err_str, sizeof(err_str), "IB device \"%s\"", in_hca_name);
	psoib_err_errno(err_str, ENODEV);
	ibv_free_device_list(dev_list);
	return 0;
    }
}


/* if hca_name == NULL choose first HCA */
static
struct ibv_context *psoib_open_hca(char *hca_name)
{
    struct ibv_device *ib_dev;
    struct ibv_context *ctx;

    ib_dev = psoib_get_dev_by_hca_name(hca_name);
    if (!ib_dev) goto err_no_hca;

    ctx = ibv_open_device(ib_dev);
    if (!ctx) goto err_open_device;

    return ctx;
    /* --- */
 err_open_device:
    psoib_err_errno("ibv_open_device() failed", errno);
    return NULL;
    /* --- */
 err_no_hca:
    return NULL;
}

static
struct ibv_cq *psoib_open_cq(struct ibv_context *ctx, int cqe_num)
{
    /* create completion queue - used for both send and receive queues */
    struct ibv_cq *cq;

    errno = 0;
    cq = ibv_create_cq(ctx, cqe_num, NULL, NULL, 0);

    if (!cq) {
	psoib_err_errno("ibv_create_cq() failed", errno);
    }

    return cq;
}

static
struct ibv_pd *psoib_open_pd(struct ibv_context *ctx)
{
    /* allocate a protection domain to be associated with QP */
    struct ibv_pd *pd;

    pd = ibv_alloc_pd(ctx);

    if (!pd) {
	psoib_err_errno("ibv_alloc_pd() failed", errno);
    }

    return pd;
}


static
void psoib_vapi_free(hca_info_t *hca_info, mem_info_t *mem_info)
{
    ibv_dereg_mr(/*hca_info->ctx,*/ mem_info->mr);
    mem_info->mr = NULL;
    free(mem_info->ptr);
    mem_info->ptr = NULL;
}


static
void print_mlock_help(unsigned size)
{
    static int called = 0;
    struct rlimit rlim;

    if (called) return;
    called = 1;

    if (size) {
	psoib_dprint(0, "OPENIB: memlock(%u) failed.", size);
    } else {
	psoib_dprint(0, "OPENIB: memlock failed.");
    }
    psoib_dprint(0, "(Check memlock limit in /etc/security/limits.conf or try 'ulimit -l')");

    if (!getrlimit(RLIMIT_MEMLOCK, &rlim)) {
	psoib_dprint(0, "Current RLIMIT_MEMLOCK: soft=%lu byte, hard=%lu byte", rlim.rlim_cur, rlim.rlim_max);
    }
}

static
int psoib_vapi_alloc(hca_info_t *hca_info, int size, enum ibv_access_flags access_perm, mem_info_t *mem_info)
{
    mem_info->mr = NULL;

    /* Region for buffers */
    mem_info->ptr = valloc(size);
    if (!mem_info->ptr) goto err_malloc;

//    printf("ibv_reg_mr(pd = %p, ptr = %p, size = %d, access_perm = 0x%x)\n",
//	   hca_info->pd, mem_info->ptr, size, access_perm);

    mem_info->mr = ibv_reg_mr(hca_info->pd, mem_info->ptr, size, access_perm);
    if (!mem_info->mr) goto err_reg_mr;

    return 0;
    /* --- */
 err_reg_mr:
    free(mem_info->ptr);
    mem_info->ptr = NULL;
    psoib_err_errno("ibv_reg_mr() failed", errno);
    if (errno == ENOMEM) print_mlock_help(size);
    return -1;
 err_malloc:
    psoib_err_errno("malloc() failed!", errno);
    return -1;
}


void psoib_con_cleanup(psoib_con_info_t *con_info, hca_info_t *hca_info)
{
    if (!hca_info) hca_info = &default_hca;

    list_del_init(&con_info->next_con_info);

    if (con_info->send.bufs.mr) {
	psoib_vapi_free(hca_info, &con_info->send.bufs);
	con_info->send.bufs.mr = 0;
    }
    if (con_info->recv.bufs.mr) {
	psoib_vapi_free(hca_info, &con_info->recv.bufs);
	con_info->recv.bufs.mr = 0;
    }
    if (con_info->qp) {
	ibv_destroy_qp(con_info->qp);
	con_info->qp = 0;
    }
}

/*
 *  move_to_rtr
 */
static
int move_to_rtr(struct ibv_qp *qp,
		unsigned int port_num,
		uint16_t remote_lid, /* remote peer's LID */
		uint32_t remote_qpn) /* remote peer's QPN */
{
    struct ibv_qp_attr attr = {
	.qp_state		= IBV_QPS_RTR,
	.path_mtu		= psoib_path_mtu,
	.dest_qp_num		= remote_qpn,
	.rq_psn			= 0, /* Packet sequence number */
	.max_dest_rd_atomic	= 1, /* Maximum number of oust. RDMA read/atomic as target */
	.min_rnr_timer		= 12, /* Minimum RNR NAK timer (old = 0) */
	.ah_attr		= {
	    .is_global	= 0, /* old av.grh_flag ? */
	    .dlid	= remote_lid,
	    .sl		= 0,  /* Service level bits ??? */
	    .src_path_bits	= 0,
	    .port_num	= port_num
	}
    };
    if (ibv_modify_qp(qp, &attr,
		      IBV_QP_STATE              |
		      IBV_QP_AV                 |
		      IBV_QP_PATH_MTU           |
		      IBV_QP_DEST_QPN           |
		      IBV_QP_RQ_PSN             |
		      IBV_QP_MAX_DEST_RD_ATOMIC |
		      IBV_QP_MIN_RNR_TIMER))
	goto err_ibv_modify_qp;

    return 0;
    /* --- */
 err_ibv_modify_qp:
    psoib_err_errno("ibv_modify_qp() move to RTR failed", errno);
    return -1;
}


/*
 *  move_to_rts
 */
static
int move_to_rts(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr = {
	.qp_state	= IBV_QPS_RTS,
	.timeout	= 14, /* old = 10 */
	.retry_cnt	= 7,  /* old = 1 */
	.rnr_retry	= 7,  /* old = 1 */
	.sq_psn	= 0,  /* Packet sequence number */
	.max_rd_atomic  = 1,  /* Number of outstanding RDMA rd/atomic ops at destination ?*/
    };

    if (ibv_modify_qp(qp, &attr,
		      IBV_QP_STATE              |
		      IBV_QP_TIMEOUT            |
		      IBV_QP_RETRY_CNT          |
		      IBV_QP_RNR_RETRY          |
		      IBV_QP_SQ_PSN             |
		      IBV_QP_MAX_QP_RD_ATOMIC))
	goto err_VAPI_modify_qp;

    return 0;
    /* --- */
 err_VAPI_modify_qp:
    psoib_err_errno("ibv_modify_qp() move to RTS failed", errno);
    return -1;
}


int psoib_con_init(psoib_con_info_t *con_info, hca_info_t *hca_info, port_info_t *port_info)
{
    unsigned int i;

    if (!hca_info) hca_info = &default_hca;
    if (!port_info) port_info = &default_port;

    con_info->ctx = hca_info->ctx;
    con_info->port_info = port_info;
    con_info->qp = NULL;
    con_info->hca_info = hca_info;

    con_info->send.bufs.mr = NULL;
    con_info->recv.bufs.mr = NULL;
    con_info->con_broken = 0;
    INIT_LIST_HEAD(&con_info->next_con_info);

    {
	struct ibv_qp_init_attr attr = {
	    .send_cq = hca_info->cq,
	    .recv_cq = hca_info->cq,
	    .cap     = {
		//.max_send_wr  = 128, /* Max outstanding WR on the SQ ??*/
		//.max_recv_wr  = 128, /* Max outstanding WR on the RQ ??*/
		//.max_send_sge = 4,   /* Max scatter/gather descriptor entries on the SQ ??*/
		//.max_recv_sge = 4,   /* Max scatter/gather descriptor entries on the RQ */
		.max_send_wr  = 128, /* Max outstanding WR on the SQ ??*/
		.max_recv_wr  = 128, /* Max outstanding WR on the RQ ??*/
		.max_send_sge = 1,   /* Max scatter/gather descriptor entries on the SQ ??*/
		.max_recv_sge = 1,   /* Max scatter/gather descriptor entries on the RQ */
		.max_inline_data = IB_MAX_INLINE,
	    },
	    .qp_type = IBV_QPT_RC
	};

	con_info->qp = ibv_create_qp(hca_info->pd, &attr);
	if (!con_info->qp) goto err_create_qp;
    }

    {
	struct ibv_qp_attr attr;

	attr.qp_state        = IBV_QPS_INIT;
	attr.pkey_index      = 0;
	attr.port_num        = port_info->port_num;
	attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
	//                 ToDo:  == VAPI_EN_REM_WRITE | VAPI_EN_REM_READ ??

	if (ibv_modify_qp(con_info->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_PKEY_INDEX         |
			  IBV_QP_PORT               |
			  IBV_QP_ACCESS_FLAGS)) goto err_modify_qp;
    }



    /*
     *  Memory for send and receive bufs
     */

    if (!psoib_global_sendq) {
	if (psoib_vapi_alloc(hca_info, IB_MTU * psoib_sendq_size,
			     0, &con_info->send.bufs))
	    goto err_alloc;
    }
    con_info->send.pos = 0;

    con_info->outstanding_cq_entries = 0;

    if (psoib_vapi_alloc(hca_info, IB_MTU * psoib_recvq_size,
			 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE,
			 &con_info->recv.bufs))
	goto err_alloc;

    /* Clear all receive magics */
    for (i = 0; i < psoib_recvq_size; i++) {
	psoib_msg_t *msg = ((psoib_msg_t *)con_info->recv.bufs.ptr) + i;
	msg->tail.magic = PSOIB_MAGIC_UNUSED;
    }

    con_info->remote_recv_pos = 0;
    con_info->recv.pos = 0;

    list_add_tail(&con_info->next_con_info, &hca_info->list_con_info);
    return 0;
    /* --- */
 err_alloc:
    psoib_con_cleanup(con_info, hca_info);
    goto return_1;
    /* --- */
 err_modify_qp:
    psoib_err_errno("ibv_modify_qp() failed", errno);
    psoib_con_cleanup(con_info, hca_info);
    goto return_1;
    /* --- */
 err_create_qp:
    psoib_err_errno("ibv_create_qp() failed", errno);
    if (errno == ENOMEM) print_mlock_help(0);
    goto return_1;
    /* --- */
 return_1:
    psoib_dprint(1, "psoib_con_init failed : %s", psoib_err_str);
    return -1;
}


int psoib_con_connect(psoib_con_info_t *con_info, psoib_info_msg_t *info_msg)
{
    con_info->remote_ptr = info_msg->remote_ptr;
    con_info->remote_rkey = info_msg->remote_rkey;

    // Initialize receive tokens
    con_info->n_recv_toks = 0;
    con_info->n_tosend_toks = 0;

    if (move_to_rtr(con_info->qp, con_info->port_info->port_num,
		    info_msg->lid, info_msg->qp_num))
	    goto err_move_to_rtr;

    if (move_to_rts(con_info->qp))
	    goto err_move_to_rts;

    // Initialize send tokens
    con_info->n_send_toks = psoib_recvq_size; // #tokens = length of _receive_ queue!

    return 0;
    /* --- */
 err_move_to_rtr:
 err_move_to_rts:
    return -1;
}

static
void psoib_cleanup_hca(hca_info_t *hca_info)
{
    if (hca_info->send.bufs.mr) {
	psoib_vapi_free(hca_info, &hca_info->send.bufs);
	hca_info->send.bufs.mr = 0;
    }
    if (hca_info->pd) {
	ibv_dealloc_pd(hca_info->pd);
	hca_info->pd = NULL;
    }
    if (hca_info->cq) {
	ibv_destroy_cq(hca_info->cq);
	hca_info->cq = NULL;
    }
    if (hca_info->ctx) {
	ibv_close_device(hca_info->ctx);
	hca_info->ctx = NULL;
    }

#if PSOIB_USE_MREGION_CACHE
    psoib_mregion_cache_cleanup();
#endif
}


static
int psoib_init_hca(hca_info_t *hca_info)
{
    struct ibv_device_attr device_attr;

    hca_info->ctx = NULL;
    hca_info->cq = NULL;
    hca_info->pd = NULL;
    hca_info->send.bufs.mr = NULL;
    INIT_LIST_HEAD(&hca_info->list_con_info);

    if (psoib_pending_tokens > psoib_recvq_size) {
	psoib_dprint(1, "warning: reset psoib_pending_tokens from %u to %u\n",
		     psoib_pending_tokens, psoib_recvq_size);
	psoib_pending_tokens = psoib_recvq_size;
    }

    hca_info->ctx = psoib_open_hca(psoib_hca);
    if (!hca_info->ctx) goto err_hca;

    if (!ibv_query_device(hca_info->ctx, &device_attr)) {
	if ((device_attr.max_cqe >= 4) &&
	    ((unsigned)device_attr.max_cqe < psoib_compq_size)) {
	    psoib_compq_size = device_attr.max_cqe;
	    psoib_dprint(1, "reset psoib_compq_size to hca limit %u\n", psoib_compq_size);
	}
    } else {
	psoib_dprint(1, "ibv_query_device() : failed");
    }

    hca_info->cq = psoib_open_cq(hca_info->ctx, psoib_compq_size);
    if (!hca_info->cq) goto err_cq;

    hca_info->pd = psoib_open_pd(hca_info->ctx);
    if (!hca_info->pd) goto err_pd;

    if (psoib_global_sendq) {
	if (psoib_vapi_alloc(hca_info, IB_MTU * psoib_sendq_size, 0, &hca_info->send.bufs))
	    goto err_alloc;
    }
    hca_info->send.pos = 0;

#ifdef IB_USE_RNDV
    INIT_LIST_HEAD(&hca_info->rma_reqs);
    hca_info->rma_reqs_reader.do_read = psoib_rma_reqs_progress;
#endif
#if PSOIB_USE_MREGION_CACHE
    psoib_mregion_cache_init();
#endif

    return 0;
    /* --- */
err_alloc:
err_pd:
err_cq:
err_hca:
    psoib_cleanup_hca(hca_info);
    return -1;
}

static
int psoib_init_port(hca_info_t *hca_info, port_info_t *port_info)
{
    port_info->hca_info = hca_info;
    port_info->port_num = psoib_port;

    {
	struct ibv_port_attr attr;
	if (ibv_query_port(hca_info->ctx, port_info->port_num, &attr))
	    goto err_query_port;

	if (attr.state != IBV_PORT_ACTIVE)
	    goto err_port_down;
	if (attr.lid == 0)
	    goto err_no_lid;

	port_info->lid = attr.lid + (uint16_t)psoib_lid_offset;
    }

    return 0;
    /* --- */
 err_query_port:
    if (errno != EINVAL) {
	psoib_err_errno("ibv_query_port() failed", errno);
    } else {
	psoib_err("init_port failed : No ACTIVE port.");
    }
    return -1;
err_port_down:
    psoib_err("Port not in state ACTIVE");
    return -1;
err_no_lid:
    psoib_err("Port has no lid (subnet manager running?)");
    return -1;
}


int psoib_init(void)
{
    static int init_state = 1;
    if (init_state == 1) {
	memset(&psoib_stat, 0, sizeof(psoib_stat));
	psoib_scan_all_ports();

	if (psoib_init_hca(&default_hca)) goto err_hca;

	if (psoib_init_port(&default_hca, &default_port)) goto err_port;
	init_state = 0;
    }

    return init_state; /* 0 = success, -1 = error */
    /* --- */
 err_port:
    psoib_cleanup_hca(&default_hca);
 err_hca:
    init_state = -1;
    psoib_dprint(1, "OPENIB disabled : %s", psoib_err_str);
    return -1;
}

static
int psoib_poll(hca_info_t *hca_info, int blocking);

/* returnvalue like write(), except on error errno is negative return */

/* It's important, that the sending side is aligned to IB_MTU_SPEC,
   else we loose a lot of performance!!! */
static inline
ssize_t _psoib_sendv(psoib_con_info_t *con_info, struct iovec *iov, size_t size, unsigned int magic)
{
    int len;
    int psoiblen;
    psoib_msg_t *_msg;
    int rc;
    psoib_msgheader_t *tail;
    hca_info_t *hca_info = con_info->hca_info;

    if (con_info->con_broken) goto err_broken;

    /* Its allowed to send, if
       At least 2 tokens left or (1 token left AND n_tosend > 0)
    */

    if ((con_info->n_send_toks < 2) &&
	((con_info->n_send_toks < 1) || (con_info->n_tosend_toks == 0))) {
	psoib_stat.busy_notokens++;
	goto err_busy;
    }

    if (con_info->outstanding_cq_entries >= psoib_sendq_size && psoib_event_count) {
	//printf("Busy local\n"); usleep(10*1000);
	psoib_stat.busy_local_cq++;
	goto err_busy;
    }

    if (psoib_outstanding_cq_entries >= psoib_compq_size && psoib_event_count) {
	// printf("Busy global\n"); usleep(10*1000);
	psoib_stat.busy_global_cq++;
	goto err_busy;
    }

    len = (size <= IB_MTU_PAYLOAD) ? size : IB_MTU_PAYLOAD;
    psoiblen = PSOIB_LEN(len);

    ringbuf_t *send = (con_info->send.bufs.mr) ? &con_info->send : &hca_info->send;
    _msg = ((psoib_msg_t *)send->bufs.ptr) + send->pos;

    tail = (psoib_msgheader_t *)((char*)_msg + psoiblen);

    tail->token = con_info->n_tosend_toks;
    tail->payload = len;
    tail->magic = magic;

    /* copy to registerd send buffer */
//    last_msg = _msg;
//    last_iov = iov;
//    last_len = len;
    pscom_memcpy_from_iov((void *)_msg, iov, len);

    {
	struct ibv_sge list = {
	    .addr	= (uintptr_t) _msg,
	    .length = psoiblen + sizeof(psoib_msgheader_t),
	    .lkey	= send->bufs.mr->lkey,
	};
	struct ibv_send_wr wr = {
	    .next	= NULL,
	    .wr_id	= (uint64_t)con_info,
	    .sg_list	= &list,
	    .num_sge	= 1,
	    .opcode	= IBV_WR_RDMA_WRITE,
	    .send_flags	= (
		(ENABLE_SEND_NOTIFICATION ? IBV_SEND_SIGNALED : 0) | /* no cq entry, if unsignaled */
		((list.length <= IB_MAX_INLINE) ? IBV_SEND_INLINE : 0)),
	    .imm_data	= 42117,

	    .wr.rdma = {
		.remote_addr = (uint64_t)PSOIB_DATA(
		    (((psoib_msg_t *)con_info->remote_ptr) + con_info->remote_recv_pos), psoiblen),
		.rkey = con_info->remote_rkey,
	    },
	};

	struct ibv_send_wr *bad_wr;

	rc = ibv_post_send(con_info->qp, &wr, &bad_wr);
    }

    if (rc != 0) goto err_ibv_post_send;

    con_info->outstanding_cq_entries++;
    psoib_outstanding_cq_entries++;

    pscom_forward_iov(iov, len);

    con_info->n_tosend_toks = 0;
    con_info->remote_recv_pos = (con_info->remote_recv_pos + 1) % psoib_recvq_size;
    send->pos = (send->pos + 1) % psoib_sendq_size;
    con_info->n_send_toks--;

    psoib_poll(hca_info, 0);

    return len;
    /* --- */
 err_busy:
    psoib_poll(hca_info, 0);
    return -EAGAIN;
    /* --- */
 err_ibv_post_send:
    if (errno == EAGAIN /* Too many posted work requests ? */) {
	psoib_stat.post_send_eagain++;
	psoib_poll(hca_info, 0);
//	printf("return2 busy , len = %d\n", size);
	return -EAGAIN;
    } else {
	psoib_stat.post_send_error++;
	psoib_err_errno("ibv_post_send() failed", errno);
//	printf("%s\n",psoib_err_str);
	con_info->con_broken = 1;
	return -EPIPE;
    }
    /* --- */
 err_broken:
    return -EPIPE;
}


ssize_t psoib_sendv(psoib_con_info_t *con_info, struct iovec *iov, size_t size)
{
	return _psoib_sendv(con_info, iov, size, PSOIB_MAGIC_IO);
}


static
void _psoib_send_tokens(psoib_con_info_t *con_info)
{
    if (con_info->n_tosend_toks >= psoib_pending_tokens) {
	if (psoib_sendv(con_info, NULL, 0) == -EAGAIN) {
	    psoib_stat.busy_token_refresh++;
	}
    }
}

void psoib_recvdone(psoib_con_info_t *con_info)
{
    con_info->n_tosend_toks++;
    con_info->n_recv_toks--;
    con_info->recv.pos = (con_info->recv.pos + 1) % psoib_recvq_size;

    // if send_tokens() fail, we will retry it in psoib_recvlook.
    _psoib_send_tokens(con_info);
}


/* returnvalue like read() , except on error errno is negative return */
int psoib_recvlook(psoib_con_info_t *con_info, void **buf)
{
#if 1 // Simpler loop because:
	// assert(con_info->n_recv_toks == 0) as long as we only poll!
	while (1) {
		psoib_msg_t *msg =
			((psoib_msg_t *)con_info->recv.bufs.ptr) + con_info->recv.pos;

		unsigned int magic = msg->tail.magic;

		if (!magic) { // Nothing received
			*buf = NULL;
			// Maybe we have to send tokens before we can receive more:
			_psoib_send_tokens(con_info);
			return (con_info->con_broken) ? -EPIPE : -EAGAIN;
		}

		msg->tail.magic = PSOIB_MAGIC_UNUSED;

		/* Fresh tokens ? */
		con_info->n_send_toks += msg->tail.token;
		con_info->n_recv_toks++;

		unsigned int len = msg->tail.payload;

		*buf = PSOIB_DATA(msg, PSOIB_LEN(len));
		if (len || (magic == PSOIB_MAGIC_EOF)) {
			// receive data or EOF
			return len;
		}

		/* skip 0 payload packages (probably fresh tokens) */
		psoib_recvdone(con_info);
	}
#else
    unsigned int magic;
    /* Check for new packages */
    {
	psoib_con_info_t *con = con_info;
	psoib_msg_t *msg = ((psoib_msg_t *)con->recv_bufs.ptr) +
	    ((con->recv_pos + con->n_recv_toks) % SIZE_SR_QUEUE);
	magic = msg->tail.magic;

	if (magic) {
//	    printf("receive magic %08x\n", msg->tail.magic);
	    msg->tail.magic = PSOIB_MAGIC_UNUSED;

	    /* Fresh tokens ? */
	    con->n_send_toks += msg->tail.token;
	    con->n_recv_toks++;
	}
    }

    while (con_info->n_recv_toks > 0) {
	psoib_msg_t *msg = ((psoib_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;
	int len = msg->tail.payload;

	*buf = PSOIB_DATA(msg, PSOIB_LEN(len));
	if (len || (magic == PSOIB_MAGIC_EOF)) {
	    // ToDo: This could be the wrong magic!!!
	    return len;
	}
	/* skip 0 payload packages */
	psoib_recvdone(con_info);
    }

    if (con_info->con_broken) {
	return -EPIPE;
    } else {
	// Maybe we have to send tokens before we ca receive more:
	_psoib_send_tokens(con_info);
	return -EAGAIN;
    }
#endif
}


/* Mark all connections of hca_info as broken */
static
void psoib_all_con_broken(hca_info_t *hca_info)
{
    struct list_head *pos;
    list_for_each(pos, &hca_info->list_con_info) {
	psoib_con_info_t *con = list_entry(pos, psoib_con_info_t, next_con_info);
	con->con_broken = 1;
    }
    errno = EPIPE;
}


static
int psoib_check_cq(hca_info_t *hca_info)
{
    struct ibv_wc wc;
    int rc;

    rc = ibv_poll_cq(hca_info->cq, 1, &wc);

    if (rc == 1) {
	if (wc.opcode == IBV_WC_RDMA_WRITE /* == VAPI_CQE_SQ_RDMA_WRITE ?*/) {
	    /* RDMA write done */
	    psoib_con_info_t *con = (psoib_con_info_t *)(unsigned long)wc.wr_id;

	    psoib_outstanding_cq_entries--;

	    if (con->magic == MAGIC_PSOIB_CONNECTION) {
		// request from a preallocated RDMA buffer
		con->outstanding_cq_entries--;

		if (wc.status == IBV_WC_SUCCESS) {
//		    printf("RDMA write done... recv: %d tosend: %d send: %d\n",
//			   con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
		    ;
		} else {
		    psoib_dprint(1, "Failed RDMA write request (status %d : %s). Connection broken!",
				 wc.status, ibv_wc_status_str(wc.status));
		    con->con_broken = 1;
		}
#ifdef IB_USE_RNDV
	    } else {
		// request from a RDMA write (rendezvous and MPI_Put)
		psoib_rma_req_t *dreq = (psoib_rma_req_t *)(unsigned long)wc.wr_id;
		int failed = wc.status != IBV_WC_SUCCESS;
//		printf("RDMA write done...\n");
		if (failed) {
		    psoib_dprint(1, "Failed RDMA write request (status %d : %s). Connection broken!",
				 wc.status, ibv_wc_status_str(wc.status));
		    dreq->ci->con_broken = 1;
		}
		psoib_rma_reqs_deq(dreq);
		dreq->io_done(dreq->priv, failed);
#endif
	    }
#ifdef IB_USE_RNDV
	} else if (wc.opcode == IBV_WC_RDMA_READ) {
		psoib_rma_req_t *req = (psoib_rma_req_t *)(unsigned long)wc.wr_id;
		int failed = wc.status != IBV_WC_SUCCESS;
		/* Dequeue and finish request: */
		perf_add("openib_post_rma_get_done");
		if (failed) {
			psoib_dprint(1, "Failed RDMA READ request (status %d : %s). Connection broken!",
				     wc.status, ibv_wc_status_str(wc.status));
			req->ci->con_broken = 1;
		}
		psoib_rma_reqs_deq(req);
		req->io_done(req, failed);
#endif
	} else if (wc.opcode == (IBV_WC_SEND  | IBV_WC_RECV) /* == VAPI_CQE_RQ_SEND_DATA*/) {
	    /* receive something */
	    psoib_con_info_t *con = (psoib_con_info_t *)(unsigned long)wc.wr_id;
//	    printf("Recv done... recv: %d tosend: %d send: %d\n",
//		   con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    if (wc.status == IBV_WC_SUCCESS) {
		psoib_msg_t *msg;
		msg = ((psoib_msg_t *)con->recv.bufs.ptr) +
		    ((con->recv.pos + con->n_recv_toks) % psoib_recvq_size);

		/* Fresh tokens ? */
		con->n_send_toks += msg->tail.token;
		con->n_recv_toks++;
	    } else {
		psoib_dprint(1, "Failed receive request (status %d : %s). Connection broken!",
			     wc.status, ibv_wc_status_str(wc.status));
		con->con_broken = 1;
	    }
	} else if (wc.opcode == IBV_WC_SEND /* VAPI_CQE_SQ_SEND_DATA */) {
	    /* Send done */
	    psoib_con_info_t *con = (psoib_con_info_t *)(unsigned long)wc.wr_id;
	    if (wc.status == IBV_WC_SUCCESS) {
//		printf("Send done... recv: %d tosend: %d send: %d\n",
//		       con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    } else {
		psoib_dprint(1, "Failed send request (status %d : %s). Connection broken!",
			     wc.status, ibv_wc_status_str(wc.status));
		con->con_broken = 1;
	    }
	} else {
	    psoib_dprint(psoib_ignore_wrong_opcodes ? 1 : 0,
			 "ibv_poll_cq(): Infiniband returned the wrong Opcode %d", wc.opcode);
	    if (!psoib_ignore_wrong_opcodes) {
		openlog(NULL, LOG_PID, LOG_USER);
		syslog(LOG_ERR, "pscom4openib: ibv_poll_cq(): Infiniband returned the wrong Opcode %d", wc.opcode);
		psoib_all_con_broken(hca_info);
	    }
	}
    }
    return rc;
}

static
int psoib_poll(hca_info_t *hca_info, int blocking)
{
    int rc;

    do {
	rc = psoib_check_cq(hca_info);
    } while (blocking && (rc != 0/*VAPI_CQ_EMPTY*/));

//    if (psoib_debug &&
//	(rc != VAPI_CQ_EMPTY) &&
//	(rc != VAPI_OK)) {
//	fprintf(stderr, "psoib_poll: %s: %s\n", VAPI_strerror_sym(rc), VAPI_strerror(rc));
//    }

    return (rc == 0 /*VAPI_CQ_EMPTY*/);
}


void psoib_progress(void)
{
    psoib_poll(&default_hca, 0);
}


psoib_con_info_t *psoib_con_create(void)
{
	psoib_con_info_t *con_info = malloc(sizeof(*con_info));
	con_info->magic = MAGIC_PSOIB_CONNECTION;
	return con_info;
}


void psoib_con_free(psoib_con_info_t *con_info)
{
	con_info->magic = 0;
	free(con_info);
}


void psoib_con_get_info_msg(psoib_con_info_t *con_info /* in */, psoib_info_msg_t *info_msg /* out */)
{
	info_msg->lid = con_info->port_info->lid;
	info_msg->qp_num = con_info->qp->qp_num;
	info_msg->remote_ptr = con_info->recv.bufs.ptr;
	info_msg->remote_rkey = con_info->recv.bufs.mr->rkey;
}



/*
 * ++ RMA rendezvous begin
 */
#ifdef IB_USE_RNDV

static
int psoib_poll(hca_info_t *hca_info, int blocking);

static
int psoib_rma_mreg_register(psoib_rma_mreg_t *mreg, void *buf, size_t size, psoib_con_info_t *ci)
{
	int hit;
	static int first_call=1;
	hca_info_t *hca_info = ci->hca_info;
	mem_info_t *mem_info = &mreg->mem_info;

	mem_info->mr = ibv_reg_mr(hca_info->pd, buf, size,
				  IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if(!mem_info->mr) goto err_reg_mr;

	mem_info->ptr = buf;
	mreg->size = size;

	return 0; /* success */

err_reg_mr:
	mem_info->ptr = NULL;
	psoib_err_errno("ibv_reg_mr() failed", errno);
	if (errno == ENOMEM) print_mlock_help(size);
	return -1;
}

static
int psoib_rma_mreg_deregister(psoib_rma_mreg_t *mreg)
{
	int ret;
	mem_info_t *mem_info = &mreg->mem_info;
	ret = ibv_dereg_mr(mem_info->mr);
	assert(ret == 0);

	return 0; /* success */
}

#if PSOIB_USE_MREGION_CACHE

#include "psoib_mregion_cache.c"

int psoib_acquire_rma_mreg(psoib_rma_mreg_t *mreg, void *buf, size_t size, psoib_con_info_t *ci)
{
	psoib_mregion_cache_t *mregc;
	if (!psoib_mregion_cache_max_size) {
		// Disabled cache
		return psoib_rma_mreg_register(mreg, buf, size, ci);
	}

	mregc = psoib_mregion_find(buf, size);
	if (mregc) {
		// cached mregion
		psoib_mregion_use_inc(mregc);
	} else {
		psoib_mregion_gc(psoib_mregion_cache_max_size);

		// create new mregion
		mregc = psoib_mregion_create(buf, size, ci);
		if (!mregc) goto err_register;

		psoib_mregion_enq(mregc);
		mregc->use_cnt = 1; /* shortcut for psoib_mregion_use_inc(mreg); */
	}

	mreg->mem_info.ptr = buf;
	mreg->size = size;
	mreg->mem_info.mr = mregc->mregion.mem_info.mr;
	mreg->mreg_cache = mregc;

	return 0;
err_register:
	psoib_dprint(3, "psoib_get_mregion() failed");
	return -1;
}


int psoib_release_rma_mreg(psoib_rma_mreg_t *mreg)
{
	if (!psoib_mregion_cache_max_size) {
		// Disabled cache
		return psoib_rma_mreg_deregister(mreg);
	}

	psoib_mregion_use_dec(mreg->mreg_cache);
	mreg->mreg_cache = NULL;

	return 0;
}

#else
int psoib_acquire_rma_mreg(psoib_rma_mreg_t *mreg, void *buf, size_t size, psoib_con_info_t *ci)
{
	return psoib_rma_mreg_register(mreg, buf, size, ci);
}

int psoib_release_rma_mreg(psoib_rma_mreg_t *mreg)
{
	return psoib_rma_mreg_deregister(mreg);
}
#endif

static
void psoib_rma_reqs_enq(psoib_rma_req_t *req)
{
	hca_info_t *hca_info = req->ci->hca_info;
	int first = list_empty(&hca_info->rma_reqs);

	list_add_tail(&req->next, &hca_info->rma_reqs);

	if (first) {
		// Start polling for completer notifications
		list_add_tail(&hca_info->rma_reqs_reader.next, &pscom.poll_reader);
	}
}

static
void psoib_rma_reqs_deq(psoib_rma_req_t *dreq)
{
	struct list_head *pos;
	psoib_rma_req_t *req = NULL;
	hca_info_t *hca_info = dreq->ci->hca_info;

#if 1
	// ToDo: disable this assert for more preformance.
	// Assert dreq is enqueued in hca_info->rma_reqs:
	list_for_each(pos, &hca_info->rma_reqs) {
		req = list_entry(pos, psoib_rma_req_t, next);
		if(req == dreq) break;
	}
	assert(req == dreq);
#endif

	list_del(&dreq->next);

	if (list_empty(&hca_info->rma_reqs)) {
		// Stop polling for completer notifications
		list_del(&hca_info->rma_reqs_reader.next);
	}
}


int psoib_post_rma_get(psoib_rma_req_t *req)
{
	int error;

	struct ibv_sge list = {
		.addr	= (uintptr_t) req->mreg.mem_info.ptr,
		.length = req->mreg.size,
		.lkey	= req->mreg.mem_info.mr->lkey,
	};
	struct ibv_send_wr wr = {
		.next	= NULL,
		.wr_id	= (uint64_t)req,
		.sg_list	= &list,
		.num_sge	= 1,
		.opcode	= IBV_WR_RDMA_READ,
		.send_flags	= IBV_SEND_SIGNALED,
		.imm_data	= 42117,

		.wr.rdma = {
			.remote_addr = req->remote_addr,
			.rkey = req->remote_key,
		},
	};

	struct ibv_send_wr *bad_wr;

	perf_add("openib_post_rma_get");

	error = ibv_post_send(req->ci->qp, &wr, &bad_wr);
	assert(!error);

	// Enqueue this request and wait for notification via completion queue.
	psoib_rma_reqs_enq(req);

	psoib_poll(req->ci->hca_info, 0);

	return 0;
}


int psoib_post_rma_put(psoib_rma_req_t *req)
{
	int error;

	struct ibv_sge list = {
		.addr	= (uintptr_t) req->mreg.mem_info.ptr,
		.length = req->mreg.size,
		.lkey	= req->mreg.mem_info.mr->lkey,
	};
	struct ibv_send_wr wr = {
		.next	= NULL,
		.wr_id	= (uint64_t)req,
		.sg_list	= &list,
		.num_sge	= 1,
		.opcode	= IBV_WR_RDMA_WRITE,
		.send_flags	= IBV_SEND_SIGNALED,
		.imm_data	= 42118,

		.wr.rdma = {
			.remote_addr = req->remote_addr,
			.rkey = req->remote_key,
		},
	};

	struct ibv_send_wr *bad_wr;

	perf_add("openib_post_rma_put");

	error = ibv_post_send(req->ci->qp, &wr, &bad_wr);
	assert(!error);

	// Enqueue this request and wait for notification via completion queue.
	psoib_rma_reqs_enq(req);

	psoib_poll(req->ci->hca_info, 0);
	psoib_outstanding_cq_entries++;

	return 0;
}


static
int psoib_rma_reqs_progress(pscom_poll_reader_t *reader)
{
	hca_info_t *hca_info = list_entry(reader, hca_info_t, rma_reqs_reader);

	psoib_poll(hca_info, 0);

	return 0;
}

#endif
/*
 * -- RMA rendezvous end
 */
