/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psp_mvapi.c: Mellanox VAPI communication
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <vapi.h>
#include <evapi.h>
#include <vapi_common.h>
/* #include <mosal.h>*/


#include "psport_priv.h"
#include "psport_mvapi.h"



/* How many connections are allowed ? */
#define MAX_QP_N	256
/* Size of the send and receive queue */
#define SIZE_SR_QUEUE	16

#define MAX_PENDING_TOKS (SIZE_SR_QUEUE - 6)

/* Completion queue size */
#define SIZE_CQ		(MAX_QP_N * SIZE_SR_QUEUE)
/* MTU on infiniband */
#define IB_MTU_SPEC	MTU1024
#define IB_MTU	(16*1024) /* must be < 65536, or change sizeof psib_msgheader_t.payload,
			     and should be a power of IB_MTU_SPEC */

#define IB_MTU_PAYLOAD	(IB_MTU - sizeof(psib_msgheader_t))
#define IB_MAX_INLINE	64 /* ToDo: Search for working values!!! */

/* I got the error
   THH(4): THHUL_qpm_post_send_req: Send queue is full (128 requests outstanding).
   if SEND_NOTIFICATION is disabled */
#define ENABLE_SEND_NOTIFICATION 1

typedef struct {
    VAPI_hca_hndl_t hca_hndl;
    VAPI_cq_hndl_t  cq_hndl; /* handle to cq */
    VAPI_pd_hndl_t pd_hndl; /* Protection domain */
} hca_info_t;

typedef struct {
    hca_info_t *hca_info;
    VAPI_hca_port_t hca_port;
    IB_port_t hca_port_idx;
} port_info_t;

typedef struct {
    void *ptr;
    VAPI_mr_hndl_t mr_hndl;
    VAPI_mr_t rep_mrw; /* responded memory region properties. */
} mem_info_t;

/* MVapi specific information about one connection */
struct psib_con_info_s {
    /* low level */
//    hca_info_t *hca_info;
    VAPI_hca_hndl_t hca_hndl;
    VAPI_qp_hndl_t qp_hndl;
    VAPI_qp_prop_t qp_prop; /* QP properties */
    IB_lid_t        lid; /* Base IB_LID. */

    /* send */
    mem_info_t	send_bufs;
    int		send_pos;

    void	*remote_ptr;
    VAPI_rkey_t remote_rkey;

    /* recv */
    mem_info_t	recv_bufs;
    int		recv_pos;

    /* higher level */
    int	n_send_toks;
    int n_recv_toks;
    int n_tosend_toks;

    int con_broken;
};

typedef struct {
    uint16_t	token;
    uint16_t	payload;
    volatile uint32_t	magic;
} psib_msgheader_t;

typedef struct {
    char __data[IB_MTU_PAYLOAD];
    psib_msgheader_t tail;
} psib_msg_t;

#define PSIB_LEN(len) ((len + 7) & ~7)
#define PSIB_DATA(buf, psiblen) ((char*)(&(buf)->tail) - psiblen)

/*
 * static variables
 */

static hca_info_t  default_hca;
static port_info_t default_port;

static char *psib_err_str = NULL;
static int psib_debug = 2;

static
void psib_err(char *str)
{
    if (psib_err_str) free(psib_err_str);

    psib_err_str = str ? strdup(str) : strdup("");
    return;
}

static
void psib_err_rc(char *str, VAPI_ret_t rc)
{
    const char *vapi_sym = VAPI_strerror_sym(rc);
    const char *vapi_err = VAPI_strerror(rc);
    int len = strlen(str) + strlen(vapi_sym) + strlen(vapi_err) + 20;
    char *msg = malloc(len);

    assert(msg);

    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, vapi_sym);
    strcat(msg, " - ");
    strcat(msg, vapi_err);

    psib_err(msg);
    free(msg);
}

/*
 *
 */
void print_hca_cap(VAPI_hca_vendor_t *hca_vendor_p, VAPI_hca_cap_t *hca_cap_p)
{
    fprintf(stderr, "=== HCA vendor info ===\n");
    fprintf(stderr, "\tvendor_id = 0x%08x\n", hca_vendor_p->vendor_id);
    fprintf(stderr, "\tvendor_part_id = %d\n", hca_vendor_p->vendor_part_id);
    fprintf(stderr, "\thw_ver = 0x%08x\n", hca_vendor_p->hw_ver);

    fprintf(stderr, "=== HCA capabilities ===\n");

    fprintf(stderr, "\tmax_num_qp = %d\n", hca_cap_p->max_num_qp);
    fprintf(stderr, "\tmax_qp_ous_wr = %d\n", hca_cap_p->max_qp_ous_wr);
    fprintf(stderr, "\tflags = 0x%08x\n", hca_cap_p->flags);
    fprintf(stderr, "\tmax_num_sg_ent = %d\n", hca_cap_p->max_num_sg_ent);
    fprintf(stderr, "\tmax_num_sg_ent_rd = %d\n", hca_cap_p->max_num_sg_ent_rd);
    fprintf(stderr, "\tmax_num_cq = %d\n", hca_cap_p->max_num_cq);
    fprintf(stderr, "\tmax_num_ent_cq = %d\n", hca_cap_p->max_num_ent_cq);
    fprintf(stderr, "\tmax_num_mr = %d\n", hca_cap_p->max_num_mr);
    fprintf(stderr, "\tmax_mr_size = "U64_FMT"\n", hca_cap_p->max_mr_size);
    fprintf(stderr, "\tmax_pd_num = %d\n", hca_cap_p->max_pd_num);
    fprintf(stderr, "\tpage_size_cap = %d\n", hca_cap_p->page_size_cap);
    fprintf(stderr, "\tphys_port_num = %d\n", hca_cap_p->phys_port_num);
    fprintf(stderr, "\tmax_pkeys = %d\n", hca_cap_p->max_pkeys);
    fprintf(stderr, "\tnode_guid = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", hca_cap_p->node_guid[0],
	    hca_cap_p->node_guid[1],
	    hca_cap_p->node_guid[2],
	    hca_cap_p->node_guid[3],
	    hca_cap_p->node_guid[4],
	    hca_cap_p->node_guid[5],
	    hca_cap_p->node_guid[6],
	    hca_cap_p->node_guid[7]);
    fprintf(stderr, "\tlocal_ca_ack_delay (Log2 4.096usec Max. RX to ACK or NAK delay) = %d\n", hca_cap_p->local_ca_ack_delay);
    fprintf(stderr, "\tmax_qp_ous_rd_atom = %d\n", hca_cap_p->max_qp_ous_rd_atom);
    fprintf(stderr, "\tmax_ee_ous_rd_atom = %d\n", hca_cap_p->max_ee_ous_rd_atom);
    fprintf(stderr, "\tmax_res_rd_atom = %d\n", hca_cap_p->max_res_rd_atom);
    fprintf(stderr, "\tmax_qp_init_rd_atom = %d\n", hca_cap_p->max_qp_init_rd_atom);
    fprintf(stderr, "\tmax_ee_init_rd_atom = %d\n", hca_cap_p->max_ee_init_rd_atom);
    {
	char s[50];
	switch ( hca_cap_p->atomic_cap) {
	case VAPI_ATOMIC_CAP_NONE:
	    strcpy(s, "VAPI_ATOMIC_CAP_NONE");
	    break;
	case VAPI_ATOMIC_CAP_HCA:
	    strcpy(s, "VAPI_ATOMIC_CAP_HCA");
	    break;
	case VAPI_ATOMIC_CAP_GLOB:
	    strcpy(s, "VAPI_ATOMIC_CAP_GLOB");
	    break;
	default:
	    strcpy(s, "invalid capability");
	}
	fprintf(stderr, "\tatomic_cap = %s\n", s);
    }
    fprintf(stderr, "\tmax_ee_num = %d\n", hca_cap_p->max_ee_num);
    fprintf(stderr, "\tmax_rdd_num = %d\n", hca_cap_p->max_rdd_num);
    fprintf(stderr, "\tmax_mw_num = %d\n", hca_cap_p->max_mw_num);
    fprintf(stderr, "\tmax_raw_ipv6_qp = %d\n", hca_cap_p->max_raw_ipv6_qp);
    fprintf(stderr, "\tmax_raw_ethy_qp = %d\n", hca_cap_p->max_raw_ethy_qp);
    fprintf(stderr, "\tmax_mcast_grp_num = %d\n", hca_cap_p->max_mcast_grp_num);
    fprintf(stderr, "\tmax_mcast_qp_attach_num = %d\n", hca_cap_p->max_mcast_qp_attach_num);
    fprintf(stderr, "\tmax_total_mcast_qp_attach_num = %d\n", hca_cap_p->max_total_mcast_qp_attach_num);
    fprintf(stderr, "\tmax_ah_num = %d\n", hca_cap_p->max_ah_num);
}

/*
 *  print_qp_props
 */
void print_qp_props(VAPI_qp_prop_t *qp_props)
{
    fprintf(stderr, "=== QP properties ===\n");
    fprintf(stderr, "\tqp_num = 0x%06x\n", qp_props->qp_num);
    fprintf(stderr, "\tmax_oust_wr_sq = %d\n", qp_props->cap.max_oust_wr_sq);
    fprintf(stderr, "\tmax_oust_wr_rq = %d\n", qp_props->cap.max_oust_wr_rq);
    fprintf(stderr, "\tmax_sg_size_sq = %d\n", qp_props->cap.max_sg_size_sq);
    fprintf(stderr, "\tmax_sg_size_rq = %d\n", qp_props->cap.max_sg_size_rq);
}

static
int psib_get_hca_name(OUT VAPI_hca_id_t *hca_id, IN const char *in_hca_name)
{
    u_int32_t num_of_hcas, i;
    VAPI_hca_id_t *hca_id_buf_p, inst_hca_id;
    VAPI_ret_t rc;

    assert(hca_id != NULL);

    if (in_hca_name && in_hca_name[0]) {
	/* Use the in name. */
	strncpy(*hca_id, in_hca_name, HCA_MAXNAME);
	return 0;
    }

    /* Search for a HCA name */
    /* hca_id not specified by the user */

    while ((rc = EVAPI_list_hcas(1, &num_of_hcas, &inst_hca_id)) == VAPI_EAGAIN) {};
    if (rc != VAPI_OK) goto err_EVAPI_list_hcas;

    switch (num_of_hcas) {
    case 0:
	psib_err("There are no HCAs installed in your system!");
	DPRINT(1, "%s", psib_err_str);
	return -1;
    case 1:
        strcpy(*hca_id, inst_hca_id);
	if (psib_debug)
	    DPRINT(2, "Infiniband HCA: %s", *hca_id);
        break;
    default:
        strcpy(*hca_id, inst_hca_id);
	if (psib_debug) {
	    DPRINT(2, "first Infiniband HCA: %s", *hca_id);
	    hca_id_buf_p = malloc(sizeof(VAPI_hca_id_t)*num_of_hcas);
	    if (!hca_id_buf_p) goto err_malloc;

	    rc = EVAPI_list_hcas(num_of_hcas, &num_of_hcas, hca_id_buf_p);
	    if (rc != VAPI_OK) goto err_EVAPI_list_hcas;

	    DPRINT(3,"The following HCAs are installed in your system.");

	    for (i = 0; i < num_of_hcas; i++) {
		DPRINT(3, "%s", hca_id_buf_p[i]);
	    }
	    free(hca_id_buf_p);
	}
    }

    return 0;
    /* --- */
 err_malloc:
    psib_err("malloc() failed!");
    return -1;
    /* --- */
 err_EVAPI_list_hcas:
    psib_err_rc("EVAPI_list_hcas() failed", rc);
    return -1;
}


/* if hca_name == NULL choose first HCA */
static
int psib_open_hca(IN char *hca_name, OUT VAPI_hca_hndl_t *hca_hndl)
{
    VAPI_hca_id_t hca_id;
    VAPI_ret_t rc;

    assert(hca_hndl != NULL);

    if (psib_get_hca_name(&hca_id, hca_name)) goto err_hca_name;

    /* try to get a handle to the given hca_id */
    rc = EVAPI_get_hca_hndl(hca_id, hca_hndl);
    if (rc != VAPI_SUCCESS) goto err_EVAPI_get_hca_hndl;

    if (psib_debug > 3) {
	VAPI_hca_vendor_t hca_vendor; /* ?? */
	VAPI_hca_cap_t hca_cap; /* HCA capabilities */

	rc = VAPI_query_hca_cap(*hca_hndl, &hca_vendor, &hca_cap);
	if (rc != VAPI_SUCCESS) goto err_VAPI_query_hca_cap;

	print_hca_cap(&hca_vendor, &hca_cap);
    }

    return 0;
    /* --- */
 err_VAPI_query_hca_cap:
    EVAPI_release_hca_hndl(*hca_hndl);
    psib_err_rc("VAPI_query_hca_cap() failed", rc);
    return -1;
    /* --- */
 err_EVAPI_get_hca_hndl:
    psib_err_rc("EVAPI_get_hca_hndl() failed", rc);
    return -1;
    /* --- */
 err_hca_name:
    return -1;
}

static
int psib_open_cq(IN VAPI_hca_hndl_t hca_hndl, IN int cqe_num, OUT VAPI_cq_hndl_t  *cq_hndl)
{
  unsigned int num_of_entries;
  VAPI_ret_t rc;

  /* create completion queue - used for both send and receive queues */
  rc = VAPI_create_cq(hca_hndl, cqe_num, cq_hndl, &num_of_entries);
  if (rc != VAPI_SUCCESS) goto err_VAPI_create_cq;

  assert(num_of_entries >= cqe_num);

  return 0;
  /* --- */
 err_VAPI_create_cq:
  psib_err_rc("VAPI_create_cq() failed", rc);
  return -1;
}

static
int psib_open_pd(IN VAPI_hca_hndl_t hca_hndl, OUT VAPI_pd_hndl_t *pd_hndl)
{
    VAPI_ret_t rc;

    /* allocate a protection domain to be associated with QP */
    rc = VAPI_alloc_pd(hca_hndl, pd_hndl);
    if (rc != VAPI_SUCCESS) goto err_VAPI_alloc_pd;

    return 0;
    /* --- */
 err_VAPI_alloc_pd:
    psib_err_rc("VAPI_alloc_pd failed", rc);
    return -1;
}

/* INOUT hca_port_idx == -1: scan for first active hca_port */
static
int psib_open_hca_port(IN VAPI_hca_hndl_t hca_hndl, IN int hca_port_idx,
		       OUT VAPI_hca_port_t *hca_port,
		       OUT IB_port_t *hca_port_idx_out)
{
    VAPI_ret_t rc;
    IB_port_t port;

    assert(hca_port);

    if (hca_port_idx > 0) {
	port = hca_port_idx;
	rc = VAPI_query_hca_port_prop(hca_hndl, port, hca_port);
	if (rc != VAPI_OK) goto err_VAPI_query_hca_port_prop;

	if (hca_port->state != PORT_ACTIVE) goto err_linkdown;
    } else {
	port = 1;
	while (1) {
	    rc = VAPI_query_hca_port_prop(hca_hndl, port, hca_port);
	    if (rc == VAPI_OK) {
		if (hca_port->state == PORT_ACTIVE)
		    break;
	    }
	    if (++port > 32) goto err_alllinkdown;
	}
    }

    if (psib_debug) {
	DPRINT(1, "Infiniband HCA Port: %d", port);
    }
    *hca_port_idx_out = port;

    return 0;
    /* --- */
 err_alllinkdown:
    psib_err("HCA all Ports are down!");
    return -1;
    /* --- */
 err_linkdown:
    {
	char msg[100];
	snprintf(msg, 99, "HCA Port %d is down!", port);
	psib_err(msg);
    }
    return -1;
    /* --- */
 err_VAPI_query_hca_port_prop:
    psib_err_rc("VAPI_query_hca_port_prop() failed", rc);
    return -1;
}

static
void psib_vapi_free(IN hca_info_t *hca_info,IN mem_info_t *mem_info)
{
    VAPI_deregister_mr(hca_info->hca_hndl, mem_info->mr_hndl);
    free(mem_info->ptr);
}

static
int psib_vapi_alloc(IN hca_info_t *hca_info, IN int size, IN VAPI_mrw_acl_t perm,
		    OUT mem_info_t *mem_info)
/*
    IN VAPI_hca_hndl_t hca_hndl, IN VAPI_pd_hndl_t pd_hndl,
		    IN VAPI_mrw_acl_t perm, IN int size,
		    OUT VAPI_mr_hndl_t *mr_hndl, OUT void **vptr,
		    OUT VAPI_lkey_t *lkey, OUT VAPI_rkey_t *rkey)
*/
{
    void *ptr;
    VAPI_mrw_t mrw;
    VAPI_ret_t rc;

    /* Region for buffers */
//    ptr = malloc(size);
    ptr = valloc(size);
    if (!ptr) goto err_malloc;

    memset(&mrw, 0, sizeof(mrw));
    mrw.type = VAPI_MR; /* Memory region */
    mrw.start = (VAPI_virt_addr_t)(MT_virt_addr_t)ptr;
    mrw.size = size;
    mrw.pd_hndl = hca_info->pd_hndl;
    mrw.acl = perm; //VAPI_EN_LOCAL_WRITE;

    rc = VAPI_register_mr(hca_info->hca_hndl,
			  &mrw, &mem_info->mr_hndl, &mem_info->rep_mrw);
    if (rc != VAPI_SUCCESS) goto err_VAPI_register_mr;

    mem_info->ptr = ptr;

    return 0;
    /* --- */
 err_VAPI_register_mr:
    free(ptr);
    psib_err_rc("VAPI_register_mr() failed", rc);
    return -1;
 err_malloc:
    psib_err("malloc() failed!");
    return -1;
}


static
void psib_cleanup_con(hca_info_t *hca_info, psib_con_info_t *con_info)
{
    if (con_info->send_bufs.mr_hndl) {
	psib_vapi_free(hca_info, &con_info->send_bufs);
	con_info->send_bufs.mr_hndl = 0;
    }
    if (con_info->recv_bufs.mr_hndl) {
	psib_vapi_free(hca_info, &con_info->recv_bufs);
	con_info->recv_bufs.mr_hndl = 0;
    }
    if (con_info->qp_hndl) {
	VAPI_destroy_qp(hca_info->hca_hndl, con_info->qp_hndl);
	con_info->qp_hndl = 0;
    }
}

/*
 *  move_to_rtr
 */
static
int move_to_rtr(IN VAPI_hca_hndl_t hca_hndl,
		IN VAPI_qp_hndl_t qp_hndl,
		IN IB_lid_t remote_lid, /* remote peer's LID */
		IN IB_wqpn_t remote_qpn) /* remote peer's QPN */
{
    VAPI_qp_attr_t       qp_attr;
    VAPI_qp_attr_mask_t  qp_attr_mask;
    VAPI_qp_cap_t        qp_cap;
    VAPI_ret_t rc;

    QP_ATTR_MASK_CLR_ALL(qp_attr_mask);
    qp_attr.qp_state = VAPI_RTR;		QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_QP_STATE);

    qp_attr.av.sl            = 0; /* Service level bits ??? */;
    qp_attr.av.grh_flag      = FALSE;
    qp_attr.av.dlid          = remote_lid;
    qp_attr.av.static_rate   = 0; /* 1x ???? */
    qp_attr.av.src_path_bits = 0;		QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_AV);

    qp_attr.path_mtu = IB_MTU_SPEC;	QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_PATH_MTU);

    /* Packet sequence number */
    qp_attr.rq_psn           = 0;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_RQ_PSN);

    /* Maximum number of oust. RDMA read/atomic as target */
    qp_attr.qp_ous_rd_atom   = 1;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_OUS_RD_ATOM);

    qp_attr.dest_qp_num = remote_qpn;	QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_DEST_QP_NUM);

    /* Minimum RNR NAK timer */
    qp_attr.min_rnr_timer = 0;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_MIN_RNR_TIMER);

    rc = VAPI_modify_qp(hca_hndl, qp_hndl, &qp_attr, &qp_attr_mask, &qp_cap);
    if (rc != VAPI_SUCCESS) goto err_VAPI_modify_qp;

    return 0;
    /* --- */
 err_VAPI_modify_qp:
    psib_err_rc("VAPI_modify_qp() faile", rc);
    return -1;
}


/*
 *  move_to_rts
 */
static
int move_to_rts(IN VAPI_hca_hndl_t hca_hndl, IN VAPI_qp_hndl_t qp_hndl)
{
    VAPI_qp_attr_t       qp_attr;
    VAPI_qp_attr_mask_t  qp_attr_mask;
    VAPI_qp_cap_t        qp_cap;
    VAPI_ret_t rc;

    QP_ATTR_MASK_CLR_ALL(qp_attr_mask);
    qp_attr.qp_state = VAPI_RTS;	QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);

    /* Packet sequence number */
    qp_attr.sq_psn   = 0;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_SQ_PSN);

    qp_attr.timeout  = 10;/*0x20*/;	QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_TIMEOUT);
    qp_attr.retry_count   = 1;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_RETRY_COUNT);
    qp_attr.rnr_retry     = 1;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_RNR_RETRY);

    /* Number of outstanding RDMA rd/atomic ops at destination */
    qp_attr.ous_dst_rd_atom  = 1;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_OUS_DST_RD_ATOM);

    rc = VAPI_modify_qp(hca_hndl, qp_hndl, &qp_attr, &qp_attr_mask, &qp_cap);
    if (rc != VAPI_SUCCESS) goto err_VAPI_modify_qp;
    return 0;
    /* --- */
 err_VAPI_modify_qp:
    psib_err_rc("VAPI_modify_qp() failed", rc);
    return -1;
}


static
int psib_init_con(hca_info_t *hca_info, port_info_t *port_info, psib_con_info_t *con_info)
{
    VAPI_qp_init_attr_t  qp_init_attr;
    VAPI_ret_t rc;
    VAPI_qp_attr_t       qp_attr;
    VAPI_qp_attr_mask_t  qp_attr_mask;
    VAPI_qp_cap_t        qp_cap;
    int i;

    con_info->qp_hndl = 0;
    con_info->lid = port_info->hca_port.lid;
    con_info->hca_hndl = hca_info->hca_hndl;
    con_info->send_bufs.mr_hndl = 0;
    con_info->recv_bufs.mr_hndl = 0;
    con_info->con_broken = 0;

    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.sq_cq_hndl = hca_info->cq_hndl;
    qp_init_attr.rq_cq_hndl = hca_info->cq_hndl;

    qp_init_attr.cap.max_oust_wr_sq = 128; /* Max outstanding WR on the SQ */
    qp_init_attr.cap.max_oust_wr_rq = 128; /* Max outstanding WR on the RQ */
    qp_init_attr.cap.max_sg_size_sq = 4;/* Max scatter/gather descriptor entries on the SQ */
    qp_init_attr.cap.max_sg_size_rq = 4;/* Max scatter/gather descriptor entries on the RQ */
    qp_init_attr.cap.max_inline_data_sq = IB_MAX_INLINE;  /* Max bytes in inline data on the SQ */
    /* max_inline_data_sq is currently valid only for VAPI_query_qp (ignored for VAPI_create_qp) */
    /* In order to enlarge the max_inline_data_sq capability, enlarge the max_sg_size_sq parameter */

    qp_init_attr.rdd_hndl = 0; /* N/A for RC transport service */
    qp_init_attr.sq_sig_type = VAPI_SIGNAL_REQ_WR;
    qp_init_attr.rq_sig_type = VAPI_SIGNAL_ALL_WR;
    qp_init_attr.pd_hndl = hca_info->pd_hndl;
    qp_init_attr.ts_type = VAPI_TS_RC; /* RC transport service */

    /* create the QP */
    rc = VAPI_create_qp(hca_info->hca_hndl, &qp_init_attr,
			&con_info->qp_hndl, &con_info->qp_prop);
    if (rc != VAPI_SUCCESS) goto err_VAPI_create_qp;

    if (psib_debug > 3)
	print_qp_props(&con_info->qp_prop);

    memset(&qp_attr, 0, sizeof(qp_attr));
    memset(&qp_attr_mask, 0, sizeof(qp_attr_mask));

    QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

    qp_attr.qp_state = VAPI_INIT;		QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);
    qp_attr.pkey_ix  = 0;			QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PKEY_IX);
    qp_attr.port     = port_info->hca_port_idx;	QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PORT);
    qp_attr.remote_atomic_flags = VAPI_EN_REM_WRITE | VAPI_EN_REM_READ;
    QP_ATTR_MASK_SET(qp_attr_mask, QP_ATTR_REMOTE_ATOMIC_FLAGS);
    /* Rem_Atomic ? if (topt_p->atomics) {
       qp_attr.remote_atomic_flags |= VAPI_EN_REM_ATOMIC_OP;
       } */

    rc = VAPI_modify_qp(hca_info->hca_hndl, con_info->qp_hndl,
			&qp_attr, &qp_attr_mask, &qp_cap);
    if (rc != VAPI_SUCCESS) goto err_VAPI_modify_qp;

    /*
     *  Memory for send and receive bufs
     */

    if (psib_vapi_alloc(hca_info, IB_MTU * SIZE_SR_QUEUE, 0, &con_info->send_bufs))
	goto err_alloc;
    con_info->send_pos = 0;

    if (psib_vapi_alloc(hca_info, IB_MTU * SIZE_SR_QUEUE,
			VAPI_EN_REMOTE_WRITE | VAPI_EN_LOCAL_WRITE, &con_info->recv_bufs))
	goto err_alloc;

    /* Clear all receive magics */
    for (i = 0; i < SIZE_SR_QUEUE; i++) {
	psib_msg_t *msg = ((psib_msg_t *)con_info->recv_bufs.ptr) + i;
	msg->tail.magic = 0;
    }

    con_info->recv_pos = 0;

    return 0;
    /* --- */
 err_alloc:
    psib_cleanup_con(hca_info, con_info);
    return -1;
    /* --- */
 err_VAPI_modify_qp:
    psib_err_rc("VAPI_modify_qp failed", rc);
    psib_cleanup_con(hca_info, con_info);
    return -1;
    /* --- */
 err_VAPI_create_qp:
    psib_err_rc("VAPI_create_qp() failed", rc);
    return -1;
}

static int psib_recvdone(psib_con_info_t *con_info);

static
int psib_connect_con(psib_con_info_t *con_info,
		     IB_lid_t remote_lid  /* remote peer's LID */,
		     IB_wqpn_t remote_qpn /* remote peer's QPN */,
		     void *remote_ptr,
		     VAPI_rkey_t remote_rkey)
{
    int i;

    con_info->remote_ptr = remote_ptr;
    con_info->remote_rkey = remote_rkey;

    if (move_to_rtr(con_info->hca_hndl, con_info->qp_hndl, remote_lid, remote_qpn)) goto err_move_to_rtr;
    con_info->n_send_toks = 0; // SIZE_SR_QUEUE;
    con_info->n_recv_toks = SIZE_SR_QUEUE;
    con_info->n_tosend_toks = 0;
    if (move_to_rts(con_info->hca_hndl, con_info->qp_hndl)) goto err_move_to_rts;

    /* Fill the receive queue */
    for (i = 0; i < SIZE_SR_QUEUE; i++) {
	/* The next call never send tokens to the
	   remote qp, because n_send_toks is 0 */
	psib_recvdone(con_info);
    }

    /* Now all recv buffers are posted. The same is true for the
       remote qp. n_tosend_toks == SIZE_SR_QUEUE and n_send_toks == 0.
       We can now exchange the tokens without sending a message: */
    assert(con_info->n_send_toks == 0);
    assert(con_info->n_tosend_toks == SIZE_SR_QUEUE);
    assert(con_info->n_recv_toks == 0);

    con_info->n_send_toks = SIZE_SR_QUEUE;
    con_info->n_tosend_toks = 0;

    return 0;
    /* --- */
 err_move_to_rtr:
 err_move_to_rts:
    return -1;
}

static
void psib_cleanup_hca(hca_info_t *hca_info)
{
    if (hca_info->pd_hndl)
	VAPI_dealloc_pd(hca_info->hca_hndl, hca_info->pd_hndl);
    if (hca_info->cq_hndl)
	VAPI_destroy_cq(hca_info->hca_hndl, hca_info->cq_hndl);
    if (hca_info->hca_hndl)
	EVAPI_release_hca_hndl(hca_info->hca_hndl);
}

static
int psib_init_hca(hca_info_t *hca_info)
{
    VAPI_hca_hndl_t hca_hndl;

    hca_info->hca_hndl = 0;
    hca_info->cq_hndl = 0;
    hca_info->pd_hndl = 0;

    if (psib_open_hca(NULL, &hca_hndl)) goto err_hca;
    hca_info->hca_hndl = hca_hndl;

    if (psib_open_cq(hca_hndl, SIZE_CQ, &hca_info->cq_hndl)) goto err_cq;

    if (psib_open_pd(hca_hndl, &hca_info->pd_hndl)) goto err_pd;

    return 0;
    /* --- */
    /* VAPI_dealloc_pd(hca_hndl, pd_hndl);*/
 err_pd:
 err_cq:
 err_hca:
    psib_cleanup_hca(hca_info);
    return -1;
}

static
int psib_init_port(hca_info_t *hca_info, port_info_t *port_info)
{
    if (psib_open_hca_port(hca_info->hca_hndl,
			   -1,
			   &port_info->hca_port,
			   &port_info->hca_port_idx)) goto err_port;
    port_info->hca_info = hca_info;
    return 0;
    /* --- */
 err_port:
    return -1;
}

int psib_init(void)
{
    static int init_state = 1;
    if (init_state == 1) {
	if (psib_init_hca(&default_hca)) goto err_hca;

	if (psib_init_port(&default_hca, &default_port)) goto err_port;
	init_state = 0;
    }

    return init_state; /* 0 = success, -1 = error */
    /* --- */
 err_port:
    psib_cleanup_hca(&default_hca);
 err_hca:
    init_state = -1;
    DPRINT(1, "MVAPI disabled : %s", psib_err_str);
    return -1;
}

static
int psib_poll(hca_info_t *hca_info, int blocking);

/* returnvalue like write(), except on error errno is negative return */

/* It's important, that the sending side is aligned to IB_MTU_SPEC,
   else we loose a lot of performance!!! */

static
int psib_sendv(psib_con_info_t *con_info, struct iovec *iov, int size)
{
    int len;
    int psiblen;
    psib_msg_t *_msg;
    VAPI_sr_desc_t sr_desc;
    VAPI_sg_lst_entry_t sg_lst;
    VAPI_ret_t rc;
    psib_msgheader_t *tail;

    if (con_info->con_broken) goto err_broken;

    /* Its allowed to send, if
       At least 2 tokens left or (1 token left AND n_tosend > 0)
    */

    if ((con_info->n_send_toks < 2) &&
	((con_info->n_send_toks < 1) || (con_info->n_tosend_toks == 0))) goto err_busy;

    len = (size <= (int)IB_MTU_PAYLOAD) ? size : (int)IB_MTU_PAYLOAD;
    psiblen = PSIB_LEN(len);

    _msg = ((psib_msg_t *)con_info->send_bufs.ptr) + con_info->send_pos;

    tail = (psib_msgheader_t *)((char*)_msg + psiblen);

    tail->token = con_info->n_tosend_toks;
    tail->payload = len;
    tail->magic = 0x1;

    /* copy to registerd send buffer */
    PSP_memcpy_from_iov_const((void *)_msg, iov, len);
//   memcpy(PSIB_DATA(msg, len), buf, len);

    sg_lst.addr = (MT_virt_addr_t)_msg;
    sg_lst.len = psiblen + sizeof(psib_msgheader_t);
    sg_lst.lkey = con_info->send_bufs.rep_mrw.l_key;

    sr_desc.id = (VAPI_wr_id_t)(unsigned long)con_info; /* User defined work request ID */
    sr_desc.opcode = VAPI_RDMA_WRITE; // use VAPI_SEND_WITH_IMM to send also imm_data
//    sr_desc.opcode = VAPI_SEND_WITH_IMM; // use VAPI_SEND_WITH_IMM to send also imm_data
    /* VAPI_SEND_WITH_IMM on lyra about +0.06 us */
    sr_desc.comp_type = ENABLE_SEND_NOTIFICATION ? VAPI_SIGNALED : VAPI_UNSIGNALED; /* no cq entry, if unsignaled */
    sr_desc.sg_lst_p = &sg_lst;
    sr_desc.sg_lst_len = 1;
    sr_desc.imm_data = 42117;
    sr_desc.fence = TRUE;   /* In case we are sending a notification after RDMA-R */
    sr_desc.set_se = FALSE;
    sr_desc.remote_addr = (MT_virt_addr_t)
	PSIB_DATA((((psib_msg_t *)con_info->remote_ptr) + con_info->send_pos), psiblen);

    sr_desc.r_key = con_info->remote_rkey;

    if (sg_lst.len > IB_MAX_INLINE) {
	rc = VAPI_post_sr(con_info->hca_hndl, con_info->qp_hndl, &sr_desc);
    } else {
	/* No speedup with EVAPI_post_inline_sr() ! (2004-03-18 1us speedup?) */
	rc = EVAPI_post_inline_sr(con_info->hca_hndl, con_info->qp_hndl, &sr_desc);
    }
    if (rc != VAPI_SUCCESS) goto err_VAPI_post_sr;

    PSP_forward_iov(iov, len);

    con_info->n_tosend_toks = 0;
    con_info->send_pos = (con_info->send_pos + 1) % SIZE_SR_QUEUE;
    con_info->n_send_toks--;

    psib_poll(&default_hca, 0);
    return len;
    /* --- */
 err_busy:
    psib_poll(&default_hca, 0);
    return -EAGAIN;
    /* --- */
 err_VAPI_post_sr:
    if (rc == VAPI_E2BIG_WR_NUM /* Too many posted work requests. */) {
	psib_poll(&default_hca, 0);
	return -EAGAIN;
    } else {
	psib_err_rc("VAPI_post_sr() failed", rc);
	con_info->con_broken = 1;
    }
 err_broken:
    return -EPIPE;
}

static
int psib_recvdone(psib_con_info_t *con_info)
{
    psib_msg_t *msg;

    msg = ((psib_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;

    con_info->n_tosend_toks++;
    con_info->n_recv_toks--;
    con_info->recv_pos = (con_info->recv_pos + 1) % SIZE_SR_QUEUE;

    if (con_info->n_tosend_toks >= MAX_PENDING_TOKS) {
	psib_sendv(con_info, NULL, 0);
    }

    return 0;
}


/* returnvalue like read() , except on error errno is negative return */
static
int psib_recvlook(psib_con_info_t *con_info, void **buf)
{
    /* Check for new packages */
    {
	psib_con_info_t *con = con_info;
	psib_msg_t *msg = ((psib_msg_t *)con->recv_bufs.ptr) +
	    ((con->recv_pos + con->n_recv_toks) % SIZE_SR_QUEUE);

	if (msg->tail.magic) {
//	    printf("receive magic %08x\n", msg->tail.magic);
	    msg->tail.magic = 0;

	    /* Fresh tokens ? */
	    con->n_send_toks += msg->tail.token;
	    con->n_recv_toks++;
	}
    }

    while (con_info->n_recv_toks > 0) {
	psib_msg_t *msg = ((psib_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;
	int len = msg->tail.payload;

	*buf = PSIB_DATA(msg, PSIB_LEN(len));
	if (len) {
	    return len;
	}
	/* skip 0 payload packages */
	psib_recvdone(con_info);
    }

    if (con_info->con_broken) {
	return -EPIPE;
    } else {
	return -EAGAIN;
    }
}

static
VAPI_ret_t psib_check_cq(hca_info_t *hca_info)
{
    VAPI_wc_desc_t comp_desc;
    VAPI_ret_t rc;
    rc = VAPI_poll_cq(hca_info->hca_hndl, hca_info->cq_hndl, &comp_desc);
    if (rc == VAPI_OK) {
	if (comp_desc.opcode == VAPI_CQE_SQ_RDMA_WRITE) {
	    /* RDMA write done */
	    psib_con_info_t *con = (psib_con_info_t *)(unsigned long)comp_desc.id;
	    if (comp_desc.status == VAPI_SUCCESS) {
		//printf("RDMA write done... recv: %d tosend: %d send: %d\n",
		//       con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    } else {
		if (psib_debug > 0) {
		    fprintf(stderr, "Failed RDMA write request (status %d). Connection broken!\n",
			    comp_desc.status);
		}
		con->con_broken = 1;
	    }
	} else if (comp_desc.opcode == VAPI_CQE_RQ_SEND_DATA) {
	    /* receive something */
	    psib_con_info_t *con = (psib_con_info_t *)(unsigned long)comp_desc.id;
//	    printf("Recv done... recv: %d tosend: %d send: %d\n",
//		   con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    if (comp_desc.status == VAPI_SUCCESS) {
		psib_msg_t *msg;
		msg = ((psib_msg_t *)con->recv_bufs.ptr) +
		    ((con->recv_pos + con->n_recv_toks) % SIZE_SR_QUEUE);

		/* Fresh tokens ? */
		con->n_send_toks += msg->tail.token;
		con->n_recv_toks++;
	    } else {
		if (psib_debug > 0) {
		    fprintf(stderr, "Failed receive request (status %d). Connection broken!\n",
			    comp_desc.status);
		}
		con->con_broken = 1;
	    }
	} else if (comp_desc.opcode == VAPI_CQE_SQ_SEND_DATA) {
	    /* Send done */
	    psib_con_info_t *con = (psib_con_info_t *)(unsigned long)comp_desc.id;
	    if (comp_desc.status == VAPI_SUCCESS) {
//		printf("Send done... recv: %d tosend: %d send: %d\n",
//		       con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    } else {
		if (psib_debug > 0) {
		    fprintf(stderr, "Failed send request (status %d). Connection broken!\n",
			   comp_desc.status);
		}
		con->con_broken = 1;
	    }
	} else {
	    fprintf(stderr, "Unknown Opcode: %d\n", comp_desc.opcode);
	}
    }
    return rc;
}

static
int psib_poll(hca_info_t *hca_info, int blocking)
{
    VAPI_ret_t rc;

    do {
	rc = psib_check_cq(hca_info);
    } while (blocking && (rc != VAPI_CQ_EMPTY));

    if (psib_debug &&
	(rc != VAPI_CQ_EMPTY) &&
	(rc != VAPI_OK)) {
	fprintf(stderr, "psib_poll: %s: %s\n", VAPI_strerror_sym(rc), VAPI_strerror(rc));
    }

    return (rc == VAPI_CQ_EMPTY);
}


#if 0
static
void DoSendAbortAllMvapi(PSP_Port_t *port, con_t *con)
{
    PSP_Request_t *req;

    while (!sendq_empty(con)) {
	req = sendq_head(con);
	req->state |= PSP_REQ_STATE_PROCESSED;
	DelFirstSendRequest(port, req, CON_TYPE_MVAPI);
    };
}

static
void mvapi_cleanup_con(PSP_Port_t *port, con_t *con)
{
    psib_cleanup_con(&default_hca, con->u.mvapi.mcon);

    list_del(&con->u.mvapi.next);
    port->mvapi.mvapi_users--;
}
#endif


static
int PSP_do_read_mvapi(PSP_Port_t *port, PSP_Connection_t *con)
{
    void *buf;
    int size;

    size = psib_recvlook(con->arch.mvapi.mcon, &buf);

    if (size > 0) {
	PSP_read_do(port, con, buf, size);

	psib_recvdone(con->arch.mvapi.mcon);
	return 1;
    } else if (size == -EAGAIN) {
	/* retry later */
	return 0;
    } else if (size == 0) {
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_REMOTECLOSE);
    } else {
	errno = -size;
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_READ_FAILED);
    }

    return 0;
}

static
void PSP_do_write_mvapi(PSP_Port_t *port, PSP_Connection_t *con)
{
    int len, rlen;
    PSP_Req_t *req = con->out.req;

    if (req) {
	len = req->u.req.iov_len;
	rlen = psib_sendv(con->arch.mvapi.mcon, req->u.req.iov, len);
	if (rlen >= 0) {
	    req->u.req.iov_len -= rlen;
	    PSP_update_sendq(port, con);
	} else if (rlen == -EAGAIN) {
	    /* retry later */
	} else {
	    errno = -rlen;
	    PSP_con_terminate(port, con, PSP_TERMINATE_REASON_WRITE_FAILED);
	}
    }
}

int PSP_do_sendrecv_mvapi(PSP_Port_t *port)
{
    struct list_head *pos, *next;
    int ret = 0;

    list_for_each_safe(pos, next, &port->mvapi_list_send) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.mvapi.next_send);
	PSP_do_write_mvapi(port, con);
    }

    /*psib_poll(&default_hca, 0);*/

    /* ToDo: Dont loop over all connections! Use a con receive queue! */
    list_for_each_safe(pos, next, &port->mvapi_list) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.mvapi.next);
	ret = PSP_do_read_mvapi(port, con);
	if (ret) break;
    }
    return ret;
}

static
void PSP_set_write_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Write %d mvapi\n", start);
    if (start) {
	if (list_empty(&con->arch.mvapi.next_send)) {
	    list_add_tail(&con->arch.mvapi.next_send, &port->mvapi_list_send);
	}
	PSP_do_write_mvapi(port, con);
	/* Dont do anything after this line.
	   PSP_do_write_mvapi() can reenter PSP_set_write_mvapi()! */
    } else {
	/* it's save to dequeue more then once */
	list_del_init(&con->arch.mvapi.next_send);
    }
}

static
void PSP_set_read_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Read %d mvapi\n", start);
}

static
void PSP_init_con_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int con_fd,
			psib_con_info_t *mcon)
{
    con->state = PSP_CON_STATE_OPEN_MVAPI;
    close(con_fd);

    con->arch.mvapi.mcon = mcon;

    INIT_LIST_HEAD(&con->arch.mvapi.next_send);
    list_add_tail(&con->arch.mvapi.next, &port->mvapi_list);

    con->set_write = PSP_set_write_mvapi;
    con->set_read = PSP_set_read_mvapi;
}

void PSP_terminate_con_mvapi(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.mvapi.mcon) {
	psib_con_info_t *mcon = con->arch.mvapi.mcon;

	list_del(&con->arch.mvapi.next_send);
	list_del(&con->arch.mvapi.next);

	psib_cleanup_con(&default_hca, mcon);
	free(mcon);

	con->arch.mvapi.mcon = NULL;
    }
}

typedef struct psib_info_msg_s {
    IB_lid_t        lid;
    VAPI_qp_num_t   qp_num;  /* QP number */
    void            *remote_ptr; /* Info about receive buffers */
    VAPI_rkey_t     remote_rkey;
} psib_info_msg_t;



int PSP_connect_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_MVAPI;
    psib_con_info_t *mcon = malloc(sizeof(*mcon));
    psib_info_msg_t msg;
    int call_cleanup_con = 0;
    int err;

    if (!env_mvapi || psib_init() || !mcon) {
	if (mcon) free(mcon);
	return 0; /* Dont use mvapi */
    }

    /* We want talk mvapi */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 1 */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_MVAPI))
	goto err_remote;

    /* step 2 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
	goto err_remote;

    err = psib_init_con(&default_hca, &default_port, mcon);
    if (!err) {
	call_cleanup_con = 1;
	err = psib_connect_con(mcon, msg.lid, msg.qp_num, msg.remote_ptr, msg.remote_rkey);
    }

    /* step 3 : send connection id's (or error) */
    msg.lid = err ? 0xffff : mcon->lid;
    msg.qp_num = mcon->qp_prop.qp_num;
    msg.remote_ptr = mcon->recv_bufs.ptr;
    msg.remote_rkey = mcon->recv_bufs.rep_mrw.r_key,

    PSP_writeall(con_fd, &msg, sizeof(msg));

    if (err) goto err_connect;

    /* step 4: mvapi initialized. Recv final ACK. */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.lid == 0xffff)) goto err_ack;

    PSP_init_con_mvapi(port, con, con_fd, mcon);

    return 1;
    /* --- */
 err_ack:
 err_connect:
    if (call_cleanup_con) psib_cleanup_con(&default_hca, mcon);
 err_remote:
    if (mcon) free(mcon);
    return 0;
}

int PSP_accept_mvapi(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_MVAPI;
    psib_con_info_t *mcon = NULL;
    psib_info_msg_t msg;

    if (!env_mvapi || psib_init())
	goto out_nomvapi;

    if (!(mcon = malloc(sizeof(*mcon))))
	goto out_nomvapi;

    if (psib_init_con(&default_hca, &default_port, mcon)) {
	DPRINT(1, "MVAPI psib_init_con failed : %s", psib_err_str);
	goto err_init_con;
    }

    /* step 1:  Yes, we talk mvapi. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send Connection id's */
    msg.lid = mcon->lid;
    msg.qp_num = mcon->qp_prop.qp_num;
    msg.remote_ptr = mcon->recv_bufs.ptr;
    msg.remote_rkey = mcon->recv_bufs.rep_mrw.r_key,

    PSP_writeall(con_fd, &msg, sizeof(msg));

    /* step 3 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.lid == 0xffff))
	goto err_remote;


    if (psib_connect_con(mcon, msg.lid, msg.qp_num, msg.remote_ptr, msg.remote_rkey))
	goto err_connect_con;

    /* step 4: MVAPI mem initialized. Send final ACK. */
    msg.lid = 0;
    PSP_writeall(con_fd, &msg, sizeof(msg));

    PSP_init_con_mvapi(port, con, con_fd, mcon);

    return 1;
    /* --- */
 err_connect_con:
    /* Send NACK */
    msg.lid = 0xffff;
    PSP_writeall(con_fd, &msg, sizeof(msg));
 err_remote:
    psib_cleanup_con(&default_hca, mcon);
 err_init_con:
 out_nomvapi:
    if (mcon) free(mcon);
    arch = PSP_ARCH_ERROR;
    PSP_writeall(con_fd, &arch, sizeof(arch));
    return 0; /* Dont use mvapi */
    /* --- */

}


void PSP_mvapi_init(PSP_Port_t *port)
{
    psib_debug = env_debug;
    port->mvapi_users = 0;
    INIT_LIST_HEAD(&port->mvapi_list);
    INIT_LIST_HEAD(&port->mvapi_list_send);
}
