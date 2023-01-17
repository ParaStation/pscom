/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * ps4_ib.c: Framework for Infiniband (VAPI)
 */

#include <vapi.h>
#include <evapi.h>
#include <vapi_common.h>
/* #include <mosal.h> */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <fcntl.h>
#include <inttypes.h>
#include <assert.h>

/* How many connections are allowed ? */
#define MAX_QP_N	256
/* Size of the send and receive queue */
#define SIZE_SR_QUEUE	16

#define MAX_PENDING_TOKS (SIZE_SR_QUEUE - 6)

/* Completion queue size */
#define SIZE_CQ		(MAX_QP_N * SIZE_SR_QUEUE)
/* MTU on infiniband */
#define IB_MTU_SPEC	MTU1024
#define IB_MTU		1024

#define IB_MTU_PAYLOAD	(IB_MTU - sizeof(psib_msgheader_t))


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

typedef struct {
    /* low level */
//    hca_info_t *hca_info;
    VAPI_hca_hndl_t hca_hndl;
    VAPI_qp_hndl_t qp_hndl;
    VAPI_qp_prop_t qp_prop; /* QP properties */
    IB_lid_t        lid; /* Base IB_LID. */

    /* send */
    mem_info_t	send_bufs;
    int		send_pos;

    /* recv */
    mem_info_t	recv_bufs;
    int		recv_pos;

    /* higher level */
    int	n_send_toks;
    int n_recv_toks;
    int n_tosend_toks;

    int con_broken;
} con_info_t;

typedef struct {
    uint16_t	token;
    uint16_t	payload;
} psib_msgheader_t;

typedef struct {
    psib_msgheader_t header;
    char data[IB_MTU_PAYLOAD];
} psib_msg_t;


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
    printf("=== HCA vendor info ===\n");
    printf("\tvendor_id = 0x%08x\n", hca_vendor_p->vendor_id);
    printf("\tvendor_part_id = %d\n", hca_vendor_p->vendor_part_id);
    printf("\thw_ver = 0x%08x\n", hca_vendor_p->hw_ver);

    printf("=== HCA capabilities ===\n");

    printf("\tmax_num_qp = %d\n", hca_cap_p->max_num_qp);
    printf("\tmax_qp_ous_wr = %d\n", hca_cap_p->max_qp_ous_wr);
    printf("\tflags = 0x%08x\n", hca_cap_p->flags);
    printf("\tmax_num_sg_ent = %d\n", hca_cap_p->max_num_sg_ent);
    printf("\tmax_num_sg_ent_rd = %d\n", hca_cap_p->max_num_sg_ent_rd);
    printf("\tmax_num_cq = %d\n", hca_cap_p->max_num_cq);
    printf("\tmax_num_ent_cq = %d\n", hca_cap_p->max_num_ent_cq);
    printf("\tmax_num_mr = %d\n", hca_cap_p->max_num_mr);
    printf("\tmax_mr_size = "U64_FMT"\n", hca_cap_p->max_mr_size);
    printf("\tmax_pd_num = %d\n", hca_cap_p->max_pd_num);
    printf("\tpage_size_cap = %d\n", hca_cap_p->page_size_cap);
    printf("\tphys_port_num = %d\n", hca_cap_p->phys_port_num);
    printf("\tmax_pkeys = %d\n", hca_cap_p->max_pkeys);
    printf("\tnode_guid = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", hca_cap_p->node_guid[0],
	   hca_cap_p->node_guid[1],
	   hca_cap_p->node_guid[2],
	   hca_cap_p->node_guid[3],
	   hca_cap_p->node_guid[4],
	   hca_cap_p->node_guid[5],
	   hca_cap_p->node_guid[6],
	   hca_cap_p->node_guid[7]);
    printf("\tlocal_ca_ack_delay (Log2 4.096usec Max. RX to ACK or NAK delay) = %d\n", hca_cap_p->local_ca_ack_delay);
    printf("\tmax_qp_ous_rd_atom = %d\n", hca_cap_p->max_qp_ous_rd_atom);
    printf("\tmax_ee_ous_rd_atom = %d\n", hca_cap_p->max_ee_ous_rd_atom);
    printf("\tmax_res_rd_atom = %d\n", hca_cap_p->max_res_rd_atom);
    printf("\tmax_qp_init_rd_atom = %d\n", hca_cap_p->max_qp_init_rd_atom);
    printf("\tmax_ee_init_rd_atom = %d\n", hca_cap_p->max_ee_init_rd_atom);
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
	printf("\tatomic_cap = %s\n", s);
    }
    printf("\tmax_ee_num = %d\n", hca_cap_p->max_ee_num);
    printf("\tmax_rdd_num = %d\n", hca_cap_p->max_rdd_num);
    printf("\tmax_mw_num = %d\n", hca_cap_p->max_mw_num);
    printf("\tmax_raw_ipv6_qp = %d\n", hca_cap_p->max_raw_ipv6_qp);
    printf("\tmax_raw_ethy_qp = %d\n", hca_cap_p->max_raw_ethy_qp);
    printf("\tmax_mcast_grp_num = %d\n", hca_cap_p->max_mcast_grp_num);
    printf("\tmax_mcast_qp_attach_num = %d\n", hca_cap_p->max_mcast_qp_attach_num);
    printf("\tmax_total_mcast_qp_attach_num = %d\n", hca_cap_p->max_total_mcast_qp_attach_num);
    printf("\tmax_ah_num = %d\n", hca_cap_p->max_ah_num);
}

/*
 *  print_qp_props
 */
void print_qp_props(VAPI_qp_prop_t *qp_props)
{
  printf("=== QP properties ===\n");
  printf("\tqp_num = 0x%06x\n", qp_props->qp_num);
  printf("\tmax_oust_wr_sq = %d\n", qp_props->cap.max_oust_wr_sq);
  printf("\tmax_oust_wr_rq = %d\n", qp_props->cap.max_oust_wr_rq);
  printf("\tmax_sg_size_sq = %d\n", qp_props->cap.max_sg_size_sq);
  printf("\tmax_sg_size_rq = %d\n", qp_props->cap.max_sg_size_rq);
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
	return -1;
    case 1:
        strcpy(*hca_id, inst_hca_id);
	if (psib_debug)
	    printf("Using HCA: %s\n", *hca_id);
        break;
    default:
        strcpy(*hca_id, inst_hca_id);
	if (psib_debug) {
	    printf("Using first HCA: %s\n", *hca_id);
	    hca_id_buf_p = malloc(sizeof(VAPI_hca_id_t)*num_of_hcas);
	    if (!hca_id_buf_p) goto err_malloc;

	    rc = EVAPI_list_hcas(num_of_hcas, &num_of_hcas, hca_id_buf_p);
	    if (rc != VAPI_OK) goto err_EVAPI_list_hcas;

	    printf("The following HCAs are installed in your system. "
		   "Please use <-h hcaid> to specify one (not implemented!).\n");
	    for (i = 0; i < num_of_hcas; i++) {
		printf("%s\n", hca_id_buf_p[i]);
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

    if (psib_debug > 1) {
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
int psib_open_cq(IN VAPI_hca_hndl_t hca_hndl, IN unsigned int cqe_num, OUT VAPI_cq_hndl_t  *cq_hndl)
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
	printf("Using HCA Port: %d\n", port);
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
	snprintf(msg, 99, "HCA Port %d is down!\n", port);
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
    ptr = malloc(size);
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

    if (psib_debug > 1) {
	printf("lkey: 0x%08x rkey: 0x%08x ptr: %p start: 0x%016lx\n",
	       mem_info->rep_mrw.l_key,
	       mem_info->rep_mrw.r_key,
	       ptr, (long)mem_info->rep_mrw.start);
    }

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
void psib_cleanup_con(hca_info_t *hca_info, con_info_t *con_info)
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
int psib_init_con(hca_info_t *hca_info, port_info_t *port_info, con_info_t *con_info)
{
    VAPI_qp_init_attr_t  qp_init_attr;
    VAPI_ret_t rc;
    VAPI_qp_attr_t       qp_attr;
    VAPI_qp_attr_mask_t  qp_attr_mask;
    VAPI_qp_cap_t        qp_cap;

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
    qp_init_attr.cap.max_inline_data_sq = 16;  /* Max bytes in inline data on the SQ */
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

    if (psib_debug > 1)
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

    if (psib_vapi_alloc(hca_info, IB_MTU * SIZE_SR_QUEUE, VAPI_EN_LOCAL_WRITE, &con_info->recv_bufs))
	goto err_alloc;
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

static int psib_recvdone(con_info_t *con_info);

static
int psib_connect_con(con_info_t *con_info,
		     IB_lid_t remote_lid  /* remote peer's LID */,
		     IB_wqpn_t remote_qpn /* remote peer's QPN */)
{
    int i;

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

#if 0
static
void psib_cleanup_port(port_info_t *port_info)
{
    (void)port_info;
}
#endif

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
    if (psib_init_hca(&default_hca)) goto err_hca;

    if (psib_init_port(&default_hca, &default_port)) goto err_port;

    return 0;
    /* --- */
 err_port:
    psib_cleanup_hca(&default_hca);
 err_hca:
    return -1;
}


/* returnvalue like write() */
static
int psib_send(con_info_t *con_info, void *buf, int size)
{
    int len;
    psib_msg_t *msg;
    VAPI_sr_desc_t sr_desc;
    VAPI_sg_lst_entry_t sg_lst;
    VAPI_ret_t rc;

    if (con_info->con_broken) goto err_broken;

    /* Its allowed to send, if
       At least 2 tokens left or (1 token left AND n_tosend > 0)
    */

    if ((con_info->n_send_toks < 2) &&
	((con_info->n_send_toks < 1) || (con_info->n_tosend_toks == 0))) goto err_busy;

    len = (size <= (int)IB_MTU_PAYLOAD) ? size : (int)IB_MTU_PAYLOAD;

    msg = ((psib_msg_t *)con_info->send_bufs.ptr) + con_info->send_pos;

    msg->header.token = con_info->n_tosend_toks;
    msg->header.payload = len;

    memcpy(&msg->data[0], buf, len);

    sg_lst.addr = (MT_virt_addr_t)msg;
    sg_lst.len = len + sizeof(psib_msgheader_t);
    sg_lst.lkey = con_info->send_bufs.rep_mrw.l_key;

    sr_desc.id = (VAPI_wr_id_t)(unsigned long)con_info; /* User defined work request ID */
    sr_desc.opcode = VAPI_SEND; // use VAPI_SEND_WITH_IMM to send also imm_data
//    sr_desc.opcode = VAPI_SEND_WITH_IMM; // use VAPI_SEND_WITH_IMM to send also imm_data
    /* VAPI_SEND_WITH_IMM on lyra about +0.06 us */
    sr_desc.comp_type = ENABLE_SEND_NOTIFICATION ? VAPI_SIGNALED : VAPI_UNSIGNALED; /* no cq entry, if unsignaled */
    sr_desc.sg_lst_p = &sg_lst;
    sr_desc.sg_lst_len = 1;
    sr_desc.imm_data = 42117;
    sr_desc.fence = TRUE;   /* In case we are sending a notification after RDMA-R */
    sr_desc.set_se = FALSE;

    rc = VAPI_post_sr(con_info->hca_hndl, con_info->qp_hndl, &sr_desc);
    if (rc != VAPI_SUCCESS) goto err_VAPI_post_sr;

    con_info->n_tosend_toks = 0;
    con_info->send_pos = (con_info->send_pos + 1) % SIZE_SR_QUEUE;
    con_info->n_send_toks--;

    return len;
    /* --- */
 err_busy:
    errno = EAGAIN;
    return -1;
    /* --- */
 err_VAPI_post_sr:
    psib_err_rc("VAPI_post_sr() failed", rc);
    con_info->con_broken = 1;
 err_broken:
    errno = EPIPE;
    return -1;
}

static
int psib_recvdone(con_info_t *con_info)
{
    psib_msg_t *msg;
    VAPI_rr_desc_t rr_desc;
    VAPI_sg_lst_entry_t sg_lst;
    VAPI_ret_t rc;

    msg = ((psib_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;

    sg_lst.addr = (MT_virt_addr_t)msg;
    sg_lst.len = IB_MTU;
    sg_lst.lkey = con_info->recv_bufs.rep_mrw.l_key;

    rr_desc.id = (VAPI_wr_id_t)(unsigned long)con_info; /* User defined work request ID */
    rr_desc.opcode = VAPI_RECEIVE;
    rr_desc.comp_type = VAPI_SIGNALED;//VAPI_SIGNALED;
    rr_desc.sg_lst_p = &sg_lst;
    rr_desc.sg_lst_len = 1;

    rc = VAPI_post_rr(con_info->hca_hndl, con_info->qp_hndl, &rr_desc);
    if (rc != VAPI_SUCCESS) goto err_VAPI_post_rr;

    con_info->n_tosend_toks++;
    con_info->n_recv_toks--;
    con_info->recv_pos = (con_info->recv_pos + 1) % SIZE_SR_QUEUE;

    if (con_info->n_tosend_toks >= MAX_PENDING_TOKS) {
	psib_send(con_info, NULL, 0);
    }

    return 0;
    /* --- */
 err_VAPI_post_rr:
    psib_err_rc("VAPI_post_rr() failed", rc);
    con_info->con_broken = 1;
// err_broken:
    errno = EPIPE;
    return -1;
}

#if 1
/* returnvalue like read() */
static
int psib_recvlook(con_info_t *con_info, void **buf)
{
    while (con_info->n_recv_toks > 0) {
	psib_msg_t *msg;
	msg = ((psib_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;

	*buf = &msg->data[0];
	if (msg->header.payload) {
	    return msg->header.payload;
	}
	/* skip 0 payload packages */
	psib_recvdone(con_info);
    }

    if (con_info->con_broken) {
	errno = EPIPE;
    } else {
	errno = EAGAIN;
    }
    return -1;
}

#else
/* returnvalue like read() */
static
int psib_recvlook(con_info_t *con_info, void **buf)
{
    if (con_info->n_recv_toks > 0) {
	psib_msg_t *msg;
	msg = ((psib_msg_t *)con_info->recv_bufs.ptr) + con_info->recv_pos;

	*buf = &msg->data[0];
	return msg->header.payload;
    } else {
	if (con_info->con_broken) {
	    errno = EPIPE;
	} else {
	    errno = EAGAIN;
	}
	return -1;
    }
}
#endif

static
VAPI_ret_t psib_check_cq(hca_info_t *hca_info)
{
    VAPI_wc_desc_t comp_desc;
    VAPI_ret_t rc;
    rc = VAPI_poll_cq(hca_info->hca_hndl, hca_info->cq_hndl, &comp_desc);
    if (rc == VAPI_OK) {
	if (comp_desc.opcode == VAPI_CQE_RQ_SEND_DATA) {
	    /* receive something */
	    con_info_t *con = (con_info_t *)(unsigned long)comp_desc.id;
//	    printf("Recv done... recv: %d tosend: %d send: %d\n",
//		   con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    if (comp_desc.status == VAPI_SUCCESS) {
		psib_msg_t *msg;
		msg = ((psib_msg_t *)con->recv_bufs.ptr) +
		    ((con->recv_pos + con->n_recv_toks) % SIZE_SR_QUEUE);

		/* Fresh tokens ? */
		con->n_send_toks += msg->header.token;
//		/* ToDo: Maybe disable the next 4 lines ? */
//		if ((con->n_recv_toks == 0) && (msg->header.payload == 0)) {
//		    /* no payload. skip packet. */
//		    psib_recvdone(con);
//		}
		con->n_recv_toks++;
	    } else {
		if (psib_debug > 0) {
		    printf("Failed receive request (status %d). Connection broken!\n",
			   comp_desc.status);
		}
		con->con_broken = 1;
	    }
	} else if (comp_desc.opcode == VAPI_CQE_SQ_SEND_DATA) {
	    /* Send done */
	    con_info_t *con = (con_info_t *)(unsigned long)comp_desc.id;
	    if (comp_desc.status == VAPI_SUCCESS) {
//		printf("Send done... recv: %d tosend: %d send: %d\n",
//		       con->n_recv_toks, con->n_tosend_toks, con->n_send_toks);
	    } else {
		if (psib_debug > 0) {
		    printf("Failed send request (status %d). Connection broken!\n",
			   comp_desc.status);
		}
		con->con_broken = 1;
	    }
	} else {
	    printf("Unknown Opcode: %d\n", comp_desc.opcode);
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
	printf("psib_poll: %s: %s\n", VAPI_strerror_sym(rc), VAPI_strerror(rc));
    }

    return (rc == VAPI_CQ_EMPTY);
}

#include <popt.h>

int arg_verbose=0;
int arg_client=0;
int arg_server=0;
int arg_loops=1000;

void usage(poptContext optCon, int exitcode, char *error, char *addl)
{
    poptPrintUsage(optCon, stderr, 0);
    if (error) fprintf(stderr, "%s: %s\n", error, addl);
    exit(exitcode);
}

void parse_opt(int argc, char **argv)
{
    int    c;            /* used for argument parsing */
    poptContext optCon;   /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
	{ "verbose"  , 'v', POPT_ARG_INT, &arg_verbose , 0,
	  "be more verbose", "level" },
	{ "server" , 's', POPT_ARGFLAG_OR, &arg_server, 0,
	  "run as server", "" },
	{ "client" , 'c', POPT_ARGFLAG_OR, &arg_client, 0,
	  "run as client", "" },
	{ "loops"  , 'l', POPT_ARG_INT, &arg_loops , 0,
	  "pp loops", "count" },
/*	{ "flag" , 'f', POPT_ARGFLAG_OR, &arg_flag, 0,
	  "flag description", "" },*/
	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };

    optCon = poptGetContext(NULL, argc,(const char **) argv, optionsTable, 0);

    if (argc < 1) {
	poptPrintUsage(optCon, stderr, 0);
	exit(1);
    }

    /* Now do options processing, get portname */
    while ((c = poptGetNextOpt(optCon)) >= 0) {

    }

    if (c < -1) {
	/* an error occurred during option processing */
	fprintf(stderr, "%s: %s\n",
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
		poptStrerror(c));
	poptPrintHelp(optCon, stderr, 0);
	exit(1);
    }

    poptFreeContext(optCon);
}


#include <sys/time.h>

static inline
unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_usec+tv.tv_sec*1000000);
}

static
void run_pp_server(hca_info_t *hca, con_info_t *con)
{
    void *rbuf;
    int ret;
    int len;
    assert(arg_client != 1);

    while (1) {
	while (1) { /* recv */
	    len = psib_recvlook(con, &rbuf);
	    if (len > 0) break;
	    if ((len < 0) && (errno != EAGAIN)) goto err_io;
	    if (len == 0) psib_recvdone(con);
	    psib_poll(hca, 1);
	}

	while(1) { /* send */
	    ret = psib_send(con, rbuf, len);
	    if (ret == len) break;
	    if (ret > 0) goto err_size;
	    if ((ret < 0) && (errno != EAGAIN)) goto err_io;
	    psib_poll(hca, 1);
	}

	psib_recvdone(con);
    }

    ret = 0;
 err_io:
    printf("IO error : %m\n");
    exit(1);
    /* --- */
 err_size:
    printf("Wrong size of message!\n");
    exit(1);
}

static
int run_pp(hca_info_t *hca, con_info_t *con, int loops, int msize)
{
    int cnt;
    void *buf = malloc(msize);
    void *rbuf;
    int ret;
    assert(arg_client == 1);

    memset(buf, 42, msize);

    for (cnt = 0; cnt < loops; cnt++) {
	while(1) { /* send */
	    ret = psib_send(con, buf, msize);
	    if (ret == msize) break;
	    if (ret > 0) goto err_size;
	    if ((ret < 0) && (errno != EAGAIN)) goto err_io;
	    psib_poll(hca, 1);
	}

	while (1) { /* recv */
	    ret = psib_recvlook(con, &rbuf);
	    if (ret == msize) break;
	    if (ret > 0) goto err_size;
	    if ((ret < 0) && (errno != EAGAIN)) goto err_io;
	    if (ret == 0) psib_recvdone(con);
	    psib_poll(hca, 1);
	}
	psib_recvdone(con);
    }

    ret = 0;
 err_io:
    free(buf);
    return ret;
    /* --- */
 err_size:
    errno = EBADMSG;
    goto err_io;
}

void
do_pp(void)
{
    con_info_t con;
    IB_lid_t remote_lid; /* remote peer's LID */
    IB_wqpn_t remote_qpn; /* remote peer's QPN */
    if (psib_init_con(&default_hca, &default_port, &con)) goto err_init_con;

    printf("Local LID / QP :  0x%04x 0x%06x\n",
	   con.lid,
	   con.qp_prop.qp_num);
    {
	int rlid, rqpn;
	while (1) {
	    printf("Remote LID and QP?\n");
	    fflush(stdout);
	    if (scanf("%x %x", &rlid, &rqpn) == 2) break;
	    printf("wrong format...\n");
	}
	remote_lid = rlid;
	remote_qpn = rqpn;
    }

    if (psib_connect_con(&con, remote_lid, remote_qpn)) goto err_connect_con;

    /* Wait until both sides reach rts */
    sleep(2);


    if (arg_client) {
	unsigned long t1, t2;
	double time;
	double throuput;
	unsigned int msgsize;
	double ms;
	int res;

	printf("%5s %8s %6s %6s\n", "msize", "loops", "time", "throughput");
	for (ms = 1.4142135; ms < IB_MTU_PAYLOAD - 1; ms = ms * 1.4142135) {
//	for (ms = 1.4142135; ms < IB_MTU_PAYLOAD - 1; ms = ms +1) {
	    msgsize = ms + 0.5;
	    /* warmup, for sync */
	    run_pp(&default_hca, &con, 2, 1);
	    t1 = getusec();
	    res = run_pp(&default_hca, &con, arg_loops, msgsize);
	    t2 = getusec();
	    time = (double)(t2 - t1) / (arg_loops * 2);
	    throuput = msgsize / time;
	    if (res == 0) {
		printf("%5d %8d %6.2f %6.2f\n", msgsize, arg_loops, time, throuput);
		fflush(stdout);
	    } else {
		printf("Error in communication: %m\n");
	    }
	}
    } else {
	printf("Server started.\n");
	run_pp_server(&default_hca, &con);
    }

    return;
    /* --- */
 err_init_con:
    printf("psib_init_con() failed : %s\n", psib_err_str);
    exit(1);
 err_connect_con:
    printf("psib_connect_con() failed : %s\n", psib_err_str);
    exit(1);
}



int main(int argc, char **argv)
{
    parse_opt(argc, argv);

    psib_debug = arg_verbose;
    if ((!arg_server && !arg_client) ||
	(arg_server && arg_client)) {
	printf("run as server or client? (-s or -c)\n");
	exit(1);
    }

    if (psib_init()) {
	printf("Initialisation of IB failed : %s\n", psib_err_str);
	exit(1);
    }

    do_pp();

    return 0;
}
