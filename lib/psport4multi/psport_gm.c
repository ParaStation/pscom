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
 * psport_gm.c: GM Myrinet communication
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include "psport_priv.h"
#include "psport_gm.h"

#include <gm.h>


#define FREE_GMPORTS { 2, 4, 5, 6, 7 }

#define GM_MAX_RBUFS		1000
#define GM_MAX_SBUFS		40
#define GM_LOWLEVEL_MTU		8184 /* must match to SIZEPARAM !!! */
#define GM_STUPID_SIZEPARAM     13
#define GM_MAX_PAYLOAD  (GM_LOWLEVEL_MTU - sizeof(psgm_msg_header_t))

/*
gm_max_length_for_size(   3) =    0
gm_max_length_for_size(   4) =    8
gm_max_length_for_size(   5) =   24
gm_max_length_for_size(   6) =   56
gm_max_length_for_size(   7) =  120
gm_max_length_for_size(   8) =  248
gm_max_length_for_size(   9) =  504
gm_max_length_for_size(  10) = 1016
gm_max_length_for_size(  11) = 2040
gm_max_length_for_size(  12) = 4088
gm_max_length_for_size(  13) = 8184
gm_max_length_for_size(  14) = 16376
gm_max_length_for_size(  15) = 32760
gm_max_length_for_size(  16) = 65528
gm_max_length_for_size(  17) = 131064
gm_max_length_for_size(  18) = 262136
*/

typedef struct psgm_msg_header_s {
    uint32_t	con_idx;
    uint32_t	_align8_;
} psgm_msg_header_t;

typedef struct psgm_msg_s {
    psgm_msg_header_t header;
    char data[GM_MAX_PAYLOAD];
} psgm_msg_t;

static char *psgm_err_str = NULL;

/* GM specific information about one connection */
struct psgm_con_info_s {
//    gmport_t	*gmport;
    unsigned int remote_node_id; /* translated remote node id. (direct usable in gm_send()) */
    unsigned int remote_port;
    int		remote_con_idx;
    int		con_broken;

    unsigned int global_remote_node_id;
};

typedef struct psgm_iobuffer_s {
    void		*buf;
    psgm_con_info_t	*gmcon; /* used by connection gmcon or NULL */
} psgm_iobuffer_t;

typedef struct gmport_s {
    struct gm_port *port;
    unsigned int global_node_id;
    unsigned int port_idx;

//    int n_stokens;
//    int n_rtokens;
    int n_sbufs;
    int s_buf_pos;
//    int n_rbufs;

    void *r_buffer[GM_MAX_RBUFS];
    psgm_iobuffer_t s_buffer[GM_MAX_SBUFS];
    unsigned int unit_idx;
} gmport_t;

static gmport_t gm_default_port;

static
void psgm_err(char *str)
{
    if (psgm_err_str) free(psgm_err_str);

    psgm_err_str = str ? strdup(str) : strdup("");
    return;
}

static
void psgm_err_rc(char *str, gm_status_t status)
{
    const char *gm_err = gm_strerror(status);
    int len = strlen(str) + strlen(gm_err) + 20;
    char *msg = malloc(len);
    assert(msg);
    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, gm_err);
    psgm_err(msg);
    free(msg);
}

static
int psgm_init_gm(gmport_t *gmport) {
    gm_status_t stat;

    memset(gmport, 0, sizeof(*gmport));
    if ((stat = gm_init()) != GM_SUCCESS) {
	psgm_err_rc("gm_init() failed ", stat);
	return -1;
    }
    return 0;
}

static
void psgm_free_buffers(gmport_t *gmport)
{
    int i;
    for (i = 0; i < GM_MAX_RBUFS; i++) {
	if (gmport->r_buffer[i]) gm_dma_free(gmport->port, gmport->r_buffer[i]);
	gmport->r_buffer[i] = NULL;
    }
    for (i = 0; i < GM_MAX_SBUFS; i++) {
	if (gmport->s_buffer[i].buf) gm_dma_free(gmport->port, gmport->s_buffer[i].buf);
	gmport->s_buffer[i].buf = NULL;
    }
}

static
int psgm_init_buffers(gmport_t *gmport)
{
    int tokens;
    int i;

    tokens = gm_num_send_tokens(gmport->port) - 1; /* -1 from gm examples. Dont know why */
    tokens = PSP_MIN(tokens, GM_MAX_SBUFS);

    gmport->n_sbufs = tokens;
    gmport->s_buf_pos = 0;

    for (i = 0; i < tokens; i++) {
	gmport->s_buffer[i].buf = gm_dma_malloc(gmport->port, GM_LOWLEVEL_MTU);
	if (!gmport->s_buffer[i].buf) goto err_dma_alloc;
    }

    tokens = gm_num_receive_tokens(gmport->port);
    tokens = PSP_MIN(tokens, GM_MAX_RBUFS);

//    gmport->n_rbufs = gmport->n_rtokens = tokens;

    for (i = 0; i < tokens; i++) {
	gmport->r_buffer[i] = gm_dma_malloc(gmport->port, GM_LOWLEVEL_MTU);
	if (!gmport->r_buffer[i]) goto err_dma_alloc;
	gm_provide_receive_buffer(gmport->port, gmport->r_buffer[i], GM_STUPID_SIZEPARAM, GM_LOW_PRIORITY);
    }

    return 0;
    /* --- */
 err_dma_alloc:
    psgm_err("GM: gm_dma_malloc() failed!");
    return -1;
}


static
void gm_send_cb(struct gm_port * p, void *context, gm_status_t status)
{
    psgm_iobuffer_t *buf = (psgm_iobuffer_t *)context;

    if (status == GM_SUCCESS) {
	buf->gmcon = NULL; /* buffer is now unused */
	return;
    }
    /* error */
    if (buf->gmcon) {
	buf->gmcon->con_broken = 1;
	buf->gmcon = NULL; /* buffer is now unused */
    } else {
	DPRINT(0, "GM: assert(gmcon) failed in gm_send_cb()");
    }

    DPRINT(2, "GM send_cb: closing connection : %s", gm_strerror(status));
}


/* returnvalue like write(), except on error errno is negative return */
static
int psgm_sendv(psgm_con_info_t *gmcon, struct iovec *iov, int size)
{
    int len;
    psgm_iobuffer_t *buf;
    psgm_msg_t *msg;
    gmport_t *gmport = &gm_default_port; /* ToDo: Use a parameter for this! */

    if (gmcon->con_broken) goto err_broken;

    buf = &gmport->s_buffer[gmport->s_buf_pos];
    if (buf->gmcon) goto err_busy;

    buf->gmcon = gmcon;

    len = (size <= (int)GM_MAX_PAYLOAD) ? size : (int)GM_MAX_PAYLOAD;

    msg = (psgm_msg_t *)buf->buf;
    msg->header.con_idx = gmcon->remote_con_idx;

    /* copy to registerd send buffer */
    PSP_memcpy_from_iov(&msg->data[0], iov, len);

    gm_send_with_callback(gmport->port, msg,
			  GM_STUPID_SIZEPARAM,
			  len + sizeof(psgm_msg_header_t),
			  GM_LOW_PRIORITY,
			  gmcon->remote_node_id,
			  gmcon->remote_port,
			  gm_send_cb, buf);

    gmport->s_buf_pos = (gmport->s_buf_pos + 1) % gmport->n_sbufs;

    return len;
    /* --- */
 err_busy:
    return -EAGAIN;
    /* --- */
 err_broken:
    return -EPIPE;
}



/* on error errno is negative size */
static
void *psgm_recvlook(int *con_idx, void **buf, int *size)
{
    void *handle;
    gm_recv_event_t *event;
    struct gm_port * port = gm_default_port.port; /* ToDo: Use parameter here ! */
    psgm_msg_t *msg;

    while (1) {
	event = gm_receive(port);

	switch (gm_ntohc(event->recv.type)) {
	case GM_NO_RECV_EVENT:
	    return NULL;
	    break;
	case GM_FAST_RECV_EVENT:
	case GM_FAST_HIGH_RECV_EVENT:
	case GM_FAST_PEER_RECV_EVENT:
	case GM_FAST_HIGH_PEER_RECV_EVENT:
	    handle = gm_ntohp(event->recv.buffer);
	    msg = (psgm_msg_t *)gm_ntohp(event->recv.message);

	    *con_idx = msg->header.con_idx;
	    *buf = &msg->data[0];
	    *size = gm_ntohl(event->recv.length) - sizeof(psgm_msg_header_t);
	    return handle;
	case GM_RECV_EVENT:
	case GM_HIGH_RECV_EVENT:
	case GM_PEER_RECV_EVENT:
	case GM_HIGH_PEER_RECV_EVENT:
	    handle = gm_ntohp(event->recv.buffer);
	    msg = (psgm_msg_t *)handle;

	    *con_idx = msg->header.con_idx;
	    *buf = &msg->data[0];
	    *size = gm_ntohl(event->recv.length) - sizeof(psgm_msg_header_t);
	    return handle;
	default:
//	    printf("Event unknown %d\n", gm_ntohc(event->recv.type));
	    gm_unknown(port, event);
	}
    }
}

static
int psgm_recvdone(void *handle)
{
    struct gm_port * port = gm_default_port.port; /* ToDo: Use parameter here ! */

    gm_provide_receive_buffer(port, handle, GM_STUPID_SIZEPARAM, GM_LOW_PRIORITY);

    return 0;
}

static
int psgm_init_port(gmport_t *gmport)
{
    unsigned int i;
    int free_ports[] = FREE_GMPORTS;
    gm_status_t stat;
    int last_unit = 8;

    for (i = 0; i < sizeof(free_ports) / sizeof(free_ports[0]); i++) {
	int pidx = free_ports[i];
	int unit;
	for (unit = 0; unit < last_unit; unit++) {
	    stat = gm_open(&gmport->port, unit, pidx, "psport4", GM_API_VERSION);
	    if (stat == GM_SUCCESS) {
		gmport->port_idx = pidx;
		gmport->unit_idx = unit;
		return 0;
	    }
	    if (stat == GM_NO_SUCH_DEVICE) {
		last_unit = unit;
	    }
	    DPRINT(5, "gm_open(%p, unit=%u, port_id=%u, \"psport4\", GM_API_VERSION=0x%x) = %d",
		   &gmport->port, unit, pidx, GM_API_VERSION, stat);
	}
    }
    psgm_err("GM:No port available!");
    return -1;
}

static
int psgm_init_node_id(gmport_t *gmport)
{
    unsigned int id;
    gm_status_t stat;

    if ((stat = gm_get_node_id(gmport->port, &id)) != GM_SUCCESS)
	goto err_get_nodeid;

    if ((stat = gm_node_id_to_global_id
	 (gmport->port, id, &gmport->global_node_id)) != GM_SUCCESS)
	goto err_globalid;

    return 0;
    /* --- */
 err_globalid:
    psgm_err_rc("gm_get_node_id() failed ", stat);
    return -1;
    /* --- */
 err_get_nodeid:
    psgm_err_rc("gm_node_id_to_global_id() failed ", stat);
    return -1;
}

static
void psgm_cleanup_gm(gmport_t *gmport)
{
    if (gmport->port) {
	psgm_free_buffers(gmport);
	gm_close(gmport->port);
	gmport->port = 0;
    }
    gm_finalize();
}

static
int psgm_init(void)
{
    static int init_state = 1;
    if (init_state == 1) {
	if (psgm_init_gm(&gm_default_port)) goto err_gm;
	if (psgm_init_port(&gm_default_port)) goto err_port;
	if (psgm_init_buffers(&gm_default_port)) goto err_port_buffers;
	if (psgm_init_node_id(&gm_default_port)) goto err_nodeid;
	init_state = 0;
	DPRINT(2, "GM INIT: global node id %08x using port %u unit %u",
	       gm_default_port.global_node_id,
	       gm_default_port.port_idx,
	       gm_default_port.unit_idx);
    }

    return init_state; /* 0 = success, -1 = error */
    /* --- */
 err_nodeid:
 err_port_buffers:
 err_port:
    psgm_cleanup_gm(&gm_default_port);
 err_gm:
    init_state = -1;

    DPRINT(1, "GM disabled : %s", psgm_err_str);

    return -1;
}

static
int psgm_init_con(gmport_t *gmport, psgm_con_info_t *gmcon)
{
    gmcon->con_broken = 0;
    gmcon->global_remote_node_id = 0;
    gmcon->remote_node_id = 0;
    gmcon->remote_port = 0;
    gmcon->remote_con_idx = 0;
//    gmcon->gmport = gmport;
    return 0;
}

static
int psgm_connect_con(gmport_t *gmport, psgm_con_info_t *gmcon, unsigned int global_node_id,
		     unsigned int port, int con_idx)
{
    gm_status_t stat;
    unsigned int remote_node_id;

    if ((stat = gm_global_id_to_node_id(gmport->port,
					global_node_id,
					&remote_node_id)) != GM_SUCCESS)
	goto err_get_node_id;

    gmcon->remote_node_id = remote_node_id;
    gmcon->remote_port = port;
    gmcon->remote_con_idx = con_idx;

    gmcon->global_remote_node_id = global_node_id;
    return 0;
    /* --- */
 err_get_node_id:
    psgm_err_rc("gm_global_id_to_node_id() failed ", stat);
    return -1;
}

#if 0
static
void DoSendAbortAllGm(PSP_Port_t *port, con_t *con)
{
    PSP_Request_t *req;

    while (!sendq_empty(con)) {
	req = sendq_head(con);
	req->state |= PSP_REQ_STATE_PROCESSED;
	DelFirstSendRequest(port, req, CON_TYPE_GM);
    };
}
#endif

static
void psgm_cleanup_con(PSP_Port_t *port, psgm_con_info_t *gmcon)
{
    /* Something to do? */
}

/* ****************************************************************** */

static
void PSP_do_write_gm(PSP_Port_t *port, PSP_Connection_t *con)
{
    int len, rlen;
    PSP_Req_t *req = con->out.req;

    if (req) {
	len = req->u.req.iov_len;
	rlen = psgm_sendv(con->arch.gm.gmcon, req->u.req.iov, len);
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

static
int PSP_do_recv_gm(PSP_Port_t *port)
{
    void *recvhandle;
    PSP_Connection_t *con;
    void *buf = buf; // suppress uninitialized warning
    int size = size; // suppress uninitialized warning
    int con_idx = con_idx; // suppress uninitialized warning

    recvhandle = psgm_recvlook(&con_idx, &buf, &size);

    if (!recvhandle) return 0;
    con = &port->con[con_idx]; /* ToDo range and typecheck ?*/

    PSP_read_do(port, con, buf, size);

    psgm_recvdone(recvhandle);
    return 1;
}

int PSP_do_sendrecv_gm(PSP_Port_t *port)
{
    struct list_head *pos, *next;

    list_for_each_safe(pos, next, &port->gm_list_send) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.gm.next_send);
	PSP_do_write_gm(port, con);
    }

    return PSP_do_recv_gm(port);
}


static
void PSP_set_write_gm(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Write %d gm\n", start);
    if (start) {
	if (list_empty(&con->arch.gm.next_send)) {
	    list_add_tail(&con->arch.gm.next_send, &port->gm_list_send);
	}
	PSP_do_write_gm(port, con);
	/* Dont do anything after this line.
	   PSP_do_write_gm() can reenter PSP_set_write_gm()! */
    } else {
	/* it's save to dequeue more then once */
	list_del_init(&con->arch.gm.next_send);
    }
}

static
void PSP_set_read_gm(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Read %d gm\n", start);
}


static
void PSP_init_con_gm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd,
		     psgm_con_info_t *gmcon)
{
    con->state = PSP_CON_STATE_OPEN_GM;
    close(con_fd);

    con->arch.gm.gmcon = gmcon;

    INIT_LIST_HEAD(&con->arch.gm.next_send);
    list_add_tail(&con->arch.gm.next, &port->gm_list);

    con->set_write = PSP_set_write_gm;
    con->set_read = PSP_set_read_gm;
}

void PSP_terminate_con_gm(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.gm.gmcon) {
	psgm_con_info_t *gmcon = con->arch.gm.gmcon;

	list_del(&con->arch.gm.next_send);
	list_del(&con->arch.gm.next);

	psgm_cleanup_con(port, gmcon);
	free(gmcon);

	con->arch.gm.gmcon = NULL;
    }
}

typedef struct psgm_info_msg_s {
    unsigned int remote_global_node_id;
    int		 remote_con_idx;
    unsigned int remote_port;
    int		error;
} psgm_info_msg_t;


int PSP_connect_gm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_GM;
    psgm_con_info_t *gmcon = malloc(sizeof(*gmcon));
    psgm_info_msg_t msg;
    int call_cleanup_con = 0;
    int err;

    if (!env_gm || psgm_init() || !gmcon) {
	if (gmcon) free(gmcon);
	return 0; /* Dont use gm */
    }
    /* We want talk gm */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 1 */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_GM))
	goto err_remote;

    /* step 2 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
	goto err_remote;

    err = psgm_init_con(&gm_default_port, gmcon);
    if (!err) {
	call_cleanup_con = 1;
	err = psgm_connect_con(&gm_default_port, gmcon,
			       msg.remote_global_node_id,
			       msg.remote_port,
			       msg.remote_con_idx);
    }

    /* step 3 : send connection id's (or error) */
    msg.error = err;
    msg.remote_global_node_id = gm_default_port.global_node_id;
    msg.remote_port = gm_default_port.port_idx;
    msg.remote_con_idx = con->con_idx;

    PSP_writeall(con_fd, &msg, sizeof(msg));

    if (err) goto err_connect;

    /* step 4: gm initialized. Recv final ACK. */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.error)) goto err_ack;

    PSP_init_con_gm(port, con, con_fd, gmcon);

    return 1;
    /* --- */
 err_ack:
 err_connect:
    if (call_cleanup_con) psgm_cleanup_con(port, gmcon);
 err_remote:
    if (gmcon) free(gmcon);
    return 0;
}



int PSP_accept_gm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_GM;
    psgm_con_info_t *gmcon = NULL;
    psgm_info_msg_t msg;

    if (!env_gm || psgm_init())
	goto out_nogm;

    if (!(gmcon = malloc(sizeof(*gmcon))))
	goto out_nogm;

    if (psgm_init_con(&gm_default_port, gmcon)) {
	DPRINT(1, "GM psgm_init_con failed : %s", psgm_err_str);
	goto err_init_con;
    }

    /* step 1:  Yes, we talk gm. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send Connection id's */
    msg.error = 0;
    msg.remote_global_node_id = gm_default_port.global_node_id;
    msg.remote_port = gm_default_port.port_idx;
    msg.remote_con_idx = con->con_idx;

    PSP_writeall(con_fd, &msg, sizeof(msg));

    /* step 3 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.error))
	goto err_remote;


    if (psgm_connect_con(&gm_default_port, gmcon, msg.remote_global_node_id,
			       msg.remote_port, msg.remote_con_idx))
	goto err_connect_con;

    /* step 4: GM initialized. Send final ACK. */
    msg.error = 0;
    PSP_writeall(con_fd, &msg, sizeof(msg));

    PSP_init_con_gm(port, con, con_fd, gmcon);

    return 1;
    /* --- */
 err_connect_con:
    /* Send NACK */
    msg.error = 1;
    PSP_writeall(con_fd, &msg, sizeof(msg));
 err_remote:
    psgm_cleanup_con(port, gmcon);
 err_init_con:
 out_nogm:
    if (gmcon) free(gmcon);
    arch = PSP_ARCH_ERROR;
    PSP_writeall(con_fd, &arch, sizeof(arch));
    return 0; /* Dont use gm */
}

void PSP_gm_init(PSP_Port_t *port)
{
    port->gm_users = 0;
    INIT_LIST_HEAD(&port->gm_list);
    INIT_LIST_HEAD(&port->gm_list_send);
}
