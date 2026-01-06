/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psgm.c: GM Myrinet communication
 */

#include "psgm.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>

#include <gm.h>

#include "pscom_util.h"

#define FREE_GMPORTS {2, 4, 5, 6, 7}

#define GM_MAX_RBUFS        1000
#define GM_MAX_SBUFS        40
#define GM_LOWLEVEL_MTU     8184 /* must match to SIZEPARAM !!! */
#define GM_STUPID_SIZEPARAM 13
#define GM_MAX_PAYLOAD      (GM_LOWLEVEL_MTU - sizeof(psgm_msg_header_t))

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

typedef union psgm_msg_header_u {
    void *con_id;

    // union! force 8 byte size!
    uint64_t _align8_;
} psgm_msg_header_t;

typedef struct psgm_msg_s {
    psgm_msg_header_t header;
    char data[GM_MAX_PAYLOAD];
} psgm_msg_t;

static char *psgm_err_str = NULL;

/* GM specific information about one connection */
struct psgm_con_info {
    //    gmport_t	*gmport;
    unsigned int remote_node_id; /* translated remote node id. (direct usable in
                                    gm_send()) */
    unsigned int remote_port;
    void *remote_con_id;
    int con_broken;

    unsigned int global_remote_node_id;
};

typedef struct psgm_iobuffer_s {
    void *buf;
    psgm_con_info_t *gmcon; /* used by connection gmcon or NULL */
} psgm_iobuffer_t;


struct gmport {
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
};


static gmport_t gm_default_port;


int psgm_debug = 2;

#define psgm_dprint(level, fmt, arg...)                                        \
    do {                                                                       \
        if ((level) <= psgm_debug) {                                           \
            fprintf(stderr, "<psgm%5d:" fmt ">\n", getpid(), ##arg);           \
            fflush(stderr);                                                    \
        }                                                                      \
    } while (0);


#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))


static void psgm_err(char *str)
{
    if (psgm_err_str) { free(psgm_err_str); }

    psgm_err_str = str ? strdup(str) : strdup("");
    return;
}

static void psgm_err_rc(char *str, gm_status_t status)
{
    const char *gm_err = gm_strerror(status);
    int len            = strlen(str) + strlen(gm_err) + 20;
    char *msg          = malloc(len);
    assert(msg);
    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, gm_err);
    psgm_err(msg);
    free(msg);
}

static int psgm_init_gm(gmport_t *gmport)
{
    gm_status_t stat;

    memset(gmport, 0, sizeof(*gmport));
    if ((stat = gm_init()) != GM_SUCCESS) {
        psgm_err_rc("gm_init() failed ", stat);
        return -1;
    }
    return 0;
}

static void psgm_free_buffers(gmport_t *gmport)
{
    int i;
    for (i = 0; i < GM_MAX_RBUFS; i++) {
        if (gmport->r_buffer[i]) {
            gm_dma_free(gmport->port, gmport->r_buffer[i]);
        }
        gmport->r_buffer[i] = NULL;
    }
    for (i = 0; i < GM_MAX_SBUFS; i++) {
        if (gmport->s_buffer[i].buf) {
            gm_dma_free(gmport->port, gmport->s_buffer[i].buf);
        }
        gmport->s_buffer[i].buf = NULL;
    }
}

static int psgm_init_buffers(gmport_t *gmport)
{
    int tokens;
    int i;

    tokens = gm_num_send_tokens(gmport->port) - 1; /* -1 from gm examples. Dont
                                                      know why */
    tokens = MIN(tokens, GM_MAX_SBUFS);

    gmport->n_sbufs   = tokens;
    gmport->s_buf_pos = 0;

    for (i = 0; i < tokens; i++) {
        gmport->s_buffer[i].buf = gm_dma_malloc(gmport->port, GM_LOWLEVEL_MTU);
        if (!gmport->s_buffer[i].buf) { goto err_dma_alloc; }
    }

    tokens = gm_num_receive_tokens(gmport->port);
    tokens = MIN(tokens, GM_MAX_RBUFS);

    //    gmport->n_rbufs = gmport->n_rtokens = tokens;

    for (i = 0; i < tokens; i++) {
        gmport->r_buffer[i] = gm_dma_malloc(gmport->port, GM_LOWLEVEL_MTU);
        if (!gmport->r_buffer[i]) { goto err_dma_alloc; }
        gm_provide_receive_buffer(gmport->port, gmport->r_buffer[i],
                                  GM_STUPID_SIZEPARAM, GM_LOW_PRIORITY);
    }

    return 0;
    /* --- */
err_dma_alloc:
    psgm_err("GM: gm_dma_malloc() failed!");
    return -1;
}


static void gm_send_cb(struct gm_port *p, void *context, gm_status_t status)
{
    psgm_iobuffer_t *buf = (psgm_iobuffer_t *)context;

    if (status == GM_SUCCESS) {
        buf->gmcon = NULL; /* buffer is now unused */
        return;
    }
    /* error */
    if (buf->gmcon) {
        buf->gmcon->con_broken = 1;
        buf->gmcon             = NULL; /* buffer is now unused */
    } else {
        psgm_dprint(0, "GM: assert(gmcon) failed in gm_send_cb()");
    }

    psgm_dprint(2, "GM send_cb: closing connection : %s", gm_strerror(status));
}


/* returnvalue like write(), except on error errno is negative return */
int psgm_sendv(psgm_con_info_t *gmcon, const struct iovec *iov, int size)
{
    int len;
    psgm_iobuffer_t *buf;
    psgm_msg_t *msg;
    gmport_t *gmport = &gm_default_port; /* ToDo: Use a parameter for this! */

    if (gmcon->con_broken) { goto err_broken; }

    buf = &gmport->s_buffer[gmport->s_buf_pos];
    if (buf->gmcon) { goto err_busy; }

    buf->gmcon = gmcon;

    len = (size <= (int)GM_MAX_PAYLOAD) ? size : (int)GM_MAX_PAYLOAD;

    msg                = (psgm_msg_t *)buf->buf;
    msg->header.con_id = gmcon->remote_con_id;

    /* copy to registerd send buffer */
    pscom_memcpy_from_iov(&msg->data[0], iov, len);

    gm_send_with_callback(gmport->port, msg, GM_STUPID_SIZEPARAM,
                          len + sizeof(psgm_msg_header_t), GM_LOW_PRIORITY,
                          gmcon->remote_node_id, gmcon->remote_port, gm_send_cb,
                          buf);

    gmport->s_buf_pos = (gmport->s_buf_pos + 1) % gmport->n_sbufs;

    return len;
    /* --- */
err_busy:
    return -EAGAIN;
    /* --- */
err_broken:
    return -EPIPE;
}


void *psgm_recvlook(void **con_id, void **buf, unsigned int *size)
{
    void *handle;
    gm_recv_event_t *event;
    struct gm_port *port = gm_default_port.port; /* ToDo: Use parameter here !
                                                  */
    psgm_msg_t *msg;

    while (1) {
        event = gm_receive(port);

        switch (gm_ntohc(event->recv.type)) {
        case GM_NO_RECV_EVENT: return NULL; break;
        case GM_FAST_RECV_EVENT:
        case GM_FAST_HIGH_RECV_EVENT:
        case GM_FAST_PEER_RECV_EVENT:
        case GM_FAST_HIGH_PEER_RECV_EVENT:
            handle = gm_ntohp(event->recv.buffer);
            msg    = (psgm_msg_t *)gm_ntohp(event->recv.message);

            *con_id = msg->header.con_id;
            *buf    = &msg->data[0];
            *size   = gm_ntohl(event->recv.length) - sizeof(psgm_msg_header_t);
            return handle;
        case GM_RECV_EVENT:
        case GM_HIGH_RECV_EVENT:
        case GM_PEER_RECV_EVENT:
        case GM_HIGH_PEER_RECV_EVENT:
            handle = gm_ntohp(event->recv.buffer);
            msg    = (psgm_msg_t *)handle;

            *con_id = msg->header.con_id;
            *buf    = &msg->data[0];
            *size   = gm_ntohl(event->recv.length) - sizeof(psgm_msg_header_t);
            return handle;
        default:
            //	    printf("Event unknown %d\n", gm_ntohc(event->recv.type));
            gm_unknown(port, event);
        }
    }
}


int psgm_recvdone(void *handle)
{
    struct gm_port *port = gm_default_port.port; /* ToDo: Use parameter here !
                                                  */

    gm_provide_receive_buffer(port, handle, GM_STUPID_SIZEPARAM,
                              GM_LOW_PRIORITY);

    return 0;
}

static int psgm_init_port(gmport_t *gmport)
{
    unsigned int i;
    int free_ports[] = FREE_GMPORTS;
    gm_status_t stat;
    int last_unit = 8;

    for (i = 0; i < sizeof(free_ports) / sizeof(free_ports[0]); i++) {
        int pidx = free_ports[i];
        int unit;
        for (unit = 0; unit < last_unit; unit++) {
            stat = gm_open(&gmport->port, unit, pidx, "pscom", GM_API_VERSION);
            if (stat == GM_SUCCESS) {
                gmport->port_idx = pidx;
                gmport->unit_idx = unit;
                return 0;
            }
            if (stat == GM_NO_SUCH_DEVICE) { last_unit = unit; }
            psgm_dprint(5,
                        "gm_open(%p, unit=%u, port_id=%u, \"pscom\", "
                        "GM_API_VERSION=0x%x) = %d",
                        &gmport->port, unit, pidx, GM_API_VERSION, stat);
        }
    }
    psgm_err("GM:No port available!");
    return -1;
}

static int psgm_init_node_id(gmport_t *gmport)
{
    unsigned int id;
    gm_status_t stat;

    if ((stat = gm_get_node_id(gmport->port, &id)) != GM_SUCCESS) {
        goto err_get_nodeid;
    }

    if ((stat = gm_node_id_to_global_id(gmport->port, id,
                                        &gmport->global_node_id)) !=
        GM_SUCCESS) {
        goto err_globalid;
    }

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

static void psgm_cleanup_gm(gmport_t *gmport)
{
    if (gmport->port) {
        psgm_free_buffers(gmport);
        gm_close(gmport->port);
        gmport->port = 0;
    }
    gm_finalize();
}


int psgm_init(void)
{
    static int init_state = 1;
    if (init_state == 1) {
        if (psgm_init_gm(&gm_default_port)) { goto err_gm; }
        if (psgm_init_port(&gm_default_port)) { goto err_port; }
        if (psgm_init_buffers(&gm_default_port)) { goto err_port_buffers; }
        if (psgm_init_node_id(&gm_default_port)) { goto err_nodeid; }
        init_state = 0;
        psgm_dprint(2, "GM INIT: global node id %08x using port %u unit %u",
                    gm_default_port.global_node_id, gm_default_port.port_idx,
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

    psgm_dprint(1, "GM disabled : %s", psgm_err_str);

    return -1;
}


int psgm_con_init(psgm_con_info_t *gmcon, gmport_t *gmport)
{
    if (!gmport) { gmport = &gm_default_port; }

    gmcon->con_broken            = 0;
    gmcon->global_remote_node_id = 0;
    gmcon->remote_node_id        = 0;
    gmcon->remote_port           = 0;
    gmcon->remote_con_id         = NULL;
    //      gmcon->gmport = gmport;
    return 0;
}


int psgm_con_connect(psgm_con_info_t *gmcon, gmport_t *gmport,
                     psgm_info_msg_t *msg)
{
    if (!gmport) { gmport = &gm_default_port; }
    gm_status_t stat;
    unsigned int remote_node_id;

    if ((stat = gm_global_id_to_node_id(gmport->port, msg->remote_global_node_id,
                                        &remote_node_id)) != GM_SUCCESS) {
        goto err_get_node_id;
    }

    gmcon->remote_node_id = remote_node_id;
    gmcon->remote_port    = msg->remote_port;
    gmcon->remote_con_id  = msg->remote_con_id;

    gmcon->global_remote_node_id = msg->remote_global_node_id;
    return 0;
    /* --- */
err_get_node_id:
    psgm_err_rc("gm_global_id_to_node_id() failed ", stat);
    psgm_dprint(2, "psgm_con_connect() : %s", psgm_err_str);
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


psgm_con_info_t *psgm_con_create(void)
{
    psgm_con_info_t *gmcon = malloc(sizeof(*gmcon));
    return gmcon;
}


void psgm_con_free(psgm_con_info_t *gmcon)
{
    free(gmcon);
}


void psgm_con_cleanup(psgm_con_info_t *gmcon)
{
    /* Something to do? */
}


void psgm_con_get_info_msg(psgm_con_info_t *gmcon, gmport_t *gm_port,
                           void *con_id, psgm_info_msg_t *msg)
{
    if (!gm_port) { gm_port = &gm_default_port; }

    msg->error                 = 0;
    msg->remote_global_node_id = gm_port->global_node_id;
    msg->remote_port           = gm_port->port_idx;
    msg->remote_con_id         = con_id;
}
