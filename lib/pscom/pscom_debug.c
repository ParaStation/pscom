/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#define _GNU_SOURCE
#include "pscom_debug.h"
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "list.h"

#include "pscom.h"
#include "pscom_env.h"
#include "pscom_priv.h"
#include "pscom_ufd.h"
#include "pscom_precon.h"

#ifndef PSCOM_ALLIN
/* MPI2 Header: */

/* from mpid/psp/include/mpidpre.h */
typedef struct MPIDI_PSP_PSCOM_Xheader {
    int32_t tag;
    uint16_t context_id;
    uint8_t type; /* one of MPID_PSP_MSGTYPE */
    uint8_t _reserved_;
    int32_t src_rank;
} MPIDI_PSP_PSCOM_Xheader_t;

/* from mpid/psp/include/mpidpre.h */
enum MPID_PSP_MSGTYPE {
    MPID_PSP_MSGTYPE_DATA,             /* Data message */
    MPID_PSP_MSGTYPE_DATA_REQUEST_ACK, /* Data message and request DATA_ACK
                                          acknowledge */
    MPID_PSP_MSGTYPE_DATA_ACK,         /* Acknowledge of DATA_REQUEST_ACK */
    MPID_PSP_MSGTYPE_CANCEL_DATA_ACK,  /* Acknowledge of CANCEL_DATA_REQUEST_ACK
                                        */
    MPID_PSP_MSGTYPE_CANCEL_DATA_REQUEST_ACK, /* Cancel an already send DATA
                                                 message. Request
                                                 CANCEL_DATA_ACK. */

    /* One Sided communication: */
    MPID_PSP_MSGTYPE_RMA_PUT,
    MPID_PSP_MSGTYPE_RMA_GET_REQ,
    MPID_PSP_MSGTYPE_RMA_GET_ANSWER,
    MPID_PSP_MSGTYPE_RMA_ACCUMULATE,

    MPID_PSP_MSGTYPE_RMA_LOCK_SHARED_REQUEST,
    MPID_PSP_MSGTYPE_RMA_LOCK_EXCLUSIVE_REQUEST,
    MPID_PSP_MSGTYPE_RMA_LOCK_ANSWER,

    MPID_PSP_MSGTYPE_RMA_UNLOCK_REQUEST,
    MPID_PSP_MSGTYPE_RMA_UNLOCK_ANSWER,

    MPID_PSP_MSGTYPE_DATA_CANCELLED, /* Data message that should be cancelled */
    MPID_PSP_MSGTYPE_MPROBE_RESERVED_REQUEST /* Message that has been reserved
                                                by mprobe */
};

/* from mpid/psp/src/mpid_debug.c */
static const char *mpid_msgtype_str(enum MPID_PSP_MSGTYPE msg_type)
{
    switch (msg_type) {
    case MPID_PSP_MSGTYPE_DATA: return "DATA";
    case MPID_PSP_MSGTYPE_DATA_REQUEST_ACK: return "DATA_REQUEST_ACK";
    case MPID_PSP_MSGTYPE_DATA_ACK: return "DATA_ACK";
    case MPID_PSP_MSGTYPE_CANCEL_DATA_ACK: return "CANCEL_DATA_ACK";
    case MPID_PSP_MSGTYPE_CANCEL_DATA_REQUEST_ACK:
        return "CANCEL_DATA_REQUEST_ACK";
    case MPID_PSP_MSGTYPE_RMA_PUT: return "RMA_PUT";

    case MPID_PSP_MSGTYPE_RMA_GET_REQ: return "RMA_GET_REQ";
    case MPID_PSP_MSGTYPE_RMA_GET_ANSWER: return "RMA_GET_ANSWER";
    case MPID_PSP_MSGTYPE_RMA_ACCUMULATE: return "RMA_ACCUMULATE";

    case MPID_PSP_MSGTYPE_RMA_LOCK_SHARED_REQUEST:
        return "RMA_LOCK_SHARED_REQUEST";
    case MPID_PSP_MSGTYPE_RMA_LOCK_EXCLUSIVE_REQUEST:
        return "RMA_LOCK_EXCLUSIVE_REQUEST";
    case MPID_PSP_MSGTYPE_RMA_LOCK_ANSWER: return "RMA_LOCK_ANSWER";
    case MPID_PSP_MSGTYPE_RMA_UNLOCK_REQUEST: return "RMA_UNLOCK_REQUEST";
    case MPID_PSP_MSGTYPE_RMA_UNLOCK_ANSWER: return "RMA_UNLOCK_ANSWER";
    case MPID_PSP_MSGTYPE_DATA_CANCELLED: return "DATA_CANCELLED";
    case MPID_PSP_MSGTYPE_MPROBE_RESERVED_REQUEST:
        return "MPROBE_RESERVED_REQUEST";
    }
    return "UNKNOWN";
}

#endif

#include "perf.c"

const char *pscom_msgtype_str(pscom_msgtype_t msg_type)
{
    switch (msg_type) {
    case PSCOM_MSGTYPE_USER: return "USER_";
    case PSCOM_MSGTYPE_RMA_WRITE: return "RMA_W";
    case PSCOM_MSGTYPE_RMA_READ: return "RMA_R";
    case PSCOM_MSGTYPE_RMA_READ_ANSWER: return "RMARA";
    case PSCOM_MSGTYPE_RENDEZVOUS_REQ: return "REN_R";
    case PSCOM_MSGTYPE_RENDEZVOUS_FIN: return "REN_F";
    case PSCOM_MSGTYPE_BCAST: return "BCAST";
    case PSCOM_MSGTYPE_BARRIER: return "BARRI";
    case PSCOM_MSGTYPE_EOF: return "EOF__";
    case PSCOM_MSGTYPE_SUSPEND: return "SUSPE";
    case PSCOM_MSGTYPE_GW_ENVELOPE: return "GWENV";
    default: return "UNKNW";
    }
}


static void pscom_dump_request(FILE *out, pscom_req_t *req)
{
    fprintf(out,
            "req#%p state:%20s xhlen:%3lu dlen:%7lu ty:%s con:%p no:%5u "
            "received:%7d",
            &req->pub, pscom_req_state_str(req->pub.state),
            req->pub.xheader_len, req->pub.data_len,
            pscom_msgtype_str(req->pub.header.msg_type), req->pub.connection,
            req->req_no,
            (int)((char *)req->cur_data.iov_base - (char *)req->pub.data));

    if (req->pending_io) {
        fprintf(out, " pending_io: %u pending_io_req: %p", req->pending_io,
                req->pending_io_req ? &req->pending_io_req->pub : NULL);
    }
    fputs("\n", out);

    if (5 <= pscom.env.debug &&
        req->pub.xheader_len >= sizeof(MPIDI_PSP_PSCOM_Xheader_t)) {
        MPIDI_PSP_PSCOM_Xheader_t *xhead =
            (MPIDI_PSP_PSCOM_Xheader_t *)&req->pub.xheader.user;
        fprintf(out, " mpi2: tag:%6d con_id:%4d src_rank:%4d type:%d(%s)\n",
                xhead->tag, xhead->context_id, xhead->src_rank, xhead->type,
                mpid_msgtype_str((enum MPID_PSP_MSGTYPE)(xhead->type)));
    }
}


static void pscom_dump_ufd(FILE *out, ufd_t *ufd)
{
    struct list_head *pos;
    unsigned cnt = 0;

    list_for_each (pos, &ufd->ufd_info) {
        ufd_info_t *ufd_info  = list_entry(pos, ufd_info_t, next);
        struct pollfd *pollfd = ufd_get_pollfd(ufd, ufd_info);
        char buf[20];

        snprintf(buf, sizeof(buf), "%s%3d(",
                 (cnt != ufd->n_ufd_pollfd) ? (cnt ? "," : "") : "|",
                 ufd_info->fd);
        if (pollfd) {
            if (pollfd->events & POLLIN) { strcat(buf, "r"); }
            if (pollfd->events & POLLOUT) { strcat(buf, "w"); }
            if (pollfd->events & POLLERR) { strcat(buf, "e"); }
            if (pollfd->events & POLLPRI) { strcat(buf, "u"); }
            if (pollfd->events & POLLHUP) { strcat(buf, "h"); }
        } else {
            strcat(buf, "-");
        }
        strcat(buf, ")");
        fputs(buf, out);
        cnt++;
    }
    fputs("\n", out);
}


static void pscom_dump_requests(FILE *out)
{
    struct list_head *pos;

    fprintf(out, "Requests:\n");

    pthread_mutex_lock(&pscom.lock_requests);
    list_for_each (pos, &pscom.requests) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, all_req_next);

        pscom_dump_request(out, req);
    }
    pthread_mutex_unlock(&pscom.lock_requests);
}


PSCOM_API_EXPORT
void pscom_dump_con(FILE *out, pscom_con_t *con)
{
    unsigned cnt;
    fprintf(out, "    con#%p type:%6s state:%8s dest:%s recvcnt:%5d", &con->pub,
            pscom_con_type_str(con->pub.type),
            pscom_con_state_str(con->pub.state),
            pscom_con_info_str(&con->pub.remote_con_info), con->recv_req_cnt);

    if (con->pub.state == PSCOM_CON_STATE_CLOSE_WAIT) {
        if (con->state.close_called) { fprintf(out, " usr_closed"); }
        if (con->state.eof_expect) { fprintf(out, " exp_eof"); }
        if (con->state.eof_received) { fprintf(out, " r_eof"); }
        if (con->state.read_failed) { fprintf(out, " r_fail"); }
    }

    if ((cnt = list_count(&con->sendq))) { fprintf(out, " sreqs:%5d", cnt); }
    if (con->in.req) { fprintf(out, " ract:%p", &con->in.req->pub); }
    if ((cnt = list_count(&con->recvq_user))) {
        fprintf(out, " ruser:%5d", cnt);
    }
    if ((cnt = list_count(&con->recvq_ctrl))) {
        fprintf(out, " rctrl:%5d", cnt);
    }
    if ((cnt = list_count(&con->recvq_rma))) { fprintf(out, " rrma:%5d", cnt); }
    fputs("\n", out);
}


static void pscom_dump_connections(FILE *out, pscom_sock_t *sock)
{
    struct list_head *pos;
    fprintf(out, "  Connections:\n");
    list_for_each (pos, &sock->connections) {
        pscom_con_t *con = list_entry(pos, pscom_con_t, next);
        pscom_dump_con(out, con);
    }
}


static void pscom_dump_socket(FILE *out, pscom_sock_t *sock)
{
    fprintf(out, "  sock#%p listen:%6d demand:%4d(%4d)  src:%s anyrecv:%6u\n",
            &sock->pub, sock->pub.listen_portno, sock->listen.usercnt,
            sock->listen.activecnt,
            pscom_con_info_str(&sock->pub.local_con_info),
            sock->recv_req_cnt_any);
    pscom_dump_connections(out, sock);
}


static void pscom_dump_sockets(FILE *out)
{
    struct list_head *pos;

    fprintf(out, "Sockets:\n");
    list_for_each (pos, &pscom.sockets) {
        pscom_sock_t *sock = list_entry(pos, pscom_sock_t, next);

        pscom_dump_socket(out, sock);
    }
}


PSCOM_API_EXPORT
void pscom_dump_connection(FILE *out, pscom_connection_t *connection)
{
    pscom_con_t *con = get_con(connection);
    assert(con->magic == MAGIC_CONNECTION);

    pscom_dump_con(out, con);
}


PSCOM_API_EXPORT
void pscom_dump_reqstat(FILE *out)
{
    fprintf(out, "Reqs:%d GenReqs: (cnt:%d  used:%d)\n", pscom.stat.reqs,
            pscom.stat.gen_reqs, pscom.stat.gen_reqs_used);
    if (pscom.stat.reqs_any_source || pscom.stat.recvq_any) {
        fprintf(out, "ReqsAnySrc:%u RecvQAnySrc:%u\n",
                pscom.stat.reqs_any_source, pscom.stat.recvq_any);
    }
    if (pscom.stat.probes) {
        fprintf(out, "Probes:%u ProbesAnySrc:%u IProbesOK:%u\n",
                pscom.stat.probes, pscom.stat.probes_any_source,
                pscom.stat.iprobes_ok);
    }
    if (pscom.stat.shm_direct || pscom.stat.shm_direct_nonshmptr ||
        pscom.stat.shm_direct_failed) {
        fprintf(out, "shmDirect:%u shmDirectNonShmptr:%u shmDirectFailed:%u\n",
                pscom.stat.shm_direct, pscom.stat.shm_direct_nonshmptr,
                pscom.stat.shm_direct_failed);
    }
    if (pscom.stat.rendezvous_reqs || pscom.stat.fallback_to_eager ||
        pscom.stat.fallback_to_sw_rndv) {
        fprintf(out, "RndvReqs:%u EagerFallback:%u swRndvFallback:%u\n",
                pscom.stat.rendezvous_reqs, pscom.stat.fallback_to_eager,
                pscom.stat.fallback_to_sw_rndv);
    }
#ifdef PSCOM_CUDA_AWARENESS
    fprintf(out, "GPUBufStg:%u GPUBufUnstg:%u\n", pscom.stat.gpu_staging,
            pscom.stat.gpu_unstaging);
#endif /* PSCOM_CUDA_AWARENESS */
}


PSCOM_API_EXPORT
void pscom_dump_info(FILE *out)
{
    pscom_dump_requests(out);
    pscom_dump_sockets(out);
    fprintf(out, "Fds:\n");
    pscom_dump_ufd(out, &pscom.ufd);

    pscom_dump_reqstat(out);
}


static void pscom_sigquit(int sig)
{
    FILE *out = pscom_debug_stream();
    fprintf(out, " +++++++++ SIGQUIT START ++++\n");
    pscom_dump_info(out);
    fprintf(out, " +++++++++ SIGQUIT END ++++++\n");
}


PSCOM_API_EXPORT
char *pscom_debug_req_str(pscom_req_t *req)
{
    static char buf[sizeof("reqUSER_: XXX(Pgpsdec)done_____")];
    if (req) {
        snprintf(buf, sizeof(buf), "req%s: %s%u(%s)",
                 pscom_msgtype_str(req->pub.header.msg_type),
                 req->magic == MAGIC_REQUEST ? "" : "!MAGIC", req->req_no,
                 pscom_req_state_str(req->pub.state));
    } else {
        snprintf(buf, sizeof(buf), "req: NULL");
    }
    return buf;
}


PSCOM_API_EXPORT
char *pscom_debug_request_str(pscom_request_t *request)
{
    return pscom_debug_req_str(get_req(request));
}


/*
 * Helpers to translate user structs into internal ones.
 */
PSCOM_API_EXPORT
pscom_req_t *pscom_get_req(pscom_request_t *request)
{
    return get_req(request);
}


PSCOM_API_EXPORT
pscom_con_t *pscom_get_con(pscom_connection_t *connection)
{
    return get_con(connection);
}


PSCOM_API_EXPORT
pscom_sock_t *pscom_get_sock(pscom_socket_t *socket)
{
    return get_sock(socket);
}


/* pscom_dump_str() is usefull in a gdb session:
 * (gdb) printf "%s\n", pscom_dump_str(10)
 */
PSCOM_API_EXPORT
char *pscom_dump_str(int level)
{
    static char *res = NULL;
    size_t size;
    FILE *out;
    int save = pscom.env.debug;
    if (res) {
        free(res);
        res = NULL;
        if (level == -1) { return res; }
    }

    out = open_memstream(&res, &size);

    pscom.env.debug = level;
    pscom_dump_info(out);
    pscom.env.debug = save;

    fclose(out);

    return res;
}


void pscom_debug_init(void)
{
    if (pscom.env.sigquit) { signal(SIGQUIT, pscom_sigquit); }
}
