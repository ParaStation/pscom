/*
 * ParaStation
 *
 * Copyright (C) 2023-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

/**
 * pscom_rma_sync_ctrl.c: tests of RMA via two-sided communication
 * semantics. In this test a client performs RMA put and get to the server side.
 * This test uses a control message to transfer synchronization data from client
 * to the server side.
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MSIZE_DEFAULT             (4 * 1024 * 1024)
#define MSGTYPE_USER              0  /* xheader msg type */
#define MSGTYPE_RMA_FLUSH_ANSWER  98 /* xheader msg type */
#define MSGTYPE_RMA_FLUSH_REQUEST 99 /* xheader msg type */

/* pscom network header common (send, recv...) */
typedef struct XHeader {
    int tag;
    int type; /* MSGTYPE */
} XHeader_t;

/* pscom network header RMA ctrl msg */
typedef struct XHeader_rma_ctrl {
    XHeader_t common;
    int issued_rma_counter;
    void *remote_sync;
} XHeader_rma_ctrl_t;


#define PSCOM_XHEADER_USER_TYPE Xheader_user_t
typedef union Xheader_user {
    XHeader_t common;
    XHeader_rma_ctrl_t rma_ctrl;
} Xheader_user_t;

/* pscom user xheader RMA */
typedef struct Xheader_rma_sync {
    void *remote_sync;
} Xheader_rma_sync_t;

/* used defined RMA xheader, which will be sent to the target side */
#define PSCOM_XHEADER_RMA_PUT_USER_TYPE Xheader_rma_sync_t
#define PSCOM_XHEADER_RMA_GET_USER_TYPE Xheader_rma_sync_t

/* user-defined data for pscom request, which will be returned back when request
 * is done */
typedef struct Request_user_rma {
    int *local_complete;
} Request_user_rma_t;

/* user-defined data for pscom request, which will be returned back when request
 * is done */
struct PSCOM_req_user {
    union {
        /* user-defined data structure used for pscom RMA APIs */
        Request_user_rma_t cbdata_rma;
    } type;
};

#include "pscom.h"

const char *arg_server    = "localhost:7100";
int arg_client            = 0;
int arg_lport             = 7100;
unsigned long arg_msgsize = MSIZE_DEFAULT;
int arg_run_once          = 0;
int arg_verbose           = 0;
int arg_help              = 0;
int arg_verify            = 0;
char *arg_progname        = NULL;

typedef struct {
    void *addr;
    size_t len;
    void *remote_sync; /* remote sync data position */
} mem_data_t;

static void print_usage(void)
{
    printf("USAGE:\n");
    printf("    %s [OPTIONS]\n\n", arg_progname);
    printf("OPTIONS:\n");
    printf("    -l, --listen        run as server and listen on port (default: "
           "%d)\n",
           arg_lport);
    printf("    -n, --msgsize=size  message size (default: %lu)\n", arg_msgsize);
    printf("    -V, --verify        verify message content\n");
    printf("    -1, --once          stop after one client\n");
    printf("    -v, --verbose       increase verbosity\n");
    printf("    -h, --help          Show this help message\n");
}


static void print_config(void)
{
    printf("Running %s with the following configuration:\n", arg_progname);
    printf("  Listen port   : %d\n", arg_lport);
    printf("  Msgsize       : %lu\n", arg_msgsize);
    printf("  Verify results: %s\n", arg_verify ? "yes" : "no");
    printf("  Run once      : %s\n", arg_run_once ? "yes" : "no");
    printf("  Verbose mode  : %s\n", arg_verbose ? "yes" : "no");
    printf("  Server        : %s\n", arg_server);
}


static void parse_opt(int argc, char **argv)
{
    int c;

    arg_progname = argv[0];

    while (1) {
        static struct option long_options[] = {
            {"client", no_argument, &arg_client, 'c'},
            {"help", no_argument, &arg_help, 1},
            {"listen", required_argument, NULL, 'l'},
            {"msgsize", required_argument, NULL, 'n'},
            {"once", no_argument, &arg_run_once, '1'},
            {"verbose", no_argument, &arg_verbose, 1},
            {"verify", no_argument, &arg_verify, 'V'},
            {0, 0, 0, 0}};

        int option_index = 0;
        c = getopt_long(argc, argv, "chl:m:n:1vV", long_options, &option_index);
        if (c == -1) { break; }

        switch (c) {
        case 0: break;
        case 'c': arg_client = 1; break;
        case 'l': arg_lport = atoi(optarg); break;
        case 'n': arg_msgsize = atol(optarg); break;
        case 'V': arg_verify = 1; break;
        case '1': arg_run_once = 1; break;
        case 'v': arg_verbose = 1; break;
        case 'h':
        default: print_usage(); exit(EXIT_FAILURE);
        }
    }

    if (arg_help) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* determine the server */
    if (optind < argc) { arg_server = argv[optind++]; }

    /* remaining arguments are ignored */
    if (optind < argc) {
        fprintf(stderr, "WARNING: Ignoring the remaining arguments: ");
        while (optind < argc) { fprintf(stderr, "%s ", argv[optind++]); }
        fprintf(stderr, "\n");
    }

    if (arg_verbose) { print_config(); }
}


#define PSCALL(func)                                                           \
    do {                                                                       \
        pscom_err_t rc;                                                        \
        rc = (func);                                                           \
        if (rc != PSCOM_SUCCESS) {                                             \
            printf(#func ": %s \n", pscom_err_str(rc));                        \
        }                                                                      \
    } while (0)


void pscom_origin_cb(pscom_request_t *req)
{
    Request_user_rma_t *rma_user = &req->user->type.cbdata_rma;
    *rma_user->local_complete += 1;
    pscom_request_free(req);
}


void pscom_put_target_cb(pscom_request_t *req)
{
    Xheader_rma_sync_t *xheader_rma = &req->xheader.rma_put.user;
    int *complete_op_count          = (int *)xheader_rma->remote_sync;
    *complete_op_count += 1;
}

void pscom_send_rma_ctrl(int tag, pscom_connection_t *con, int msgtype,
                         int issued_count, void **remote_sync)
{
    XHeader_rma_ctrl_t xhead; /* use the largest structure */
    xhead.common.tag  = tag;
    xhead.common.type = msgtype;

    if (msgtype == MSGTYPE_RMA_FLUSH_REQUEST) {
        xhead.issued_rma_counter = issued_count;
        xhead.remote_sync        = *remote_sync;
        pscom_send(con, &xhead, sizeof(XHeader_rma_ctrl_t), NULL, 0);
    } else {
        printf("invalid msg for SendRmaCtrl!\n");
    }
}

static int pscom_accept_rma_ctrl(pscom_request_t *req,
                                 pscom_connection_t *connection,
                                 pscom_header_net_t *header_net)
{
    XHeader_t *xhead     = &req->xheader.user.common;
    XHeader_t *xhead_net = &header_net->xheader->user.common;

    return ((header_net->xheader_len == sizeof(XHeader_rma_ctrl_t)) &&
            (xhead->type == xhead_net->type) && (xhead->tag == xhead_net->tag));
}

void pscom_recv_rma_ctrl(int tag, pscom_connection_t *con, int msgtype)
{
    pscom_request_t *req = PSCOM_REQUEST_CREATE();

    XHeader_rma_ctrl_t *xhead = &req->xheader.user.rma_ctrl;

    /* prepare the xheader */
    xhead->common.tag  = tag;
    xhead->common.type = msgtype;

    /* prepare the pscom request */
    req->data       = NULL;
    req->data_len   = 0;
    req->connection = con;

    req->xheader_len     = sizeof(XHeader_rma_ctrl_t);
    req->ops.recv_accept = pscom_accept_rma_ctrl;

    pscom_post_recv(req);
    pscom_wait(req);

    pscom_request_free(req);
}

void do_recv_rma_flush_req(pscom_request_t *req)
{
    /* This is an pscom callback. Global lock state undefined! */
    XHeader_rma_ctrl_t *xhead_ctrl = &req->xheader.user.rma_ctrl;

    /* get ops number from source*/
    int *complete_op_count = (int *)xhead_ctrl->remote_sync;
    while (*complete_op_count != xhead_ctrl->issued_rma_counter) {
        pscom_wait_any();
    }

    /* reuse original header, but overwrite type and xheader_len: */
    xhead_ctrl->common.type = MSGTYPE_RMA_FLUSH_ANSWER;
    req->xheader_len        = sizeof(XHeader_rma_ctrl_t);
    req->ops.io_done        = pscom_request_free;

    pscom_post_send(req);
}

static pscom_request_t *do_recv_forward_to(void (*io_done)(pscom_request_t *req),
                                           pscom_header_net_t *header_net)
{
    pscom_request_t *req = PSCOM_REQUEST_CREATE();

    assert(header_net->xheader_len <= sizeof(req->xheader));

    req->xheader_len = header_net->xheader_len;
    req->ops.io_done = io_done;

    return req;
}


static pscom_request_t *pscom_receive_dispatch(pscom_connection_t *connection,
                                               pscom_header_net_t *header_net)
{
    XHeader_t *xhead = &header_net->xheader->user.common;

    if (xhead->type == MSGTYPE_USER) {
        /* fastpath */
        return NULL;
    }

    switch (xhead->type) {
    case MSGTYPE_RMA_FLUSH_REQUEST:
        return do_recv_forward_to(do_recv_rma_flush_req, header_net);
    default: return NULL;
    }
}


static void run_rma_server(pscom_connection_t *con)
{
    /* init memory region */
    char *buf = malloc(arg_msgsize);
    memset(buf, 0, sizeof(arg_msgsize));

    pscom_socket_t *socket   = con->socket;
    socket->ops.default_recv = pscom_receive_dispatch;

    /* sync counter */
    int complete_op_count = 0;

    void *rkeybuf  = NULL;
    size_t bufsize = 0;
    pscom_memh_t memh;
    pscom_err_t errcode;

    /* register memory region */
    errcode = pscom_mem_register(socket, (void *)buf, arg_msgsize, &memh);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "memory region registration failed in at least one plugin. "
                "errno: %s\n",
                pscom_err_str(errcode));
    }
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "no memory region is registered due to invalid socket, "
                        "or invalid address and length.\n");
    }

    errcode = pscom_rkey_buffer_pack((void **)&rkeybuf, &bufsize, memh);
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "no valid memory region handle is provided and remote "
                        "buffer is not packed and returned as NULL.\n");
    }

    pscom_register_rma_callbacks(pscom_put_target_cb, memh, PSCOM_RMA_PUT);
    pscom_register_rma_callbacks(NULL, memh, PSCOM_RMA_GET);

    /* pass rkeybuf via send/recv to the peer for getting access to this memory
     * region */
    pscom_request_t *sreq = pscom_request_create(0, 0);
    /* inform the peer of the size of rkeybuf */
    pscom_req_prepare(sreq, con, (void *)&bufsize, sizeof(size_t), NULL, 0);
    pscom_post_send(sreq);
    pscom_wait(sreq);

    /* send the rkeybuf to the peer */
    if (bufsize != 0) {
        pscom_req_prepare(sreq, con, rkeybuf, bufsize, NULL, 0);
        pscom_post_send(sreq);
        pscom_wait(sreq);
    }

    /* memory segment information and synchronization data */
    mem_data_t mem_seg  = {0, 0, 0};
    mem_seg.addr        = buf;
    mem_seg.len         = arg_msgsize;
    mem_seg.remote_sync = (void *)&complete_op_count;

    /* pass mem_seg info via send/recv to the peer for getting access to this
     * memory region */
    pscom_req_prepare(sreq, con, (void *)&mem_seg, sizeof(mem_data_t), NULL, 0);
    pscom_post_send(sreq);
    pscom_wait(sreq);

    /* wait for end label by receiving an end label from the origin */
    int label             = 0;
    pscom_request_t *rreq = pscom_request_create(0, 0);
    pscom_req_prepare(rreq, con, (void *)&label, sizeof(int), NULL, 0);
    pscom_post_recv(rreq);
    pscom_wait(rreq);
    assert(label);

    /* server side does nothing for the rma get */
    int errs = 0;
    if (arg_verify) {
        size_t idx;
        for (idx = 0; idx < mem_seg.len; idx++) {
            if (buf[idx] != (char)idx % 127) {
                fprintf(stderr,
                        "pscom_post_rma_put() got corrupted data at idx "
                        "%zu (%d vs. %d) for a message size of %zu\n",
                        idx, buf[idx], (char)idx, mem_seg.len);
                errs++;
                break;
            }
        }
    }

    /* release all the buffers and objects */
    pscom_request_free(sreq);
    pscom_request_free(rreq);

    if (arg_verbose) {
        if (errs) {
            printf("pscom_post_rma_put() got %d errors!\n", errs);
        } else {
            printf("pscom_post_rma_put() got no errors!\n");
        }
    }


    free(buf);
    pscom_rkey_buffer_release(rkeybuf);
    errcode = pscom_mem_deregister(memh);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "memory region deregistration failed in at least one plugin. "
                "errno: %s\n",
                pscom_err_str(errcode));
    }


    printf("server side: RMA test with synchronization via control messages "
           "passed!\n");
}


static void do_rma_client(pscom_connection_t *con)
{
    int issued_op_count = 0;
    int local_complete  = 0;
    void *rkeybuf       = NULL;
    size_t bufsize      = 0;
    pscom_err_t errcode;

    pscom_socket_t *socket   = con->socket;
    socket->ops.default_recv = pscom_receive_dispatch;

    /* receive rkeybuf size */
    pscom_request_t *rreq = pscom_request_create(0, 0);
    pscom_req_prepare(rreq, con, (void *)&bufsize, sizeof(size_t), NULL, 0);
    pscom_post_recv(rreq);
    pscom_wait(rreq);

    /* receive rkeybuf */
    if (bufsize > 0) {
        rkeybuf = malloc(bufsize);
        pscom_req_prepare(rreq, con, rkeybuf, bufsize, NULL, 0);
        pscom_post_recv(rreq);
        pscom_wait(rreq);
    }

    /* generate rkey locally using rkeybuf from the peer */
    pscom_rkey_t rkey;
    errcode = pscom_rkey_generate(con, rkeybuf, bufsize, &rkey);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "remote key generation failed in the plugin. errno: %s\n",
                pscom_err_str(errcode));
    }
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "remote key is not generated due to invalid remote key "
                        "buffer.\n");
    }

    /* receive mem information */
    mem_data_t *mem_info = (mem_data_t *)malloc(sizeof(mem_data_t));
    pscom_req_prepare(rreq, con, (void *)mem_info, sizeof(mem_data_t), NULL, 0);
    pscom_post_recv(rreq);
    pscom_wait(rreq);

    /* allocate buf for RMA communication */
    size_t msgsize = mem_info->len;
    char *getbuf   = malloc(msgsize);
    char *putbuf   = malloc(msgsize);
    for (size_t idx = 0; idx < msgsize; idx++) {
        putbuf[idx] = (char)idx % 127;
    }
    memset(getbuf, 0, sizeof(msgsize));


    int errs = 0;

    /* use pscom_rma_put() to transfer data to the exposed memory region */
    pscom_request_t *putreq = pscom_request_create(sizeof(
                                                       pscom_xheader_rma_put_t),
                                                   sizeof(Request_user_rma_t));

    /* essential data required by pscom */
    putreq->rma.origin_addr = putbuf;
    putreq->rma.target_addr = mem_info->addr;
    putreq->rma.rkey        = rkey;
    putreq->data_len        = msgsize;
    putreq->connection      = con;
    putreq->ops.io_done     = pscom_origin_cb;

    /* data defined by user and sent to the target side */
    putreq->xheader.rma_put.user.remote_sync = mem_info->remote_sync;

    /* information returned back to the callback at origin side when request is
     * finished */
    Request_user_rma_t *rma_user = &putreq->user->type.cbdata_rma;
    rma_user->local_complete     = &local_complete;

    /* post put request via pscom RMA API */
    pscom_post_rma_put(putreq);
    issued_op_count++;

    /* local completion */
    while (local_complete != issued_op_count) { pscom_wait_any(); }

    /* sync of remote completion */
    pscom_send_rma_ctrl(0, con, MSGTYPE_RMA_FLUSH_REQUEST, issued_op_count,
                        &mem_info->remote_sync);
    pscom_recv_rma_ctrl(0, con, MSGTYPE_RMA_FLUSH_ANSWER);

    //----------------------------------------------------------------------

    /* use pscom_rma_get() to fetch data from the exposed memory region */
    pscom_request_t *getreq = pscom_request_create(sizeof(
                                                       pscom_xheader_rma_get_t),
                                                   sizeof(Request_user_rma_t));
    /* essential data required by pscom */
    getreq->rma.origin_addr = getbuf;
    getreq->rma.target_addr = mem_info->addr;
    getreq->rma.rkey        = rkey;
    getreq->data_len        = msgsize;
    getreq->connection      = con;
    getreq->ops.io_done     = pscom_origin_cb;

    /* data defined by user and sent to the target side */
    getreq->xheader.rma_get.user.remote_sync = mem_info->remote_sync;

    /* information returned back to the callback at origin side when request is
     * finished */
    rma_user                 = &getreq->user->type.cbdata_rma;
    rma_user->local_complete = &local_complete;

    /* post get request via pscom RMA API */
    pscom_post_rma_get(getreq);
    issued_op_count++;

    /* local completion = remote completion with rma get*/
    while (local_complete != issued_op_count) { pscom_wait_any(); }

    if (arg_verify) {
        size_t idx;
        for (idx = 0; idx < msgsize; idx++) {
            if (getbuf[idx] != (char)idx % 127) {
                fprintf(stderr,
                        "pscom_post_rma_get() got corrupted data at idx "
                        "%zu (%d vs. %d) for a message size of %zu\n",
                        idx, getbuf[idx], (char)idx, msgsize);
                errs++;
                break;
            }
        }
    }

    /* sync by sending an end label to target */
    pscom_request_t *sreq = pscom_request_create(0, 0);
    int label             = 1;
    pscom_req_prepare(sreq, con, (void *)&label, sizeof(int), NULL, 0);
    pscom_post_send(sreq);
    pscom_wait(sreq);

    if (arg_verbose) {
        if (errs) {
            printf("pscom_post_rma_get() got %d errors!\n", errs);
        } else {
            printf("pscom_post_rma_get() got no errors!\n");
        }
    }

    /* release all the buffers and objects */
    pscom_request_free(sreq);
    pscom_request_free(rreq);
    free(getbuf);
    free(mem_info);
    free(putbuf);
    errcode = pscom_rkey_destroy(rkey);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr, "remote key destroy failed in the plugin. errno: %s\n",
                pscom_err_str(errcode));
    }


    printf("client side: RMA test with synchronization via control messages "
           "passed!\n");
}


static void do_accept(pscom_connection_t *con)
{
    printf("New connection from %s via %s\n",
           pscom_con_info_str(&con->remote_con_info),
           pscom_con_type_str(con->type));
}


int main(int argc, char **argv)
{
    pscom_socket_t *socket;
    pscom_connection_t *con;
    pscom_err_t rc;

    parse_opt(argc, argv);

    rc = pscom_init(PSCOM_VERSION);
    assert(rc == PSCOM_SUCCESS);

    socket = pscom_open_socket(0, 0);

    if (!arg_client) { // server
        socket->ops.con_accept = do_accept;
        do {
            PSCALL(pscom_listen(socket, arg_lport));

            printf("Waiting for client.\nCall client with:\n");
            printf("%s -c %s", argv[0], pscom_listen_socket_str(socket));
            if (arg_msgsize != MSIZE_DEFAULT) {
                printf(" -n %ld\n", arg_msgsize);
            } else {
                printf("\n");
            }
            fflush(stdout);

            while (1) {
                con = pscom_get_next_connection(socket, NULL);
                if (con) {
                    break;
                } else {
                    pscom_wait_any();
                }
            }
            pscom_stop_listen(socket);

            run_rma_server(con);
            pscom_close_connection(con);

            if (arg_run_once) { pscom_close_socket(socket); }
            if (arg_verbose) { pscom_dump_info(stdout); }
        } while (!arg_run_once);
    } else {
        con = pscom_open_connection(socket);
        assert(con);

        PSCALL(pscom_connect_socket_str(con, arg_server));

        do_rma_client(con);
        pscom_close_connection(con);
        pscom_close_socket(socket);
        if (arg_verbose) { pscom_dump_info(stdout); }
    }

    return 0;
}
