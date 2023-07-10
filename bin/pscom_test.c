/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <popt.h>
#include <assert.h>

#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BROWN   "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define NORM    "\033[39m"

enum msg_type { MSG_TYPE_REQUEST_TEST = 1, MSG_TYPE_MSG_ORDERING = 2 };

struct xheader {
    enum msg_type type;
    int tag;
};


enum test_type { MSG_ORDERING = 1, EXIT };

struct data_request_test {
    enum test_type test_type;
};

struct data_msg_ordering {
    int tag;
    int index;
    char data[0];
    long magic;
};


struct PSCOM_req_user {
    union {
        struct data_request_test request_test;
        struct data_msg_ordering msg_ordering;
    } req;
};

#define PSCOM_XHEADER_USER_TYPE struct xheader

#include "pscom.h"

const char *arg_server_str = "localhost:5006";

static const int guard = 0x4434312;

#define ARG_SERVER 0x0001
#define ARG_CLIENT 0x0002
int arg_type = 0;

int arg_listenport = 5006;
int arg_verbose    = 0;

void parse_opt(int argc, char **argv)
{
    int c;
    poptContext optCon;
    const char *no_arg;

    struct poptOption optionsTable[] = {
        {"server", 's', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_type, ARG_SERVER,
         "run as server", NULL},

        {"listen", 'l', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
         &arg_listenport, 'l', "listen on port", "port"},

        {"client", 'c', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_type, ARG_CLIENT,
         "run as client", NULL},

        {"verbose", 'v', POPT_ARG_NONE, NULL, 'v', "increase verbosity", NULL},
        POPT_AUTOHELP POPT_TABLEEND};

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);

    poptSetOtherOptionHelp(optCon, "[server]");

    while ((c = poptGetNextOpt(optCon)) >= 0) {
        switch (c) { // c = poptOption.val;
        case 'v': arg_verbose++; break;
        case 'l':
            arg_type |= ARG_SERVER;
            break;
            // default: fprintf(stderr, "unhandled popt value %d\n", c); break;
        }
    }

    if (c < -1) { /* an error occurred during option processing */
        fprintf(stderr, "%s: %s\n",
                poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    {
        const char *s;
        s = poptGetArg(optCon);
        if (s) {
            arg_type |= ARG_CLIENT;
            arg_server_str = s;
        }
    }

    no_arg = poptGetArg(optCon); // should return NULL
    if (no_arg) {
        fprintf(stderr, "%s: %s\n", no_arg, poptStrerror(POPT_ERROR_BADOPT));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    poptFreeContext(optCon);
}


pscom_socket_t *sock;
pscom_connection_t *connection = NULL;
const char *progname;

void abort_on_error(const char *msg, pscom_err_t error)
{
    fprintf(stderr, "%s : %s\n", msg, pscom_err_str(error));
    exit(1);
}


static void init_common(void)
{
    pscom_init(PSCOM_VERSION);
    sock = pscom_open_socket(0, 0);
    if (!sock) {
        abort_on_error("pscom_open_socket() failed", PSCOM_ERR_STDERROR);
    }
}


void connection_accept_server(pscom_connection_t *new_connection)
{
    if (!connection) {
        printf("New connection from %s via %s\n",
               pscom_con_info_str(&new_connection->remote_con_info),
               pscom_con_type_str(new_connection->type));
        connection = new_connection;
    } else {
        printf("New connection from %s via %s closing!\n",
               pscom_con_info_str(&new_connection->remote_con_info),
               pscom_con_type_str(new_connection->type));
        pscom_close_connection(new_connection);
    }
}


void conn_error_server(pscom_connection_t *connection, pscom_op_t operation,
                       pscom_err_t error)
{
    printf("Error on connection from %s via %s : %s : %s\n",
           pscom_con_info_str(&connection->remote_con_info),
           pscom_con_type_str(connection->type), pscom_op_str(operation),
           pscom_err_str(error));
}


struct PSCOM_socket_ops socket_ops_server = {
    .con_accept   = connection_accept_server,
    .con_error    = conn_error_server,
    .default_recv = NULL, // default_recv_server
};


static void io_done_default(pscom_request_t *req)
{
    printf("Request %p state %s io_done (xhlen:%3lu, dlen:%4lu)\n", req,
           pscom_req_state_str(req->state), req->xheader_len, req->data_len);
}


int recv_accept_request_test(pscom_request_t *req, pscom_connection_t *con,
                             pscom_header_net_t *header)
{
    return header->xheader->user.type == MSG_TYPE_REQUEST_TEST;
}

void request_test(pscom_connection_t *con, int test)
{
    pscom_request_t *req = PSCOM_REQUEST_CREATE();

    req->xheader_len = sizeof(struct xheader);
    req->data_len    = sizeof(req->user->req.request_test);
    req->data        = &req->user->req.request_test;

    req->connection  = con;
    req->ops.io_done = io_done_default;

    req->xheader.user.type                = MSG_TYPE_REQUEST_TEST;
    req->user->req.request_test.test_type = test;

    pscom_post_send(req);
    pscom_wait(req);
    assert(pscom_req_successful(req));

    pscom_request_free(req);
}


int get_test(pscom_connection_t *con)
{
    pscom_request_t *req = PSCOM_REQUEST_CREATE();
    int res;

    req->xheader_len = sizeof(struct xheader);
    req->data_len    = sizeof(req->user->req.request_test);
    req->data        = &req->user->req.request_test;

    req->connection      = con;
    req->ops.recv_accept = recv_accept_request_test;
    req->ops.io_done     = io_done_default;

    pscom_post_recv(req);
    pscom_wait(req);

    if (pscom_req_successful(req)) {
        res = req->user->req.request_test.test_type;
    } else {
        res = EXIT;
    }

    pscom_request_free(req);

    return res;
}


static int msg_ordering_jobs = 0;

static void io_done_msg_ordering(pscom_request_t *req)
{
    printf("### Request %p state %s io_done_msg_ordering (hlen:%3lu, "
           "dlen:%4lu) recv_tag %d expect_tag %d idx %d\n",
           req, pscom_req_state_str(req->state), req->xheader_len,
           req->data_len, req->xheader.user.tag,
           req->user->req.msg_ordering.tag, req->user->req.msg_ordering.index);
    printf("Header: %s\n",
           pscom_dumpstr(&req->header, req->xheader_len + sizeof(req->header)));
    printf("Data:   %s\n",
           pscom_dumpstr(req->data, pscom_min(32, req->data_len)));

    // tag ok?
    assert((req->xheader.user.tag == req->user->req.msg_ordering.tag) ||
           !pscom_req_successful(req));
    // guard ok?
    int *guard_sent = (void *)((uint64_t)&req->user->req.msg_ordering.data +
                               req->data_len);
    assert(memcmp(guard_sent, &guard, sizeof(guard)) == 0);

    pscom_request_free(req);
    msg_ordering_jobs--;
}


int recv_accept_msg_ordering(pscom_request_t *req, pscom_connection_t *con,
                             pscom_header_net_t *header)
{
    return header->xheader->user.tag == req->user->req.msg_ordering.tag;
}

static void server_msg_ordering(pscom_connection_t *con)
{
    struct {
        pscom_connection_t *con;
        int tag;
        int data_len;
    } n[] = {{con, 6, 100}, {con, 5, 100}, {con, 4, 100}, {NULL, 3, 100},
             {con, 2, 100}, {con, 1, 100}, {NULL, 0, 0}};
    int i;

    for (i = 0; n[i].tag; i++) {
        pscom_request_t *req = pscom_request_create(
            sizeof(req->xheader),
            sizeof(req->user->req.msg_ordering) + n[i].data_len);

        req->xheader_len = sizeof(req->xheader);
        req->data_len    = n[i].data_len;
        req->data        = &req->user->req.msg_ordering.data;

        req->user->req.msg_ordering.tag   = n[i].tag;
        req->user->req.msg_ordering.index = i;
        void *data_ptr = (void *)((uint64_t)&req->user->req.msg_ordering.data +
                                  n[i].data_len);
        memcpy(data_ptr, &guard, sizeof(guard));

        req->connection      = n[i].con;
        req->socket          = con->socket;
        req->ops.recv_accept = recv_accept_msg_ordering;
        req->ops.io_done     = io_done_msg_ordering;

        pscom_post_recv(req);
        msg_ordering_jobs++;
    }

    while (msg_ordering_jobs) { pscom_wait_any(); }
    printf(GREEN "All jobs done\n" NORM);
}


static void client_msg_ordering(pscom_connection_t *con)
{
    struct {
        int tag;
        int data_len;
    } n[] = {{1, 100}, {2, 100}, {3, 10}, {4, 100}, {5, 100}, {6, 100}, {0, 0}};
    int i;

    for (i = 0; n[i].tag; i++) {
        unsigned int j;
        pscom_request_t *req = pscom_request_create(
            sizeof(req->xheader),
            sizeof(req->user->req.msg_ordering) + n[i].data_len);

        req->xheader_len                  = sizeof(req->xheader);
        req->data_len                     = n[i].data_len;
        req->data                         = &req->user->req.msg_ordering.data;
        req->xheader.user.type            = MSG_TYPE_MSG_ORDERING;
        req->xheader.user.tag             = n[i].tag;
        req->user->req.msg_ordering.tag   = n[i].tag;
        req->user->req.msg_ordering.index = i;
        void *data_ptr = (void *)((uint64_t)&req->user->req.msg_ordering.data +
                                  n[i].data_len);
        memcpy(data_ptr, &guard, sizeof(guard));

        req->connection = con;

        req->ops.recv_accept = recv_accept_msg_ordering;
        req->ops.io_done     = io_done_msg_ordering;

        for (j = 0; j < req->data_len; j++) {
            ((char *)req->data)[j] = (char)j;
        }
        pscom_post_send(req);
        msg_ordering_jobs++;
    }

    while (msg_ordering_jobs) {
        printf("Jobs %d\n", msg_ordering_jobs);
        pscom_wait_any();
        printf("Jobs %d\n", msg_ordering_jobs);
    }
}


int running = 1;

static void run_server(void)
{
    int rc;
    init_common();

    sock->ops = socket_ops_server;

    rc = pscom_listen(sock, arg_listenport);
    if (rc) { abort_on_error("pscom_listen() failed", rc); }

    if (0) {
        pscom_connection_t *con = pscom_open_connection(sock);
        if (!con) {
            abort_on_error("pscom_open_connection()", PSCOM_ERR_STDERROR);
        }

        pscom_err_t rc = pscom_connect(con, -1, -1);
        if (rc) { abort_on_error("pscom_connect_socket_str()", rc); }

        pscom_close_connection(con);
    }

    printf("Start client with:\n");
    printf("%s -c %s\n", progname, pscom_listen_socket_str(sock));

    running = 1;
    while (running) {
        pscom_connection_t *con;
        while (!connection) { pscom_wait_any(); }

        con = connection;

        while (connection) {
            enum test_type type;
            type = get_test(con);
            switch (type) {
            case MSG_ORDERING:
                printf("MSG_ORDERING\n");

                server_msg_ordering(con);
                break;
            case EXIT:
                printf("EXIT\n");
                pscom_close_connection(con);
                connection = NULL;
                running    = 0;
                break;
            default: printf("Unknown test %d requested\n", type);
            }
        }
    }
}


static void run_client(void)
{
    init_common();

    printf("Connect server on %s\n", arg_server_str);
    pscom_connection_t *con = pscom_open_connection(sock);
    if (!con) { abort_on_error("pscom_open_connection()", PSCOM_ERR_STDERROR); }

    pscom_err_t rc = pscom_connect_socket_str(con, arg_server_str);
    if (rc) { abort_on_error("pscom_connect_socket_str()", rc); }

    printf("Connected!\n");


    request_test(con, MSG_ORDERING);
    client_msg_ordering(con);

    printf("sleep(5)\n");
    sleep(5);
    pscom_close_connection(con);
    printf("Connection closed!\n");
    printf("sleep(5)\n");
    sleep(5);
    pscom_close_socket(sock);

    //	running = 1;
    //	while (running) {
    //		pscom_wait_any();
    //	}
}


int main(int argc, char **argv)
{
    progname = strdup(argc && argv[0] ? argv[0] : "< ??? >");
    parse_opt(argc, argv);

    pscom_set_debug(arg_verbose);

    switch (arg_type) {
    case ARG_SERVER: run_server(); break;
    case ARG_CLIENT: run_client(); break;

    case 0:
    default: {
        if (arg_verbose) { fprintf(stderr, "run as server AND client.\n"); }
        if (fork()) {
            run_server();
        } else {
            run_client();
        }
    }
    }

    return 0;
}
