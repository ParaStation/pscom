/*
 * ParaStation
 *
 * Copyright (C) 2023-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_rma_get.c: RMA over pscom
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pscom.h"


#define MAXMSIZE_DEFAULT (4 * 1024 * 1024)
#define MINMSIZE_DEFAULT 0

const char *arg_server     = "localhost:7100";
int arg_client             = 0;
int arg_lport              = 7100;
unsigned long arg_maxmsize = MAXMSIZE_DEFAULT;
unsigned long arg_minmsize = MINMSIZE_DEFAULT;
int arg_run_once           = 0;
int arg_verbose            = 0;
int arg_help               = 0;
int arg_verify             = 0;
char *arg_progname         = NULL;


typedef struct {
    void *addr;
    size_t len;
} mem_data_t;


static void print_usage(void)
{
    printf("USAGE:\n");
    printf("    %s [OPTIONS]\n\n", arg_progname);
    printf("OPTIONS:\n");
    printf("    -l, --listen        run as server and listen on port (default: "
           "%d)\n",
           arg_lport);
    printf("    -m, --minsize=size  minimal messagesize (default: %lu)\n",
           arg_minmsize);
    printf("    -n, --maxsize=size  maximum messagesize (default: %lu)\n",
           arg_maxmsize);
    printf("    -V, --verify        verify message content\n");
    printf("    -1, --once          stop after one client\n");
    printf("    -v, --verbose       increase verbosity\n");
    printf("    -h, --help          Show this help message\n");
}


static void print_config(void)
{
    printf("Running %s with the following configuration:\n", arg_progname);
    printf("  Listen port   : %d\n", arg_lport);
    printf("  Minsize       : %lu\n", arg_minmsize);
    printf("  Maxsize       : %lu\n", arg_maxmsize);
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
            {"minsize", required_argument, NULL, 'm'},
            {"maxsize", required_argument, NULL, 'n'},
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
        case 'm': arg_minmsize = atol(optarg); break;
        case 'n': arg_maxmsize = atol(optarg); break;
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


static void run_rma_server(pscom_connection_t *con)
{
    pscom_socket_t *socket = con->socket;

    char *buf     = malloc(arg_maxmsize);
    size_t length = arg_maxmsize;

    size_t idx;
    for (idx = 0; idx < length; idx++) { buf[idx] = (char)idx % 127; }

    void *rkeybuf  = NULL;
    size_t bufsize = 0;
    pscom_memh_t memh;
    pscom_err_t errcode;

    /* register memory region */
    errcode = pscom_mem_register(socket, (void *)buf, length, &memh);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "memory region registration failed in at least one plugin. "
                "errno: %s\n",
                pscom_err_str(errcode));
    }
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "no memory region is registered due to invalid socket, "
                        "or "
                        "invalid address and length.\n");
    }

    errcode = pscom_rkey_buffer_pack((void **)&rkeybuf, &bufsize, memh);
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "no valid memory region handle is provided and remote "
                        "buffer is not "
                        "packed and returned as NULL.\n");
    }

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
    mem_data_t *mem_info = (mem_data_t *)malloc(sizeof(mem_data_t));
    mem_info->addr       = buf;
    mem_info->len        = length;
    pscom_req_prepare(sreq, con, (void *)mem_info, sizeof(mem_data_t), NULL, 0);
    pscom_post_send(sreq);
    pscom_wait(sreq);

    /* wait and sync by receiving an end label from the origin */
    int label             = 0;
    pscom_request_t *rreq = pscom_request_create(0, 0);
    pscom_req_prepare(rreq, con, (void *)&label, sizeof(int), NULL, 0);
    pscom_post_recv(rreq);
    pscom_wait(rreq);
    assert(label);

    /* release all the buffers and objects */
    pscom_request_free(sreq);
    pscom_request_free(rreq);
    pscom_rkey_buffer_release(rkeybuf);

    free(buf);
    free(mem_info);
    errcode = pscom_mem_deregister(memh);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "memory region deregistration failed in at least one plugin. "
                "errno: %s\n",
                pscom_err_str(errcode));
    }
    printf("server side: pscom_post_rma_get() is done for one epoch!\n");
}


static void do_rma_client(pscom_connection_t *con)
{
    void *rkeybuf  = NULL;
    size_t bufsize = 0;
    pscom_err_t errcode;

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

    /* receive mem information */
    mem_data_t *mem_info = (mem_data_t *)malloc(sizeof(mem_data_t));
    pscom_req_prepare(rreq, con, (void *)mem_info, sizeof(mem_data_t), NULL, 0);
    pscom_post_recv(rreq);
    pscom_wait(rreq);

    /* allocate buf for RMA communication */
    char *buf = malloc(mem_info->len);

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

    size_t msgsize;
    double ms;
    int correct = 1;
    int errs    = 0;
    for (ms = (double)arg_minmsize; (size_t)(ms + 0.5) <= (size_t)arg_maxmsize;
         ms = ms < 2.0 ? ms + 1 : ms * 1.4142135623730950488) {
        msgsize = (size_t)(ms + 0.5);

        /* use pscom_rma_get() to fetch data from the exposed memory region */
        pscom_request_t *rma_req =
            pscom_request_create(sizeof(pscom_xheader_rma_get_t), 0);

        rma_req->rma.origin_addr = buf;
        rma_req->rma.target_addr = mem_info->addr;
        rma_req->rma.rkey        = rkey;
        rma_req->connection      = con;
        rma_req->data_len        = msgsize;

        correct = arg_verify;

        pscom_post_rma_get(rma_req);
        pscom_wait(rma_req);

        if (arg_verify) {
            size_t idx;
            for (idx = 0; idx < msgsize; idx++) {
                if (buf[idx] != (char)idx % 127) {
                    fprintf(stderr,
                            "pscom_post_rma_get() got corrupted data at idx "
                            "%zu (%d vs. %d) for a message size of %zu\n",
                            idx, buf[idx], (char)idx, msgsize);
                    correct = 0;
                    errs++;
                    break;
                }
            }
        }
        if (correct && arg_verbose) {
            printf("pscom_post_rma_get() for %zu bytes successful.\n", msgsize);
        }
    }

    /* sync by sending an end label to target */
    pscom_request_t *sreq = pscom_request_create(0, 0);
    int label             = 1;
    pscom_req_prepare(sreq, con, (void *)&label, sizeof(int), NULL, 0);
    pscom_post_send(sreq);
    pscom_wait(sreq);

    if (arg_verify) {
        if (errs) {
            printf("pscom_post_rma_get() got %d errors!\n", errs);
        } else {
            printf("pscom_post_rma_get() got no errors!\n");
        }
    }

    /* release all the buffers and objects */
    pscom_request_free(rreq);
    pscom_request_free(sreq);
    free(rkeybuf);
    free(mem_info);
    free(buf);
    errcode = pscom_rkey_destroy(rkey);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr, "remote key destroy failed in the plugin. errno: %s\n",
                pscom_err_str(errcode));
    }
    printf("client side: pscom_post_rma_get() is done for one epoch!\n");
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

    socket = pscom_open_socket(0, 0, PSCOM_RANK_UNDEFINED,
                               PSCOM_SOCK_FLAG_INTRA_JOB);

    if (!arg_client) { // server
        socket->ops.con_accept = do_accept;
        do {
            PSCALL(pscom_listen(socket, arg_lport));
            char *ep_str = NULL;
            rc           = pscom_socket_get_ep_str(socket, &ep_str);
            assert(rc == PSCOM_SUCCESS);
            printf("Waiting for client.\nCall client with:\n");
            printf("%s -c %s", argv[0], ep_str);
            pscom_socket_free_ep_str(ep_str);
            if ((arg_minmsize == MINMSIZE_DEFAULT) ||
                (arg_maxmsize != MAXMSIZE_DEFAULT)) {
                printf(" -m %ld -n %ld\n", arg_minmsize, arg_maxmsize);
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
        // tcp direct connect
        PSCALL(pscom_connect(con, arg_server, PSCOM_RANK_UNDEFINED,
                             PSCOM_CON_FLAG_DIRECT));

        do_rma_client(con);
        pscom_close_connection(con);
        pscom_close_socket(socket);
        if (arg_verbose) { pscom_dump_info(stdout); }
    }

    return 0;
}
