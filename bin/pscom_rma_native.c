/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

/**
 * pscom_rma_native.c: native RMA over pscom
 * In this test, various native RMA operations are tested for implementation
 * validity. The native RMA is only supported by pscom4ucp plugin, so
 * 'PSP_UCP=2' has to be set on the client side.
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "pscom.h"


const char *arg_server = "localhost:7100";
int arg_client         = 0;
int arg_lport          = 7100;
int arg_run_once       = 0;
int arg_verbose        = 0;
int arg_help           = 0;
char *arg_progname     = NULL;

/* hardcoded data size for the test */
#define DATASIZE 5

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
    printf("    -1, --once          stop after one client\n");
    printf("    -v, --verbose       increase verbosity\n");
    printf("    -h, --help          Show this help message\n");
}


static void print_config(void)
{
    printf("Running %s with the following configuration:\n", arg_progname);
    printf("  Listen port   : %d\n", arg_lport);
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
            {"once", no_argument, &arg_run_once, '1'},
            {"verbose", no_argument, &arg_verbose, 'v'},
            {0, 0, 0, 0}};

        int option_index = 0;
        c = getopt_long(argc, argv, "chl:1v", long_options, &option_index);
        if (c == -1) { break; }

        switch (c) {
        case 0: break;
        case 'c': arg_client = 1; break;
        case 'l': arg_lport = atoi(optarg); break;
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


#define PSCALL(func, rc)                                                       \
    do {                                                                       \
        rc = (func);                                                           \
        if (rc != PSCOM_SUCCESS) {                                             \
            printf(#func ": %s \n", pscom_err_str(rc));                        \
        }                                                                      \
    } while (0)


static void run_rma_server(pscom_connection_t *con)
{
    pscom_socket_t *socket = con->socket;

    int *buf      = malloc(DATASIZE * sizeof(int));
    size_t length = DATASIZE * sizeof(int);
    memset(buf, 0, length);

    void *rkeybuf  = NULL;
    size_t bufsize = 0;
    pscom_memh_t memh;
    pscom_err_t errcode;

    /* register memory region */
    errcode = pscom_mem_register(socket, (void *)buf, length, &memh);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "Memory region registration failed in at least one plugin. "
                "errno: %s\n",
                pscom_err_str(errcode));
    }
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "No memory region is registered due to invalid socket, "
                        "or invalid address and length.\n");
    }

    errcode = pscom_rkey_buffer_pack((void **)&rkeybuf, &bufsize, memh);
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "No valid memory region handle is provided and remote "
                        "buffer is not packed and returned as NULL.\n");
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
                "Memory region deregistration failed in at least one plugin. "
                "errno: %s\n",
                pscom_err_str(errcode));
    }
    printf("Server side: pscom_post_rma_get() is done for one epoch!\n");
}


static void do_rma_client(pscom_connection_t *con)
{
    void *rkeybuf  = NULL;
    size_t bufsize = 0;
    pscom_err_t errcode;
    pscom_err_t check_rma           = 0;
    pscom_err_t check_rma_atomic_op = 0;
    /* used for synchronization by sending an end label */
    pscom_request_t *sreq           = pscom_request_create(0, 0);
    int label                       = 1;

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

    /* generate rkey locally using rkeybuf from the peer */
    pscom_rkey_t rkey;
    errcode = pscom_rkey_generate(con, rkeybuf, bufsize, &rkey);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr,
                "Remote key generation failed in the plugin. errno: %s\n",
                pscom_err_str(errcode));
        goto exit;
    }
    if (errcode == PSCOM_ERR_INVALID) {
        fprintf(stderr, "Remote key is not generated due to invalid remote key "
                        "buffer.\n");
        goto exit;
    }

    int buf[DATASIZE];
    int compare_buf[DATASIZE];
    int result_buf[DATASIZE];

    for (int i = 0; i < DATASIZE; i++) {
        buf[i]         = 99;
        compare_buf[i] = 0;
        result_buf[i]  = 0;
    }

    /* use pscom_rma_put() to send data to the exposed memory region */
    check_rma = pscom_native_rma_is_available(con, rkey, PSCOM_RMA_PUT);
    if (check_rma != PSCOM_SUCCESS) {
        fprintf(stderr, "Native rma put is not available.\n");
        goto exit;
    }

    pscom_request_t *req_put = pscom_request_create(0, 0);
    req_put->rma.origin_addr = buf;
    req_put->rma.target_addr = mem_info->addr;
    req_put->rma.rkey        = rkey;
    req_put->connection      = con;
    req_put->data_len        = DATASIZE * sizeof(int);
    req_put->ops.io_done     = pscom_request_free;

    req_put->rma.native_rma = 1;
    req_put->rma.data_type  = PSCOM_INT;

    pscom_post_rma_put(req_put);
    PSCALL(pscom_rma_connection_flush(con), errcode);

    //=====================================================================
    /* use pscom_rma_get() to fetch data from the exposed memory region */
    check_rma = pscom_native_rma_is_available(con, rkey, PSCOM_RMA_GET);
    if (check_rma != PSCOM_SUCCESS) {
        fprintf(stderr, "Native rma get is not available.\n");
        goto exit;
    }

    pscom_request_t *req_get = pscom_request_create(0, 0);

    req_get->rma.origin_addr = result_buf;
    req_get->rma.target_addr = mem_info->addr;
    req_get->rma.rkey        = rkey;
    req_get->connection      = con;
    req_get->data_len        = DATASIZE * sizeof(int);
    req_get->ops.io_done     = pscom_request_free;
    req_get->rma.native_rma  = 1;
    req_get->rma.data_type   = PSCOM_INT;

    pscom_post_rma_get(req_get);
    PSCALL(pscom_rma_connection_flush(con), errcode);

    /* check result buffer value, the value at target should be 99 */
    for (int i = 0; i < DATASIZE; i++) { assert(result_buf[i] == 99); }

    //=====================================================================
    /* use pscom_rma_acc() to add buf to the exposed memory region */
    check_rma = pscom_native_rma_is_available(con, rkey, PSCOM_RMA_ACCUMULATE);
    if (check_rma != PSCOM_SUCCESS) {
        fprintf(stderr, "Native rma acc is not available.\n");
        goto exit;
    }
    check_rma_atomic_op = pscom_native_rma_atomic_op_is_available(
        con, rkey, PSCOM_SUM, PSCOM_INT, DATASIZE * sizeof(int),
        PSCOM_RMA_ACCUMULATE);
    if (check_rma_atomic_op != PSCOM_SUCCESS) {
        fprintf(stderr, "Atomic check for native rma acc failed.\n");
        goto exit;
    }

    // set buf to 2
    for (int i = 0; i < DATASIZE; i++) { buf[i] = 2; }

    pscom_request_t *req_acc = pscom_request_create(0, 0);
    req_acc->rma.origin_addr = buf;
    req_acc->rma.target_addr = mem_info->addr;
    req_acc->rma.rkey        = rkey;
    req_acc->connection      = con;
    req_acc->data_len        = DATASIZE * sizeof(int);
    req_acc->ops.io_done     = pscom_request_free;

    req_acc->rma.native_rma    = 1;
    req_acc->rma.data_type     = PSCOM_INT;
    req_acc->rma.rma_atomic_op = PSCOM_SUM;

    pscom_post_rma_accumulate(req_acc);
    PSCALL(pscom_rma_connection_flush(con), errcode);
    /* the value at target should be 101. */

    req_get = pscom_request_create(0, 0);

    req_get->rma.origin_addr = result_buf;
    req_get->rma.target_addr = mem_info->addr;
    req_get->rma.rkey        = rkey;
    req_get->connection      = con;
    req_get->data_len        = DATASIZE * sizeof(int);
    req_get->ops.io_done     = pscom_request_free;
    req_get->rma.native_rma  = 1;
    req_get->rma.data_type   = PSCOM_INT;

    pscom_post_rma_get(req_get);
    PSCALL(pscom_rma_connection_flush(con), errcode);

    /* check result buffer value, the value at target should be 101 after acc */
    for (int i = 0; i < DATASIZE; i++) { assert(result_buf[i] == 101); }

    //=====================================================================
    /* use pscom_rma_get_acc() to fetch the data and add buf to the exposed
     * memory region */
    check_rma = pscom_native_rma_is_available(con, rkey,
                                              PSCOM_RMA_GET_ACCUMULATE);
    if (check_rma != PSCOM_SUCCESS) {
        fprintf(stderr, "Native rma get acc is not available.\n");
        goto exit;
    }
    check_rma_atomic_op = pscom_native_rma_atomic_op_is_available(
        con, rkey, PSCOM_SUM, PSCOM_INT, DATASIZE * sizeof(int),
        PSCOM_RMA_GET_ACCUMULATE);
    if (check_rma_atomic_op != PSCOM_SUCCESS) {
        fprintf(stderr, "Atomic check for native rma get acc failed.\n");
        goto exit;
    }

    /* now buf is 2 */
    pscom_request_t *req_get_acc = pscom_request_create(0, 0);
    req_get_acc->rma.origin_addr = buf;
    req_get_acc->rma.target_addr = mem_info->addr;
    req_get_acc->rma.result_addr = result_buf;
    req_get_acc->rma.rkey        = rkey;
    req_get_acc->connection      = con;
    req_get_acc->data_len        = DATASIZE * sizeof(int);
    req_get_acc->ops.io_done     = pscom_request_free;

    req_get_acc->rma.native_rma    = 1;
    req_get_acc->rma.data_type     = PSCOM_INT;
    req_get_acc->rma.rma_atomic_op = PSCOM_SUM;

    pscom_post_rma_get_accumulate(req_get_acc);
    PSCALL(pscom_rma_connection_flush(con), errcode);
    /* the value at target should be 103. */
    /* check result buffer value */
    for (int i = 0; i < DATASIZE; i++) { assert(result_buf[i] == 101); }

    //=====================================================================
    /* use pscom_rma_cas() to compare the value at target with compare_addr and
     * fetch the data from target and put value in `buf` to target buffer after
     * comparison */
    check_rma = pscom_native_rma_is_available(con, rkey,
                                              PSCOM_RMA_COMPARE_AND_SWAP);
    if (check_rma != PSCOM_SUCCESS) {
        fprintf(stderr, "Native rma cas is not available.\n");
        goto exit;
    }
    check_rma_atomic_op = pscom_native_rma_atomic_op_is_available(
        con, rkey, -1, PSCOM_INT, sizeof(int), PSCOM_RMA_COMPARE_AND_SWAP);
    if (check_rma_atomic_op != PSCOM_SUCCESS) {
        fprintf(stderr, "Atomic check for native rma cas failed.\n");
        goto exit;
    }


    buf[0]         = 88;
    compare_buf[0] = 103;

    pscom_request_t *req_cas  = pscom_request_create(0, 0);
    req_cas->rma.origin_addr  = &buf[0];
    req_cas->rma.target_addr  = mem_info->addr;
    req_cas->rma.result_addr  = &result_buf[0];
    req_cas->rma.compare_addr = &compare_buf[0];
    req_cas->rma.rkey         = rkey;
    req_cas->connection       = con;
    req_cas->data_len         = sizeof(int);
    req_cas->ops.io_done      = pscom_request_free;

    req_cas->rma.native_rma = 1;
    req_cas->rma.data_type  = PSCOM_INT;

    pscom_post_rma_compare_swap(req_cas);
    PSCALL(pscom_rma_connection_flush(con), errcode);

    /* check result buffer value, compare == target, so target value should be
     * 88 */
    assert(result_buf[0] == 103);

    //===================================================================
    /* now get the new value from target */
    req_get = pscom_request_create(0, 0);

    req_get->rma.origin_addr = &result_buf[0];
    req_get->rma.target_addr = mem_info->addr;
    req_get->rma.rkey        = rkey;
    req_get->connection      = con;
    req_get->data_len        = sizeof(int);
    req_get->ops.io_done     = pscom_request_free;
    req_get->rma.native_rma  = 1;
    req_get->rma.data_type   = PSCOM_INT;

    pscom_post_rma_get(req_get);
    PSCALL(pscom_rma_connection_flush(con), errcode);

    /* check result buffer value, the value at target should be 88 after cas */
    assert(result_buf[0] == 88);


    printf("client side: all native RMA communications are done!\n");

exit:
    //=======================================================================
    /* sync by sending an end label to target */
    pscom_req_prepare(sreq, con, (void *)&label, sizeof(int), NULL, 0);
    pscom_post_send(sreq);
    pscom_wait(sreq);
    pscom_request_free(sreq);

    /* release all the buffers and objects */
    pscom_request_free(rreq);

    free(rkeybuf);
    free(mem_info);
    errcode = pscom_rkey_destroy(rkey);
    if (errcode == PSCOM_ERR_STDERROR) {
        fprintf(stderr, "Remote key destroy failed in the plugin. errno: %s\n",
                pscom_err_str(errcode));
    }
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
            PSCALL(pscom_listen(socket, arg_lport), rc);
            char *ep_str = NULL;
            rc           = pscom_socket_get_ep_str(socket, &ep_str);
            assert(rc == PSCOM_SUCCESS);
            printf("Waiting for client.\nCall client with:\n");
            printf("%s -c %s\n", argv[0], ep_str);
            fflush(stdout);
            pscom_socket_free_ep_str(ep_str);

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
                             PSCOM_CON_FLAG_DIRECT),
               rc);

        do_rma_client(con);
        pscom_close_connection(con);
        pscom_close_socket(socket);
        if (arg_verbose) { pscom_dump_info(stdout); }
    }

    return 0;
}
