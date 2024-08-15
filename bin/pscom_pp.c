/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_pp.c: PingPong over pscom
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pscom.h"

#define MINSIZE_OPT 1000
#define MAXSIZE_OPT 1001
#define XHEADER_OPT 1002
#define VALLOC_OPT  1003

const char *arg_server = "localhost:7100";
int arg_client         = 0;
int arg_lport          = 7100;

unsigned arg_loops   = 1024;
unsigned arg_maxtime = 3000;
#define MAX_XHEADER 100
unsigned arg_xheader       = 12;
unsigned long arg_maxmsize = 4 * 1024 * 1024;
unsigned long arg_minmsize = 0;
int arg_run_once           = 0;
int arg_verbose            = 0;
int arg_histo              = 0;
int arg_valloc             = 0;
int arg_verify             = 0;
int arg_help               = 0;
char *arg_progname         = NULL;


static void print_usage(void)
{
    printf("USAGE:\n");
    printf("    %s [OPTIONS]\n\n", arg_progname);
    printf("OPTIONS:\n");
    printf("    -l, --listen        run as server and listen on port (default: "
           "%d)\n",
           arg_lport);
    printf("    -n, --loops=COUNT   pp loops (default: %d)\n", arg_loops);
    printf("    -t, --time=ms       max time (default: %d)\n", arg_maxtime);
    printf("        --minsize=size  minimal messagesize (default: %lu)\n",
           arg_minmsize);
    printf("        --maxsize=size  maximum messagesize (default: %lu)\n",
           arg_maxmsize);
    printf("        --xheader=size  xheader size (default: %d)\n", arg_xheader);
    printf("        --valloc        use valloc() instead of malloc for "
           "send/receive buffers\n");
    printf("    -i, --histo         Measure each ping pong\n");
    printf("    -V, --verify        verify message content\n");
    printf("    -1, --once          stop after one client\n");
    printf("    -v, --verbose       increase verbosity\n");
    printf("    -h, --help          Show this help message\n");
}


static void print_config(void)
{
    printf("Running %s with the following configuration:\n", arg_progname);
    printf("  Listen port   : %d\n", arg_lport);
    printf("  Loops         : %d\n", arg_loops);
    printf("  Time          : %d\n", arg_maxtime);
    printf("  Minsize       : %lu\n", arg_minmsize);
    printf("  Maxsize       : %lu\n", arg_maxmsize);
    printf("  Xheader size  : %d\n", arg_xheader);
    printf("  Use valloc()  : %s\n", arg_valloc ? "yes" : "no");
    printf("  Histogram     : %s\n", arg_histo ? "yes" : "no");
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
            {"histo", no_argument, &arg_histo, 'i'},
            {"listen", required_argument, NULL, 'l'},
            {"loops", required_argument, NULL, 'n'},
            {"maxsize", required_argument, NULL, MAXSIZE_OPT},
            {"minsize", required_argument, NULL, MINSIZE_OPT},
            {"once", no_argument, &arg_run_once, '1'},
            {"time", required_argument, NULL, 't'},
            {"valloc", no_argument, NULL, VALLOC_OPT},
            {"verbose", no_argument, &arg_verbose, 1},
            {"verify", no_argument, &arg_verify, 'V'},
            {"xheader", required_argument, NULL, XHEADER_OPT},
            {0, 0, 0, 0}};

        int option_index = 0;
        c = getopt_long(argc, argv, "chil:n:1t:vV", long_options, &option_index);

        if (c == -1) { break; }

        switch (c) {
        case 0: break;
        case 'c': arg_client = 1; break;
        case 'l': arg_lport = atoi(optarg); break;
        case 'n': arg_loops = atoi(optarg); break;
        case 't': arg_maxtime = atoi(optarg); break;
        case MINSIZE_OPT: arg_minmsize = atol(optarg); break;
        case MAXSIZE_OPT: arg_maxmsize = atol(optarg); break;
        case XHEADER_OPT: arg_xheader = atoi(optarg); break;
        case VALLOC_OPT: arg_valloc = 1; break;
        case 'V': arg_verify = 1; break;
        case '1': arg_run_once = 1; break;
        case 'i': arg_histo = 1; break;
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


#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#include <sys/time.h>

static inline unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000);
}


static void run_pp_server(pscom_connection_t *con)
{
    void *buf = arg_valloc ? valloc(arg_maxmsize) : malloc(arg_maxmsize);
    pscom_request_t *req;
    unsigned i;

    req = pscom_request_create(MAX_XHEADER, 0);

    for (i = 0; i < MAX_XHEADER; i++) {
        req->xheader.user[i] = (char)(i + 0xe1);
    }

    if (arg_verbose) { printf("Buffer: buf:%p\n", buf); }

    while (1) {
        pscom_req_prepare(req, con, buf, arg_maxmsize, NULL, MAX_XHEADER);
        pscom_post_recv(req);

        pscom_wait(req);

        if (!pscom_req_successful(req)) { break; }
        if (arg_verbose) {
            printf("Receive %u xheader :%s\n", req->header.xheader_len,
                   pscom_dumpstr(&req->xheader, req->header.xheader_len));

            printf("        %lu data :%s\n",
                   (unsigned long)req->header.data_len,
                   pscom_dumpstr(req->data, MIN(req->header.data_len, 64)));
        }

        req->xheader_len = req->header.xheader_len;
        req->data_len    = req->header.data_len;
        pscom_post_send(req);

        pscom_wait(req);
    }

    pscom_request_free(req);
    free(buf);
}


static int pp_loop(pscom_request_t *sreq, pscom_request_t *rreq, unsigned loops)
{
    unsigned cnt;
    for (cnt = 0; cnt < loops; cnt++) {
        pscom_post_send(sreq);

        // printf("SEND %d data :%s\n", msize,
        //       pscom_dumpstr(sbuf, MIN(msize, 16)));
        pscom_post_recv(rreq);

        pscom_wait(sreq);
        pscom_wait(rreq);
    }
    return !pscom_req_successful(rreq);
}


static int pp_loop_verify(pscom_request_t *sreq, pscom_request_t *rreq,
                          unsigned loops)
{
    unsigned cnt, i, err = 0;
    for (cnt = 0; cnt < loops; cnt++) {
        for (i = 0; i < sreq->data_len; i++) {
            ((unsigned char *)sreq->data)[i] = (unsigned char)(cnt + i);
        }
        pscom_post_send(sreq);

        // printf("SEND %d data :%s\n", msize,
        //       pscom_dumpstr(sbuf, MIN(msize, 16)));
        pscom_post_recv(rreq);

        pscom_wait(sreq);
        pscom_wait(rreq);

        if (rreq->data_len != sreq->data_len) {
            printf("Corrupted data_len in msg %u! (recv:%5lu != send:%5lu)\n",
                   cnt, rreq->data_len, sreq->data_len);
            err = 1;
        }
        for (i = 0; i < rreq->data_len; i++) {
            if (((unsigned char *)rreq->data)[i] != (unsigned char)(cnt + i)) {
                printf("Corrupted byte #%u in msg %u! (is:%3u != should:%3u)\n",
                       i, cnt, ((unsigned char *)rreq->data)[i],
                       (unsigned char)(cnt + i));
                err = 1;
            };
        }
    }
    return !pscom_req_successful(rreq) || err;
}


static int pp_loop_histo(pscom_request_t *sreq, pscom_request_t *rreq,
                         unsigned loops)
{
    unsigned cnt;
    size_t msize        = sreq->data_len;
    unsigned long *time = malloc(sizeof(*time) * loops + 1);
    for (cnt = 0; cnt < loops; cnt++) {
        time[cnt] = getusec();
        pscom_post_send(sreq);

        // printf("SEND %d data :%s\n", msize,
        //       pscom_dumpstr(sbuf, MIN(msize, 16)));
        pscom_post_recv(rreq);

        pscom_wait(rreq);
    }

    printf("Message size %7lu. Rtt/2[usec]\n", msize);
    for (cnt = 1; cnt < loops; cnt++) {
        printf("%5d %8.1f\n", cnt, (double)(time[cnt] - time[cnt - 1]) / 2.0);
    }
    fflush(stdout);
    free(time);
    return !pscom_req_successful(rreq);
}


static int run_pp_c(pscom_connection_t *con, size_t msize, unsigned xsize,
                    unsigned loops,
                    int (*pp_loop)(pscom_request_t *sreq, pscom_request_t *rreq,
                                   unsigned loops))
{
    unsigned cnt;
    void *sbuf = arg_valloc ? valloc(msize) : malloc(msize);
    void *rbuf = arg_valloc ? valloc(msize) : malloc(msize);
    int ret;
    pscom_request_t *sreq;
    pscom_request_t *rreq;

    memset(sbuf, 42, msize);
    memset(rbuf, 42, msize);

    sreq = pscom_request_create(xsize, 0);
    rreq = pscom_request_create(xsize, 0);

    if (arg_verbose) {
        printf("Buffers: sbuf:%p[%lu] rbuf:%p[%lu]\n", sbuf, msize, rbuf, msize);
        for (cnt = 0; cnt < xsize; cnt++) {
            sreq->xheader.user[cnt] = (char)(cnt + 1);
        }
    }

    pscom_req_prepare(sreq, con, sbuf, msize, NULL, xsize);
    pscom_req_prepare(rreq, con, rbuf, msize, NULL, xsize);

    ret = pp_loop(sreq, rreq, loops);

    pscom_request_free(sreq);
    pscom_request_free(rreq);
    free(sbuf);
    free(rbuf);

    return ret;
}


static void do_pp_client(pscom_connection_t *con)
{
    unsigned long t1, t2;
    double time;
    double throuput;
    size_t msgsize;
    double ms;
    int res;
    double loops = arg_loops;
    int (*pp_loop_func)(pscom_request_t *sreq, pscom_request_t *rreq,
                        unsigned loops);

    if (arg_xheader > MAX_XHEADER) { arg_xheader = MAX_XHEADER; }

    printf("Xheader : %d bytes\n", arg_xheader);
    printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
    printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
    for (ms = (double)arg_minmsize; (size_t)(ms + 0.5) <= (size_t)arg_maxmsize;
         ms = ms < 2.0 ? ms + 1 : ms * 1.4142135623730950488) {
        unsigned int iloops = (unsigned)(loops + 0.5);
        msgsize             = (size_t)(ms + 0.5);

        /* warmup, for sync */
        run_pp_c(con, 2, 2, 2, pp_loop);

        if (arg_verify) {
            pp_loop_func = pp_loop_verify;
        } else if (arg_histo) {
            pp_loop_func = pp_loop_histo;
        } else {
            pp_loop_func = pp_loop;
        }

        t1  = getusec();
        res = run_pp_c(con, msgsize, arg_xheader, iloops, pp_loop_func);
        t2  = getusec();

        time     = (double)(t2 - t1) / (iloops * 2);
        throuput = (double)msgsize / time;
        if (res == 0) {
            printf("%7lu %8u %8.2f %8.2f%s\n", msgsize, iloops, time, throuput,
                   pp_loop_func == pp_loop_verify ? " ok" : "");
            fflush(stdout);
        } else {
            printf("%7lu Error in communication...\n", msgsize);
        }

        {
            double t = (double)(t2 - t1) / 1000;
            while (t > arg_maxtime) {
                loops = loops / 1.4142135;
                t /= 1.4142135;
            }
            if (loops < 1) { loops = 1; }
        }
    }

    return;
}


static void do_accept(pscom_connection_t *con)
{
    printf("New connection from %s via %s\n",
           pscom_con_info_str(&con->remote_con_info),
           pscom_con_type_str(con->type));
}

#define PSCALL(func)                                                           \
    do {                                                                       \
        pscom_err_t rc;                                                        \
        rc = (func);                                                           \
        if (rc != PSCOM_SUCCESS) {                                             \
            printf(#func ": %s\n", pscom_err_str(rc));                         \
            exit(1);                                                           \
        }                                                                      \
    } while (0)


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
            printf("%s -c %s\n", argv[0], pscom_listen_socket_str(socket));
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

            run_pp_server(con);
            pscom_close_connection(con);

            if (arg_run_once) { pscom_close_socket(socket); }
            if (arg_verbose) { pscom_dump_info(stdout); }
        } while (!arg_run_once);
    } else {
        con = pscom_open_connection(socket);
        assert(con);

        PSCALL(pscom_connect_socket_str(con, arg_server));

        do_pp_client(con);
        pscom_close_connection(con);
        pscom_close_socket(socket);
        if (arg_verbose) { pscom_dump_info(stdout); }
    }

    return 0;
}
