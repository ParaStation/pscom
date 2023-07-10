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
#include <math.h>
#include <popt.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "psdapl.h"

#define DEBUG_MESSAGES 0

const char *arg_server_addr = NULL;

int arg_loops   = 1024;
int arg_maxtime = 3000;
#define MAX_XHEADER 100
unsigned arg_maxmsize = 4 * 1024 * 1024;
int arg_run_once      = 0;
int arg_verbose       = 0;

static void parse_opt(int argc, char **argv)
{
    int c;
    poptContext optCon;
    const char *no_arg;

    struct poptOption optionsTable[] = {
        {"loops", 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT, &arg_loops, 0,
         "pp loops", "count"},
        {"time", 't', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT, &arg_maxtime, 0,
         "max time", "ms"},
        {"maxsize", 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT, &arg_maxmsize,
         0, "maximal messagesize", "size"},

        {"once", '1', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_run_once, 1,
         "stop after one client", NULL},

        {"verbose", 'v', POPT_ARG_NONE, NULL, 'v', "increase verbosity", NULL},
        POPT_AUTOHELP POPT_TABLEEND};

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);

    poptSetOtherOptionHelp(optCon, "[serveraddr]");

    while ((c = poptGetNextOpt(optCon)) >= 0) {
        switch (c) { // c = poptOption.val;
        case 'v':
            arg_verbose++;
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

    //	arg_1 = poptGetArg(optCon);
    //	arg_2 = poptGetArg(optCon);
    /* if (arg_client)*/ {
        const char *server = poptGetArg(optCon);
        if (server) { arg_server_addr = server; }
    }

    no_arg = poptGetArg(optCon); // should return NULL
    if (no_arg) {
        fprintf(stderr, "%s: %s\n", no_arg, poptStrerror(POPT_ERROR_BADOPT));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    poptFreeContext(optCon);
}


void pscom_env_get_str(char **val, char *name)
{
    char *aval;

    aval = getenv(name);
    if (aval) {
        *val = aval;
        if (arg_verbose) { printf("set %s = %s", name, *val); }
    } else {
        if (arg_verbose >= 2) { printf("default %s = %s", name, *val); }
    }
}


static void idle(void)
{
    //	volatile unsigned y;
    //	y++;
    //	sched_yield();
}


static int send_all(psdapl_con_info_t *ci, char *buf, unsigned count)
{
    int len;
    int c = count;

    while (c > 0) {
        struct iovec iov;
        iov.iov_base = buf;
        iov.iov_len  = c;
        len          = psdapl_sendv(ci, &iov, c);
        if (len < 0) {
            if (len == -EAGAIN) {
                idle();
                continue;
            } else {
                printf("sendv returned error: %s\n", strerror(-len));
                exit(-1);
            }
        }
        c -= len;
        buf += len;
    }

    return count;
}


static inline int psdapl_recvlook_block(psdapl_con_info_t *ci, void **buf)
{
    int len;
    while (1) {
        len = psdapl_recvlook(ci, buf);
        if (len >= 0) { return len; }

        if (len != -EAGAIN) {
            printf("receive returned an error : %s\n", strerror(-len));
            exit(1);
        }
        idle();
    }
}


int recv_all(psdapl_con_info_t *ci, char *buf)
{
    void *rbuf;
    int len;

    len = psdapl_recvlook_block(ci, &rbuf);
    if (len == 0) { /* EOF */
        return 0;
    }
    unsigned msgsize = *(unsigned *)rbuf;
    unsigned count   = msgsize;

    while (1) {
        memcpy(buf, rbuf, len);
        psdapl_recvdone(ci);
        count -= len;
        if (!count) { break; }

        buf += len;

        len = psdapl_recvlook_block(ci, &rbuf);
        if (len == 0) { /* EOF */
            return 0;
        }
    }

    return msgsize;
}


static void run_pp_server(psdapl_con_info_t *ci)
{
    char *buf = malloc(arg_maxmsize);
    int msgsize;

    while (1) {
        msgsize = recv_all(ci, buf);

        if (DEBUG_MESSAGES) {
            static int allcount = 0;
            allcount++;
            printf("received: msgsize:%u %s\n", msgsize, buf + sizeof(unsigned));
            sprintf(buf + sizeof(unsigned), "ServerRet#%d", allcount);
            printf("Send:                %s\n", buf + sizeof(unsigned));
        }

        send_all(ci, buf, msgsize);
        if (msgsize <= 0) { break; }
    }
    if (msgsize == 0) {
        printf("receive EOF\n");
    } else {
        printf("receive error : %s\n", strerror(-msgsize));
    }
}


static int run_pp_c(psdapl_con_info_t *ci, unsigned msgsize, unsigned loops)
{
    unsigned cnt;
    if (msgsize < sizeof(unsigned)) { msgsize = sizeof(unsigned); }

    char *buf          = malloc(msgsize);
    *((unsigned *)buf) = msgsize;

    for (cnt = 0; cnt < loops; cnt++) {
        if (DEBUG_MESSAGES) {
            sprintf(buf + sizeof(unsigned), "C2S#%d", cnt);
            printf("Send:     %s\n", buf + sizeof(unsigned));
        }
        send_all(ci, buf, msgsize);
        recv_all(ci, buf);

        if (DEBUG_MESSAGES) {
            printf("received: %s\n", buf + sizeof(unsigned));
        }
    }

    free(buf);
    return 0;
}


static inline unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000);
}


static void run_pp_client(psdapl_con_info_t *ci)
{
    unsigned long t1, t2;
    double time;
    double throuput;
    unsigned int msgsize;
    double ms;
    int res;
    double loops = arg_loops;

    printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
    printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
    for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
        unsigned int iloops = loops;
        msgsize             = ms + 0.5;

        /* warmup, for sync */
        run_pp_c(ci, 20, 5);

        t1  = getusec();
        res = run_pp_c(ci, msgsize, iloops);
        t2  = getusec();

        time     = (double)(t2 - t1) / (iloops * 2);
        throuput = msgsize / time;
        if (res == 0) {
            printf("%7d %8d %8.2f %8.2f\n", msgsize, iloops, time, throuput);
            fflush(stdout);
        } else {
            printf("Error in communication...\n");
        }

        {
            double t = (t2 - t1) / 1000;
            while (t > arg_maxtime) {
                loops = loops / 1.4142135;
                t /= 1.4142135;
            }
            if (loops < 1) { loops = 1; }
        }
    }
    // psdapl_send_eof(ci);
}


int main(int argc, char **argv)
{
    int rc;

    parse_opt(argc, argv);

    psdapl_debug = arg_verbose;

    psdapl_socket_t *socket;
    socket = psdapl_socket_create();
    assert(socket);

    psdapl_con_info_t *ci;
    ci = psdapl_con_create(socket);
    assert(ci);

    if (!arg_server_addr) { // server
        rc = psdapl_listen(socket);
        assert(rc == 0);
        do {
            psdapl_info_msg_t msg;
            psdapl_con_get_info_msg(ci, &msg);
            printf("Waiting for client.\nCall client with:\n");
            printf("%s %s\n", argv[0], psdapl_addr2str(&msg));
            fflush(stdout);

            rc = psdapl_accept_wait(ci);
            if (rc) { continue; }

            run_pp_server(ci);

            //			psdapl_con_close(ci);

        } while (!arg_run_once);
    } else {
        psdapl_info_msg_t msg;

        rc = psdapl_str2addr(&msg, arg_server_addr);
        if (rc) {
            printf("Can parse server address \"%s\"\n", arg_server_addr);
            exit(1);
        }

        rc = psdapl_connect(ci, &msg);
        if (rc) {
            printf("Connect server at \"%s\" failed\n", arg_server_addr);
            exit(1);
        }

        run_pp_client(ci);
    }

    return 0;
}
