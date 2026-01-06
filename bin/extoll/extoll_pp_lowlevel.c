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
 * extoll_pp_lowlevel.c: PingPong over extoll interface
 *
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <popt.h>
#include <rma2.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// Compat stuff for missing Extoll includes:
// typedef struct RMA_Connection_s RMA_Connection;
// typedef struct RMA_Endpoint_s RMA_Endpoint;
// typedef struct RMA_Region_s RMA_Region;

#include "rma2.h" /* Extoll librma interface */

#define VERSION "EXTOLL_PP1.0"

// PSEXTOLL_MSGLEN(len) is a round up of len to the next multiple of 64 bytes
// (cacheline)
#define PSEXTOLL_MSGLEN(len)  (((len) + 63) & ~63)
#define PSEXTOLL_MSGLEN8(len) (((len) + 7) & ~7)

int arg_loops   = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024 - 8)
int arg_maxmsize                     = MAX_MSIZE;
int arg_verbose                      = 0;
int arg_with_completion_notification = 0;
const char *arg_port                 = "5534";
const char *arg_servername           = NULL;
int arg_nokill                       = 0;
int arg_imm_put                      = 0;
int is_server                        = 1;

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

        {"event", 'e', POPT_ARGFLAG_OR | POPT_ARG_VAL,
         &arg_with_completion_notification, 1, "wait for completion events", ""},

        {"nokill", 'k', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_nokill, 1,
         "Dont kill the server afterwards", NULL},

        {"imm", 'i', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_imm_put, 1,
         "Use immediate puts", ""},

        {"port", 'p', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_STRING, &arg_port, 0,
         "server port to use", "port"},

        {"verbose", 'v', POPT_ARG_NONE, NULL, 'v', "increase verbosity", NULL},

        POPT_AUTOHELP POPT_TABLEEND // Add help option and terminate table
    };

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);

    poptSetOtherOptionHelp(optCon, "[serveraddr]");

    while ((c = poptGetNextOpt(optCon)) >= 0) {
        switch (c) { // c = poptOption.val;
        case 'v': arg_verbose++; break;
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
    arg_servername = poptGetArg(optCon);
    is_server      = !arg_servername;

    no_arg = poptGetArg(optCon); // should return NULL
    if (no_arg) {
        fprintf(stderr, "%s: %s\n", no_arg, poptStrerror(POPT_ERROR_BADOPT));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    poptFreeContext(optCon);
}


#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#include <sys/time.h> /* IWYU pragma: keep */

static inline unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000);
}


typedef struct msg_buf {
    char _buf_[MAX_MSIZE];
    char buf[0];
#define TAIL_SIZE 8
    volatile uint32_t len;
    volatile uint32_t mark;
} msg_buf_t;


static void idle(void)
{
    volatile unsigned y = 0;
    y++;
    //	sched_yield();
}

#define RANK_CLIENT 1
#define RANK_SERVER 0

msg_buf_t *s_buf;
msg_buf_t *r_buf;
RMA2_NLA remote_rbuf;
RMA2_Nodeid remote_nodeid;
RMA2_VPID remote_vpid;
RMA2_Handle remote_handle; // The connection from rma2_connect

RMA2_Port extoll_port;
RMA2_Handle extoll_handle;
RMA2_Region *extoll_s_region;
RMA2_Region *extoll_r_region;

RMA2_NLA my_rbuf;
RMA2_Nodeid my_nodeid;
RMA2_VPID my_vpid;

unsigned my_rank = 0xffffffff;


typedef struct {
    RMA2_NLA rbuf_nla;
    RMA2_Nodeid nodeid;
    RMA2_VPID vpid;
} pp_info_msg_t;


static void extoll_rc_check(int rc, char *msg)
{
    if (rc == RMA2_SUCCESS) { return; }
    rma2_perror(rc, msg);
    exit(1);
}


static void init_bufs(void)
{
    int rc;

    s_buf              = valloc(sizeof(*s_buf) + 1);
    *(char *)&s_buf[1] = 0xeeU;
    r_buf              = valloc(sizeof(*r_buf) + 1);
    *(char *)&r_buf[1] = 0xeeU;

    memset(s_buf->_buf_, 0x11, sizeof(s_buf->_buf_));
    memset(r_buf->_buf_, 0x22, sizeof(r_buf->_buf_));

    r_buf->mark = 0;
    s_buf->mark = 0;

    //	assert(sizeof(*s_buf) == 4 * 1024);
    rc = rma2_register(extoll_port, s_buf, sizeof(*s_buf), &extoll_s_region);
    extoll_rc_check(rc, "rma2_register() for s_buf");

    //	assert(sizeof(*r_buf) == 4 * 1024);
    rc = rma2_register(extoll_port, r_buf, sizeof(*r_buf), &extoll_r_region);
    extoll_rc_check(rc, "rma2_register() for r_buf");

    rc = rma2_get_nla(extoll_r_region, 0, &my_rbuf);
    extoll_rc_check(rc, "rma2_get_nla() for my_rbuf");

    my_nodeid = rma2_get_nodeid(extoll_port);
    my_vpid   = rma2_get_vpid(extoll_port);
}


static void pp_info_get(pp_info_msg_t *msg)
{
    msg->rbuf_nla = my_rbuf;
    msg->nodeid   = my_nodeid;
    msg->vpid     = my_vpid;
}


static void pp_info_set(pp_info_msg_t *msg)
{
    remote_nodeid = msg->nodeid;
    remote_vpid   = msg->vpid;
    remote_rbuf   = msg->rbuf_nla;
}


static void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
    printf("Lokal:  nodeid:%8hu vpid:%8hu recvnla: 0x%16lx\n", msg->nodeid,
           msg->vpid, msg->rbuf_nla);

    fprintf(peer, VERSION " nodeid:%8hu vpid:%8hu recvnla: 0x%lx\n",
            msg->nodeid, msg->vpid, msg->rbuf_nla);
    fflush(peer);
}


static void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
    int rc;

    rc = fscanf(peer, VERSION " nodeid:%8hu vpid:%8hu recvnla: 0x%lx",
                &msg->nodeid, &msg->vpid, &msg->rbuf_nla);
    if (rc != 3) {
        error(1, 0, "Parsing error! Only %d fields. Version mismatch?\n", rc);
    }

    printf("Remote: nodeid:%8hu vpid:%8hu recvnla: 0x%16lx\n", msg->nodeid,
           msg->vpid, msg->rbuf_nla);
}


static void init(FILE *peer)
{
    int rc;
    pp_info_msg_t lmsg, rmsg;

    rc = rma2_open(&extoll_port);
    extoll_rc_check(rc, "rma2_open()");

    init_bufs();

    /* Get local peer information */
    pp_info_get(&lmsg);

    if (is_server) {
        pp_info_write(peer, &lmsg);
        pp_info_read(peer, &rmsg);
    } else {
        pp_info_read(peer, &rmsg);
        pp_info_write(peer, &lmsg);
    }

    pp_info_set(&rmsg);

    rc = rma2_connect(extoll_port, remote_nodeid, remote_vpid,
                      RMA2_CONN_DEFAULT, &remote_handle);
    extoll_rc_check(rc, "rma2_connect()");

    printf("I'm the %s\n", is_server ? "server" : "client");
    sleep(1);
}


static inline void extoll_send(unsigned len)
{
    int rc;

    // memcpy(s_buf->buf - len, r_buf->buf - len, len);

    s_buf->len  = len;
    s_buf->mark = 1;

    // printf ("send msglen: %d cachelines %d sizeof(s_buf) %d  %p %p\n",
    // msglen, (msglen >> 6) - 1, (int)sizeof(*s_buf), s_buf, r_buf);

    if (!arg_imm_put) {
        unsigned msglen = PSEXTOLL_MSGLEN(len + TAIL_SIZE);
        rc = rma2_post_put_bt(extoll_port, remote_handle, extoll_s_region,
                              (unsigned)sizeof(*s_buf) - msglen, msglen,
                              remote_rbuf + sizeof(*s_buf) - msglen,
                              arg_with_completion_notification
                                  ? RMA2_COMPLETER_NOTIFICATION
                                  : 0,
                              /* RMA2_Command_Modifier */ 0);
        assert(rc == RMA2_SUCCESS);

        if (arg_with_completion_notification) {
            RMA2_Notification *notip;

            rc = rma2_noti_get_block(extoll_port, &notip);
            assert(rc == RMA2_SUCCESS);
            rma2_noti_free(extoll_port, notip);
        }
    } else {
        unsigned msglen = PSEXTOLL_MSGLEN8(len + TAIL_SIZE);

        uint64_t *buf = (uint64_t *)((char *)s_buf + sizeof(*s_buf) - msglen);
        RMA2_NLA dest_address = remote_rbuf + sizeof(*s_buf) - msglen;

        while (msglen) {
            rc = rma2_post_immediate_put(extoll_port, remote_handle, 7, *buf,
                                         dest_address,
                                         /* RMA2_Notification_Spec */ 0,
                                         /* RMA2_Command_Modifier */ 0);
            assert(rc == RMA2_SUCCESS);

            buf++;
            msglen -= 8;
            dest_address += 8;
        }
    }
}

#if 0
static char *dumpstr(void *buf, int size)
{
    static char *ret = NULL;
    char *tmp;
    int s;
    char *b;
    if (ret) { free(ret); }
    ret = (char *)malloc(size * 5 + 4);
    tmp = ret;
    s   = size;
    b   = (char *)buf;
    for (; s; s--, b++) { tmp += sprintf(tmp, "<%02x>", (unsigned char)*b); }
    *tmp++ = '\'';
    s      = size;
    b      = (char *)buf;
    for (; s; s--, b++) {
        /* *tmp++ = isprint(*b) ? *b: '.';*/
        *tmp++ = ((*b >= 32) && (*b < 127)) ? *b : '.';
    }
    *tmp++ = '\'';
    *tmp++ = 0;
    return ret;
}
#endif

static inline void extoll_recv(void)
{
    while (r_buf->mark != 1) {
        idle();
        // printf("x_buf: %s\n", dumpstr(r_buf->buf - 64, 8 + 64 + 1));
        // sleep(5);
    }
    // printf("r_buf: %s\n", dumpstr(r_buf->buf - 64, 8 + 64 + 1));
    r_buf->mark = 0;
}


static void run_pp_server(void)
{
    while (1) {
        extoll_recv();

        unsigned len = r_buf->len;
        extoll_send(len);
    }
}


static int run_pp_c(int msize, int loops)
{
    int cnt;
    assert(msize <= MAX_MSIZE);
    // printf("Send %d\n", msize);
    for (cnt = 0; cnt < loops; cnt++) {
        unsigned len = msize;

        extoll_send(len);

        extoll_recv();
    }
    return 0;
}


static void do_pp_client(void)
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
        unsigned int iloops = (unsigned int)(loops + 0.5);
        msgsize             = (unsigned int)(ms + 0.5);

        /* warmup, for sync */
        run_pp_c(1, 2);

        t1  = getusec();
        res = run_pp_c(msgsize, iloops);
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


/************************************************************
 *
 * Connection establishment via TCP
 */

#define SCALL(func)                                                            \
    do {                                                                       \
        if ((func) < 0) {                                                      \
            printf(#func ": %s\n", strerror(errno));                           \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#define INET_ADDR_SPLIT(addr)                                                  \
    ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >> 8) & 0xff,        \
        (addr) & 0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"


static FILE *get_peer(void)
{
    int fd;

    struct addrinfo hints = {.ai_flags    = AI_CANONNAME,
                             //.ai_family   = AF_UNSPEC,
                             .ai_family   = AF_INET,
                             .ai_socktype = SOCK_STREAM};
    struct addrinfo *addrinfo;

    int n;
    n = getaddrinfo(arg_servername ? arg_servername : "0", arg_port, &hints,
                    &addrinfo);
    if (n) {
        addrinfo = NULL;
        printf("getaddrinfo() failed: %s\n", gai_strerror(n));
        exit(1);
    }

    if (is_server) {
        int val = 1;
        int listen_fd;
        SCALL(listen_fd = socket(PF_INET, SOCK_STREAM, 0));

        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&val,
                   sizeof(val));

        SCALL(bind(listen_fd, addrinfo->ai_addr, addrinfo->ai_addrlen));
        SCALL(listen(listen_fd, 1));
        printf("Waiting for connection\n");
        fd = accept(listen_fd, NULL, 0);
    } else {
        struct sockaddr_in *si = (struct sockaddr_in *)addrinfo->ai_addr;
        assert(si->sin_family == AF_INET);
        SCALL(fd = socket(PF_INET, SOCK_STREAM, 0));
        printf("Connect to " INET_ADDR_FORMAT " \n",
               INET_ADDR_SPLIT(ntohl(si->sin_addr.s_addr)));

        SCALL(connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen));
    }

    if (addrinfo) { freeaddrinfo(addrinfo); }
    return fdopen(fd, "a+");
}


int main(int argc, char **argv)
{
    FILE *peer;

    parse_opt(argc, argv);

    peer = get_peer();
    init(peer);

    if (is_server) { // server
        if (!arg_nokill) {
            // Kill the server with SIGSTOP if the peer disappear.
            int fd = fileno(peer);
            SCALL(fcntl(fd, F_SETOWN, getpid()));
            SCALL(fcntl(fd, F_SETSIG, SIGINT));
            SCALL(fcntl(fd, F_SETFL, O_ASYNC));
        }
        run_pp_server();
    } else {
        sleep(2);
        do_pp_client();
    }

    return 0;
}
