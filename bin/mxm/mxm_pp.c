/*
 * ParaStation
 *
 * Copyright (C) 2014-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * mxm_pp.c: PingPong over Mellanox MXM interface
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <fcntl.h>
#include <assert.h>
#include <popt.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>

#include <mxm/api/mxm_api.h>
#include <mxm/api/mxm_config.h>


#define VERSION "MXM_PP1.0"

#define MXM_EP_ADDR_LEN (256)

// PSMXM_MSGLEN(len) is a round up of len to the next multiple of 64 bytes
// (cacheline)
#define PSMXM_MSGLEN(len)  (((len) + 63) & ~63)
#define PSMXM_MSGLEN8(len) (((len) + 7) & ~7)

int arg_loops   = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024 - 8)
int arg_maxmsize           = MAX_MSIZE;
int arg_verbose            = 0;
const char *arg_port       = "5539";
const char *arg_servername = NULL;
int arg_nokill             = 0;
int is_server              = 1;

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

        {"nokill", 'k', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_nokill, 1,
         "Dont kill the server afterwards", NULL},

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

#include <sys/time.h>

static inline unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000);
}


typedef struct msg_buf {
#define HEAD_SIZE 8
    volatile uint32_t len;
    volatile uint32_t mark;
    char buf[MAX_MSIZE];
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

struct mxm_pp_context {
    struct {
        int flag_no_optimization : 1; // if true: Don't configure MXM for
                                      // maximal performance, be more portable.
    } params;

    mxm_h mxm_mxmh;
    mxm_ep_h mxm_ep;
    mxm_mq_h mxm_mq;
    mxm_conn_h mxm_conn;

    void *mem_access_buf;
    size_t mem_access_buf_size;
    mxm_mem_key_t mem_access_buf_mkey;

    char mxm_ep_addr[MXM_EP_ADDR_LEN];
    char mxm_remote_ep_addr[MXM_EP_ADDR_LEN];

    mxm_send_req_t sreq;
    mxm_recv_req_t rreq;
};

struct mxm_pp_context mxm_ctx;

unsigned my_rank = 0xffffffff;


typedef struct {
    char mxm_ep_addr[MXM_EP_ADDR_LEN];
} pp_info_msg_t;


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


#include "mxm_util.c"


static void mxm_rc_check(int rc, char *msg)
{
    if (rc == MXM_OK) { return; }
    fprintf(stderr, "%s : %s", msg, mxm_error_string(rc));
    exit(1);
}


static void init_bufs(struct mxm_pp_context *ctx)
{
    int rc;
    assert(ctx->mem_access_buf_size >= (sizeof(*s_buf) + sizeof(*r_buf)));

    s_buf = ctx->mem_access_buf;
    r_buf = ctx->mem_access_buf + ctx->mem_access_buf_size / 2;

    memset(s_buf->buf, 0x11, sizeof(s_buf->buf));
    memset(r_buf->buf, 0x22, sizeof(r_buf->buf));

    r_buf->mark = 0;
    s_buf->mark = 0;
}


static void init_reqs(struct mxm_pp_context *ctx)
{

    init_send_req(ctx, &ctx->sreq, s_buf, sizeof(*s_buf));
    init_recv_req(ctx, &ctx->rreq, r_buf, sizeof(*r_buf));

    ctx->sreq.base.conn = ctx->mxm_conn;
    // ctx->rreq.base.conn = ctx->mxm_conn; // NULL = Any, conn = Sourced
}


static void pp_info_get(pp_info_msg_t *msg)
{
    memcpy(msg->mxm_ep_addr, mxm_ctx.mxm_ep_addr, sizeof(msg->mxm_ep_addr));
}


static void pp_info_set(pp_info_msg_t *msg)
{
    memcpy(mxm_ctx.mxm_remote_ep_addr, msg->mxm_ep_addr,
           sizeof(mxm_ctx.mxm_remote_ep_addr));
}


static void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
    printf("Local:  msg: %s ...\n", dumpstr(msg, 16));

    fprintf(peer, VERSION "\n");
    fwrite(msg, sizeof(*msg), 1, peer);
    fflush(peer);
}


static void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
    int rc;

    rc = fscanf(peer, VERSION "\n");
    if (rc != 0) {
        error(1, 0, "Parsing error! Only %d fields. Version mismatch?\n", rc);
    }

    rc = (int)fread(msg, sizeof(*msg), 1, peer);
    if (rc != 1) { error(1, 0, "Reading info message failed!\n"); }

    printf("Remote: msg: %s ...\n", dumpstr(msg, 16));
}


static void init(FILE *peer)
{
    int rc;
    pp_info_msg_t lmsg, rmsg;

    rc = init_ctx(&mxm_ctx);
    if (rc) { exit(1); }

    init_bufs(&mxm_ctx);

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

    rc = connect_eps(&mxm_ctx);
    if (rc) { exit(1); }

    printf("I'm the %s\n", is_server ? "server" : "client");
    sleep(1);

    init_reqs(&mxm_ctx);
}


static inline void mxm_send(unsigned len)
{
    int rc;
    // unsigned msglen = PSMXM_MSGLEN(len + HEAD_SIZE);
    unsigned msglen = len + HEAD_SIZE;

    // memcpy(s_buf->buf - len, r_buf->buf - len, len);

    s_buf->len  = len;
    s_buf->mark = 1;

    mxm_ctx.sreq.base.data.buffer.length = msglen;
    mxm_ctx.sreq.base.conn               = mxm_ctx.mxm_conn;

    mxm_req_send(&mxm_ctx.sreq);
    mxm_req_wait(&mxm_ctx.sreq.base);

    assert(mxm_ctx.sreq.base.error == MXM_OK);

    // printf ("send msglen: %d cachelines %d sizeof(s_buf) %d  %p %p\n",
    // msglen, (msglen >> 6) - 1, (int)sizeof(*s_buf), s_buf, r_buf);

    //	unsigned msglen = PSMXM_MSGLEN(len + TAIL_SIZE);
    /*
    rc = rma2_post_put_bt(mxm_port, remote_handle, mxm_s_region,
                          sizeof(*s_buf) - msglen, msglen,
                          remote_rbuf + sizeof(*s_buf) - msglen,
                          arg_with_completion_notification ?
    RMA2_COMPLETER_NOTIFICATION : 0, / * RMA2_Command_Modifier * / 0); assert(rc
    == RMA2_SUCCESS);
*/
}

static inline void mxm_recv(void)
{
    mxm_req_recv(&mxm_ctx.rreq);
    mxm_req_wait(&mxm_ctx.rreq.base);
    assert(mxm_ctx.rreq.base.error == MXM_OK);
}


static void run_pp_server(void)
{
    while (1) {
        mxm_recv();

        unsigned len = r_buf->len;
        mxm_send(len);
    }
}


static int run_pp_c(int msize, int loops)
{
    int cnt;
    assert(msize <= MAX_MSIZE);
    // printf("Send %d\n", msize);
    for (cnt = 0; cnt < loops; cnt++) {
        unsigned len = msize;

        mxm_send(len);

        mxm_recv();
        // assert(r_buf->len == len);
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
        (addr)&0xff
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
