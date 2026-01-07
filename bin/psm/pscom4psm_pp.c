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
 * psm_pp.c: PingPong over QLogics psm interface
 *
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <popt.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <error.h>
#include <errno.h>
#include <inttypes.h>
#include "pscom_priv.h"
#define VERSION "PSCOM4PSM_PP1.0"

#undef PSCOM_CUDA_AWARENESS

pscom_t pscom = {.env = {.readahead = 100, .psm_uniq_id = 0, .debug_stats = 0}};

#include "pspsm.h"

int arg_loops   = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024)
int arg_maxmsize           = MAX_MSIZE;
int arg_verbose            = 0;
const char *arg_port       = "5538";
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
    uint32_t len;
    char data[MAX_MSIZE];
} msg_buf_t;


msg_buf_t *s_buf;
msg_buf_t *r_buf;

pspsm_con_info_t *_con;


static void rc_check(int ret, char *msg)
{
    if (!ret) { return; }

    fprintf(stderr, "%s : %s\n", msg, strerror(-ret));
    exit(1);
}


static void pspsm_init_bufs(void)
{
    s_buf              = valloc(sizeof(*s_buf) + 1);
    *(char *)&s_buf[1] = (char)0xee;
    r_buf              = valloc(sizeof(*r_buf) + 1);
    *(char *)&r_buf[1] = (char)0xee;

    memset(s_buf->data, 0x11, sizeof(s_buf->data));
    memset(r_buf->data, 0x22, sizeof(r_buf->data));
}


#define SEC_IN_NS 1000000000ULL

#define PSPSM_INFO_FMT  "epid:%016lx id:%016lx"
#define PSPSM_INFO(msg) (unsigned long)(msg)->epid, (unsigned long)(msg)->id

static void pp_info_read(FILE *peer, pspsm_info_msg_t *msg)
{
    int rc;

    rc = fscanf(peer, VERSION "\n");
    if (rc != 0) {
        error(1, 0, "Parsing error! Only %d from 0 fields. Version mismatch?\n",
              rc);
    }

    rc = (int)fread(msg, sizeof(*msg), 1, peer);
    printf("remote: " PSPSM_INFO_FMT "\n", PSPSM_INFO(msg));
    assert(rc == 1);
}


static void pp_info_write(FILE *peer, pspsm_info_msg_t *msg)
{
    printf("local:  " PSPSM_INFO_FMT "\n", PSPSM_INFO(msg));
    fprintf(peer, VERSION "\n");
    fwrite(msg, sizeof(*msg), 1, peer);
    fflush(peer);
}

#define DUMMY_CON ((struct PSCOM_con *)0x313321)
#define DUMMY_REQ ((struct PSCOM_req *)0x123321)

static void init(FILE *peer)
{
    int rc;
    pspsm_info_msg_t lmsg, rmsg;

    rc = pspsm_init();
    rc_check(rc, "pspsm_init");

    _con = pspsm_con_create();
    assert(_con);

    pspsm_con_init(_con, DUMMY_CON);

    pspsm_con_get_info_msg(_con, &lmsg);

    if (is_server) {
        pp_info_write(peer, &lmsg);
        pp_info_read(peer, &rmsg);
    } else {
        pp_info_read(peer, &rmsg);
        pp_info_write(peer, &lmsg);
    }

    pspsm_con_connect(_con, &rmsg);

    printf("I'm the %s\n", is_server ? "server" : "client");
    sleep(1);

    pspsm_init_bufs();
}


static void cleanup(void)
{
    pspsm_con_cleanup(_con);
    pspsm_con_free(_con);
    _con = NULL;
    pspsm_close_endpoint();
    pspsm_finalize_mq();
}


static inline void pspsm_send(size_t len)
{
    int rc;
    size_t slen;
    struct iovec iov[2];

    s_buf->len = (uint32_t)len;

    slen            = len + sizeof(s_buf->len);
    iov[0].iov_base = s_buf;
    iov[0].iov_len  = slen;
    iov[1].iov_base = NULL;
    iov[1].iov_len  = 0;

    // memcpy(s_buf->buf, r_buf->buf, len);

    rc = pspsm_sendv(_con, iov, DUMMY_REQ);

    if (rc == 0) {
        // send done.
    } else if (rc == -EAGAIN) {
        // send pending. Wait for write done
        while (pspsm_send_pending(_con)) { pspsm_progress(); }
    } else {
        rc_check(rc, "pspsm_sendv");
    }
}


static inline unsigned pspsm_recv(void)
{
    int rc;

    rc = pspsm_recv_start(_con, (char *)r_buf, sizeof(*r_buf));
    assert(rc == 0);

    while (pspsm_recv_pending(_con)) { pspsm_progress(); }

    return r_buf->len;
}


static void run_pp_server(void)
{
    while (1) {
        unsigned len = pspsm_recv();
        pspsm_send(len);
    }
}


static int run_pp_c(size_t msize, int loops)
{
    int cnt;
    assert(msize <= MAX_MSIZE);

    // printf("Send %d\n", msize);

    for (cnt = 0; cnt < loops; cnt++) {
        size_t len = msize;
        size_t rlen;

        pspsm_send(len);
        rlen = pspsm_recv();
        assert(rlen == len);
    }
    return 0;
}


static void do_pp_client(void)
{
    unsigned long t1, t2;
    double time;
    double throuput;
    size_t msgsize;
    double ms;
    int res;
    double loops = arg_loops;

    printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
    printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
    for (ms = 0.0 /*1.4142135*/; ms < arg_maxmsize;
         ms = (ms < 128) ? (ms + 1) : (ms * 1.4142135)) {
        unsigned int iloops = (unsigned)(loops + 0.5);
        msgsize             = (size_t)(ms + 0.5);

        /* warmup, for sync */
        run_pp_c(1, 2);

        t1  = getusec();
        res = run_pp_c(msgsize, iloops);
        t2  = getusec();

        time     = (double)(t2 - t1) / (iloops * 2);
        throuput = (double)msgsize / time;
        if (res == 0) {
            printf("%7zu %8d %8.2f %8.2f\n", msgsize, iloops, time, throuput);
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


/*
 * Implement upper layer functions usually implemented by libpscom or
 * libpscom4psm.
 */
void pscom_write_done(struct PSCOM_con *con, struct PSCOM_req *req, size_t len)
{
}


void pscom_read_done_unlock(struct PSCOM_con *con, char *buf, size_t len)
{
}


static void poll_user_inc(void)
{
}


static void poll_user_dec(void)
{
}


static void pscom_psm_post_recv_check(struct PSCOM_con *con)
{
}


/* C include from libpscom4psm */
#include "pspsm.c"


int main(int argc, char **argv)
{
    FILE *peer;

    parse_opt(argc, argv);

    pspsm_debug_stream = stderr;
    pspsm_debug        = arg_verbose + 2;

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

    if (arg_verbose) { pspsm_print_stats(); }

    cleanup();

    return 0;
}
