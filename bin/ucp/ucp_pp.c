/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * ucp_pp.c: PingPong over UCP
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
#include <inttypes.h>

#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>


#define VERSION "UCP_PP1.0"
// #define TRACE(code) code
#define TRACE(code)


int arg_loops   = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024)
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

#define X_UCP_MAX_ADDR 256

typedef struct {
    ucp_address_t *ucp_address;
    size_t size;
} x_ucp_address_t;


x_ucp_address_t local_addr  = {.ucp_address = 0};
x_ucp_address_t remote_addr = {.ucp_address = 0};

ucp_worker_h ucp_worker;
ucp_context_h ucp_context;
ucp_ep_h ucp_ep;

#define UCP_TAG 47

typedef struct {
    size_t size;
    char addr[X_UCP_MAX_ADDR];
} pp_info_msg_t;


static void init_bufs(void)
{
    s_buf              = valloc(sizeof(*s_buf) + 1);
    *(char *)&s_buf[1] = 0xeeU;
    r_buf              = valloc(sizeof(*r_buf) + 1);
    *(char *)&r_buf[1] = 0xeeU;

    memset(s_buf->data, 0x11, sizeof(s_buf->data));
    memset(r_buf->data, 0x22, sizeof(r_buf->data));
}


static void pp_info_get(pp_info_msg_t *msg)
{
    msg->size = local_addr.size;
    if (msg->size > sizeof(msg->addr)) {
        printf("pp_info_msg_t.addr to small. Should be at least %zu\n",
               msg->size);
    }
    assert(msg->size <= sizeof(msg->addr));
    memcpy(msg->addr, local_addr.ucp_address, msg->size);
}


static void pp_info_set(pp_info_msg_t *msg)
{
    remote_addr.size        = msg->size;
    remote_addr.ucp_address = realloc(remote_addr.ucp_address, msg->size);
    memcpy(remote_addr.ucp_address, msg->addr, msg->size);
}


static void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
    printf("Lokal:  size:%u %s\n", (unsigned)msg->size,
           dumpstr(msg->addr, (int)msg->size));

    fwrite(msg, sizeof(*msg), 1, peer);
    fflush(peer);
}


static void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
    size_t rc;
    rc = fread(msg, sizeof(*msg), 1, peer);
    if (rc != 1) { error(1, 0, "Receiving handshake error!\n"); }

    printf("Remote: size:%u %s\n", (unsigned)msg->size,
           dumpstr(msg->addr, (int)msg->size));
}


static void psucp_init(void)
{
    ucs_status_t status;
    ucp_config_t *config;
    ucp_params_t ucp_params;
    ucp_worker_params_t ucp_worker_params;

    /* UCP initialization */
    status = ucp_config_read(NULL, NULL, &config);
    assert(status == UCS_OK);

    memset(&ucp_params, 0, sizeof(ucp_params));
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES |
                            UCP_PARAM_FIELD_REQUEST_SIZE |
                            UCP_PARAM_FIELD_REQUEST_INIT;
    ucp_params.features        = UCP_FEATURE_TAG;
    ucp_params.request_size    = 16; // sizeof(struct ucx_context);
    ucp_params.request_init    = NULL;
    ucp_params.request_cleanup = NULL;

    status = ucp_init(&ucp_params, config, &ucp_context);
    assert(status == UCS_OK);

    ucp_config_print(config, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);
    ucp_config_release(config);


    memset(&ucp_worker_params, 0, sizeof(ucp_worker_params));
    ucp_worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    ucp_worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(ucp_context, &ucp_worker_params, &ucp_worker);
    assert(status == UCS_OK);

    status = ucp_worker_get_address(ucp_worker, &local_addr.ucp_address,
                                    &local_addr.size);
    assert(status == UCS_OK);
}


static void psucp_connect(void)
{
    ucs_status_t status;
    ucp_ep_params_t ep_params;

    memset(&ep_params, 0, sizeof(ep_params));
    ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
    ep_params.address    = remote_addr.ucp_address;

    status = ucp_ep_create(ucp_worker, &ep_params, &ucp_ep);
    assert(status == UCS_OK);
}


static void init(FILE *peer)
{
    pp_info_msg_t lmsg, rmsg;

    psucp_init();
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

    psucp_connect();

    printf("I'm the %s\n", is_server ? "server" : "client");
    sleep(1);
}


// "wait" from tools/perf/ucp_tests.cc
static inline ucs_status_t wait(void *request, int is_requestor)
{
    if (!UCS_PTR_IS_PTR(request)) { return UCS_PTR_STATUS(request); }

    while (!ucp_request_is_completed(request)) {
        ucp_worker_progress(ucp_worker);
        /*
          if (is_requestor) {
                progress_requestor();
        } else {
                progress_responder();
        }
        */
    }
    ucp_request_free(request);
    return UCS_OK;
}

// "wait" from test/examples/ucp_hello_world.c
/*
static void wait_X(ucp_worker_h *ucp_worker, struct ucx_context *context)
{
    while (context->completed == 0)
        ucp_worker_progress(*ucp_worker);
}
*/

static void send_done(void *request, ucs_status_t status)
{
    TRACE(printf("%s:%u:%s\n", __FILE__, __LINE__, __func__));
}


static void recv_done(void *request, ucs_status_t status,
                      ucp_tag_recv_info_t *info)
{
    TRACE(printf("%s:%u:%s\n", __FILE__, __LINE__, __func__));
}


static inline void myucp_send(unsigned len)
{
    unsigned slen = len + (unsigned)sizeof(s_buf->len);

    void *request;
    ucs_status_t status;

    s_buf->len = len;

    TRACE(printf("%s:%u:%s slen:%u\n", __FILE__, __LINE__, __func__, slen));
    request = ucp_tag_send_nb(ucp_ep, s_buf, slen, ucp_dt_make_contig(1),
                              UCP_TAG, /*(ucp_send_callback_t)*/ send_done);
    TRACE(printf("%s:%u:%s\n", __FILE__, __LINE__, __func__));
    status = wait(request, 1);

    TRACE(printf("%s:%u:%s\n", __FILE__, __LINE__, __func__));
    assert(status == UCS_OK);
}


static inline unsigned myucp_recv(void)
{
    void *request;
    ucs_status_t status;
    ucp_tag_message_h msg_tag;
    ucp_tag_recv_info_t info_tag;

    r_buf->len = 0;


    while (1) {
        msg_tag = ucp_tag_probe_nb(ucp_worker, UCP_TAG,
                                   (ucp_tag_t)~0 /* tag bit mask */,
                                   1 /* remove */, &info_tag); /* What an ugly
                                                                  API :-( */
        if (msg_tag != NULL) { break; }
        ucp_worker_progress(ucp_worker);
    }

    assert(info_tag.length <= sizeof(*r_buf));

    TRACE(printf("%s:%u:%s info_tag.length %zu\n", __FILE__, __LINE__, __func__,
                 info_tag.length));

    request = ucp_tag_msg_recv_nb(ucp_worker, r_buf, info_tag.length,
                                  ucp_dt_make_contig(1), msg_tag,
                                  /*(ucp_tag_recv_callback_t)*/ recv_done);

    status = wait(request, 1);

    assert(status == UCS_OK);

    TRACE(printf("%s:%u:%s len %u\n", __FILE__, __LINE__, __func__, r_buf->len));
    return r_buf->len;

    /*
    enum ucp_ret ret;

    uint32_t mlen;
    int rlen;
    uint32_t sourceid;
    uint8_t tag;
    char *r = (char *)r_buf;

    ret = ucp_recv(&ucp_port, r, 64,
                     &mlen, &sourceid, &tag, 0);
    myucp_ret_check(ret, "ucp_recv() 1");
    assert(mlen >= sizeof(r_buf->len));

    r += mlen;
    rlen = r_buf->len + sizeof(r_buf->len) - mlen;

    //printf("Recv1: len %u msglen %u rest %u ptr %p\n", r_buf->len, mlen, rlen,
    r);

    while (rlen > 0) {
            ret = ucp_recv(&ucp_port, r, 64,
                             &mlen, &sourceid, &tag, 0);
            myucp_ret_check(ret, "ucp_recv() 2");
            //printf("Recv2: len %u msglen %u rest %u ptr %p\n", r_buf->len,
    mlen, rlen, r);

            r += mlen;
            rlen -= mlen;
            // Warning: mlen is 8 byte alligned which could make rlen negative!
            // assert(rlen >= 0) will fail.
    }
    return r_buf->len;
    */
    return 1;
}


static void run_pp_server(void)
{
    while (1) {
        unsigned len = myucp_recv();
        myucp_send(len);
    }
}


static int run_pp_c(int msize, int loops)
{
    int cnt;
    assert(msize <= MAX_MSIZE);

    // printf("Send %d\n", msize);

    for (cnt = 0; cnt < loops; cnt++) {
        unsigned len = msize;
        unsigned rlen;

        myucp_send(len);
        rlen = myucp_recv();
        assert(rlen == len);
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
    for (ms = 0.0 /*1.4142135*/; ms < arg_maxmsize;
         ms = (ms < 128) ? (ms + 1) : (ms * 1.4142135)) {
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

/* clang-format off
 *
 * Local Variables:
 *  compile-command: "module load ucx && gcc ucp_pp.c -Wall -W -Wno-unused * -Wno-unused-parameter -L${UCX_HOME}/lib -I${UCX_HOME}/include -O2 -lpopt * -lucp -o ucp_pp"
 * End:
 *
 * clang-format on
 */
