/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <portals4.h>

//#define TRACE(code) code
#define TRACE(code)

#define MAX_SIZE   (8 * 1024 * 1024)
#define MATCH_BITS 0xDEADBEEF

#define PTL_CHECK(call)                                                        \
    do {                                                                       \
        int rc = (call);                                                       \
        if (rc != PTL_OK) {                                                    \
            fprintf(stderr, "%s: %d\n", #call, rc);                            \
            exit(1);                                                           \
        }                                                                      \
    } while (0);


typedef struct optargs {
    int num_rounds;
    int max_time;
    int max_size;
    int help;
    int nokill;
    int verbose;
    int is_server;
    char *port;
    char *progname;
    char *servername;
} optargs_t;

optargs_t opts = {
    .num_rounds = 1024,
    .max_time   = 3000,
    .max_size   = MAX_SIZE,
    .help       = 0,
    .nokill     = 0,
    .port       = "5539",
    .verbose    = 0,
    .is_server  = 1,
    .servername = NULL,
};


typedef struct {
    ptl_process_t pid;
    ptl_pt_index_t pti;
} pp_info_msg_t;


typedef union msg_header {
    struct {
        uint32_t last_msg;
        uint32_t loops;
    } info;
    uint64_t header;
} msg_header_t;

pp_info_msg_t rmsg;
pp_info_msg_t lmsg;

char *s_buf;
char *r_buf;

ptl_handle_ni_t nih;
ptl_handle_md_t mdh;
ptl_handle_ct_t cth_send;
ptl_handle_ct_t cth_recv;
ptl_handle_eq_t eqh_send;
ptl_handle_eq_t eqh_recv;
ptl_handle_le_t leh;
ptl_pt_index_t pti;


static void print_opts(void)
{
    printf("'%s' will be run with the following options:\n", opts.progname);
    printf("  Rounds per size      : %d\n", opts.num_rounds);
    printf("  Maximum time per size: %d\n", opts.max_time);
    printf("  Maximum message size : %d\n", opts.max_size);
    printf("  Server               : %s\n", opts.is_server ? "yes" : "no");
    printf("  Client               : %s\n", opts.is_server ? "no" : "yes");
    printf("  Port                 : %s\n", opts.port);
    printf("  Servername           : %s\n", opts.servername);
}


static void print_usage(void)
{
    printf("USAGE:\n");
    printf("    %s [OPTIONS] [serveraddr]\n\n", opts.progname);
    printf("OPTIONS:\n");
    printf("    -n, --num-rounds    Number of rounds per message size\n");
    printf("    -t, --time          Maximum time per message size\n");
    printf("    -s, --size          Maximum message size\n");
    printf("    -p, --port          Server port to use\n");
    printf("    -v, --verbose       Increase verbosity\n");
    printf("    -h, --help          Show this help message\n");
}


static void parse_opt(int argc, char **argv)
{
    int c;

    opts.progname = argv[0];

    while (1) {
        static struct option long_options[] = {
            {"num-rounds", required_argument, 0, 'n'},
            {"time", required_argument, 0, 't'},
            {"size", required_argument, 0, 's'},
            {"port", required_argument, 0, 'p'},
            {"help", no_argument, &opts.help, 1},
            {"verbose", no_argument, &opts.verbose, 1},
            {0, 0, 0, 0}};

        int option_index = 0;

        c = getopt_long(argc, argv, "n:t:s:p:hv", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 0: break;
        case 'n': opts.num_rounds = atoi(optarg); break;
        case 't': opts.max_time = atoi(optarg); break;
        case 's': opts.max_size = atoi(optarg); break;
        case 'p': opts.port = optarg; break;
        case 'v': opts.verbose = 1; break;
        case '?': break;
        case 'h':
        default: print_usage(); exit(EXIT_FAILURE);
        }
    }

    opts.servername = argv[optind++];
    opts.is_server  = !opts.servername;

    if (optind < argc) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    if (opts.help) {
        print_usage();
        exit(EXIT_FAILURE);
    }
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


static void pp_info_get(pp_info_msg_t *msg)
{
    PTL_CHECK(PtlGetPhysId(nih, &msg->pid));
    msg->pti = pti;
}


size_t recv_data(void *buffer, size_t length, int sock)
{
    size_t bytes_received = 0;
    while (bytes_received < length) {
        bytes_received += recv(sock,
                               (void *)((uint64_t)buffer + bytes_received),
                               length - bytes_received, 0);
    }

    return bytes_received;
}

size_t send_data(void *buffer, size_t length, int sock)
{
    size_t bytes_sent = 0;
    while (bytes_sent < length) {
        bytes_sent += send(sock, (void *)((uint64_t)buffer + bytes_sent),
                           length - bytes_sent, 0);
    }

    return bytes_sent;
}


static void create_and_init_bufs(void)
{
    /* get page-aligned memory */
    posix_memalign((void **)&s_buf, sysconf(_SC_PAGESIZE), opts.max_size);
    posix_memalign((void **)&r_buf, sysconf(_SC_PAGESIZE), opts.max_size);

    /* initialize the buffers */
    memset(s_buf, 0x11, opts.max_size);
    memset(r_buf, 0x22, opts.max_size);

    /* create memory descriptor for the send buffer */
    ptl_md_t md = {
        .start     = (void *)s_buf,
        .length    = opts.max_size,
        .options   = PTL_MD_EVENT_CT_ACK | PTL_MD_EVENT_CT_SEND,
        .eq_handle = PTL_EQ_NONE, /* eqh_send, */
        .ct_handle = cth_send,
    };
    PTL_CHECK(PtlMDBind(nih, &md, &mdh));

    /* request a portals index */
    PTL_CHECK(PtlPTAlloc(nih, 0, eqh_recv, PTL_PT_ANY, &pti));

    /* create a list entry for the receive buffer */
    ptl_me_t me = {
        .start             = (void *)r_buf,
        .length            = opts.max_size,
        .ct_handle         = cth_recv,
        .uid               = PTL_UID_ANY,
        .options           = PTL_ME_OP_PUT,
        .match_bits        = MATCH_BITS,
        .match_id.phys.nid = PTL_NID_ANY,
        .match_id.phys.pid = PTL_PID_ANY,
        .ignore_bits       = 0,
    };
    PTL_CHECK(PtlMEAppend(nih, pti, &me, PTL_PRIORITY_LIST, NULL, &leh));

    /* wait for the link event */
    ptl_event_t event;
    PTL_CHECK(PtlEQWait(eqh_recv, &event));
    assert(event.type == PTL_EVENT_LINK);
}


static void cleanup_bufs(void)
{
    /* release the portal index */
    PTL_CHECK(PtlPTFree(nih, pti));

    /* release the memory descriptor */
    PTL_CHECK(PtlMDRelease(mdh));

    /* free the memory buffers */
    free(s_buf);
    free(r_buf);
}

static void psportals4_init(void)
{
    /* initialize portals4 library */
    PTL_CHECK(PtlInit());

    /* initialize the network interface */
    PTL_CHECK(PtlNIInit(PTL_IFACE_DEFAULT, /* use the default interface */
                        (PTL_NI_MATCHING | PTL_NI_PHYSICAL),
                        PTL_PID_ANY, /* let portals4 choose the pid */
                        NULL,        /* do not impose resource limits */
                        NULL,   /* do not retrieve the actual resource limits */
                        &nih)); /* handle to the network interface */

    /* build the event queues */
    PTL_CHECK(PtlEQAlloc(nih, 65536, &eqh_send));
    PTL_CHECK(PtlEQAlloc(nih, 65536, &eqh_recv));

    /* create counting events */
    PTL_CHECK(PtlCTAlloc(nih, &cth_recv));
    PTL_CHECK(PtlCTAlloc(nih, &cth_send));
}

static void psportals4_finalize(void)
{
    /* release EQ resources */
    PTL_CHECK(PtlEQFree(eqh_send));
    PTL_CHECK(PtlEQFree(eqh_recv));

    /* release CT resources */
    PTL_CHECK(PtlCTFree(cth_send));
    PTL_CHECK(PtlCTFree(cth_recv));

    /* cleanup the portals4 library */
    PtlFini();
}


static void init(int sock)
{
    psportals4_init();
    create_and_init_bufs();

    /* Get local peer information */
    pp_info_get(&lmsg);

    if (opts.is_server) {
        send_data(&lmsg, sizeof(lmsg), sock);
        recv_data(&rmsg, sizeof(rmsg), sock);
    } else {
        recv_data(&rmsg, sizeof(rmsg), sock);
        send_data(&lmsg, sizeof(lmsg), sock);
    }

    printf("I'm the %s\n", opts.is_server ? "server" : "client");
}

static void finalize(void)
{
    cleanup_bufs();
    psportals4_finalize();
}

static inline void wait(void *request, int is_requestor)
{
}

static inline void send_msg(unsigned len, unsigned last_msg, unsigned loops)
{
    ptl_ct_event_t event;

    msg_header_t msg_header = {
        .info =
            {
                .last_msg = last_msg,
                .loops    = loops,
            },
    };

    /* send the data */
    PTL_CHECK(
        PtlPut(mdh, /* local memory handle */
               0,   /* local offset */
               len, /* amount of bytes to be sent */
               last_msg ? PTL_OC_ACK_REQ
                        : PTL_NO_ACK_REQ, /* do not request an acknowledgment */
               rmsg.pid,                  /* peer process ID */
               rmsg.pti,                  /* remote portals index */
               MATCH_BITS,                /* match bits */
               0,                         /* remote offset */
               NULL,                      /* local user pointer */
               msg_header.header));       /* header */

    /* wait for the according event */
    if (last_msg) {
        PTL_CHECK(PtlCTWait(cth_send, loops + 1, &event));
        assert(event.failure == 0);
    }
}


static inline unsigned recv_msg(uint64_t *last_msg)
{
    ptl_event_t event;

    /* wait for an incoming message */
    do {
        PTL_CHECK(PtlEQWait(eqh_recv, &event));
        if (event.type != PTL_EVENT_PUT) {
            printf("unexpected event: %i\n", (int)event.type);
        } else {
            break;
        }
    } while (1);

    if (last_msg)
        *last_msg = event.hdr_data;

    return (unsigned)(event.rlength);
}


static void run_pp_server(void)
{
    msg_header_t msg_header = {0};
    while (1) {
        unsigned len = recv_msg(&msg_header.header);
        send_msg(len, msg_header.info.last_msg, msg_header.info.loops);
    }
}


static int run_pp_c(int msize, int loops)
{
    int cnt;
    assert(msize <= MAX_SIZE);

    // printf("Send %d\n", msize);

    for (cnt = 0; cnt < loops; cnt++) {
        unsigned len = msize;
        unsigned rlen;

        send_msg(len, (cnt == (loops - 1)), loops);
        rlen = recv_msg(NULL);
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
    double loops = opts.num_rounds;

    printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
    printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
    for (ms = 0.0 /*1.4142135*/; ms < opts.max_size;
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
            while (t > opts.max_time) {
                loops = loops / 1.4142135;
                t /= 1.4142135;
            }
            if (loops < 1)
                loops = 1;
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


static int get_peer(void)
{
    int fd;

    struct addrinfo hints = {.ai_flags    = AI_CANONNAME,
                             .ai_family   = AF_INET,
                             .ai_socktype = SOCK_STREAM};
    struct addrinfo *addrinfo;

    int n;
    n = getaddrinfo(opts.servername ? opts.servername : "0", opts.port, &hints,
                    &addrinfo);
    if (n) {
        addrinfo = NULL;
        printf("getaddrinfo() failed: %s\n", gai_strerror(n));
        exit(1);
    }

    if (opts.is_server) {
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

    if (addrinfo)
        freeaddrinfo(addrinfo);
    return fd;
}


int main(int argc, char **argv)
{
    int peer;

    /* parse and print benchmark configuration */
    parse_opt(argc, argv);
    print_opts();

    peer = get_peer();
    init(peer);

    if (opts.is_server) {
        if (!opts.nokill) {
            // Kill the server with SIGSTOP if the peer disappear.
            SCALL(fcntl(peer, F_SETOWN, getpid()));
            SCALL(fcntl(peer, F_SETSIG, SIGINT));
            SCALL(fcntl(peer, F_SETFL, O_ASYNC));
        }
        run_pp_server();
    } else {
        sleep(2);
        do_pp_client();
    }


    finalize();

    return 0;
}
