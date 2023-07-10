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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <fcntl.h>
#include <assert.h>
#include <popt.h>
#include <ctype.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pscommon.h>
#include <psi.h>
#include <psiinfo.h>
#include <pse.h>

#include "psport4.h"
#include "psport_util.h"

int arg_verbose        = 0;
int arg_version        = 0;
int arg_progress       = 0;
int arg_manual         = 0;
const char *arg_server = NULL;

int arg_localport = PSP_ANYPORT;
#define DEFAULT_maxmsize 65536
int arg_maxmsize      = DEFAULT_maxmsize;
const char *arg_ocmd  = NULL;
const char *arg_ofile = NULL;
const char *arg_icmd  = NULL;
const char *arg_ifile = NULL;

const char *arg_cp = NULL;

const char *arg_nodes = NULL;
const char *arg_hosts = NULL;

int rem_argc;
char **rem_argv;

#define DEFAULT_ntokens 16
unsigned int arg_ntokens = DEFAULT_ntokens;
#define DEFAULT_nlowtokens 3
unsigned int arg_nlowtokens = DEFAULT_nlowtokens;

unsigned long stat_bytes_tx = 0;
unsigned long long stat_time_start;

char *nodeList = NULL;

const char *command_name = "pscp";

const char *copy_command_src  = "/bin/tar cvPf -";
const char *copy_command_dest = "/bin/tar xPf -";

#define _STR(arg) #arg
#define STR(arg)  _STR(arg)

/*
 * Print version info
 */
static void printVersion(void)
{
    char revision[] = "$Revision: 4439 $";
    fprintf(stderr, "psmstart %s\b \n", revision + 11);
}

static char *getNLFromNodes(const char *nl_descr)
{
    static char *nl = NULL, *ret;

    if (!strcasecmp(nl_descr, "all")) {
        ret = nl = realloc(nl, sizeof(char) * PSC_getNrOfNodes());
        if (!ret) {
            fprintf(stderr, "%s: no memory\n", __func__);
        } else {
            memset(ret, 1, PSC_getNrOfNodes());
        }
    } else {
        char *tmp_descr = strdup(nl_descr);
        if (!tmp_descr) {
            fprintf(stderr, "%s: no memory\n", __func__);
            ret = NULL;
        } else {
            ret = PSC_parseNodelist(tmp_descr);
            free(tmp_descr);
            if (!ret) { printf("Illegal nodelist '%s'\n", nl_descr); }
        }
    }
    return ret;
}

static char *getNLFromHosts(const char *hl_descr)
{
    static char *nl = NULL;
    char *host, *work, *tmp_descr;

    nl = realloc(nl, sizeof(char) * PSC_getNrOfNodes());
    if (!nl) {
        PSC_log(-1, "%s: no memory\n", __func__);
        return NULL;
    }
    memset(nl, 0, PSC_getNrOfNodes());

    tmp_descr = strdup(hl_descr);
    if (!tmp_descr) {
        fprintf(stderr, "%s: no memory\n", __func__);
        return NULL;
    }

    host = strtok_r(tmp_descr, ", ", &work);

    while (host) {
        PSnodes_ID_t node;
        struct hostent *hp = gethostbyname(host);
        struct in_addr addr;
        int err;

        if (!hp) { break; }

        memcpy(&addr, hp->h_addr_list[0], sizeof(addr));
        err = PSI_infoNodeID(-1, PSP_INFO_HOST, &addr.s_addr, &node, 1);

        if (err || node == -1) { break; }

        nl[node] = 1;
        host     = strtok_r(NULL, ", ", &work);
    }

    if (host) { printf("Illegal hostname '%s'\n", host); }
    free(tmp_descr);
    return host ? nl : NULL;
}

void parse_opt(int argc, char **argv)
{
    int rc;             /* used for argument parsing */
    poptContext optCon; /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
        {"cp", 'C', POPT_ARG_STRING, &arg_cp, 0, "copy files with /bin/tar",
         "files"},

        {"ocmd", 'O', POPT_ARG_STRING, &arg_ocmd, 0, "output command", "cmd"},
        {"output", 'o', POPT_ARG_STRING, &arg_ofile, 0,
         "output file\t(default stdout)", "filename"},

        {"icmd", 'I', POPT_ARG_STRING, &arg_icmd, 0, "input command", "cmd"},
        {"input", 'i', POPT_ARG_STRING, &arg_ifile, 0,
         "input file\t(default stdin)", "filename"},

        {"server", 's', POPT_ARG_STRING, &arg_server, 0, "server address",
         "address"},
        {"lport", 'l', POPT_ARG_INT, &arg_localport, 0, "local port", "port"},
        {"manual", 'm', POPT_ARG_INT, &arg_manual, 0,
         "manual start of <num> client processes", "num"},

        {"hosts", 'h', POPT_ARG_STRING, &arg_hosts, 0,
         "hosts to copy to\t(default to all)", "hostlist"},
        {"nodes", 'n', POPT_ARG_STRING, &arg_nodes, 0,
         "nodes to copy to\t(default to all)", "nodelist"},

        {"progress", 'p', POPT_ARG_NONE, &arg_progress, 0,
         "show progress of distribution", NULL},

        {"maxsize", 0, POPT_ARG_INT, &arg_maxmsize, 0,
         "maximum messagesize\t(default " STR(DEFAULT_maxmsize) ")", "size"},
        {"tokens", 0, POPT_ARG_INT, &arg_ntokens, 0,
         "number of tokens\t(default " STR(DEFAULT_ntokens) ")", "num"},
        {"lowtokens", 0, POPT_ARG_INT, &arg_maxmsize, 0,
         "minimum number of tokens\t(default " STR(DEFAULT_nlowtokens) ")",
         "num"},
        {"verbose", 'v', POPT_ARG_INT, &arg_verbose, 0, "be more verbose",
         "level"},
        {"version", 'V', POPT_ARG_NONE, &arg_version, -1,
         "output version information and exit", NULL},

        POPT_AUTOHELP{NULL, 0, 0, NULL, 0, NULL, NULL}};

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);

    if (argc < 1) {
        poptPrintUsage(optCon, stderr, 0);
        exit(1);
    }

    /* Now do options processing, get portname */
    while ((rc = poptGetNextOpt(optCon)) >= 0) {}

    if (rc < -1) {
        /* an error occurred during option processing */
        fprintf(stderr, "%s: %s\n",
                poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
                poptStrerror(rc));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    if (arg_hosts && arg_nodes) {
        poptPrintHelp(optCon, stderr, 0);
        fprintf(stderr, "\n--hosts and --hosts are mutual exclusive!\n\n");
        exit(1);
    }

    if (arg_manual && (arg_nodes || arg_hosts)) {
        poptPrintHelp(optCon, stderr, 0);
        fprintf(stderr, "\nno list of clients if --manual is given!\n\n");
        exit(1);
    }

    poptFreeContext(optCon);
}

static inline unsigned long long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000LL);
}

typedef struct {
    int32_t node;
    int32_t port;
} client_info_t;


char *append(char *str1, const char *str2)
{
    if (!str1) {
        return str2 ? strdup(str2) : NULL;
    } else if (!str2) {
        return str1;
    } else {
        size_t len1 = strlen(str1);
        str1        = realloc(str1, strlen(str1) + strlen(str2) + 1);
        strcpy(str1 + len1, str2);
        return str1;
    }
}


char *get_remote_command(PSP_PortH_t porth)
{
    char *res = NULL;
    char buf[30];
    res = append(res, command_name);

    if (arg_manual) { res = append(res, " -m 1"); }

    res = append(res, " -s ");
    res = append(res, PSP_local_name(porth));

    if (arg_maxmsize != DEFAULT_maxmsize) {
        snprintf(buf, sizeof(buf), " --maxsize %d", arg_maxmsize);
        res = append(res, buf);
    }

    if (arg_ocmd) {
        res = append(res, " -O '");
        res = append(res, arg_ocmd);
        res = append(res, "'");
    }

    if (arg_ofile) {
        res = append(res, " -o ");
        res = append(res, arg_ofile);
    }

    if (arg_verbose) {
        snprintf(buf, sizeof(buf), " -v %d", arg_verbose);
        res = append(res, buf);
    }

    if (arg_progress) { res = append(res, " -p"); }

    return res;
}

int build_remote_argv(PSP_PortH_t porth)
{
    /* @todo */
    char buf[30];

    rem_argv = malloc(20 * sizeof(*rem_argv));
    rem_argc = 0;

    rem_argv[rem_argc++] = strdup(command_name);

    rem_argv[rem_argc++] = "-s";
    rem_argv[rem_argc++] = strdup(PSP_local_name(porth));

    if (arg_maxmsize != DEFAULT_maxmsize) {
        rem_argv[rem_argc++] = "--maxsize";
        snprintf(buf, sizeof(buf), "%d", arg_maxmsize);
        rem_argv[rem_argc++] = strdup(buf);
    }

    if (arg_ocmd) {
        rem_argv[rem_argc++] = "-O";
        rem_argv[rem_argc++] = strdup(arg_ocmd);
    }

    if (arg_ofile) {
        rem_argv[rem_argc++] = "-o";
        rem_argv[rem_argc++] = strdup(arg_ofile);
    }

    if (arg_verbose) {
        rem_argv[rem_argc++] = "-v";
        snprintf(buf, sizeof(buf), "%d", arg_verbose);
        rem_argv[rem_argc++] = strdup(buf);
    }

    if (arg_progress) { rem_argv[rem_argc++] = "-p"; }

    return rem_argc;
}


PSP_PortH_t start_server(void)
{
    PSP_PortH_t porth = PSP_OpenPort(arg_localport);

    if (!porth) {
        fprintf(stderr, "PSP_OpenPort() failed : %s\n", strerror(errno));
        exit(1);
    }

    if (arg_manual) {
        char *rcmd;
        rcmd = get_remote_command(porth);
        fprintf(stderr, "Remote command:\n%s\n", rcmd);
        free(rcmd);
    } else {
        build_remote_argv(porth);
    }

    return porth;
}

typedef struct client_entry_s {
    client_info_t node_info;
    int con_id;
} client_entry_t;


int cmp_client_entry(const void *_arg1, const void *_arg2)
{
    const client_entry_t *c1 = _arg1;
    const client_entry_t *c2 = _arg2;

    if (c1->node_info.node < c2->node_info.node) {
        return 1;
    } else if (c1->node_info.node > c2->node_info.node) {
        return -1;
    } else if (c1->node_info.port < c2->node_info.port) {
        return 1;
    } else if (c1->node_info.port > c2->node_info.port) {
        return -1;
    } else {
        return 0;
    }
}

int assign_clients(PSP_PortH_t porth, int cnt)
{
    client_entry_t *clients;
    int i, ret;

    if (cnt <= 0) { return -1; }

    clients = malloc(sizeof(client_entry_t) * cnt);
    for (i = 0; i < cnt; i++) {
        struct {
            PSP_Header_t head_psp;
            client_info_t info;
        } header;
        PSP_RequestH_t req;

        req = PSP_IReceive(porth, NULL /*buf*/, 0 /*buflen*/, &header.head_psp,
                           sizeof(header) - sizeof(header.head_psp),
                           NULL /* cb */, 0 /*cb_param*/);

        if (arg_manual) {
            fprintf(stderr, "Waiting for client %d (%d)\n", i + 1, cnt);
        }

        PSP_Wait(porth, req);

        if (arg_verbose > 1) {
            struct in_addr addr;
            addr.s_addr = header.info.node;
            fprintf(stderr, "New client from node %s:%d\n", inet_ntoa(addr),
                    header.info.port);
        }
        clients[i].node_info = header.info;
        clients[i].con_id    = header.head_psp.addr.from;
    }

    // Sort all clients by IP address
    qsort(clients, cnt, sizeof(clients[0]), cmp_client_entry);

    for (i = 0; i < cnt; i++) {
        struct {
            PSP_Header_t head_psp;
            client_info_t info;
        } header;
        PSP_RequestH_t req;
        int cur_clientid = clients[i].con_id;
        if (i > 0) {
            header.info = clients[i - 1].node_info;
        } else {
            header.info.node = -1;
            header.info.port = 0;
        }

        // Send Ack (with forward info):

        req = PSP_ISend(porth, NULL, 0, &header.head_psp,
                        sizeof(header) - sizeof(header.head_psp), cur_clientid,
                        0);

        PSP_Wait(porth, req);
    }

    ret = clients[cnt - 1].con_id;

    free(clients);

    return ret;
}


PSP_PortH_t start_client(int *forward_id)
{
    PSP_PortH_t porth;
    int server_id;
    struct {
        PSP_Header_t head_psp;
        client_info_t info;
    } header;

    porth = PSP_OpenPort(PSP_ANYPORT);
    if (!porth) { goto err_psp_open_port; }

    server_id = PSP_Connect_name(porth, arg_server);
    if (server_id < 0) { goto err_psp_connect; }

    /* send my address */
    header.info.node = PSP_GetNodeID();
    header.info.port = PSP_GetPortNo(porth);

    PSP_Wait(porth,
             PSP_ISend(porth, NULL, 0, &header.head_psp,
                       sizeof(header) - sizeof(header.head_psp), server_id, 0));

    /* receive ack from server */
    PSP_Wait(porth, PSP_IReceiveFrom(porth, NULL, 0, &header.head_psp,
                                     sizeof(header) - sizeof(header.head_psp),
                                     NULL, NULL, server_id));
    /* connect the client */
    if (header.info.node != -1) {
        *forward_id = PSP_Connect(porth, header.info.node, header.info.port);
        if (*forward_id < 0) { goto err_psp_connect; }
        if (arg_verbose > 1) {
            struct in_addr addr;
            addr.s_addr = header.info.node;
            fprintf(stderr, "Forward data to client %s:%d)\n", inet_ntoa(addr),
                    header.info.port);
        }
    } else {
        *forward_id = -1;
        if (arg_verbose > 1) {
            fprintf(stderr, "Forward data to client <none>)\n");
        }
    }

    return porth;

err_psp_open_port:
    fprintf(stderr, "PSP_OpenPort(): %s\n", strerror(errno));
    exit(1);
err_psp_connect:
    fprintf(stderr, "PSP_Connect(%s): %s\n", arg_server, strerror(errno));
    exit(1);
}


typedef struct ps_send_info_s {
    PSP_PortH_t porth;
    int dest;
    /* running request: */
    int in_use;
    unsigned int tokens;
    PSP_Header_t head;
    PSP_RequestH_t req;
} ps_send_info_t;

typedef struct ps_recv_info_s {
    PSP_PortH_t porth;
    int src;
    /* running request: */
    int in_use;
    unsigned int tokens;
    PSP_Header_t head;
    PSP_RequestH_t req;
} ps_recv_info_t;

void ps_send_flush(ps_send_info_t *info)
{
    if (info->in_use) {
        PSP_Wait(info->porth, info->req);
        info->in_use = 0;
    }
    if (info->tokens == 0) {
        PSP_Header_t head;
        PSP_RequestH_t req;
        req = PSP_IReceiveFrom(info->porth, NULL, 0, &head, 0, NULL, 0,
                               info->dest);
        PSP_Wait(info->porth, req);
        info->tokens = arg_ntokens;
    }
}

void ps_send_close(ps_send_info_t *info)
{
    PSP_Header_t head;
    PSP_RequestH_t req;

    ps_send_flush(info);
    if (info->dest == -1) { return; }
    req = PSP_IReceiveFrom(info->porth, NULL, 0, &head, 0, NULL, 0, info->dest);
    PSP_Wait(info->porth, req);
}

void ps_send(ps_send_info_t *info, char *buf, unsigned int len)
{
    ps_send_flush(info);
    if (info->dest != -1) {
        info->in_use = 1;
        info->req = PSP_ISend(info->porth, buf, len, &info->head, 0, info->dest,
                              0);
        info->tokens--;
    }
    stat_bytes_tx += len;
}

void ps_send_info_init(ps_send_info_t *info, PSP_PortH_t porth, int dest)
{
    info->porth  = porth;
    info->dest   = dest;
    info->in_use = 0;
    info->tokens = arg_ntokens;

    ps_send(info, NULL, 0);
    info->tokens = arg_ntokens; // dont count the hello
}

unsigned int ps_recv(ps_recv_info_t *info, char *buf, unsigned int len)
{
    PSP_Header_t head;
    PSP_RequestH_t req;
    int rlen;

    req = PSP_IReceiveFrom(info->porth, buf, len, &head, 0, NULL, 0, info->src);
    PSP_Wait(info->porth, req);
    rlen = head.datalen;

    info->tokens--;
    if (info->tokens <= arg_nlowtokens) {
        req = PSP_ISend(info->porth, NULL, 0, &head, 0, info->src, 0);
        PSP_Wait(info->porth, req);
        info->tokens += arg_ntokens;
    }
    return rlen;
}

void ps_recv_close(ps_recv_info_t *info)
{
    PSP_Header_t head;
    PSP_RequestH_t req;

    req = PSP_ISend(info->porth, NULL, 0, &head, 0, info->src, 0);
    PSP_Wait(info->porth, req);
}


void ps_recv_info_init(ps_recv_info_t *info, PSP_PortH_t porth /*, int src*/)
{
    int src;
    // recv Hello to get the src address (from ps_send_info_init)
    PSP_Header_t head;
    PSP_RequestH_t req;

    req = PSP_IReceive(porth, NULL, 0, &head, 0, NULL, 0);
    PSP_Wait(porth, req);
    src = head.addr.from;

    info->porth  = porth;
    info->src    = src;
    /* running request: */
    info->in_use = 0;
    info->tokens = arg_ntokens;
}

void print_stat(int newline)
{
    unsigned long long now;
    double dt;
    now = getusec();
    dt  = (double)(now - stat_time_start) / 1000000.0;
    fprintf(stderr, "%10ld bytes in %7.3f seconds (%7.2f MB/s)    %c",
            stat_bytes_tx, dt, (double)stat_bytes_tx / (1024.0 * 1024.0) / dt,
            newline ? '\n' : '\r');
    fflush(stderr);
}

// volatile
int timer_called = 0;

void timer(int sig)
{
    timer_called = 1;
    /* dont call print_stat/printf from a signal handler! */
}

void set_timer(int first, int interval, void (*timer)(int))
{
    struct itimerval val;

    signal(SIGALRM, timer);

    val.it_interval.tv_sec  = interval;
    val.it_interval.tv_usec = 0;
    val.it_value.tv_sec     = first;
    val.it_value.tv_usec    = 0;

    setitimer(ITIMER_REAL, &val, NULL);
}

void doServer(void)
{
    int forward_id, numClients;
    ps_send_info_t sinfo;
    FILE *input = NULL;
    PSnodes_ID_t node;
    PSP_PortH_t porth;
    char *buf, *buf2;

    buf = malloc(arg_maxmsize);
    if (!buf) {
        perror("malloc(buf)");
        exit(1);
    }
    buf2 = malloc(arg_maxmsize);
    if (!buf2) {
        perror("malloc(buf2)");
        exit(1);
    }

    input = stdin;
    if (arg_ifile) {
        input = fopen(arg_ifile, "r");
        if (!input) {
            fprintf(stderr, "Cant open file '%s' for reading : %s\n", arg_ifile,
                    strerror(errno));
            exit(1);
        }
    } else if (arg_icmd) {
        input = popen(arg_icmd, "r");
        if (!input) {
            fprintf(stderr, "Cant start input command '%s' : %s\n", arg_icmd,
                    strerror(errno));
            exit(1);
        }
    }

    porth = start_server();

    if (arg_manual) {
        numClients = arg_manual;
    } else {
        int clientRank = 1;

        if (arg_hosts) {
            nodeList = getNLFromHosts(arg_hosts);
        } else if (arg_nodes) {
            nodeList = getNLFromNodes(arg_nodes);
        } else {
            nodeList = getNLFromNodes("all");
        }

        if (!nodeList && !arg_manual) {
            fprintf(stderr, "Unknown clients\n");
            exit(1);
        }

        /* Start clients */
        for (node = 0; node < PSC_getNrOfNodes(); node++) {
            if (node == PSC_getMyID()) { continue; }
            if (nodeList[node]) {
                int ret = PSE_spawnAdmin(node, clientRank, rem_argc, rem_argv,
                                         0);
                if (!ret) { clientRank++; }
            }
        }
        numClients = clientRank - 1;
        if (arg_verbose) {
            fprintf(stderr, "Distribute to %d clients\n", numClients);
        }
    }

    forward_id = assign_clients(porth, numClients);
    PSP_StopListen(porth);
    ps_send_info_init(&sinfo, porth, forward_id);

    stat_time_start = getusec();
    // read from stdin, forward to forward_id
    while (1) {
        int len;
        char *tmp;

        len = (int)read(fileno(input), buf, arg_maxmsize);
        if (len <= 0) { break; }

        ps_send(&sinfo, buf, len);
        // swap buffers (ps_send use PSP_ISend. We can read more
        // data, while we transmit the old data.)
        tmp  = buf;
        buf  = buf2;
        buf2 = tmp;

        if (timer_called) {
            print_stat(arg_cp ? 1 : 0);
            timer_called = 0;
        }
    }

    if (arg_ifile) {
        fclose(input);
    } else if (arg_icmd) {
        pclose(input);
    }

    // Send eof:
    ps_send(&sinfo, NULL, 0);
    ps_send_close(&sinfo);

    free(buf);
    free(buf2);
}

void doClient(void)
{
    int forward_id;
    ps_recv_info_t rinfo;
    ps_send_info_t sinfo;
    FILE *output = NULL;
    PSP_PortH_t porth;
    char *buf, *buf2;

    buf = malloc(arg_maxmsize);
    if (!buf) {
        perror("malloc(buf)");
        exit(1);
    }
    buf2 = malloc(arg_maxmsize);
    if (!buf2) {
        perror("malloc(buf2)");
        exit(1);
    }

    output = stdout;

    if (arg_ofile) {
        output = fopen(arg_ofile, "w");
        if (!output) {
            fprintf(stderr, "Cant open file '%s' for writing : %s\n", arg_ofile,
                    strerror(errno));
            exit(1);
        }
    } else if (arg_ocmd) {
        output = popen(arg_ocmd, "w");
        if (!output) {
            fprintf(stderr, "Cant start output command '%s' : %s\n", arg_icmd,
                    strerror(errno));
            exit(1);
        }
    }

    porth = start_client(&forward_id);
    ps_recv_info_init(&rinfo, porth);
    ps_send_info_init(&sinfo, porth, forward_id);
    PSP_StopListen(porth);

    stat_time_start = getusec();
    while (1) {
        int len;
        char *tmp;

        len = ps_recv(&rinfo, buf, arg_maxmsize);
        ps_send(&sinfo, buf, len);

        if (len <= 0) { break; }
        assert(fwrite(buf, 1, len, output) == (unsigned)len);

        tmp  = buf;
        buf  = buf2;
        buf2 = tmp;

        if (timer_called) {
            if (arg_manual) { print_stat(0); }
            timer_called = 0;
        }
    }

    if (arg_ofile) {
        fclose(output);
    } else if (arg_ocmd) {
        pclose(output);
    }
    ps_recv_close(&rinfo);
    ps_send_close(&sinfo);
    free(buf2);
    free(buf);
}

int main(int argc, char **argv)
{
    int rank = 0;

    command_name = argv[0];
    parse_opt(argc, argv);

    if (arg_version) {
        printVersion();
        return 0;
    }

    if (arg_cp) {
        size_t slen = strlen(copy_command_src) + strlen(arg_cp) + 1000;
        char *icmd  = malloc(slen);
        snprintf(icmd, slen, "%s %s", copy_command_src, arg_cp);
        arg_icmd = icmd;
        arg_ocmd = copy_command_dest;

        fprintf(stderr, " input command: %s\n", arg_icmd);
    }

    if (arg_icmd && arg_ifile) {
        fprintf(stderr, "Warning: Ignoring -icmd %s, because -i is set\n",
                arg_icmd);
        arg_icmd = NULL;
    }
    if (arg_ocmd && arg_ofile) {
        fprintf(stderr, "Warning: Ignoring -ocmd %s, because -o is set\n",
                arg_ocmd);
        arg_ocmd = NULL;
    }

    if (PSP_Init() != PSP_OK) {
        fprintf(stderr, "PSP_Init() failed!\n");
        exit(1);
    }

    if (!arg_manual) {
        /* HACK HACK HACK */
        setenv("__PSI_MASTERNODE", "-1", 0);
        setenv("__PSI_MASTERPORT", "-1", 0);
        PSE_initialize();

        rank = PSE_getRank();
    } else if (arg_server) {
        rank = 1;
    }

    if (rank < 0) {
        /* original process, let's spawn rank 0 and become logger */
        setenv("PSI_NOMSGLOGGERDONE", "", 1);
        PSE_spawnAdmin(-1, 0, argc, argv, 0);
    } else if (rank == 0) {
        /* server */
        if (arg_progress) { set_timer(1, 1, timer); }
        doServer();
    } else {
        /* client */
        if (arg_progress && arg_manual) { set_timer(1, 1, timer); }
        doClient();
    }

    if (!arg_manual) { PSI_release(PSC_getMyTID()); }

    if ((!rank || arg_manual) && arg_progress) { print_stat(1); }

    return 0;
}
