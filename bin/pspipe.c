/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005,2006 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
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

#include "psport4.h"
#include "psport_util.h"

int arg_verbose=0;
const char *arg_server = NULL;

int arg_localport=PSP_ANYPORT;
#define DEFAULT_maxmsize 65536
int arg_maxmsize = DEFAULT_maxmsize;
int arg_cnt = 1;
const char *arg_ocmd = NULL;
const char *arg_ofile = NULL;
const char *arg_icmd = NULL;
const char *arg_ifile = NULL;

const char *arg_cp = NULL;

unsigned int arg_ntokens = 16;
unsigned int arg_nlowtokens = 3;

unsigned long stat_bytes_tx = 0;
unsigned long long stat_time_start;

const char *command_name = "pspipe";

const char *copy_command_src  = "/bin/tar cvPf -";
const char *copy_command_dest = "/bin/tar xPf -";

//char *arg_ifile = NULL; ToDo:
//char *arg_icmd = NULL; ToDo:

#define MAX_XHEADER 8
#define _STR(arg) #arg
#define STR(arg) _STR(arg)

void parse_opt(int argc, char **argv)
{
    int c;            /* used for argument parsing */
    poptContext optCon;   /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
	{ "cp"  , 'C', POPT_ARG_STRING, &arg_cp , 0,
	  "copy files with /bin/tar", "files" },

	{ "ocmd"  , 'O', POPT_ARG_STRING, &arg_ocmd , 0,
	  "output command", "cmd" },
	{ "output" , 'o', POPT_ARG_STRING, &arg_ofile , 0,
	  "output file\t(default stdout)", "filename" },

	{ "icmd"  , 'I', POPT_ARG_STRING, &arg_icmd , 0,
	  "input command", "cmd" },
	{ "input", 'i', POPT_ARG_STRING, &arg_ifile , 0,
	  "input file\t(default stdin)", "filename" },


	{ "verbose"  , 'v', POPT_ARG_INT, &arg_verbose , 0,
	  "be more verbose", "level" },
	{ "server" , 's', POPT_ARG_STRING, &arg_server, 0,
	  "server address", "address" },
	{ "lport" , 'l', POPT_ARG_INT, &arg_localport, 0,
	  "local port", "port" },

	{ "cnt" , 'c', POPT_ARG_INT, &arg_cnt, 0,
	  "#clients\t(default 1)", "count" },

	{ "maxsize"  , 0, POPT_ARG_INT, &arg_maxmsize , 0,
	  "maximal messagesize\t(default " STR(DEFAULT_maxmsize) ")", "size" },

	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };

    optCon = poptGetContext(NULL, argc,(const char **) argv, optionsTable, 0);

    if (argc < 1) {
	poptPrintUsage(optCon, stderr, 0);
	exit(1);
    }

    /* Now do options processing, get portname */
    while ((c = poptGetNextOpt(optCon)) >= 0) {

    }

    if (c < -1) {
	/* an error occurred during option processing */
	fprintf(stderr, "%s: %s\n",
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
		poptStrerror(c));
	poptPrintHelp(optCon, stderr, 0);
	exit(1);
    }

    poptFreeContext(optCon);
}

#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

static inline
unsigned long long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_usec+tv.tv_sec*1000000LL);
}


typedef struct client_info_s {
    int32_t node;
    int32_t port;
} client_info_t;


char *append(char *str1, const char *str2)
{
    if (!str1) {
	return strdup(str2);
    } else {
	unsigned int len1 = strlen(str1);
	str1 = realloc(str1, strlen(str1) + strlen(str2) + 1);
	strcpy(str1 + len1, str2);
	return str1;
    }
}


char *get_remote_command(PSP_PortH_t porth)
{
    char *res = NULL;
    char buf[30];
    res = append(res, command_name);

    res = append(res, " -s ");
    res = append(res, PSP_local_name(porth));

    if (arg_maxmsize != DEFAULT_maxmsize) {
	snprintf(buf, sizeof(buf), " --maxsize %d", arg_maxmsize);
	res = append(res, buf);
    }

    if (arg_ocmd) {
	res = append(res, " --ocmd '");
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

    return res;
}


PSP_PortH_t start_server(void)
{
    PSP_PortH_t porth;
    char *rcmd;
    // Iam the server
    porth = PSP_OpenPort(arg_localport);
    if (!porth) goto err_psp_open_port;

    rcmd = get_remote_command(porth);
    fprintf(stderr, "Remote command:\n%s\n", rcmd);
    free(rcmd);

    return porth;
    /* --- */
 err_psp_open_port:
    fprintf(stderr, "PSP_OpenPort() failed : %s\n", strerror(errno));
    exit(1);
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
    } else return 0;
}

int assign_clients(PSP_PortH_t porth, int cnt)
{
    client_entry_t *clients = malloc(sizeof(client_entry_t) * cnt);
    int i;

    for (i = 0; i < cnt; i++) {
	struct {
	    PSP_Header_t head_psp;
	    client_info_t info;
	} header;
	PSP_RequestH_t req;

	req = PSP_IReceive(porth, NULL /*buf*/, 0 /*buflen*/,
			   &header.head_psp, sizeof(header) - sizeof(header.head_psp) /* xheaderlen */,
			   NULL /* cb */, 0/*cb_param*/);

	fprintf(stderr, "Waiting for clients %d (%d)\n", i + 1, cnt);

	PSP_Wait(porth, req);

	if (arg_verbose) fprintf(stderr, "New client from node %u.%u.%u.%u:%d\n",
				 //header.head_psp.addr.from,
				 HIPQUAD(header.info.node),
				 header.info.port);

	clients[i].node_info = header.info;
	clients[i].con_id = header.head_psp.addr.from;
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

	req = PSP_ISend(porth, NULL, 0,
			&header.head_psp, sizeof(header) - sizeof(header.head_psp) /* xheaderlen */,
			cur_clientid, 0);

	PSP_Wait(porth, req);
    }

    return cnt > 0 ? clients[cnt - 1].con_id : -1;
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
    if (!porth) goto err_psp_open_port;

    server_id = PSP_Connect_name(porth, arg_server);
    if (server_id < 0) goto err_psp_connect;

    /* send my address */
    header.info.node = PSP_GetNodeID();
    header.info.port = PSP_GetPortNo(porth);

    PSP_Wait(porth,
	     PSP_ISend(porth, NULL, 0,
		       &header.head_psp, sizeof(header) - sizeof(header.head_psp),
		       server_id, 0));

    /* receive ack from server */
    PSP_Wait(porth,
	     PSP_IReceiveFrom(porth, NULL, 0,
			      &header.head_psp, sizeof(header) - sizeof(header.head_psp),
			      NULL, NULL, server_id));
    /* connect the client */
    if (header.info.node != -1) {
	*forward_id = PSP_Connect(porth, header.info.node, header.info.port);
	if (*forward_id < 0) goto err_psp_connect;
	if (arg_verbose) fprintf(stderr, "Forward data to client %u.%u.%u.%u:%d)\n",
				 //header.head_psp.addr.from,
				 HIPQUAD(header.info.node),
				 header.info.port);
    } else {
	*forward_id = -1;
	if (arg_verbose) fprintf(stderr, "Forward data to client <none>)\n");
    }

    return porth;
    /* --- */
 err_psp_open_port:
    fprintf(stderr, "PSP_OpenPort() failed!\n");
    exit(1);
 err_psp_connect:
    fprintf(stderr, "PSP_Connect(%s) failed : %s\n", arg_server, strerror(errno));
    exit(1);
}


typedef struct ps_send_info_s {
    PSP_PortH_t	porth;
    int		dest;
    /* running request: */
    int		in_use;
    unsigned int	tokens;
    PSP_Header_t	head;
    PSP_RequestH_t	req;
} ps_send_info_t;

typedef struct ps_recv_info_s {
    PSP_PortH_t	porth;
    int		src;
    /* running request: */
    int		in_use;
    unsigned int	tokens;
    PSP_Header_t	head;
    PSP_RequestH_t	req;
} ps_recv_info_t;

void ps_send_flush(ps_send_info_t *info)
{
    if (info->in_use) {
	PSP_Wait(info->porth, info->req);
	info->in_use = 0;
    }
    if (info->tokens == 0) {
	PSP_Header_t	head;
	PSP_RequestH_t req;
	//fprintf(stderr,"wait for token \n");
	req = PSP_IReceiveFrom(info->porth, NULL, 0, &head, 0, NULL, 0, info->dest);
	PSP_Wait(info->porth, req);
	//fprintf(stderr,"wait for token done\n");
	info->tokens = arg_ntokens;
    }
}

void ps_send_close(ps_send_info_t *info)
{
    PSP_Header_t	head;
    PSP_RequestH_t req;

    ps_send_flush(info);

    if (info->dest == -1) return;
    //fprintf(stderr,"wait for token \n");
    req = PSP_IReceiveFrom(info->porth, NULL, 0, &head, 0, NULL, 0, info->dest);
    PSP_Wait(info->porth, req);
}

void ps_send(ps_send_info_t *info, char *buf, unsigned int len)
{
    ps_send_flush(info);

    if (info->dest != -1) {
	info->in_use = 1;
	info->req = PSP_ISend(info->porth, buf, len, &info->head, 0, info->dest, 0);
	info->tokens --;
    }
    stat_bytes_tx += len;
}

void ps_send_info_init(ps_send_info_t *info, PSP_PortH_t porth, int dest)
{
    info->porth = porth;
    info->dest = dest;
    info->in_use = 0;

    info->tokens = arg_ntokens;

    // Say hello
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

    info->tokens --;
    if (info->tokens <= arg_nlowtokens) {
	//fprintf(stderr,"send token \n");
	req = PSP_ISend(info->porth, NULL, 0, &head, 0, info->src, 0);
	PSP_Wait(info->porth, req);
	//fprintf(stderr,"send token done\n");
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


void ps_recv_info_init(ps_recv_info_t *info, PSP_PortH_t porth/*, int src*/)
{
    int src;
    // recv Hello to get the src address (from ps_send_info_init)
    PSP_Header_t head;
    PSP_RequestH_t req;

    req = PSP_IReceive(porth, NULL, 0, &head, 0, NULL, 0);
    PSP_Wait(porth, req);
    src = head.addr.from;

    // init

    info->porth = porth;
    info->src = src;
    /* running request: */
    info->in_use = 0;
    info->tokens = arg_ntokens;

}

void print_stat(int newline)
{
    unsigned long long now;
    double dt;
    now = getusec();
    dt = (now - stat_time_start) / 1000000.0;
    fprintf(stderr, "%10ld bytes in %7.3f seconds (%7.2f MB/s)    %c",
	    stat_bytes_tx, dt,
	    stat_bytes_tx / (1024.0 * 1024.0) / dt,
	    newline ? '\n' : '\r');
    fflush(stderr);
}


//volatile
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

	val.it_interval.tv_sec = interval;
	val.it_interval.tv_usec = 0;
	val.it_value.tv_sec = first;
	val.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &val, NULL);
}


int main(int argc, char **argv)
{
    char *buf, *buf2;
    PSP_PortH_t porth;

    command_name = argv[0];

    parse_opt(argc, argv);

    if (arg_cp) {
	unsigned int slen = strlen(copy_command_src) + strlen(arg_cp) + 1000;
	char *icmd = malloc(slen);
	snprintf(icmd, slen,"%s %s", copy_command_src, arg_cp);
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


    if (PSP_Init() != PSP_OK) goto err_psp_init;

    buf = malloc(arg_maxmsize);
    if (!buf) { perror("malloc"); exit(1); }

    buf2 = malloc(arg_maxmsize);
    if (!buf2) { perror("malloc"); exit(1); }

    if (arg_verbose > 1) {
	set_timer(1, 1 ,timer);
    }

    if (arg_server == NULL) {
	// I am the server
	int forward_id;
	ps_send_info_t sinfo;
	FILE *input = NULL;

	input = stdin;

	if (arg_ifile) {
	    input = fopen(arg_ifile, "r");
	    if (!input) {
		fprintf(stderr, "Cant open file '%s' for reading : %s\n", arg_ifile, strerror(errno));
		exit(1);
	    }
	} else if (arg_icmd) {
	    input = popen(arg_icmd, "r");
	    if (!input) {
		fprintf(stderr, "Cant start input command '%s' : %s\n", arg_icmd, strerror(errno));
		exit(1);
	    }
	}


	porth = start_server();

	forward_id = assign_clients(porth, arg_cnt);

	PSP_StopListen(porth);

	ps_send_info_init(&sinfo, porth, forward_id);

	stat_time_start = getusec();
	// read from stdin, forward to forward_id
	while (1) {
	    int len;
	    char *tmp;
	    // fprintf(stderr, "Tokens s:%3d\n", sinfo.tokens);

	    len = read(fileno(input), buf, arg_maxmsize);
	    if (len <= 0) break;

	    ps_send(&sinfo, buf, len);
	    // swap buffers (ps_send use PSP_ISend. We can read more
	    // data, while we transmit the old data.)
	    tmp = buf; buf = buf2; buf2 = tmp;

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

	//fprintf(stderr, "Done\n");
    } else {
	// I am a client
	int forward_id;
	ps_recv_info_t rinfo;
	ps_send_info_t sinfo;
	FILE *output = NULL;

	output = stdout;

	if (arg_ofile) {
	    output = fopen(arg_ofile, "w");
	    if (!output) {
		fprintf(stderr, "Cant open file '%s' for writing : %s\n", arg_ofile, strerror(errno));
		exit(1);
	    }
	} else if (arg_ocmd) {
	    output = popen(arg_ocmd, "w");
	    if (!output) {
		fprintf(stderr, "Cant start output command '%s' : %s\n", arg_icmd, strerror(errno));
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

	    //fprintf(stderr, "Tokens s:%3d r:%3d\n", sinfo.tokens, rinfo.tokens);

	    len = ps_recv(&rinfo, buf, arg_maxmsize);

	    ps_send(&sinfo, buf, len);

	    if (len <= 0) break;
	    assert(fwrite(buf, 1, len, output) == (unsigned) len);

	    tmp = buf; buf = buf2; buf2 = tmp;

	    if (timer_called) {
		print_stat(0);
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
	//fprintf(stderr, "Done\n");
    }

    if (arg_verbose) {
	print_stat(1);
    }

    free(buf);
    free(buf2);

    return 0;
    /* --- */
 err_psp_init:
    fprintf(stderr, "PSP_Init() failed!\n");
    exit(1);
    /* --- */
}
