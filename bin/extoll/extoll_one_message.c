/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * extoll_one_message: Send one message over extoll interface
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

// Compat stuff for missing Extoll includes:
//typedef struct RMA_Connection_s RMA_Connection;
//typedef struct RMA_Endpoint_s RMA_Endpoint;
//typedef struct RMA_Region_s RMA_Region;

#include "rma.h" /* Extoll librma interface */

#define VERSION "EXTOLL_ONE1.0"

int arg_soffset = 0; // s_buf offset
int arg_roffset = 0; // r_buf offset
int arg_clines = 1; // cachelines
int arg_verbose = 0;

const char *arg_port = "5535";
const char *arg_servername = NULL;
int arg_nokill = 0;

int is_server = 1;

static
void parse_opt(int argc, char **argv)
{
	int c;
	poptContext optCon;
	const char *no_arg;

	struct poptOption optionsTable[] = {
		{ "soffset"  , 's', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_soffset, 0, "s_buf offset", "offset" },
		{ "roffset"  , 'r', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_roffset, 0, "r_buf offset", "offset" },
		{ "clines"  , 'c', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_clines, 0, "cachelines to send", "count" },

		{ "nokill" , 'k', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_nokill, 1, "Dont kill the server afterwards", NULL },

		{ "port" , 'p', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_STRING,
		  &arg_port, 0, "server port to use", "port" },

		{ "verbose"	, 'v', POPT_ARG_NONE,
		  NULL		, 'v', "increase verbosity", NULL },
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext(NULL, argc, (const char **) argv, optionsTable, 0);

	poptSetOtherOptionHelp(optCon, "[serveraddr]");

	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch (c) { // c = poptOption.val;
		case 'v': arg_verbose++; break;
		}
	}

	if (c < -1) { /* an error occurred during option processing */
		fprintf(stderr, "%s: %s\n",
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

//	arg_1 = poptGetArg(optCon);
//	arg_2 = poptGetArg(optCon);
	arg_servername = poptGetArg(optCon);
	is_server = !arg_servername;

	no_arg = poptGetArg(optCon); // should return NULL
	if (no_arg) {
		fprintf(stderr, "%s: %s\n",
			no_arg, poptStrerror(POPT_ERROR_BADOPT));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

	poptFreeContext(optCon);
}


#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

#include <sys/time.h>

static inline
unsigned long getusec(void)
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return (tv.tv_usec+tv.tv_sec*1000000);
}


typedef struct msg_buf
{
	char buf[8192];
} msg_buf_t;


msg_buf_t	*s_buf;
msg_buf_t	*r_buf;
RMA_NLA		remote_rbuf;
RMA_Nodeid	remote_nodeid;
RMA_Vpid	remote_vpid;
RMA_Handle	remote_handle; // The connection from rma_connect

RMA_Port extoll_port;
RMA_Handle extoll_handle;
RMA_Region* extoll_s_region;
RMA_Region* extoll_r_region;

RMA_NLA		my_rbuf;
RMA_Nodeid	my_nodeid;
RMA_Vpid	my_vpid;


typedef struct {
	RMA_NLA		rbuf_nla;
	RMA_Nodeid	nodeid;
	RMA_Vpid	vpid;
} pp_info_msg_t;


static
void extoll_rc_check(int rc, char *msg)
{
	if (rc == RMA_SUCCESS) return;
	rma_perror(rc, msg);
	exit(1);
}


static
void init_bufs(void)
{
	int rc;

	s_buf = valloc(sizeof(*s_buf) + 1); *(char *)&s_buf[1] = 0xee;
	r_buf = valloc(sizeof(*r_buf) + 1); *(char *)&r_buf[1] = 0xee;

	memset(s_buf, 0x11, sizeof(*s_buf));
	memset(r_buf, 0x22, sizeof(*r_buf));

	rc = rma_register(extoll_port, s_buf, sizeof(*s_buf), &extoll_s_region);
	extoll_rc_check(rc, "rma_register() for s_buf");

	rc = rma_register(extoll_port, r_buf, sizeof(*r_buf), &extoll_r_region);
	extoll_rc_check(rc, "rma_register() for r_buf");

	rc = rma_get_nla(extoll_r_region, 0, &my_rbuf);
	extoll_rc_check(rc, "rma_get_nla() for my_rbuf");

	my_nodeid = rma_get_nodeid(extoll_port);
	my_vpid = rma_get_vpid(extoll_port);
}


static
void pp_info_get(pp_info_msg_t *msg)
{
	msg->rbuf_nla = my_rbuf;
	msg->nodeid = my_nodeid;
	msg->vpid = my_vpid;
}


static
void pp_info_set(pp_info_msg_t *msg)
{
	remote_nodeid = msg->nodeid;
	remote_vpid = msg->vpid;
	remote_rbuf = msg->rbuf_nla;
}


static
void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
	printf("Lokal:  nodeid:%8hu vpid:%8hu recvnla: 0x%16lx\n",
	       msg->nodeid, msg->vpid, msg->rbuf_nla);

	fprintf(peer, VERSION " nodeid:%8hu vpid:%8hu recvnla: 0x%lx\n",
		msg->nodeid, msg->vpid, msg->rbuf_nla);
	fflush(peer);
}


static
void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
	int rc;

	rc = fscanf(peer, VERSION " nodeid:%8hu vpid:%8hu recvnla: 0x%lx",
		    &msg->nodeid, &msg->vpid, &msg->rbuf_nla);
	if (rc != 3) error(1, 0, "Parsing error! Only %d fields. Version mismatch?\n", rc);

	printf("Remote: nodeid:%8hu vpid:%8hu recvnla: 0x%16lx\n",
	       msg->nodeid, msg->vpid, msg->rbuf_nla);
}


static
void init(FILE *peer)
{
	int rc;
	pp_info_msg_t lmsg, rmsg;

	rc = rma_open(&extoll_port);
	extoll_rc_check(rc, "rma_open()");

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

	rc = rma_connect(extoll_port, remote_nodeid, remote_vpid, &remote_handle);
	extoll_rc_check(rc, "rma_connect()");

	printf("I'm the %s\n", is_server ? "server" : "client");
}

/* ---------------------------------------------------------- */

static
char *dumpstr(void *buf, int size)
{
    static char *ret=NULL;
    char *tmp;
    int s;
    char *b;
    if (ret) free(ret);
    ret = (char *)malloc(size * 5 + 4);
    tmp = ret;
    s = size; b = (char *)buf;
    for (; s ; s--, b++){
	    tmp += sprintf(tmp, "%02x ", (unsigned char)*b);
    }
    if (0) {
	    *tmp++ = '\'';
	    s = size; b = (char *)buf;
	    for (; s ; s--, b++){
		    /* *tmp++ = isprint(*b) ? *b: '.';*/
		    *tmp++ = ((*b >= 32) && (*b < 127)) ? *b: '.';
	    }
	    *tmp++ = '\'';
    }
    *tmp++ = 0;
    return ret;
}

static
void dump_msg(void *buf, int offset, int size)
{
	while (offset < size) {
		int len = size - offset > 32 ? 32 : size - offset;
		printf("%04x : %s\n", offset, dumpstr(buf + offset, len));
		offset += len;
	}
}


static
void run_server(void)
{
	unsigned i;
	int rc;
	for (i = 0; i < sizeof(*s_buf); i++) s_buf->buf[i] = i;

	rc = rma_post_put_cl(extoll_port, remote_handle, extoll_s_region,
			     arg_soffset, arg_clines,
			     remote_rbuf + arg_roffset,
			     0 /* RMA_COMPLETER_NOTIFICATION */);
	assert(rc == RMA_SUCCESS);

	sleep(2);
	dump_msg(r_buf, 0, 8192 + 1);
	sleep(2);
	dump_msg(r_buf, 0, 8192 + 1);
}


static
void run_client(void)
{
	run_server();
}


/************************************************************
 *
 * Connection establishment via TCP
 */

#define SCALL(func) do {				\
    if ((func) < 0) {					\
	printf( #func ": %s\n", strerror(errno));	\
	exit(1);					\
    }							\
}while (0)

#define INET_ADDR_SPLIT(addr) ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >>  8) & 0xff, (addr) & 0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"


static
FILE *get_peer(void)
{
	int fd;

	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		//.ai_family   = AF_UNSPEC,
		.ai_family   = AF_INET,
		.ai_socktype = SOCK_STREAM
	};
	struct addrinfo *addrinfo;

	int n;
	n = getaddrinfo(arg_servername ? arg_servername : "0", arg_port, &hints, &addrinfo);
	if (n) {
		addrinfo = NULL;
		printf("getaddrinfo() failed: %s\n", gai_strerror(n));
		exit(1);
	}

	if (is_server) {
		int val = 1;
		int listen_fd;
		SCALL(listen_fd = socket(PF_INET, SOCK_STREAM, 0));

		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
			   (void*) &val, sizeof(val));

		SCALL(bind(listen_fd, addrinfo->ai_addr, addrinfo->ai_addrlen));
		SCALL(listen(listen_fd, 1));
		printf("Waiting for connection\n");
		fd = accept(listen_fd, NULL, 0);
	} else {
		struct sockaddr_in *si = (struct sockaddr_in *)addrinfo->ai_addr;
		assert(si->sin_family == AF_INET);
		SCALL(fd = socket(PF_INET, SOCK_STREAM, 0));
		printf("Connect to "INET_ADDR_FORMAT" \n",
		       INET_ADDR_SPLIT(ntohl(si->sin_addr.s_addr)));

		SCALL(connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen));
	}

	if (addrinfo) freeaddrinfo(addrinfo);
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
		run_server();
	} else {
		run_client();
	}

	return 0;
}
