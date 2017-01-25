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
 * extoll_pp_velo.c: PingPong over extolls velo interface
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

#include <velo2.h>

#define VERSION "EXTOLL_VELO_PP1.0"


int arg_loops = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024)
int arg_maxmsize = MAX_MSIZE;
int arg_verbose = 0;
const char *arg_port = "5534";
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
		{ "loops"  , 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_loops , 0, "pp loops", "count" },
		{ "time"  , 't', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxtime, 0, "max time", "ms" },
		{ "maxsize"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxmsize , 0, "maximal messagesize", "size" },

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
	uint32_t	len;
	char		data[MAX_MSIZE];
} msg_buf_t;


msg_buf_t	*s_buf;
msg_buf_t	*r_buf;

velo2_port_t	velo2_port; // by velo2_open()

velo2_nodeid_t	remote_nodeid;
velo2_vpid_t	remote_vpid;
velo2_connection_t remote_connection; // by velo2_connect()

velo2_nodeid_t	my_nodeid;
velo2_vpid_t	my_vpid;


typedef struct {
	velo2_nodeid_t	nodeid;
	velo2_vpid_t	vpid;
} pp_info_msg_t;


static
void extoll_ret_check(enum velo2_ret ret, char *msg)
{
	if (ret == VELO2_RET_SUCCESS) return;
	switch (ret) {
	case VELO2_RET_SUCCESS:
		fprintf(stderr, "%s : operation was successful\n", msg); break;
	case VELO2_RET_ERROR:
		fprintf(stderr, "%s : an error occured\n", msg); break;
	case VELO2_RET_NO_MSG:
		fprintf(stderr, "%s : no valid message\n", msg); break;
	case VELO2_RET_NO_MATCH:
		fprintf(stderr, "%s : no valid message match\n", msg); break;
	case VELO2_RET_ERR_FDOPEN:
		fprintf(stderr, "%s : error during open operation\n", msg); break;
	case VELO2_RET_ERR_MMAP:
		fprintf(stderr, "%s : error during mmap operation\n", msg); break;
	case VELO2_RET_INVALID_MBOX:
		fprintf(stderr, "%s : mailbox id not valid\n", msg); break;
	case VELO2_RET_INVALID_NODE:
		fprintf(stderr, "%s : node id not valid\n", msg); break;
	default:
		fprintf(stderr, "%s : Unknown velo2 error %d\n", msg, ret);
	}
	exit(1);
}


static
void init_bufs(void)
{
	s_buf = valloc(sizeof(*s_buf) + 1); *(char *)&s_buf[1] = 0xeeU;
	r_buf = valloc(sizeof(*r_buf) + 1); *(char *)&r_buf[1] = 0xeeU;

	memset(s_buf->data, 0x11, sizeof(s_buf->data));
	memset(r_buf->data, 0x22, sizeof(r_buf->data));

	my_nodeid = velo2_get_nodeid(&velo2_port);
	my_vpid = velo2_get_vpid(&velo2_port);
}


static
void pp_info_get(pp_info_msg_t *msg)
{
	msg->nodeid = my_nodeid;
	msg->vpid = my_vpid;
}


static
void pp_info_set(pp_info_msg_t *msg)
{
	remote_nodeid = msg->nodeid;
	remote_vpid = msg->vpid;
}


static
void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
	printf("Lokal:  nodeid:%8" SCNu32 " vpid:%8" SCNu32 "\n",
	       msg->nodeid, msg->vpid);

	fprintf(peer, VERSION " nodeid:%8" SCNu32 " vpid:%8" SCNu32 "\n",
		msg->nodeid, msg->vpid);
	fflush(peer);
}


static
void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
	int rc;
	rc = fscanf(peer, VERSION " nodeid:%8" SCNu32 " vpid:%8" SCNu32,
		    &msg->nodeid, &msg->vpid);
	if (rc != 2) error(1, 0, "Parsing error! Only %d fields. Version mismatch?\n", rc);

	printf("Remote: nodeid:%8" SCNu32 " vpid:%8" SCNu32 "\n",
	       msg->nodeid, msg->vpid);
}


static
void init(FILE *peer)
{
	enum velo2_ret ret;
	pp_info_msg_t lmsg, rmsg;

	ret = velo2_open(&velo2_port);
	extoll_ret_check(ret, "velo2_open()");

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

	ret = velo2_connect(&velo2_port, &remote_connection,
			    remote_nodeid, remote_vpid);
	extoll_ret_check(ret, "velo2_connect()");

	printf("I'm the %s\n", is_server ? "server" : "client");
	sleep(1);
}


static inline
void extoll_send(unsigned len)
{
	enum velo2_ret ret;
	unsigned slen;
	char *s;
	s_buf->len = len;

	slen = len + (unsigned)sizeof(s_buf->len);
	s = (char *)s_buf;
	//memcpy(s_buf->buf, r_buf->buf, len);
	while (slen) {
		unsigned next_len = (slen > 64) ? 64 : slen;

		//printf("Send %u next %u rest %u ptr %p\n", len, next_len, slen, s);
		ret = velo2_send(&remote_connection, s,
				 next_len, 0x00, 0);
		extoll_ret_check(ret, "velo2_send()");

		slen -= next_len;
		s += next_len;
	}
}


static inline
unsigned extoll_recv(void)
{
	enum velo2_ret ret;

	uint32_t mlen;
	int rlen;
	uint32_t sourceid;
	uint8_t tag;
	char *r = (char *)r_buf;

	ret = velo2_recv(&velo2_port, r, 64,
			 &mlen, &sourceid, &tag, 0);
	extoll_ret_check(ret, "velo2_recv() 1");
	assert(mlen >= sizeof(r_buf->len));

	r += mlen;
	rlen = r_buf->len + (unsigned)sizeof(r_buf->len) - mlen;

	//printf("Recv1: len %u msglen %u rest %u ptr %p\n", r_buf->len, mlen, rlen, r);

	while (rlen > 0) {
		ret = velo2_recv(&velo2_port, r, 64,
				 &mlen, &sourceid, &tag, 0);
		extoll_ret_check(ret, "velo2_recv() 2");
		//printf("Recv2: len %u msglen %u rest %u ptr %p\n", r_buf->len, mlen, rlen, r);

		r += mlen;
		rlen -= mlen;
		// Warning: mlen is 8 byte alligned which could make rlen negative!
		// assert(rlen >= 0) will fail.
	}
	return r_buf->len;
}


static
void run_pp_server(void)
{
	while (1) {
		unsigned len = extoll_recv();
		extoll_send(len);
	}
}


static
int run_pp_c(int msize, int loops)
{
	int cnt;
	assert(msize <= MAX_MSIZE);

	//printf("Send %d\n", msize);

	for (cnt = 0; cnt < loops; cnt++) {
		unsigned len = msize;
		unsigned rlen;

		extoll_send(len);
		rlen = extoll_recv();
		assert(rlen == len);
	}
	return 0;
}


static
void do_pp_client(void)
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
	for (ms = 0.0/*1.4142135*/; ms < arg_maxmsize;
	     ms = (ms < 128) ? (ms + 1) : (ms * 1.4142135)) {
		unsigned int iloops = (unsigned int)(loops + 0.5);
		msgsize = (unsigned int)(ms + 0.5);

		/* warmup, for sync */
		run_pp_c(1, 2);

		t1 = getusec();
		res = run_pp_c(msgsize, iloops);
		t2 = getusec();

		time = (double)(t2 - t1) / (iloops * 2);
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
			if (loops < 1) loops = 1;
		}
	}

	return;
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
		run_pp_server();
	} else {
		sleep(2);
		do_pp_client();
	}

	return 0;
}
