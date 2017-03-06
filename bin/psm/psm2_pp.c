/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2011 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psm_pp.c: PingPong over QLogics psm interface
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
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
#include <inttypes.h>

#include <psm2.h>
#include <psm2_mq.h>

#define VERSION "PSM2_PP1.0"


int arg_loops = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024)
int arg_maxmsize = MAX_MSIZE;
int arg_verbose = 0;
const char *arg_port = "5538";
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

psm2_ep_t	my_ep;
psm2_mq_t	my_mq;
psm2_epid_t	my_epid;
psm2_uuid_t	my_uuid;

psm2_epid_t	remote_epid;	// from the info message
psm2_epaddr_t	remote_epaddr;	// set by psm_ep_connect(.. remote_epid ...)
psm2_uuid_t	remote_uuid;	// from the info message


typedef struct {
	uint32_t	len; // = sizeof(pp_info_msg_t)
	psm2_uuid_t	uuid;
	psm2_epid_t	epid;
} pp_info_msg_t;


static
void pspsm_ret_check(psm2_error_t ret, char *msg)
{
	if (ret == PSM2_OK) return;

	fprintf(stderr, "%s : %s\n", msg,
		psm2_error_get_string(ret));
	exit(1);
}


#define PSPSM_UUID_FMT							\
	"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:"	\
	"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

#define PSPSM_EPID_FMT	"0x%"PRIx64


#define MQ_FLAGS_NONE  0
#define MQ_TAG	       1ULL
#define MQ_TAGSEL_ALL  0ULL
#define MQ_NO_CONTEXT_PTR   ((void *)NULL)


static
char *pspsm_uuid_str(psm2_uuid_t uuid)
{
	static char uuid_str[16 * 3 + 4];
	snprintf(uuid_str, sizeof(uuid_str), PSPSM_UUID_FMT,
		 uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		 uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
	return uuid_str;
}


static
void pspsm_init_bufs(void)
{
	s_buf = valloc(sizeof(*s_buf) + 1); *(char *)&s_buf[1] = 0xee;
	r_buf = valloc(sizeof(*r_buf) + 1); *(char *)&r_buf[1] = 0xee;

	memset(s_buf->data, 0x11, sizeof(s_buf->data));
	memset(r_buf->data, 0x22, sizeof(r_buf->data));
}


static
void pspsm_init_con(void)
{
	psm2_error_t ret;
	pspsm_init_bufs();

	ret = psm2_ep_open(my_uuid, NULL, &my_ep, &my_epid);
	pspsm_ret_check(ret, "psm2_ep_open()");

	ret = psm2_mq_init(my_ep, PSM2_MQ_ORDERMASK_ALL, NULL, 0, &my_mq);
	pspsm_ret_check(ret, "psm2_mq_init()");
}

#define SEC_IN_NS   1000000000ULL

static
void pspsm_connect(void)
{
	psm2_error_t ret;
	psm2_error_t errors[1];

	ret = psm2_ep_connect(my_ep, 1, &remote_epid, NULL, errors,
			      &remote_epaddr, 0);
	pspsm_ret_check(ret, "psm2_ep_connect()");
}


static
void pspsm_init_uuid(void)
{
	memset(my_uuid, 42, sizeof(my_uuid));
	// uuid[0] = getuid();
}


static
void pp_info_get(pp_info_msg_t *msg)
{
	msg->len = sizeof(*msg);
	memcpy(msg->uuid, my_uuid, sizeof(msg->uuid));
	msg->epid = my_epid;
}


static
void pp_info_set(pp_info_msg_t *msg)
{
	assert(sizeof(*msg) == msg->len);
	memcpy(remote_uuid, msg->uuid, sizeof(remote_uuid));
	remote_epid = msg->epid;
}


static
void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
	printf("Lokal:  uuid:%s epid:" PSPSM_EPID_FMT "\n",
	       pspsm_uuid_str(msg->uuid), msg->epid);

	fprintf(peer, VERSION " len:%d uuid:%s epid:" PSPSM_EPID_FMT "\n",
		msg->len, pspsm_uuid_str(msg->uuid), msg->epid);
	fflush(peer);
}


static
void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
	int rc;

	rc = fscanf(peer, VERSION " len:%d uuid:" PSPSM_UUID_FMT " epid:" PSPSM_EPID_FMT,
		    &msg->len,
		    &msg->uuid[0], &msg->uuid[1], &msg->uuid[2], &msg->uuid[3],
		    &msg->uuid[4], &msg->uuid[5], &msg->uuid[6], &msg->uuid[7],
		    &msg->uuid[8], &msg->uuid[9], &msg->uuid[10], &msg->uuid[11],
		    &msg->uuid[12], &msg->uuid[13], &msg->uuid[14], &msg->uuid[15],
		    &msg->epid);
	if (rc != 18) error(1, 0, "Parsing error! Only %d from 18 fields. Version mismatch?\n", rc);

	printf("Remote: uuid:%s epid:" PSPSM_EPID_FMT "\n",
	       pspsm_uuid_str(msg->uuid), msg->epid);
}


static
void init(FILE *peer)
{
	psm2_error_t ret;
	pp_info_msg_t lmsg, rmsg;
	int verno_minor = PSM2_VERNO_MINOR;
	int verno_major = PSM2_VERNO_MAJOR;

	ret = psm2_init(&verno_major, &verno_minor);
	pspsm_ret_check(ret, "psm2_init()");

	// Init uuid:
	pspsm_init_uuid();

	pspsm_init_con();

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
	pspsm_connect();

	printf("I'm the %s\n", is_server ? "server" : "client");
	sleep(1);
}


static inline
void pspsm_send(unsigned len)
{
	psm2_error_t ret;
	unsigned slen;

	s_buf->len = len;

	slen = len + sizeof(s_buf->len);

	//memcpy(s_buf->buf, r_buf->buf, len);

	ret = psm2_mq_send(my_mq, remote_epaddr,
			   MQ_FLAGS_NONE,  /* no flags, not a sync send */
			   MQ_TAG, /* don't care tag */
			   s_buf, slen);
	pspsm_ret_check(ret, "psm_mq_send()");
}


static inline
unsigned pspsm_recv(void)
{
	psm2_error_t ret;
	psm2_mq_req_t req;
	psm2_mq_status_t status;

	ret = psm2_mq_irecv(my_mq,
			    MQ_TAG, /* don't care tag */
			    MQ_TAGSEL_ALL, /* always successfully tag match */
			    MQ_FLAGS_NONE, /* no flags */
			    r_buf,
			    sizeof(*r_buf),
			    MQ_NO_CONTEXT_PTR,
			    &req);
	pspsm_ret_check(ret, "psm2_mq_irecv");

	ret = psm2_mq_wait(&req, &status);
	pspsm_ret_check(ret, "psm2_mq_wait");
	pspsm_ret_check(status.error_code, "psm_mq_wait->status");

	return r_buf->len;
}


static
void run_pp_server(void)
{
	while (1) {
		unsigned len = pspsm_recv();
		pspsm_send(len);
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

		pspsm_send(len);
		rlen = pspsm_recv();
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
		unsigned int iloops = loops;
		msgsize = ms + 0.5;

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
			double t = (t2 - t1) / 1000;
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
