/*
 * ParaStation
 *
 * Copyright (C) 2008,2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
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
#include <error.h>

#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_env.h"

int arg_loops = 1024;
int arg_maxtime = 3000;
int arg_maxmsize = 4 * 1024 * 1024;
int arg_run_once = 0;
const char *arg_port = "5534";
int arg_poll_char = 0;
int arg_verbose = 0;
int arg_nokill = 0;

//int arg_histo = 0;
const char *arg_servername = NULL;

int is_client;

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

		{ "port" , 'p', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_STRING,
		  &arg_port, 0, "server port to use", "port" },

//		{ "histo" , 'i', POPT_ARGFLAG_OR | POPT_ARG_VAL,
//		  &arg_histo, 1, "Measure each ping pong", NULL },

		{ "once" , '1', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_run_once, 1, "stop after one client", NULL },

		{ "char" , 'c', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_poll_char, 1, "poll on a char instead of uint32", NULL },

		{ "nokill" , 'k', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_nokill, 1, "Dont kill the server afterwards", NULL },

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
		//default: fprintf(stderr, "unhandled popt value %d\n", c); break;
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

	no_arg = poptGetArg(optCon); // should return NULL
	if (no_arg) {
		fprintf(stderr, "%s: %s\n",
			no_arg, poptStrerror(POPT_ERROR_BADOPT));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

	poptFreeContext(optCon);
}


/* !!!! C Source include !!! */
#define perf_add(id) do {} while (0)
void *pscom_malloc(unsigned size) {
	return malloc(size);
}

void pscom_free(void *ptr) {
	free(ptr);
}

#include "psoib.c"
pscom_t pscom = {
	/* parameter from environment */
	.env = PSCOM_ENV_defaults,
	/* statistic */
	.stat = {
		.reqs = 0,
		.gen_reqs = 0,
		.gen_reqs_used = 0,
		.progresscounter = 0,
		.progresscounter_check = 0,
	},
};


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


static
void psoib_error(const char *msg)
{
	fprintf(stderr, "%s : %s", msg, psoib_err_str ? psoib_err_str : "???");
	exit(1);
}



#define PP_MTU		(2*1024)
#define PP_PAYLOAD	(PP_MTU - sizeof(pp_msg_header_t))
#define PP_SENDQ_SIZE	psoib_sendq_size
#define PP_RECVQ_SIZE	psoib_recvq_size


typedef struct {
	uint32_t	src;
	uint32_t	dest;
	uint32_t	seqno;
	uint32_t	ackno;
	uint32_t	size;
} pp_msg_header_t;


typedef struct {
	pp_msg_header_t header;
	char data[PP_PAYLOAD];
} pp_msg_t;


typedef struct {
	ringbuf_t send;
	ringbuf_t recv;
	unsigned sends_uncomleted; // count send WRs in progress
	unsigned int recv_posted; // count posted receives
	unsigned int recv_done; // count receives

	struct ibv_qp *qp;
} pp_endpoint_t;


typedef struct {
	uint32_t	qp_num; // remote qp number
	struct ibv_ah	*ah;
} pp_con_t;


pp_endpoint_t pp_ep_local;


static
void _pp_post_recv(void)
{
	pp_msg_t *msg = ((pp_msg_t*)pp_ep_local.recv.bufs.ptr) +
		((pp_ep_local.recv.pos +
		  pp_ep_local.recv_posted) % PP_RECVQ_SIZE);

	struct ibv_sge list = {
		.addr	= (uintptr_t)msg,
		.length = PP_MTU,
		.lkey	= pp_ep_local.recv.bufs.mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id	    = 0x6731, // ID only
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;
	int rc;

	assert(pp_ep_local.recv_posted < PP_RECVQ_SIZE);

	rc = ibv_post_recv(pp_ep_local.qp, &wr, &bad_wr);

	if (rc) error(1, errno, "ibv_post_recv()");

	pp_ep_local.recv_posted++;
}


static
void pp_post_recvs(void)
{
	unsigned i;
	for (i = pp_ep_local.recv_posted; i < PP_RECVQ_SIZE; i++) {
		_pp_post_recv();
	}
}


static
void pp_progress(void)
{
	hca_info_t *hca_info = &default_hca;

	struct ibv_wc wc;
	int rc;

	rc = ibv_poll_cq(hca_info->cq, 1, &wc);

	if (rc == 1) {
		// handle IBV_WC_RECV with a fast "if", other wc.opcode with "switch".

		if (wc.opcode == IBV_WC_RECV) {
			if (wc.status != IBV_WC_SUCCESS) {
				error(1, 0, "ibv_poll_cq() : IBV_WC_RECV with status %d",
				      wc.status);
			}
			pp_ep_local.recv_done++;
		} else switch (wc.opcode) {
			case IBV_WC_SEND:
				if (wc.status != IBV_WC_SUCCESS) {
					error(1, 0, "ibv_poll_cq() : IBV_WC_SEND with status %d",
					      wc.status);
				}
				pp_ep_local.sends_uncomleted--;
				break;
			default:
				error(1, 0, "ibv_poll_cq() : Unknown opcode: %d", wc.opcode);
			}
	}
}


void pp_recv(void)
{
	pp_post_recvs();
	while (!pp_ep_local.recv_done) {
		pp_progress();
	}

	// Ack the receive:
	pp_ep_local.recv_done--;
	pp_ep_local.recv_posted--;
}


static
void pp_send(pp_con_t *con, void *data, unsigned len)
{
	assert(len <= PP_PAYLOAD);

	// Busywaiting for a free send queue
	while (pp_ep_local.sends_uncomleted >= PP_SENDQ_SIZE) {
		pp_progress();
	}

	pp_msg_t *msg = ((pp_msg_t*)pp_ep_local.send.bufs.ptr) +
		pp_ep_local.send.pos;

	struct ibv_sge list = {
		.addr	= (uintptr_t) msg,
		.length = sizeof(msg->header) + len,
		.lkey	= pp_ep_local.send.bufs.mr->lkey
	};
	struct ibv_send_wr wr = {
		.wr_id	    = 0x6731, // ID only
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IBV_WR_SEND,
		.send_flags = IBV_SEND_SIGNALED,
		.wr         = {
			.ud = {
				 .ah          = con->ah,
				 .remote_qpn  = con->qp_num,
				 .remote_qkey = 0x11111111
			 }
		}
	};
	struct ibv_send_wr *bad_wr;
	int rc;

	// ToDo: Init header
	memcpy(msg->data, data, len);

	rc = ibv_post_send(pp_ep_local.qp, &wr, &bad_wr);
	if (rc) error(1, errno, "ibv_post_send()");

	pp_ep_local.send.pos = (pp_ep_local.send.pos + 1) % PP_SENDQ_SIZE;
	pp_ep_local.sends_uncomleted++;
}

static
void pp_init_endpoint(hca_info_t *hca_info, port_info_t *port_info)
{
	int rc;
	struct ibv_qp *qp;

	/* Send buffers */
	pp_ep_local.send.pos = 0;
	pp_ep_local.sends_uncomleted = 0;

	rc = psoib_vapi_alloc(hca_info, PP_MTU * PP_SENDQ_SIZE,
			      0, &pp_ep_local.send.bufs);
	if (rc) psoib_error("psoib_vapi_alloc(sendq)");


	/* Receive buffers */
	pp_ep_local.recv.pos = 0;
	pp_ep_local.recv_posted = 0;
	pp_ep_local.recv_done = 0;

	rc = psoib_vapi_alloc(hca_info, PP_MTU * PP_RECVQ_SIZE,
			      IBV_ACCESS_LOCAL_WRITE, &pp_ep_local.recv.bufs);
	if (rc) psoib_error("psoib_vapi_alloc(recvq)");

	/* UD queue pair */
	{
		struct ibv_qp_init_attr attr = {
			.send_cq = hca_info->cq,
			.recv_cq = hca_info->cq,
			.cap     = {
				.max_send_wr  = PP_SENDQ_SIZE,
				.max_recv_wr  = PP_RECVQ_SIZE,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_UD,
		};

		qp = ibv_create_qp(hca_info->pd, &attr);
		if (!qp) error(1, errno, "ibv_create_qp()");
	}

	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port_info->port_num,
			.qkey            = 0x11111111
		};

		rc = ibv_modify_qp(qp, &attr,
				   IBV_QP_STATE              |
				   IBV_QP_PKEY_INDEX         |
				   IBV_QP_PORT               |
				   IBV_QP_QKEY);
		if (rc) error(1, errno, "ibv_modify_qp(IBV_QPS_INIT)");
	}

	pp_ep_local.qp = qp;

	/* Post receive requests before moving to rtr and rts */
	pp_post_recvs();


	/* init -> rtr */
	{
		struct ibv_qp_attr attr = {
			.qp_state		= IBV_QPS_RTR
		};

		rc = ibv_modify_qp(qp, &attr, IBV_QP_STATE);
		if (rc) error(1, errno, "ibv_modify_qp(IBV_QPS_RTR)");
	}
	/* rtr -> rts */
	{
		struct ibv_qp_attr attr = {
			.qp_state		= IBV_QPS_RTS,
			.sq_psn			= 0 /* my packet seqno */
		};

		rc = ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN);
		if (rc) error(1, errno, "ibv_modify_qp(IBV_QPS_RTS)");
	}
}


static
void pp_connect(pp_con_t *con, uint16_t lid, uint32_t qp_num)
{
	con->qp_num = qp_num;

	{
		hca_info_t *hca_info = &default_hca;
		port_info_t *port_info = &default_port;

		struct ibv_ah_attr ah_attr = {
			.is_global     = 0,
			.dlid          = lid,
			.sl            = 0, // service level
			.src_path_bits = 0,
			.port_num      = port_info->port_num
		};

		con->ah = ibv_create_ah(hca_info->pd, &ah_attr);
		if (!con->ah) error(1, errno, "ibv_create_ah()");
	}
}


#define VERSION "OPENIB_UD_PP1.0"

typedef struct {
	uint32_t	qp_num;
	uint16_t	lid;
} pp_info_msg_t;


static
void pp_info_get(pp_info_msg_t *msg)
{
	assert(pp_ep_local.qp);

	msg->qp_num = pp_ep_local.qp->qp_num;
	msg->lid = default_port.lid;
}


static
void pp_info_write(FILE *peer, pp_info_msg_t *msg)
{
	printf("Lokal:  lid:%u qp:%u\n",
	       msg->lid, msg->qp_num);

	fprintf(peer, VERSION " lid:%u qp:%u pollchar:%d\n",
		msg->lid, msg->qp_num,
		arg_poll_char);
	fflush(peer);
}


static
void pp_info_read(FILE *peer, pp_info_msg_t *msg)
{
	int rc;
	unsigned a1, a2;

	rc = fscanf(peer, VERSION " lid:%u qp:%u pollchar:%d",
		    &a1, &a2,
		    &arg_poll_char);

	msg->lid = a1;
	msg->qp_num = a2;

	printf("Remote: lid:%u qp:%u pollchar:%d\n",
	       msg->lid, msg->qp_num,
	       arg_poll_char);

	if (rc != 3) error(1, 0, "Parsing error! Only %d fields\n", rc);
}


static
void pscom_openib_init(FILE *peer, pp_con_t *con)
{
	pp_info_msg_t lmsg, rmsg;
	int rc;
	pscom.env.debug = arg_verbose;
	pscom_env_get_int(&pscom.env.debug, ENV_DEBUG);
	psoib_debug = pscom.env.debug;

	pscom_env_get_str(&psoib_hca, ENV_OPENIB_HCA);
	pscom_env_get_uint(&psoib_port, ENV_OPENIB_PORT);
	pscom_env_get_uint(&psoib_path_mtu, ENV_OPENIB_PATH_MTU);
	pscom_env_get_uint(&psoib_sendq_size, ENV_OPENIB_SENDQ_SIZE);
	pscom_env_get_uint(&psoib_recvq_size, ENV_OPENIB_RECVQ_SIZE);
	pscom_env_get_uint(&psoib_compq_size, ENV_OPENIB_COMPQ_SIZE);
	psoib_pending_tokens = psoib_pending_tokens_suggestion();
	pscom_env_get_uint(&psoib_pending_tokens, ENV_OPENIB_PENDING_TOKENS);

	if (psoib_sendq_size + psoib_recvq_size > psoib_compq_size) {
		psoib_compq_size = psoib_sendq_size + psoib_recvq_size;
		printf("Increase cq size to %d\n", psoib_compq_size);
	}

	rc = psoib_init();
	if (rc) psoib_error("psoib_init()");

	/* Initialize send and receive queues */
	pp_init_endpoint(&default_hca, &default_port);

	/* Get local peer information */
	pp_info_get(&lmsg);

	if (is_client) {
		pp_info_write(peer, &lmsg);
		pp_info_read(peer, &rmsg);
	} else {
		pp_info_read(peer, &rmsg);
		pp_info_write(peer, &lmsg);
	}

	/* Connect */
	pp_connect(con, rmsg.lid, rmsg.qp_num);
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


FILE *get_peer(int passive)
{
	int fd;

	struct addrinfo hints = {
		.ai_flags = AI_CANONNAME,
		.ai_family   = AF_UNSPEC,
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

	if (passive) {
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
		SCALL(fd = socket(PF_INET, SOCK_STREAM, 0));

		SCALL(connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen));
	}

	if (addrinfo) freeaddrinfo(addrinfo);
	return fdopen(fd, "a+");
}


/************************************************************
 *
 * Ping Pong benchmark code
 */

static char *abuffer;
const unsigned abuffer_size = 16 * 1024 * 1024;

pp_con_t pp_con;

static inline
int x_recv(void)
{
//	printf("recv start\n");
	pp_recv();
//	printf("recv done\n");
	return 1;
}


static inline
void x_send(unsigned msgsize)
{
//	printf("send start %u\n", msgsize);
	pp_send(&pp_con, abuffer, msgsize);
//	printf("send done\n");
}


static
void run_pp_server(void)
{
	while (1) {
		int len;
		len = x_recv();
		x_send(len);
	}
}


static
int run_pp_c(int msize, int loops)
{
	int cnt;
	for (cnt = 0; cnt < loops; cnt++) {
		x_send(msize);
		x_recv();
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

	if (1) {
		printf("Warning! This is not a ping pong with msize Messagesize!!!\n");
		printf("Server only sends 1 byte back!\n");
	}
	printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
	printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
	for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
		unsigned int iloops = loops;
		msgsize = ms + 0.5;

		//if (((unsigned)msgsize < 4) && !arg_poll_char) continue;

		//if (msgsize >= IB_MTU * psoib_sendq_size) break;
		//if (msgsize >= IB_MTU * psoib_recvq_size) break;
		//if (arg_pscom && (unsigned)msgsize > IB_MTU_PAYLOAD) break;
		if ((unsigned)msgsize > PP_PAYLOAD) break;

		/* warmup, for sync */
		run_pp_c(4, 2);

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




int main(int argc, char **argv)
{
	FILE *peer;

	parse_opt(argc, argv);
	is_client = !!arg_servername;

	peer = get_peer(!is_client);
	pscom_openib_init(peer, &pp_con);

	abuffer = malloc(abuffer_size);
	memset(abuffer, 24, abuffer_size);

	if (!is_client) { // server
		printf("Server\n");

		if (!arg_nokill) {
			// Kill the server with SIGSTOP if the peer disappear.
			int fd = fileno(peer);
			SCALL(fcntl(fd, F_SETOWN, getpid()));
			SCALL(fcntl(fd, F_SETSIG, SIGINT));
			SCALL(fcntl(fd, F_SETFL, O_ASYNC));
		}
		run_pp_server();
	} else {
		printf("Client\n");
		do_pp_client();
	}

	return 0;
}
