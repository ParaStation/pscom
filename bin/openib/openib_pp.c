/*
 * ParaStation
 *
 * Copyright (C) 2008 ParTec Cluster Competence Center GmbH, Munich
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

#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_env.h"

int arg_loops = 1024;
int arg_maxtime = 3000;
int arg_maxmsize = 4 * 1024 * 1024;
int arg_run_once = 0;
const char *arg_port = "5532";
int arg_poll_char = 0;
int arg_verbose = 0;
int arg_nokill = 0;
int arg_pscom = 0;
int arg_read = 0;
int arg_recvoffset = 0;
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

		{ "roff"  , 'r', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_recvoffset , 0, "receive buffer offset", "bytes" },

		{ "port" , 'p', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_STRING,
		  &arg_port, 0, "server port to use", "port" },

//		{ "histo" , 'i', POPT_ARGFLAG_OR | POPT_ARG_VAL,
//		  &arg_histo, 1, "Measure each ping pong", NULL },

		{ "once" , '1', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_run_once, 1, "stop after one client", NULL },

		{ "char" , 'c', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_poll_char, 1, "poll on a char instead of uint32", NULL },

		{ "pscom" , 's', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_pscom, 1, "poll via pscom's psoib_sendv()", NULL },

		{ "read" , 0, POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_read, 1, "One direction RDMA read (no pp!)", NULL},

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

psoib_con_info_t *mcon;

static
void psoib_rc_check(const char *msg, int rc)
{
	if (rc) {
		fprintf(stderr, "%s : %s : %s\n", msg, psoib_err_str ? psoib_err_str : "???", strerror(rc));
		exit(1);
	}
}


static inline
void x_recv(void)
{
	if (arg_poll_char) {
		volatile char *mark = (char *)mcon->recv.bufs.ptr + arg_recvoffset;

		while (*mark != 0x42) {}
		*mark = 0;
	} else {
		volatile uint32_t *mark = (uint32_t *)((char *)mcon->recv.bufs.ptr + arg_recvoffset);

		while (*mark != 0x42424242) {}
		*mark = 0;
	}
}


static inline
void x_send(unsigned msgsize)
{
	int rc;
	mem_info_t *send_bufs = &mcon->send.bufs;
	volatile uint32_t *mark = send_bufs->ptr;
	*mark = 0x42424242;

	struct ibv_sge list = {
		.addr	= (uintptr_t) mark,
		.length = msgsize,
		.lkey	= send_bufs->mr->lkey,
	};

	struct ibv_send_wr wr = {
		.next	= NULL,
		.wr_id	= (uint64_t)mcon,
		.sg_list	= &list,
		.num_sge	= 1,
		.opcode	= IBV_WR_RDMA_WRITE,
		.send_flags	= (
			(ENABLE_SEND_NOTIFICATION ? IBV_SEND_SIGNALED : 0) | /* no cq entry, if unsignaled */
			((list.length <= IB_MAX_INLINE) ? IBV_SEND_INLINE : 0)),
		.imm_data	= 42117,

		.wr.rdma = {
			.remote_addr = (uint64_t)mcon->remote_ptr + arg_recvoffset,
			.rkey = mcon->remote_rkey,
		},
	};

	struct ibv_send_wr *bad_wr;

	rc = ibv_post_send(mcon->qp, &wr, &bad_wr);
	psoib_rc_check("ibv_post_send", rc);

	{
		/* poll on cq */
		struct ibv_wc wc;

		do {
			rc = ibv_poll_cq(default_hca.cq, 1, &wc);
			if (rc > 0) {
				if (wc.status != IBV_WC_SUCCESS) {
					fprintf(stderr, "Completion with error\n");
					fprintf(stderr, "Failed status %d: wr_id %d\n",
						wc.status, (int) wc.wr_id);
					exit(1);
				}
			} else if (rc < 0) {
				fprintf(stderr, "poll CQ failed %d\n", rc);
				exit(1);
			} // else: rc == 0
		} while (rc);
	}
}


static inline
void x_send_read(unsigned msgsize)
{
	int rc;
	mem_info_t *send_bufs = &mcon->send.bufs;
	volatile uint32_t *mark = send_bufs->ptr;
	*mark = 0x42424242;

	struct ibv_sge list = {
		.addr	= (uintptr_t) mark,
		.length = msgsize,
		.lkey	= send_bufs->mr->lkey,
	};

	struct ibv_send_wr wr = {
		.next	= NULL,
		.wr_id	= (uint64_t)mcon,
		.sg_list	= &list,
		.num_sge	= 1,
		.opcode	= IBV_WR_RDMA_READ,
		.send_flags	= IBV_SEND_SIGNALED,
		// (
		//	(ENABLE_SEND_NOTIFICATION ? IBV_SEND_SIGNALED : 0) | /* no cq entry, if unsignaled */
		//	((list.length <= IB_MAX_INLINE) ? IBV_SEND_INLINE : 0)),
		.imm_data	= 42117,

		.wr.rdma = {
			.remote_addr = (uint64_t)mcon->remote_ptr + arg_recvoffset,
			.rkey = mcon->remote_rkey,
		},
	};

	struct ibv_send_wr *bad_wr;
	rc = ibv_post_send(mcon->qp, &wr, &bad_wr);
	psoib_rc_check("ibv_post_send", rc);

	{
		/* poll on cq */
		struct ibv_wc wc;
		unsigned waitcnt = 1;

		do {
			rc = ibv_poll_cq(default_hca.cq, 1, &wc);
			if (rc > 0) {
				waitcnt--;
				if (wc.status != IBV_WC_SUCCESS) {
					fprintf(stderr, "Completion with error\n");
					fprintf(stderr, "Failed status %d: wr_id %d\n",
						wc.status, (int) wc.wr_id);
					exit(1);
				}
			} else if (rc < 0) {
				fprintf(stderr, "poll CQ failed %d\n", rc);
				exit(1);
			} // else: rc == 0
		} while (waitcnt || rc);
	}
}


static
int x_recv_pscom(void)
{
	void *buf;
	int size;

	while (1) {
		size = psoib_recvlook(mcon, &buf);
		if (size >= 0) {
			psoib_recvdone(mcon);
			return size;
		} else if ((size == -EINTR) || (size == -EAGAIN)) {
			continue;
		} else {
			// Error
			errno = -size;
			perror("psoib_recvlook");
			exit(1);
		}
	}
}


static char abuffer[IB_MTU_PAYLOAD + 100];

static
void x_send_pscom(unsigned msglen)
{
	int len;
	struct iovec amsg = {
		.iov_base = abuffer,
		.iov_len = msglen,
	};

	len = psoib_sendv(mcon, &amsg, msglen);
	assert(len == (int)msglen);

	// Flush cq:
	while (mcon->outstanding_cq_entries) {
		psoib_progress();
	}
}


static
void run_pp_server(void)
{
	if (arg_read) {
		while (1) {
			x_recv(); // Only drain the receive queue
		}
	} else if (!arg_pscom) {
		while (1) {
			x_recv();
			x_send(8); // ToDo:
		}
	} else {
		while (1) {
			int len;
			len = x_recv_pscom();
			x_send_pscom(len);
		}
	}
}


static
int run_pp_c(int msize, int loops)
{
	int cnt;
	if (arg_read) {
		for (cnt = 0; cnt < loops; cnt++) {
			// Only RDMA Read and wait for completion.
			x_send_read(msize);
		}
	} else if (!arg_pscom) {
		for (cnt = 0; cnt < loops; cnt++) {
			x_send(msize);
			x_recv();
		}
	} else {
		for (cnt = 0; cnt < loops; cnt++) {
			int len;
			x_send_pscom(msize);
			len = x_recv_pscom();
			assert(len == msize);
		}
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

	memset(abuffer, 24, sizeof(*abuffer));

	if (!arg_pscom || arg_read) {
		printf("WARNING! This is not a ping pong with msize Messagesize!!!\n");
	}
	printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
	printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
	for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
		unsigned int iloops = (unsigned)loops;
		msgsize = (unsigned)(ms + 0.5);

		if (((unsigned)msgsize < 4) && !arg_poll_char) continue;

		if (msgsize >= IB_MTU * psoib_sendq_size) break;
		if (msgsize >= IB_MTU * psoib_recvq_size) break;
		if (arg_pscom && (unsigned)msgsize > IB_MTU_PAYLOAD) break;

		/* warmup, for sync */
		run_pp_c(4, 2);

		t1 = getusec();
		res = run_pp_c(msgsize, iloops);
		t2 = getusec();

		if (arg_read) {
			time = (double)(t2 - t1) / (iloops);
		} else {
			// Half round trip time:
			time = (double)(t2 - t1) / (iloops * 2);
		}
		throuput = msgsize / time;
		if (res == 0) {
			printf("%7d %8d %8.2f %8.2f\n", msgsize, iloops, time, throuput);
			fflush(stdout);
		} else {
			printf("Error in communication...\n");
		}

		{
			double t = (double)(t2 - t1) / 1000.0;
			while (t > arg_maxtime) {
				loops = loops / 1.4142135;
				t /= 1.4142135;
			}
			if (loops < 1) loops = 1;
		}
	}

	return;
}

#define VERSION "OPENIB_PP1.0"

static void info_write(FILE *peer, psoib_info_msg_t *msg)
{
	printf("Lokal:  lid:%u qp:%u ptr:%p rkey:%u\n",
	       msg->lid, msg->qp_num,
	       msg->remote_ptr, msg->remote_rkey);

	fprintf(peer, VERSION " lid:%u qp:%u ptr:%p rkey:%u roff:%d pollchar:%d pscom:%d\n",
		msg->lid, msg->qp_num,
		msg->remote_ptr, msg->remote_rkey,
		arg_recvoffset, arg_poll_char, arg_pscom);
	fflush(peer);
}


static void info_read(FILE *peer, psoib_info_msg_t *msg)
{
	int rc;
	unsigned a1, a2, a4;

	rc = fscanf(peer, VERSION " lid:%u qp:%u ptr:%p rkey:%u roff:%d pollchar:%d pscom:%d",
		    &a1, &a2,
		    &msg->remote_ptr, &a4, &arg_recvoffset, &arg_poll_char, &arg_pscom);

	msg->lid = (uint16_t)a1;
	msg->qp_num = a2;
	msg->remote_rkey = a4;

	printf("Remote: lid:%u qp:%u ptr:%p rkey:%u roff:%d pollchar:%d pscom:%d\n",
	       msg->lid, msg->qp_num,
	       msg->remote_ptr, msg->remote_rkey,
	       arg_recvoffset, arg_poll_char, arg_pscom);

	if (rc != 7) {
		printf("Parsing error! Only %d fields\n", rc);
		exit(1);
	}
}


static
void pscom_openib_init(FILE *peer)
{
	psoib_info_msg_t lmsg, rmsg;
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

	rc = psoib_init();
	psoib_rc_check("psoib_init()", rc);

	mcon = psoib_con_create();
	assert(mcon);

	rc = psoib_con_init(mcon, NULL, NULL);
	psoib_rc_check("psoib_con_init()", rc);

	if (arg_read) {
		// RDMA Read require different MR permissions. Hack: Overwrite buffer allocations:
		psoib_vapi_free(&default_hca, &mcon->send.bufs);
		psoib_vapi_free(&default_hca, &mcon->recv.bufs);

		rc = psoib_vapi_alloc(&default_hca, IB_MTU * psoib_sendq_size,
				      IBV_ACCESS_LOCAL_WRITE, &mcon->send.bufs);
		psoib_rc_check("psoib_vapi_alloc(IBV_ACCESS_LOCAL_WRITE, &mcon->send.bufs)", rc);

		rc = psoib_vapi_alloc(&default_hca, IB_MTU * psoib_recvq_size,
				      IBV_ACCESS_REMOTE_READ, &mcon->recv.bufs);
		psoib_rc_check("psoib_vapi_alloc(IBV_ACCESS_REMOTE_READ, &mcon->recv.bufs)", rc);
	}

	psoib_con_get_info_msg(mcon, &lmsg);

	if (is_client) {
		info_write(peer, &lmsg);
		info_read(peer, &rmsg);
	} else {
		info_read(peer, &rmsg);
		info_write(peer, &lmsg);
	}

	rc = psoib_con_connect(mcon, &rmsg);
	psoib_rc_check("psoib_con_connect()", rc);
}

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

int main(int argc, char **argv)
{
	FILE *peer;

	parse_opt(argc, argv);
	is_client = !!arg_servername;

	if (arg_pscom || arg_read) {
		// Increase defaults to get a larger RDMA buffer.
		psoib_sendq_size = 256;
		psoib_recvq_size = 256;
	}

	peer = get_peer(!is_client);
	pscom_openib_init(peer);

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
