/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_pp.c: PingPong over pscom
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <fcntl.h>
#include <assert.h>
#include <popt.h>
#include <ctype.h>
#include <limits.h>

#include "pscom.h"


const char *arg_server = "localhost:7100";
int arg_client = 0;
int arg_lport = 7100;

unsigned arg_loops = 1024;
unsigned arg_maxtime = 3000;
#define MAX_XHEADER 100
unsigned arg_xheader = 12;
unsigned long arg_maxmsize = 4 * 1024 * 1024;
unsigned long arg_minmsize = 0;
int arg_run_once = 0;
int arg_verbose = 0;
int arg_histo = 0;
int arg_valloc = 0;
int arg_verify = 0;

static
void parse_opt(int argc, char **argv)
{
	int c;
	poptContext optCon;
	const char *no_arg;

	struct poptOption optionsTable[] = {
		{ "listen" , 'l', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_lport, 0, "run as server and listen on", "port" },


		{ "client" , 'c', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_client, 1, "run as client", NULL },

		{ "loops"  , 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_loops , 0, "pp loops", "count" },
		{ "time"  , 't', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxtime, 0, "max time", "ms" },
		{ "minsize"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_LONG,
		  &arg_minmsize , 0, "minimal messagesize", "size" },
		{ "maxsize"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_LONG,
		  &arg_maxmsize , 0, "maximal messagesize", "size" },
		{ "xheader"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_xheader , 0, "xheader size", "size" },

		{ "valloc"  , 0, POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_valloc , 1, "use valloc() instead of malloc for send/receive buffers", NULL },

		{ "histo" , 'i', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_histo, 1, "Measure each ping pong", NULL },

		{ "verify", 'V', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_verify, 1, "verify message content", NULL },

		{ "once" , '1', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_run_once, 1, "stop after one client", NULL },

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
	/* if (arg_client)*/ {
		const char *server = poptGetArg(optCon);
		if (server) arg_server = server;
	}

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


static
void run_pp_server(pscom_connection_t *con)
{
	void *buf = arg_valloc ? valloc(arg_maxmsize) : malloc(arg_maxmsize);
	pscom_request_t *req;
	unsigned i;

	req = pscom_request_create(MAX_XHEADER, 0);

	for (i = 0; i < MAX_XHEADER; i++) {
		req->xheader.user[i] = (char)(i + 0xe1);
	}

	if (arg_verbose) {
		printf("Buffer: buf:%p\n", buf);
	}

	while (1) {
		pscom_req_prepare(req, con, buf, arg_maxmsize, NULL, MAX_XHEADER);
		pscom_post_recv(req);

		pscom_wait(req);

		if (!pscom_req_successful(req)) break;
		if (arg_verbose) {
			printf("Receive %u xheader :%s\n",
			       req->header.xheader_len,
			       pscom_dumpstr(&req->xheader, req->header.xheader_len));

			printf("        %lu data :%s\n",
			       (unsigned long)req->header.data_len,
			       pscom_dumpstr(req->data, MIN(req->header.data_len, 64)));
		}

		req->xheader_len = req->header.xheader_len;
		req->data_len = req->header.data_len;
		pscom_post_send(req);

		pscom_wait(req);
	}

	pscom_request_free(req);
	free(buf);
}


static
int pp_loop(pscom_request_t *sreq, pscom_request_t *rreq, unsigned loops)
{
	unsigned cnt;
	for (cnt = 0; cnt < loops; cnt++) {
		pscom_post_send(sreq);

		// printf("SEND %d data :%s\n", msize,
		//       pscom_dumpstr(sbuf, MIN(msize, 16)));
		pscom_post_recv(rreq);

		pscom_wait(sreq);
		pscom_wait(rreq);
	}
	return !pscom_req_successful(rreq);
}


static
int pp_loop_verify(pscom_request_t *sreq, pscom_request_t *rreq, unsigned loops)
{
	unsigned cnt, i, err = 0;
	for (cnt = 0; cnt < loops; cnt++) {
		for (i = 0; i < sreq->data_len; i++) {
			((unsigned char *)sreq->data)[i] = (unsigned char)(cnt + i);
		}
		pscom_post_send(sreq);

		// printf("SEND %d data :%s\n", msize,
		//       pscom_dumpstr(sbuf, MIN(msize, 16)));
		pscom_post_recv(rreq);

		pscom_wait(sreq);
		pscom_wait(rreq);

		if (rreq->data_len != sreq->data_len) {
			printf("Corrupted data_len in msg %u! (recv:%5lu != send:%5lu)\n",
			       cnt, rreq->data_len, sreq->data_len);
			err = 1;
		}
		for (i = 0; i < rreq->data_len; i++) {
			if (((unsigned char *)rreq->data)[i] != (unsigned char)(cnt + i)) {
				printf("Corrupted byte #%u in msg %u! (is:%3u != should:%3u)\n",
				       i, cnt, ((unsigned char *)rreq->data)[i], (unsigned char)(cnt + i));
				err = 1;
			};
		}
	}
	return !pscom_req_successful(rreq) || err;
}


static
int pp_loop_histo(pscom_request_t *sreq, pscom_request_t *rreq, unsigned loops)
{
	unsigned cnt;
	size_t msize = sreq->data_len;
	unsigned long *time = malloc(sizeof(*time) * loops + 1);
	for (cnt = 0; cnt < loops; cnt++) {
		time[cnt] = getusec();
		pscom_post_send(sreq);

		// printf("SEND %d data :%s\n", msize,
		//       pscom_dumpstr(sbuf, MIN(msize, 16)));
		pscom_post_recv(rreq);

		pscom_wait(rreq);
	}

	printf("Message size %7lu. Rtt/2[usec]\n", msize);
	for (cnt = 1; cnt < loops; cnt++) {
		printf("%5d %8.1f\n", cnt, (double)(time[cnt] - time[cnt - 1]) / 2.0);
	}
	fflush(stdout);
	free(time);
	return !pscom_req_successful(rreq);
}


static
int run_pp_c(pscom_connection_t *con, size_t msize, unsigned xsize, unsigned loops,
	     int (*pp_loop)(pscom_request_t *sreq, pscom_request_t *rreq, unsigned loops))
{
	unsigned cnt;
	void *sbuf = arg_valloc ? valloc(msize) : malloc(msize);
	void *rbuf = arg_valloc ? valloc(msize) : malloc(msize);
	int ret;
	pscom_request_t *sreq;
	pscom_request_t *rreq;

	memset(sbuf, 42, msize);
	memset(rbuf, 42, msize);

	sreq = pscom_request_create(xsize, 0);
	rreq = pscom_request_create(xsize, 0);

	if (arg_verbose) {
		printf("Buffers: sbuf:%p[%lu] rbuf:%p[%lu]\n", sbuf, msize, rbuf, msize);
		for (cnt = 0; cnt < xsize; cnt++) {
			sreq->xheader.user[cnt] = (char)(cnt + 1);
		}
	}

	pscom_req_prepare(sreq, con, sbuf, msize, NULL, xsize);
	pscom_req_prepare(rreq, con, rbuf, msize, NULL, xsize);

	ret = pp_loop(sreq, rreq, loops);

	pscom_request_free(sreq);
	pscom_request_free(rreq);
	free(sbuf);
	free(rbuf);

	return ret;
}


static
void do_pp_client(pscom_connection_t *con)
{
	unsigned long t1, t2;
	double time;
	double throuput;
	size_t msgsize;
	double ms;
	int res;
	double loops = arg_loops;
	int (*pp_loop_func)(pscom_request_t *sreq, pscom_request_t *rreq, unsigned loops);

	if (arg_xheader > MAX_XHEADER) arg_xheader = MAX_XHEADER;

	printf("Xheader : %d bytes\n", arg_xheader);
	printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
	printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
	for (ms = (double)arg_minmsize; (size_t)(ms + 0.5) <= (size_t)arg_maxmsize; ms = ms < 2.0 ? ms + 1 : ms * 1.4142135623730950488) {
		unsigned int iloops = (unsigned)(loops + 0.5);
		msgsize = (size_t)(ms + 0.5);

		/* warmup, for sync */
		run_pp_c(con, 2, 2, 2, pp_loop);

		if (arg_verify) {
			pp_loop_func = pp_loop_verify;
		} else if (arg_histo) {
			pp_loop_func = pp_loop_histo;
		} else {
			pp_loop_func = pp_loop;
		}

		t1 = getusec();
		res = run_pp_c(con, msgsize, arg_xheader, iloops, pp_loop_func);
		t2 = getusec();

		time = (double)(t2 - t1) / (iloops * 2);
		throuput = (double)msgsize / time;
		if (res == 0) {
			printf("%7lu %8u %8.2f %8.2f%s\n", msgsize, iloops, time, throuput,
			       pp_loop_func == pp_loop_verify ? " ok" : "");
			fflush(stdout);
		} else {
			printf("%7lu Error in communication...\n", msgsize);
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


static
void do_accept(pscom_connection_t *con)
{
	printf("New connection from %s via %s\n",
	       pscom_con_info_str(&con->remote_con_info),
	       pscom_con_type_str(con->type));
}

#define PSCALL(func) do {					\
	pscom_err_t rc;						\
	rc = (func);						\
	if (rc != PSCOM_SUCCESS) {				\
		printf( #func ": %s\n", pscom_err_str(rc));	\
		exit(1);					\
	}							\
} while (0)


int main(int argc, char **argv)
{
	pscom_socket_t *socket;
	pscom_connection_t *con;
	pscom_err_t rc;

	parse_opt(argc, argv);

	rc = pscom_init(PSCOM_VERSION);
	assert(rc == PSCOM_SUCCESS);

	socket = pscom_open_socket(0,0);

	if (!arg_client) { // server
		socket->ops.con_accept = do_accept;
		do {
			PSCALL(pscom_listen(socket, arg_lport));

			printf("Waiting for client.\nCall client with:\n");
			printf("%s -c %s\n", argv[0], pscom_listen_socket_str(socket));
			fflush(stdout);

			while (1) {
				con = pscom_get_next_connection(socket, NULL);
				if (con) {
					break;
				} else {
					pscom_wait_any();
				}
			}
			pscom_stop_listen(socket);

			run_pp_server(con);
			pscom_close_connection(con);

			if (arg_run_once) pscom_close_socket(socket);
			if (arg_verbose) pscom_dump_info(stdout);
		} while (!arg_run_once);
	} else {
		con = pscom_open_connection(socket);
		assert(con);

		PSCALL(pscom_connect_socket_str(con, arg_server));

		do_pp_client(con);
		pscom_close_connection(con);
		pscom_close_socket(socket);
		if (arg_verbose) pscom_dump_info(stdout);
	}

	return 0;
}
