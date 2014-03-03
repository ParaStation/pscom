/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2008 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * pscom_bcast_pp: PingPong with pscom_bcast and a group of size 2.
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

#include "pscom.h"


const char *arg_server = "localhost:7100";
int arg_client = 0;
int arg_lport = 7100;

int arg_loops = 1024;
int arg_maxtime = 3000;
#define MAX_XHEADER 100
int arg_xheader = 10;
int arg_maxmsize = 4 * 1024 * 1024;
int arg_verbose = 0;
int arg_post_bcast = 0;

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
		{ "maxsize"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxmsize , 0, "maximal messagesize", "size" },
		{ "xheader"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_xheader , 0, "xheader size", "size" },

		{ "post"     , 0, POPT_ARG_NONE,
		  &arg_post_bcast, 0, "user pscom_post_bcast instead of pscom_bcast", NULL },

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
void run_pp(pscom_socket_t *socket, pscom_group_t *group, unsigned msize, unsigned xsize, unsigned loops)
{
	unsigned cnt;
	void *buf = malloc(msize);
	char *xbuf = malloc(xsize);

	memset(buf, 42, msize);

	if (arg_verbose) {
		for (cnt = 0; cnt < xsize; cnt++) {
			xbuf[cnt] = cnt + 1;
		}
	}

	if (!arg_post_bcast) {
		for (cnt = 0; cnt < loops; cnt++) {
			pscom_bcast(group, 0, xbuf, xsize, buf, msize);
			pscom_bcast(group, 1, xbuf, xsize, buf, msize);

			// printf("SEND %d data :%s\n", msize,
			//       pscom_dumpstr(sbuf, MIN(msize, 16)));
		}
	} else {
		pscom_request_t *req = pscom_request_create(sizeof(req->xheader.bcast) + xsize, 0);

		req->xheader_len = sizeof(req->xheader.bcast) + xsize;
		req->xheader.bcast.group_id = pscom_group_get_id(group);
		req->xheader.bcast.bcast_root = 0;

		req->data_len = msize;
		req->data = buf;

		req->socket = socket;

		for (cnt = 0; cnt < loops; cnt++) {
			req->xheader.bcast.bcast_root = 0;
			pscom_post_bcast(req);
			pscom_wait(req);

			req->xheader.bcast.bcast_root = 1;
			pscom_post_bcast(req);
			pscom_wait(req);
		}

		pscom_request_free(req);
	}

//err_io:
	free(buf);
	free(xbuf);
}


static
void do_pp(pscom_connection_t *con_server, pscom_connection_t *con_client,
	   unsigned my_rank /* 0 == server, 1 == client */)
{
	unsigned long t1, t2;
	double time;
	double throuput;
	unsigned int msgsize;
	double ms;
	double loops = arg_loops;

	if (arg_xheader > MAX_XHEADER) arg_xheader = MAX_XHEADER;

	pscom_group_t *group;
	pscom_socket_t *socket = con_server->socket;
	pscom_connection_t *cons[2] = { con_server, con_client }; // server (me) as rank 0

	printf("#rank0:%s\n", pscom_con_info_str(&con_server->remote_con_info));
	printf("#rank1:%s\n", pscom_con_info_str(&con_client->remote_con_info));

	group = pscom_group_open(socket, 42, my_rank, 2, cons);

	printf("Xheader : %d bytes\n", arg_xheader);
	printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
	printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
	for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
		unsigned int iloops = loops;
		msgsize = ms + 0.5;

		/* warmup, for sync */
		run_pp(socket, group, 2, 2, 2);

		t1 = getusec();
		run_pp(socket, group, msgsize, arg_xheader, iloops);
		t2 = getusec();

		time = (double)(t2 - t1) / (iloops * 2);
		throuput = msgsize / time;

		printf("%7d %8d %8.2f %8.2f\n", msgsize, iloops, time, throuput);
		fflush(stdout);

		{
			double t = (t2 - t1) / 1000;
			while (t > arg_maxtime) {
				loops = loops / 1.4142135;
				t /= 1.4142135;
			}
			if (loops < 1) loops = 1;
		}
	}

	pscom_group_close(group);

	return;
}


static
void do_accept(pscom_connection_t *con)
{
	printf("New connection from %s\n", pscom_con_info_str(&con->remote_con_info));
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
	pscom_connection_t *con_loop;
	pscom_err_t rc;

	parse_opt(argc, argv);

	rc = pscom_init(PSCOM_VERSION);
	assert(rc == PSCOM_SUCCESS);

	socket = pscom_open_socket(0,0);

	con_loop = pscom_open_connection(socket);
	rc = pscom_connect(con_loop, -1, -1);
	assert(rc == PSCOM_SUCCESS);

	if (!arg_client) { // server
		socket->ops.con_accept = do_accept;

		PSCALL(pscom_listen(socket, arg_lport));

		printf("Waiting for client.\nCall client with:\n");
		printf("%s -c %s", argv[0], pscom_listen_socket_str(socket));
		if (arg_loops != 1024) printf(" --loops=%u", arg_loops);
		if (arg_maxtime != 3000) printf(" --time=%u", arg_maxtime);
		if (arg_maxmsize != 4 * 1024 * 1024)
			printf(" --maxsize=%u", arg_maxmsize);
		if (arg_xheader != 10)
			printf(" --xheader=%u", arg_xheader);
		if (arg_post_bcast)
			printf(" --post");
		printf("\n");
		fflush(stdout);

		con = NULL;
		while (1) {
			con = pscom_get_next_connection(socket, con);
			if (con && con != con_loop) {
				break;
			} else {
				pscom_wait_any();
			}
		}
		pscom_stop_listen(socket);

		do_pp(con_loop, con, 0);
		pscom_close_connection(con);

		if (arg_verbose) pscom_dump_info(stdout);
	} else {
		con = pscom_open_connection(socket);
		assert(con);

		PSCALL(pscom_connect_socket_str(con, arg_server));

		do_pp(con, con_loop, 1);
		if (arg_verbose) pscom_dump_info(stdout);
	}

	pscom_close_socket(socket);

	return 0;
}
