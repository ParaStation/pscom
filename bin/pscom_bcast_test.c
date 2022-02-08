/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_bcast_test.c: Test pscom_bcast()
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
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include "pscom.h"


const char *arg_server = "localhost:7100";
int arg_verbose = 0;
unsigned arg_np = 2;
int arg_server_only = 0;

static
void parse_opt(int argc, char **argv)
{
	int c;
	poptContext optCon;
	const char *no_arg;

	struct poptOption optionsTable[] = {
		{ "np"	, 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_np, 'n', "number of procs to wait for", "np" },
		{ "server"	, 's', POPT_ARG_NONE,
		  &arg_server_only, 's', "server only", NULL },
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

static
void exit_on_error(pscom_err_t rc, char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
static
void exit_on_error(pscom_err_t rc, char *fmt, ...)
{
	if (rc == PSCOM_SUCCESS) return;

	va_list arg;
	va_start(arg, fmt);
	vfprintf(stderr, fmt, arg);
	va_end(arg);
	fprintf(stderr, " : %s\n", pscom_err_str(rc));
	exit(1);
}

struct hello {
	char buf[20];
	char vc[100];
	unsigned np;
};


struct Connection {
	pscom_connection_t *con;
	struct hello hello;
};


struct Connection *connections = NULL;
unsigned connections_received = 0;
unsigned connections_accepted = 0;

static
void hello_received(pscom_request_t *req)
{
	unsigned con_idx;
	struct Connection *Con = NULL;
	pscom_connection_t *con;

	for (con_idx = 0; con_idx < connections_received; con_idx++) {
		if (connections[con_idx].con == req->connection) {
			Con = &connections[con_idx];
			break;
		}
	}

	pscom_request_free(req); req = NULL;
	assert(Con);
	con = Con->con;

	if (arg_verbose) printf("server receive: %s : %s : np = %d\n",
				Con->hello.vc, Con->hello.buf, Con->hello.np);

	if (Con->hello.np != arg_np) {
		printf("Reject connection from %s : wrong np (%d) should be (%d)\n",
		       pscom_con_info_str(&con->remote_con_info),
		       Con->hello.np,
		       arg_np);
		pscom_close_connection(con);
		connections[con_idx] =  connections[connections_received - 1];
		connections_received--;
		return;
	}

	connections_accepted++;
	if (connections_accepted == arg_np) {
		unsigned rank;

		for (rank = 0; rank < arg_np; rank++) {
			struct Connection *Con = &connections[rank];
			unsigned drank;
			pscom_send(Con->con, NULL, 0, &rank, sizeof(rank));
			for (drank = 0; drank < arg_np; drank++) {
				struct Connection *dCon = &connections[drank];
				pscom_send(Con->con, NULL, 0, &dCon->hello, sizeof(dCon->hello));
			}

			if (Con->con->type != PSCOM_CON_TYPE_LOOP) {
				pscom_close_connection(Con->con);
			}
			Con->con = NULL;
		}
	}
}


static
void do_accept(pscom_connection_t *con)
{
	if (connections_received == arg_np) {
		printf("Reject connection from %s\n", pscom_con_info_str(&con->remote_con_info));
		pscom_close_connection(con);

		return;
	}
	if (arg_verbose) printf("New connection from %s\n", pscom_con_info_str(&con->remote_con_info));

	if (!connections) {
		connections = malloc(sizeof(*connections) * arg_np);
	}

	struct Connection *Con = &connections[connections_received];
	Con->con = con;
	connections_received++;

	pscom_request_t *req = pscom_request_create(0, 0);

	req->xheader_len = 0;
	req->data = &Con->hello;
	req->data_len = sizeof(Con->hello);
	req->ops.io_done = hello_received;
	req->connection = con;

	pscom_post_recv(req);
}

unsigned my_rank;
pscom_connection_t **connections_client;
unsigned connections_client_count = 0;
pscom_socket_t *sock_client;
pscom_group_t *group;

static
void do_accept_client(pscom_connection_t *con)
{
	unsigned rank;
	pscom_err_t rc;

	 // Nothing to do for LOOP connections:
	if (con->type == PSCOM_CON_TYPE_LOOP) return;

	rc = pscom_recv(con, NULL, NULL, 0, &rank, sizeof(rank));
	exit_on_error(rc, "pscom_recv(rank)");

	connections_client[rank] = con;
	connections_client_count++;
}

static
void bcast_test(unsigned buflen, unsigned groot)
{
	char *buf = malloc(buflen);

	pscom_request_t *req = pscom_request_create(0, 0);
	req->xheader_len = sizeof(req->xheader.bcast);
	req->xheader.bcast.group_id = 42;
	req->xheader.bcast.bcast_root = groot; // root rank
	snprintf(buf, buflen, "Hello Bcast from %d", my_rank);

	req->data_len = buflen;//strlen(buf) + 1;
	req->data = buf;

	req->socket = sock_client;
	// if (my_rank != groot) sleep(2);
	// if (my_rank == groot) sleep(2);

	pscom_post_bcast(req);

	pscom_wait(req);
	printf("%5d : rank %2d:received:%s: state:%s\n",
	       getpid(), my_rank, buf, pscom_req_state_str(req->state));
	fflush(stdout);
	free(buf);
	pscom_request_free(req);
}


static
void bcast_test2(unsigned xlen, unsigned buflen, unsigned groot)
{
	char *xbuf = malloc(xlen);
	char *buf = malloc(buflen);

	snprintf(buf, buflen, "rank %d", my_rank);
	snprintf(xbuf, xlen, "xrank %d", my_rank);

	pscom_bcast(group, groot,
		    xbuf, xlen,
		    buf, buflen);


	printf("%5d : rank %2d:received:(%s)%s\n",
	       getpid(), my_rank,
	       xbuf, buf);
	fflush(stdout);

	free(buf);
	free(xbuf);
}


int main(int argc, char **argv)
{
	pscom_socket_t *sock_srv;
	pscom_err_t rc;

	parse_opt(argc, argv);

	rc = pscom_init(PSCOM_VERSION);
	exit_on_error(rc, "pscom_init()");

	sock_srv = pscom_open_socket(0,0);
	pscom_con_type_mask_only(sock_srv, PSCOM_CON_TYPE_TCP);

	// try to be the server:
	sock_srv->ops.con_accept = do_accept;

	int lport; // listening port
	rc = pscom_parse_socket_str(arg_server, NULL, &lport);
	if (rc != PSCOM_SUCCESS) {
		fprintf(stderr, "Server: '%s'\n", arg_server);
		exit_on_error(rc, "parse server ");
	}


	rc = pscom_listen(sock_srv, lport);
	if (rc != PSCOM_SUCCESS) {
		// ignore error
	}

	if (arg_server_only) {
		while (1) {
			pscom_wait_any();
		}
	}

	pscom_connection_t *con_server;

	con_server = pscom_open_connection(sock_srv);
	assert(con_server);

	if (arg_verbose) printf("connect %s\n", arg_server);

	rc = pscom_connect_socket_str(con_server, arg_server);
	if (rc != PSCOM_SUCCESS) {
		fprintf(stderr, "Server: '%s'\n", arg_server);
		exit_on_error(rc, "pscom_connect_socket_str ");
	}

	struct hello h;

	sprintf(h.buf, "n%d", getpid());

	sock_client = pscom_open_socket(0,0);
	sock_client->ops.con_accept = do_accept_client;
	connections_client = malloc(arg_np * sizeof(*connections_client));

	rc = pscom_listen(sock_client, PSCOM_ANYPORT);
	exit_on_error(rc, "pscom_listen(sock_client, PSCOM_ANYPORT)");

	const char *me = pscom_listen_socket_str(sock_client);

	if (arg_verbose) printf("listening on %s\n", me);
	assert(strlen(me) < sizeof(h.vc));

	strcpy(h.vc, me);
	h.np = arg_np;

	// if (arg_verbose) printf("send vc (np = %d)\n", h.np);
	pscom_send(con_server, NULL, 0, &h, sizeof(h));

	rc = pscom_recv(con_server, NULL, NULL, 0 , &my_rank, sizeof(my_rank));
	exit_on_error(rc, "pscom_recv() my rank");

	if (arg_verbose) printf("my rank:%3d\n", my_rank);

	{
		char name[10];
		snprintf(name, sizeof(name), "r%d", my_rank);
		pscom_socket_set_name(sock_client, name);
	}

	unsigned i;
	for (i = 0; i < arg_np; i++) {
		rc = pscom_recv(con_server, NULL, NULL, 0, &h, sizeof(h));
		exit_on_error(rc, "pscom_recv() vc from server");

		if (arg_verbose) printf("#%2d: %s : %s\n", i, h.vc, h.buf);

		if (i <= my_rank) {
			pscom_connection_t *con = pscom_open_connection(sock_client);
			connections_client[i] = con;
			connections_client_count++;
			if (i < my_rank) {
				rc = pscom_connect_socket_str(con, h.vc);
				exit_on_error(rc, "pscom_connect_socket_str(con, %s)", h.vc);

				pscom_send(con, NULL, 0, &my_rank, sizeof(my_rank));
			} else  {
				rc = pscom_connect(con, -1, -1); // Loopback
				exit_on_error(rc, "pscom_connect(-1, -1)");
			}
		}
	}

	pscom_stop_listen(sock_srv);
	pscom_close_connection(con_server);
	pscom_close_socket(sock_srv);

	while (connections_client_count != arg_np) {
		pscom_wait_any();
	}
	pscom_stop_listen(sock_client);

	/******************************************************
	  my_rank		: my rank
	  connections_client[0:arg_np] : all client connections
	  sock_client           : socket of all connections
	*/

	group = pscom_group_open(sock_client,
				 42, my_rank,
				 arg_np, connections_client);

	bcast_test(100, 0);
	bcast_test(10000000, 0);

	bcast_test(100, pscom_min(arg_np - 1, 2));

	for (i = 0; i < 5; i++) {
		bcast_test(100000, pscom_min(arg_np - 1, 6));
	}

	bcast_test2(40, 400, pscom_min(arg_np - 1, 3));
	bcast_test2(40, 400, pscom_min(arg_np - 1, 1));

	while (0) {
		pscom_wait_any();
	}

	if (arg_verbose) {
		printf("waiting on barrier (rank %d)\n", my_rank);
	}

//	if (my_rank == 1) sleep(4);

	pscom_barrier(group);

	if (arg_verbose) {
		printf("barrier done       (rank %d)\n", my_rank);
	}

	pscom_barrier(group);
//	printf("barrier %d\n", __LINE__);sleep(2);
	pscom_barrier(group);
//	printf("barrier %d\n", __LINE__);sleep(2);

	if (arg_verbose) pscom_dump_info(stderr);
	pscom_group_close(group);
	pscom_close_socket(sock_client);

	return 0;
}
