/*
 * ParaStation
 *
 * Copyright (C) 2009-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <popt.h>
#include <assert.h>
#include <error.h>
#include "pscom.h"

#define BLACK	"\033[30m"
#define RED	"\033[31m"
#define GREEN	"\033[32m"
#define BROWN	"\033[33m"
#define BLUE	"\033[34m"
#define MAGENTA	"\033[35m"
#define CYAN	"\033[36m"
#define WHITE	"\033[37m"
#define NORM	"\033[39m"


int arg_listenport = 5046;
int arg_verbose = 0;
int arg_send = 0;
int connections = 0;
pscom_socket_t *sock;
pscom_connection_t *connection = NULL;
const char *progname;

void abort_on_error(const char *msg, pscom_err_t error)
{
	if (!error) return;
	printf(RED "%s : %s" NORM "\n", msg, pscom_err_str(error));
	exit(1);
}


void connection_accept_server(pscom_connection_t *new_connection)
{
	connections++;

	printf(GREEN "New connection %p from %s via %s (#%d)" NORM "\n",
	       new_connection,
	       pscom_con_info_str(&new_connection->remote_con_info),
	       pscom_con_type_str(new_connection->type),
	       connections);
}


void conn_error_server(pscom_connection_t *connection,
		       pscom_op_t operation, pscom_err_t error)
{
	printf(RED "Error on connection from %s via %s : %s : %s" NORM "\n",
	       pscom_con_info_str(&connection->remote_con_info),
	       pscom_con_type_str(connection->type),
	       pscom_op_str(operation),
	       pscom_err_str(error));
}


struct PSCOM_socket_ops socket_ops_server = {
	.con_accept = connection_accept_server,
	.con_error = conn_error_server,
	.default_recv = NULL, //default_recv_server
};



int main(int argc, char **argv)
{
	pscom_err_t rc;
	char *server;
	int cnt = 0;

	progname = strdup(argc && argv[0] ? argv[0] : "< ??? >");
	/* pscom_set_debug(arg_verbose); */

	server = argv[1];

	pscom_init(PSCOM_VERSION);
	sock = pscom_open_socket(0, 0);
	if (!sock) abort_on_error("pscom_open_socket() failed", PSCOM_ERR_STDERROR);
	sock->ops = socket_ops_server;

	pscom_socket_set_name(sock, !server ? "server" : "client");

	if (!server) {
		/* start server */
		printf("Start clients with: %s localhost:%d\n",
		       progname, arg_listenport);
		rc = pscom_listen(sock, arg_listenport);
		if (rc) abort_on_error("pscom_listen() failed", rc);

		while (1) {
			pscom_wait_any();
		}
	} else {
		while (1) {
			cnt++;
			printf("Connection %d\n", cnt);
			pscom_connection_t *con = pscom_open_connection(sock);

			rc = pscom_connect_socket_str(con, server);
			if (rc) abort_on_error("pscom_connect_socket_str()", rc);
			// sleep(1);
		}
	}

	return 0;
}

/*
 * Local Variables:
 *  compile-command: "gcc -I/opt/parastation/include -L/opt/parastation/lib64 -lpscom pscom_maxcon.c  -Wall -W -O2 -o pscom_maxcon && LD_LIBRARY_PATH=/opt/parastation/lib64 ./pscom_maxcon"
 * End:
 *
 */
