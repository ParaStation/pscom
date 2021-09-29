/*
 * ParaStation
 *
 * Copyright (C) 2012-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/*
 * A simple message dispatcher.
 *
 * Start server with "pscom_dispatch"
 * Start some clients with "pscom_dispatch localhost:5060"
 *
 *
 *
 * client A               server         client B
 * --------               ------         --------
 *   x   ---- HELLO ->       x
 *   x  <- HELLO_RESPONSE -  x
 *   x   ---- HELLO_BCAST -> x
 *                           x - HELLO ->  x
 *   x  <- CLIENT_INFO(B) -- x             |
 *   |                       |            wait for
 *  wait for              dispatch        hellos
 *  hellos
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <error.h>
#include "pscom.h"

unsigned arg_listenport = 5060;
pscom_socket_t *pscom_socket;
pscom_connection_t *pscom_con = NULL;

typedef struct xhead {
	enum {
		HELLO,
		HELLO_RESPONSE,
		HELLO_BCAST,
		CLIENT_INFO,
	} msg_type;
} xhead_t;


void msg_hello(pscom_connection_t *con, void *data, size_t data_len)
{
	printf("Receive HELLO from %s ('%s')\n", pscom_con_str(con), (char*)data);
	pscom_send(con, &(xhead_t) { .msg_type = HELLO_RESPONSE}, sizeof(xhead_t),
			   "Hello Client", 13);
}

void msg_hello_response(pscom_connection_t *con, void *data, size_t data_len)
{
	printf("Receive HELLO_RESPONSE from %s ('%s')\n", pscom_con_str(con), (char*)data);
}

void msg_client_info(pscom_connection_t *con, void *data, size_t data_len)
{
	printf("Receive CLIENT_INFO : '%s'\n", (char*)data);
}

void msg_hello_bcast(pscom_connection_t *con, void *data, size_t data_len)
{
	printf("Receive HELLO_BCAST from %s ('%s')\n", pscom_con_str(con), (char*)data);

	pscom_connection_t *c;

	/* Forward data to all other clients as a HELLO */
	for (c = pscom_get_next_connection(pscom_socket, NULL);
	     c; c = pscom_get_next_connection(pscom_socket, c)) {
		if (c != con) {
			pscom_send(c, &(xhead_t) { .msg_type = HELLO}, sizeof(xhead_t),
				   data, data_len);
		}
	}

	/* Send a client list back .*/
	for (c = pscom_get_next_connection(pscom_socket, NULL);
	     c; c = pscom_get_next_connection(pscom_socket, c)) {
		const char *c_info = pscom_con_str(c);
		if (c != con) {
			pscom_send(con, &(xhead_t) { .msg_type = CLIENT_INFO}, sizeof(xhead_t),
				   (void *)c_info, strlen(c_info) + 1);
		}
	}
}

int recv_accept(pscom_request_t *request,
		pscom_connection_t *connection,
		pscom_header_net_t *header_net)
{
	/* Allocate data for this message */
	request->data = malloc(header_net->data_len);
	request->data_len = header_net->data_len;
	return 1;
}

void con_error(pscom_connection_t *connection,
	       pscom_op_t operation,
	       pscom_err_t error)
{
	printf("con_error : %s : operation %s : %s\n",
	       pscom_con_str(connection),
	       pscom_op_str(operation),
	       pscom_err_str(error));
}

void dispatch(void)
{
	pscom_request_t *req = pscom_request_create(sizeof(xhead_t), 0);
	assert(req);

	req->data = NULL;
	while (1) {
		req->connection = NULL;
		req->socket = pscom_socket;
		req->data = NULL;
		req->ops.recv_accept = recv_accept;
		pscom_post_recv(req);
		pscom_wait(req);

		xhead_t *xhead = (xhead_t*)&req->xheader;

		assert(pscom_req_successful(req));

		switch(xhead->msg_type) {
		case HELLO:
			msg_hello(req->connection, req->data, req->data_len);
			break;
		case HELLO_RESPONSE:
			msg_hello_response(req->connection, req->data, req->data_len);
			break;
		case HELLO_BCAST:
			msg_hello_bcast(req->connection, req->data, req->data_len);
			break;
		case CLIENT_INFO:
			msg_client_info(req->connection, req->data, req->data_len);
			break;
		default:
			printf("Skip unknown message %u from %s\n", xhead->msg_type,
			       pscom_con_str(req->connection));
		}

		if (req->data) free(req->data);
		req->data = NULL;
	}
}




int main(int argc, char **argv)
{
	char *arg_serveraddr = argc > 1 ? argv[1] : NULL;
	pscom_err_t rc;

	pscom_init(PSCOM_VERSION);

	pscom_socket = pscom_open_socket(0, 0);
	assert(pscom_socket);

	/* Use only TCP connections */
	pscom_con_type_mask_only(pscom_socket, PSCOM_CON_TYPE_TCP);

	/* Dump errors from connections */
	pscom_socket->ops.con_error = con_error;

	if (!arg_serveraddr) {
		/* Set my name to "server" */
		pscom_socket_set_name(pscom_socket, "server");

		/* I am a server. Start listening. */
		rc = pscom_listen(pscom_socket, arg_listenport);
		if (rc) error(-1, errno, "pscom_listen : %s\n", pscom_err_str(rc));

		printf("Connect server with :\n%s %s\n", argv[0], pscom_listen_socket_str(pscom_socket));

	} else {
		/* I am a client. Connect the serve. */

		pscom_con = pscom_open_connection(pscom_socket);
		assert(pscom_con);

		rc = pscom_connect_socket_str(pscom_con, arg_serveraddr);
		if (rc) error(-1, errno, "pscom_connect(%s) : %s\n", arg_serveraddr, pscom_err_str(rc));

		pscom_send(pscom_con, &(xhead_t) { .msg_type = HELLO}, sizeof(xhead_t),
			   "Hello Server", 13);
		pscom_send(pscom_con, &(xhead_t) { .msg_type = HELLO_BCAST}, sizeof(xhead_t),
			   "Hello World", 13);
	}
	dispatch();

	return 0;
}
