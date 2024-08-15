/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
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
#include <popt.h>
#include <error.h>

#include "pscom.h"


#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BROWN   "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define NORM    "\033[39m"


const char *arg_peer_str = "localhost:5046@bar";

const char *arg_listenname = "foo";
int arg_listenport         = 5016;
int arg_verbose            = 0;
int arg_send               = 0;

void parse_opt(int argc, char **argv)
{
    int c;
    poptContext optCon;
    const char *no_arg;

    struct poptOption optionsTable[] = {
        {"send", 's', POPT_ARGFLAG_OR | POPT_ARG_VAL, &arg_send, 1,
         "first send", NULL},

        {"lport", 'l', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
         &arg_listenport, 0, "listen on port", "port"},

        {"lname", 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_STRING,
         &arg_listenname, 0, "listen on name", "name"},

        {"verbose", 'v', POPT_ARG_NONE, NULL, 'v', "increase verbosity", NULL},

        POPT_AUTOHELP POPT_TABLEEND // Add help option and terminate table
    };

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);

    poptSetOtherOptionHelp(optCon, "[peer address]");

    while ((c = poptGetNextOpt(optCon)) >= 0) {
        switch (c) { // c = poptOption.val;
        case 'v':
            arg_verbose++;
            break;
            // default: fprintf(stderr, "unhandled popt value %d\n", c); break;
        }
    }

    if (c < -1) { /* an error occurred during option processing */
        fprintf(stderr, "%s: %s\n",
                poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    {
        const char *s;
        s = poptGetArg(optCon);
        if (s) { arg_peer_str = s; }
    }

    no_arg = poptGetArg(optCon); // should return NULL
    if (no_arg) {
        fprintf(stderr, "%s: %s\n", no_arg, poptStrerror(POPT_ERROR_BADOPT));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    poptFreeContext(optCon);
}


pscom_socket_t *sock;
pscom_connection_t *connection = NULL;
const char *progname;

void abort_on_error(const char *msg, pscom_err_t error)
{
    if (!error) { return; }
    printf(RED "%s : %s" NORM "\n", msg, pscom_err_str(error));
    exit(1);
}


void connection_accept_server(pscom_connection_t *new_connection)
{
    printf(GREEN "New connection %p from %s via %s" NORM "\n", new_connection,
           pscom_con_info_str(&new_connection->remote_con_info),
           pscom_con_type_str(new_connection->type));
    /*
            if (!connection) {
                    connection = new_connection;
            } else {
                    printf("New connection from %s via %s closing!\n",
                           pscom_con_info_str(&new_connection->remote_con_info),
                           pscom_con_type_str(new_connection->type));
                    pscom_close_connection(new_connection);
            }
    */
}


void conn_error_server(pscom_connection_t *connection, pscom_op_t operation,
                       pscom_err_t error)
{
    printf(RED "Error on connection from %s via %s : %s : %s" NORM "\n",
           pscom_con_info_str(&connection->remote_con_info),
           pscom_con_type_str(connection->type), pscom_op_str(operation),
           pscom_err_str(error));
}


struct PSCOM_socket_ops socket_ops_server = {
    .con_accept   = connection_accept_server,
    .con_error    = conn_error_server,
    .default_recv = NULL, // default_recv_server
};


int main(int argc, char **argv)
{
    pscom_err_t rc;
    int ret;

    progname = strdup(argc && argv[0] ? argv[0] : "< ??? >");
    parse_opt(argc, argv);

    pscom_set_debug(arg_verbose);

    pscom_init(PSCOM_VERSION);
    sock = pscom_open_socket(0, 0);
    if (!sock) {
        abort_on_error("pscom_open_socket() failed", PSCOM_ERR_STDERROR);
    }
    sock->ops = socket_ops_server;

    pscom_socket_set_name(sock, arg_listenname);

    rc = pscom_listen(sock, arg_listenport);
    if (rc) { abort_on_error("pscom_listen() failed", rc); }

    pscom_connection_t *con = pscom_open_connection(sock);

    rc = pscom_connect_socket_str(con, arg_peer_str);
    if (rc) { abort_on_error("pscom_connect_socket_str()", rc); }

    if (0) { // dummy connection
        pscom_connection_t *cond = pscom_open_connection(sock);
        rc = pscom_connect_socket_str(cond, "localhost:8912@dummy");
        if (rc) { abort_on_error("pscom_connect_socket_str()", rc); }
    }

    // printf("Lokal connection: %p\n", con);

    {
        int peer_port;
        char peer_name[8];

        ret = pscom_parse_socket_ondemand_str(arg_peer_str, NULL, &peer_port,
                                              &peer_name);
        if (ret) { error(1, errno, "parse peer address failed"); }

        printf("Call:\n");
        printf("%s -l %d -n %1.8s %s%s\n", progname, peer_port, peer_name,
               pscom_listen_socket_ondemand_str(sock), arg_send ? "" : " -s");
    }

    pscom_stop_listen(sock);

    if (arg_send) {
        printf("Send in 2 sec\n");
        sleep(2);
        char buf[1] = "x";

        pscom_send(con, NULL, 0, buf, 1);
        printf("Send: %1.1s\n", buf);

        rc = pscom_recv(con, NULL, NULL, 0, buf, 1);
        if (rc) { abort_on_error("pscom_recv()", rc); }
        printf("Receive: %1.1s\n", buf);
    } else {
        char buf[1] = "o";
        rc          = pscom_recv(con, NULL, NULL, 0, buf, 1);
        if (rc) { abort_on_error("pscom_recv()", rc); }
        printf("Receive: %1.1s\n", buf);

        buf[0] = 'y';
        pscom_send(con, NULL, 0, buf, 1);
        printf("Send: %1.1s\n", buf);
    }

    //	sleep(10);
    puts(CYAN);
    pscom_dump_info(stdout);
    puts(NORM);

    pscom_flush(con);
    pscom_close_connection(con);
    pscom_close_socket(sock);

    return 0;
}
