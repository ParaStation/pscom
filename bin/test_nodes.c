/*
 * ParaStation
 *
 * Copyright (C) 2001-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>

#include <popt.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "pscom.h"
#ifdef PSMGMT_ENABLED
#include "pse.h"
extern short PSC_getMyID(void);
#endif

#define INET_ADDR_SPLIT(addr) ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >>  8) & 0xff, (addr) & 0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"

#define maxnp (4*1024)
#define DEFAULT_PORT 6020

static int arg_np=-1;
static int arg_port=PSCOM_ANYPORT;
static int arg_cnt=1;
static int arg_map=0;
static int arg_type=0;
static int arg_manual=0;
static int arg_rlimit_nofile=-1;
static int arg_verbose = 0;
static const char *arg_server = NULL;
int conrecv[maxnp][maxnp];
pscom_con_type_t con_type[maxnp][maxnp];
int map_node[maxnp];
int map_port[maxnp];
pscom_connection_t *map_conn[maxnp] = { NULL };
int map_psid[maxnp];
#define HOSTNAME_SIZE 16
char map_nodename[maxnp][HOSTNAME_SIZE]; // = { [0 ... maxnp-1 ] = "???" };
int myrank = -1;
int master_node = -1;
int master_port = -1;
int finish=0;
pscom_socket_t *pscom_socket = NULL;
int changes = 1;
int i_am_server = 0;

static
int get_unused_rank(void);
void send_test_response(int from, int to, int type);

#define max_used_con_types 50
#define con_type_error 49

const char *
con_type_str(int type)
{
    if (type == con_type_error) {
	return "Error";
    } else {
	return pscom_con_type_str(type);
    }
}


void time_handler_old(int signal)
{
    int j,k;
    int used_con_types[max_used_con_types];
    int ranks_n;
    char *space;
    if (!changes) {
	fprintf(stdout, ".");
	goto out;
    }
#ifndef __DECC
    fprintf(stdout,"\e[H");
    fprintf(stdout,"\e[2J");
#endif
    ranks_n = arg_manual ? get_unused_rank() : arg_np;
    space = ranks_n < 40 ? " " : "";

    /* 1st line */
    if (ranks_n > 100) {
	fprintf(stdout,"                     ");
	for (j = 0; j < ranks_n; j++) {
	    if (j < 100) {
		fprintf(stdout," %s", space);
	    } else {
		fprintf(stdout,"%1d%s", (j / 100) % 10, space);
	    }
	}
	fprintf(stdout,"\n");
    }
    /* 2nd line */
    fprintf(stdout,"                     ");
    for (j = 0; j < ranks_n; j++) {
	if (j < 10) {
	    fprintf(stdout," %s", space);
	} else {
	    fprintf(stdout,"%1d%s", (j / 10) % 10, space);
	}
    }
    fprintf(stdout,"\n");

    /* 3rd line */
    /*              1234 1234 1234567890 */
    fprintf(stdout,"rank psid %10s ", "nodename");
    for (j = 0; j < ranks_n; j++)
	fprintf(stdout,"%1d%s", j % 10, space);
    fprintf(stdout,"\n");

    memset(used_con_types, 0, sizeof(used_con_types));
    /* map */
    for (j = 0; j < ranks_n; j++) {
	fprintf(stdout,"%4d %4d %10s ", j, map_psid[j], map_nodename[j]);
	for (k = 0;k < ranks_n; k++) {
	    if (!arg_type) {
		if (conrecv[j][k])
		    fprintf(stdout,"%1d%s", conrecv[j][k], space);
		else
		    fprintf(stdout,".%s", space);
	    } else {
		unsigned ctype = con_type[j][k];
		if (ctype == PSCOM_CON_TYPE_NONE) {
		    fprintf(stdout,"?%s", space);
		} else {
		    fprintf(stdout, "%c%s", con_type_str(ctype)[0], space);
		    if (ctype < max_used_con_types) used_con_types[ctype] = 1;
		}
	    }
	}
	fprintf(stdout,"\n");
    }

    if (arg_type) {
	fprintf(stdout,"Types: ");
	for (j = PSCOM_CON_TYPE_LOOP; j < max_used_con_types; ++j) {
	    if (!used_con_types[j]) continue;
	    const char *state = con_type_str(j);
	    fprintf(stdout,"  %c=%s", state[0], state);
	}
	fprintf(stdout,"\n");
    }
out:
    fflush(stdout);
    changes = 0;
}


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


#include <stdlib.h>

static
void set_rlimit_nofile(int rlimit_nofile)
{
    struct rlimit rl;
    int rc;

    rl.rlim_cur = rlimit_nofile;  /* Soft limit */
    rl.rlim_max = rlimit_nofile;  /* Hard limit */

    rc = setrlimit(RLIMIT_NOFILE, &rl);

    if (rc < 0) perror("Setting RLIMIT_NOFILE");
}


void print_list(int *ilist,int size)
{
    int i;
    int first,last;
//    qsort(ilist,size,sizeof(int *));
    if (!size){
	fprintf(stdout,"none");
	return;
    }
    first=0;
    last=0;
    for (i=1;i<size;i++){
	if (ilist[i] == ilist[i-1] + 1){
	    last = i;
	}else{
	    last=i-1;
	    if (first==last){
		fprintf(stdout,"%d,",ilist[first]);
	    }else{
		fprintf(stdout,"%d-%d,",ilist[first],ilist[last]);
	    }
	    first=i;
	    last=i;
	}
    }
    if (first==last){
	fprintf(stdout,"%d",ilist[first]);
    }else{
	fprintf(stdout,"%d-%d",ilist[first],ilist[last]);
    }
}

int print_list_compare(const void *a, const void *b)
{
    int va = *(int*)a;
    int vb = *(int*)b;
    if (va > vb)
	return 1;
    else
	return -1;
}

void print_list_sort(int *ilist,int size)
{
    int *silist = (int *)malloc(size * sizeof(int));
    int sisize = 0;
    int i;
    if (!size) return;
    qsort(ilist,size,sizeof(int),print_list_compare);
    silist[sisize++] = ilist[ 0 ];
    for (i=1;i<size;i++){
	if (silist[sisize-1] != ilist[i]){
	    silist[sisize++] = ilist[ i ];
	}
    }
    print_list(silist,sisize);

    free(silist);
}

int answer_equal(int i,int j)
{
    int k;
    for (k=1;k<arg_np;k++){

	if (((conrecv[i][k] > 0) ^
	     (conrecv[j][k] > 0)))
	    return 0;
    }
    return 1;
}

void time_handler(int signal)
{
    int i,j;
    int *checked = (int *)malloc(sizeof(int) * arg_np);
    int tmpsize;
    int *tmp = (int *)malloc(sizeof(int) * arg_np);
    int *tmphost = (int *)malloc(sizeof(int) * arg_np);
    int tmpsize2;
    int *tmp2 = (int *)malloc(sizeof(int) * arg_np);
    int *tmphost2 = (int *)malloc(sizeof(int) * arg_np);

    memset(checked, 0, arg_np * sizeof(int));
    memset(tmp, 0, arg_np * sizeof(int));
    memset(tmphost, 0, arg_np * sizeof(int));
    memset(tmp2, 0, arg_np * sizeof(int));
    memset(tmphost2, 0, arg_np * sizeof(int));
    if (!changes) {
	fprintf(stdout, ".");
	goto out;
    }
//    fprintf(stdout,"\e[H");
//    fprintf(stdout,"\e[2J");
    fprintf(stdout, "---------------------------------------\n");
    fprintf(stdout, "Master node %10s\n", map_nodename[0]);

    /* No Answer:*/
    tmpsize=0;
    for (j = 0; j < arg_np; j++) {
	if (!map_conn[j]) {
	    checked[j] = 1;
	    tmp[tmpsize++] = j;
	}
    }
    if (tmpsize) {
	fprintf(stdout,"Wait for answer from process: ");
	print_list(tmp, tmpsize);
	fprintf(stdout, "\n");
    }

    /* Answer: */
    for (j = 0; j < arg_np; j++) {
	tmpsize = 0;
	if (checked[j]) continue;
	checked[j] = 1;
	tmphost[tmpsize] = map_psid[j];
	tmp[tmpsize++] = j;

	/* Find equal lines */
	for (i=j+1;i<arg_np;i++){
	    if (!checked[i] && answer_equal(j,i)) {
		tmphost[tmpsize] = map_psid[i];
		tmp[tmpsize++] = i;
		checked[i] = 1;
	    }
	}

	/* to */
	tmpsize2 = 0;
	tmphost2[tmpsize2] = map_psid[0];
	tmp2[tmpsize2++] = 0;
	for (i = 1; i < arg_np; i++) {
	    if (conrecv[j][i] > 0) {
		tmphost2[tmpsize2] = map_psid[i];
		tmp2[tmpsize2++] = i;
	    }
	}

	fprintf(stdout,"Process ");
	print_list(tmp,tmpsize);
	if (tmpsize2){
	    fprintf(stdout," to ");
	    print_list(tmp2,tmpsize2);
	    fprintf(stdout," ( node ");
	    print_list_sort(tmphost,tmpsize);
	    fprintf(stdout," to ");
	    print_list_sort(tmphost2,tmpsize2);
	    fprintf(stdout," ) OK\n");
	}else{
	    fprintf(stdout," waiting ( node ");
	    print_list_sort(tmphost,tmpsize);
	    fprintf(stdout,")\n");
	}
//	fprintf(stdout,"%3d(node %3d) ",j,mapnode[j]);
    }



//        for (j=0;j<arg_np;j++){
//	fprintf(stdout,"%3d(node %3d) ",j,mapnode[j]);
//	 for (k=0;k<arg_np;k++){
//	    fprintf(stdout,"%1d ",conrecv[j][k]);
//	}
//	fprintf(stdout,"\n");
//        }
out:
    fflush(stdout);
    free(checked);
    free(tmp);
    free(tmphost);
    free(tmp2);
    free(tmphost2);
    changes = 0;
}


void init_conns(int np)
{
    int i, j;
    for (i = 0; i < np; i++) {
	map_node[i] = -1;
	map_port[i] = -1;
	map_conn[i] = NULL;
	map_psid[i] = -1;
	memcpy(map_nodename[i], "???", 4);
	for (j = 0; j < np; j++) {
	    conrecv[i][j]=0;
	    con_type[i][j] = PSCOM_CON_TYPE_NONE;
	}
    }
}


static
int get_unused_rank(void)
{
    int rank;
    for (rank = 0; rank < maxnp; rank++) {
	if (!map_conn[rank]) {
	    return rank;
	}
    }
    fprintf(stderr, "Too many connections. test_nodes compile time maxnp=%u\n", maxnp);
    exit(1);
}


static
int rank_of_connection(pscom_connection_t *con) {
    int rank;
    for (rank = 0; rank < maxnp; rank++) {
	if (map_conn[rank] == con) {
	    return rank;
	}
    }
    return -1;
}


void connect_to_rank(int rank, int node, int port)
{
    if (map_conn[rank]) {
//	printf("Double connect to rank %d from rank %d\n",
//	       rank, myrank);
	return; /* already connected */
    }

//    fprintf(stderr, "Connecting from %04u to %04u %s\n",
//	    myrank, rank,
//	    pscom_socket_str(node, port));

    pscom_connection_t *con = pscom_open_connection(pscom_socket);

    map_conn[rank] = con;
    map_node[rank] = node;
    map_port[rank] = port;

    pscom_err_t rc = pscom_connect(con, node, port);

    if (rc) {
	fprintf(stderr, "Connect to rank %d from rank %d failed : %s\n",
		rank, myrank, pscom_err_str(rc));
	pscom_close_connection(con);
	con = NULL;
	if (rank == 0) exit(1);
    }
}


static
void con_error_handler(pscom_connection_t *connection, pscom_op_t operation, pscom_err_t error)
{
    if (error == PSCOM_ERR_EOF) return; // do not report EOF

    if (map_conn[0] == connection) {
	fprintf(stderr, "#%u: Master Connection to %s : %s, Exiting.\n",
		myrank,
		pscom_con_info_str(&connection->remote_con_info),
		pscom_err_str(error));
	exit(1);
    } else {
	int peer_rank = rank_of_connection(connection);
	if (peer_rank >= 0) {
	    send_test_response(myrank, peer_rank, con_type_error);
	}

	fprintf(stderr, "#%u: Connection to #%u %s : %s\n",
		myrank,
		peer_rank,
		pscom_con_info_str(&connection->remote_con_info),
		pscom_err_str(error));
    }
}


static
void set_myrank(int rank)
{
    myrank = rank;
    char name[10];
    sprintf(name, "rank%04u", myrank);
    pscom_socket_set_name(pscom_socket, name);
}


#define MSG_INFO_TO_MASTER 1
#define MSG_INFO_TO_SLAVE 2
#define MSG_INFO_SLAVE_TO_SLAVE 3
#define MSG_TEST_REQUEST 4
#define MSG_TEST 5
#define MSG_TEST_RESPONSE 6
#define MSG_EXIT 7

typedef struct test_xheader_s {
    int type;

    int rank;
    int port,node;

    int from;
    int to;
    char hostname[HOSTNAME_SIZE];
    int psid;
    int con_type;
} test_xheader_t;


void send_msg(pscom_connection_t *connection,
	  void *xheader, unsigned int xheader_len,
	  void *data, unsigned int data_len)
{
    if (!connection) return;

    pscom_send(connection, xheader, xheader_len,
	       data, data_len);
}


void send_info_to_master()
{
    test_xheader_t msg;

    /* Connect to master (rank 0) */
    connect_to_rank(0, master_node, master_port);

    /* Send info to master */
    msg.type = MSG_INFO_TO_MASTER;
    msg.rank = myrank;
    msg.node = pscom_get_nodeid();
    msg.port = pscom_get_portno(pscom_socket);
#ifdef PSMGMT_ENABLED
    msg.psid = arg_manual ? 0 : PSC_getMyID();
#else
    msg.psid = 0;
#endif

    gethostname(msg.hostname, HOSTNAME_SIZE);
    msg.hostname[HOSTNAME_SIZE - 1] = 0;

    send_msg(map_conn[0], &msg, sizeof(msg), NULL, 0);
}


static
void recv_info_from_master()
{
    if (myrank == -1) {
	pscom_err_t err;
	int rank;

	err = pscom_recv_from(map_conn[0],
			      NULL, 0,
			      &rank, sizeof(myrank));
	exit_on_error(err, "recv_info_from_master");

	set_myrank(rank);
    }
}

void send_info_to_slave(int about, int to)
{
    test_xheader_t msg;

    /* Send info to slave */
    msg.type = MSG_INFO_TO_SLAVE;
    msg.rank = about;
    msg.node = map_node[about];
    msg.port = map_port[about];

    send_msg(map_conn[to], &msg, sizeof(msg), NULL, 0);
}

void send_info_slave_to_slave(int to)
{
    test_xheader_t msg;

    msg.type = MSG_INFO_SLAVE_TO_SLAVE;
    msg.rank = myrank;

    send_msg(map_conn[to], &msg, sizeof(msg), NULL, 0);
}

void send_test_request(int to, int from)
{
    test_xheader_t msg;

    msg.type = MSG_TEST_REQUEST;
    msg.from = from;
    msg.to = to;

    send_msg(map_conn[from], &msg, sizeof(msg), NULL, 0);
}

void send_test(int to)
{
    test_xheader_t msg;

    msg.type = MSG_TEST;
    msg.from = myrank;
    msg.to = to;

    send_msg(map_conn[to], &msg, sizeof(msg), NULL, 0);
}

void send_test_response(int from, int to, int type)
{
    test_xheader_t msg;

    msg.type = MSG_TEST_RESPONSE;
    msg.from = from;
    msg.to = to;
    msg.con_type = type;
    send_msg(map_conn[0], &msg, sizeof(msg), NULL, 0);
}

void send_exit(int to)
{
    test_xheader_t msg;

    msg.type = MSG_EXIT;

    send_msg(map_conn[to], &msg, sizeof(msg), NULL, 0);
}


static
void spawn_manual_master(int argc, char **argv, int np)
{
    int me = pscom_get_nodeid();

    if (arg_server) {
	int rc = pscom_parse_socket_str(arg_server, &master_node, &master_port);
	exit_on_error(rc, "Server: '%s'\n", arg_server);

	if ((master_port == 0) && (master_node == me)) {
	    // i am the server (rank=0).
	    i_am_server = 1;

	    if (arg_port == -1) {
		// Use default port, if not specified otherwise.
		arg_port = DEFAULT_PORT;
	    }
	    arg_server = NULL;
	}
	if (master_port == 0) {
	    master_port = arg_port == -1 ? DEFAULT_PORT : arg_port;
	}
    } else {
	i_am_server = 1;
	master_node = me;
    }
    if (arg_verbose) {
	fprintf(stderr, "Me: "INET_ADDR_FORMAT" %s\n", INET_ADDR_SPLIT(me), i_am_server ? "server" : "client");
	fflush(stderr);
    }
}


static
void spawn_manual(int argc, char **argv, int np)
{
    if (i_am_server) {
	set_myrank(0);
	master_port = pscom_get_portno(pscom_socket);
	printf("Call:\n%s %s\n", argv[0], pscom_socket_str(master_node, master_port));
    }
}


static
void spawn_master(int argc, char **argv, int np)
{
#ifndef PSMGMT_ENABLED
    arg_manual = 1;
#endif
    if (arg_manual) {
	spawn_manual_master(argc, argv, np);
	return;
    }
#ifdef PSMGMT_ENABLED
    PSE_initialize();

    myrank = PSE_getRank();

    if (myrank == -1){
	/* I am the logger */
	/* Set default to none: */
	setenv("PSI_NODES_SORT","NONE",0);
	/* Loop nodes first. */
	setenv("PSI_LOOP_NODES_FIRST", "1", 0);
	if (strcmp(getenv("PSI_LOOP_NODES_FIRST"), "0") == 0) {
	    /* Workaround: If the user overwrite the env with "0", unset the
	       env. The pse layer only checks for the definition and
	       do not evaluate the value!. */
	    unsetenv("PSI_LOOP_NODES_FIRST");
	}
	PSE_getPartition(np);
	PSE_spawnMaster(argc, argv);
	/* Never be here ! */
	exit(1);
    }

    /* PSE_registerToParent(); */
#endif
}


static
void spawn_pse(int argc, char **argv, int np)
{
#ifdef PSMGMT_ENABLED
    if (myrank == 0) {
	/* Master node: Set parameter from rank 0 */
	PSE_spawnTasks(np-1, pscom_get_nodeid(), pscom_get_portno(pscom_socket), argc, argv);
    }
    master_node = PSE_getMasterNode();
    master_port = PSE_getMasterPort();
#endif
}


static
void spawn(int argc, char **argv, int np)
{
    if (arg_manual) {
	spawn_manual(argc, argv, np);
    } else {
	spawn_pse(argc, argv, np);
    }
}

void run(int argc,char **argv,int np)
{
//    PSP_PortH_t rawporth;
    int j,k,end;
    FILE *out;
    struct itimerval timer;
    struct itimerval timer_old;


    /* Initialize Myrinet */
    if (pscom_init(PSCOM_VERSION)) {
	perror("pscom_init() failed!");
	exit(-1);
    }
    spawn_master(argc, argv, np);

    pscom_socket = pscom_open_socket(0, 0);

    pscom_socket->ops.con_error = con_error_handler;

    if (pscom_listen(pscom_socket, arg_port)) {
	if ((errno == EADDRINUSE) && i_am_server && (arg_port == DEFAULT_PORT)) {
	    // server already started? Try again as a client with rank > 0 with any port.
	    i_am_server = 0;
	    arg_port = PSCOM_ANYPORT;
	    if (pscom_listen(pscom_socket, arg_port)) {
		perror("Cant bind any port!");
		exit(-1);
	    }
	} else {
	    perror("Cant bind port!");
	    exit(-1);
	}
    }

    init_conns(np);

    spawn(argc, argv, np);

    /* Init output */
    out = stdout;
    if (myrank ==  0) {
	int rc;
	timer.it_interval.tv_sec=1;
	timer.it_interval.tv_usec=500*1000;
	timer.it_value.tv_sec=1;
	timer.it_value.tv_usec=500*1000;
	if (arg_map){
	    signal(SIGALRM,time_handler_old);
	}else{
	    signal(SIGALRM,time_handler);
	}
	rc = setitimer(ITIMER_REAL,&timer,&timer_old);
	assert(rc == 0);
	//rc = setitimer(ITIMER_VIRTUAL,&timer,&timer_old);
    }

    send_info_to_master();
    recv_info_from_master();

    end = np * np * arg_cnt;
//    for (i=0;(i<end)||(rank>0);i++){

    pscom_request_t *req = pscom_request_create(sizeof(test_xheader_t), 0);
    test_xheader_t *head;
    while (end) {
	req->data_len = 0;
	req->xheader_len = sizeof(*head);
	req->connection = NULL;
	req->socket = pscom_socket;

	changes = 1;
	pscom_post_recv(req);
	pscom_wait(req);

	if (!pscom_req_successful(req)) {
	    fprintf(stderr, "pscom_recv() failed : %s\n", pscom_req_state_str(req->state));
	    continue;
	}
	head = (test_xheader_t *)&req->xheader;

	// fprintf(out,"Recv (%d) from node %s\n", head->type, pscom_con_str(req->connection));
	switch (head->type){
	case MSG_INFO_TO_MASTER: { /* Only the master receive this type */
	    int r = head->rank;
	    if (r == -1) {
		r = get_unused_rank();
		send_msg(req->connection, NULL, 0, &r, sizeof(r));
	    }
	    map_node[r] = head->node;
	    map_port[r] = head->port;
	    map_conn[r] = req->connection;
	    map_psid[r] = head->psid;
	    memcpy(map_nodename[r], head->hostname, HOSTNAME_SIZE);

	    for (j = 0; j < np; j++) {
		if (map_conn[j]) {
		    /* send new info about r to all already connected slaves j */
		    if (r <= j) send_info_to_slave(r, j);
		    /* send info about all already connected slaves j to r */
		    if (j < r) /* dont send twice */
			send_info_to_slave(j, r);
		}
	    }

	    /* Now check all new connections */
	    for (k = 0; k < arg_cnt; k++) {
		for (j = 0; j < np; j++) {
		    if (map_conn[j]) {
			if (r <= j)
			    send_test_request(r, j); /* test j to r */
			if (j < r) /* dont test twice */
			    send_test_request(j, r); /* test r to j */
		    }
		}
	    }
	    break;
	}
	case MSG_INFO_TO_SLAVE: { /* slave received info about a slave */
	    connect_to_rank(head->rank, head->node, head->port);
	    send_info_slave_to_slave(head->rank);
	    break;
	}
	case MSG_INFO_SLAVE_TO_SLAVE: { /* slave received info about a slave */
	    int r = head->rank;
	    map_conn[r] = req->connection;
	    break;
	}
	case MSG_TEST_REQUEST: {
	    send_test(head->to);
	    break;
	}
	case MSG_TEST: {
	    send_test_response(head->from, head->to, req->connection->type);
	    break;
	}
	case MSG_TEST_RESPONSE: { /* only the master receive the response */
	    conrecv[head->from][head->to] += 1;
	    con_type[head->from][head->to] = head->con_type;
	    end--;
	    /* Now test other direction */
	    if (head->from > head->to)
		send_test_request(head->from, head->to);
	    break;
	}
	case MSG_EXIT:{ /* Recv EXIT from master */
#ifdef PSMGMT_ENABLED
	    if (!arg_manual) PSE_finalize();
#endif
	    exit(0);
	}
	default:{
	    /* never be here */
	    fprintf(out, "recv type %d\n", head->type);
	}
	}
    }
    pscom_request_free(req);

    /* Exit all slaves: */
    for (j = 1 /* not to master (me) */; j < np; j++) {
	if (map_conn[j]) {
	    send_exit(j);
	}
    }

    signal(SIGALRM,SIG_IGN);
    if (arg_map){
	time_handler_old(0);
    }else{
	time_handler(0);
    }

    fprintf(out,"All connections ok\n");
    fclose(out);

#ifdef PSMGMT_ENABLED
    if (!arg_manual) PSE_finalize();
#endif
}


int main(int argc, char *argv[])
{
    poptContext optCon;   /* context for parsing command-line options */
    int rc;

    struct poptOption optionsTable[] = {
	{ "np", '\0', POPT_ARG_INT | POPT_ARGFLAG_ONEDASH,
	  &arg_np, 0, "number of processes to start", "num"},
	{ "cnt", '\0', POPT_ARG_INT | POPT_ARGFLAG_ONEDASH,
	  &arg_cnt, 0, "number of test messages to send", "num"},
	{ "map", '\0', POPT_ARG_NONE | POPT_ARGFLAG_ONEDASH,
	  &arg_map, 0, "print map", NULL},
	{ "type", 't', POPT_ARG_NONE | POPT_ARGFLAG_ONEDASH,
	  &arg_type, 0, "print connection type", NULL},
	{ "manual", 'm', POPT_ARG_NONE | POPT_ARGFLAG_ONEDASH,
	  &arg_manual, 0, "manual processes start", NULL},
	{ "listen" , 'l', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARGFLAG_ONEDASH | POPT_ARG_INT,
	  &arg_port, 0, "listen on", "port" },
	{ "rlnofile", '\0', POPT_ARG_INT | POPT_ARGFLAG_ONEDASH,
	  &arg_rlimit_nofile, 0, "set RLIMIT_NOFILE (soft and hard)", "num"},
	{ "verbose"	, 'v', POPT_ARGFLAG_OR | POPT_ARG_VAL,
	  &arg_verbose, 1, "increase verbosity", NULL },
	POPT_AUTOHELP
	{ NULL, '\0', 0, NULL, 0, NULL, NULL}
    };

    //printf(__DATE__" "__TIME__"\n");

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);
    rc = poptGetNextOpt(optCon);

    if (rc < -1) {
	/* an error occurred during option processing */
	poptPrintUsage(optCon, stderr, 0);
	fprintf(stderr, "%s: %s\n",
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
		poptStrerror(rc));
	return 1;
    }

    {
	const char *server = poptGetArg(optCon);
	if (server) {
	    arg_server = server;
	    arg_manual = 1;
	}
    }

    if (arg_np <= 0) {
	if (arg_manual) {
	    arg_np = maxnp;
	} else {
	    fprintf(stderr, "missing arg -np\n");
	    exit(1);
	}
    }

    if (arg_np > maxnp) {
	fprintf(stderr, "to many processes (max. %d)\n", maxnp);
	exit(1);
    }

    if (arg_type) arg_map = 1;

    if (arg_rlimit_nofile != -1) set_rlimit_nofile(arg_rlimit_nofile);

    run(argc, argv, arg_np);

    return 0;
}
