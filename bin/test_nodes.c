/*
 * ParaStation
 *
 * Copyright (C) 2001-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>

#include <popt.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "pscom.h"
#include "pse.h"
extern short PSC_getMyID(void);

#define maxnp 2048

static int arg_np=-1;
static int arg_port=PSCOM_ANYPORT;
static int arg_cnt=1;
static int arg_map=0;
static int arg_type=0;
static int arg_rlimit_nofile=-1;
int conrecv[maxnp][maxnp];
pscom_con_type_t con_type[maxnp][maxnp];
int map_node[maxnp];
int map_port[maxnp];
pscom_connection_t *map_conn[maxnp];
int map_psid[maxnp];
#define HOSTNAME_SIZE 16
char map_nodename[maxnp][HOSTNAME_SIZE]; // = { [0 ... maxnp-1 ] = "???" };
int myrank;

int finish=0;
pscom_socket_t *pscom_socket = NULL;


void time_handler_old(int signal)
{
    int j,k;
#define max_used_con_types 30
    int used_con_types[max_used_con_types];
#ifndef __DECC
    fprintf(stdout,"\e[H");
    fprintf(stdout,"\e[2J");
#endif
    /* 1st line */
    if (arg_np > 100) {
	fprintf(stdout,"                     ");
	for (j = 0; j < arg_np; j++) {
	    if (j < 100) {
		fprintf(stdout,"  ");
	    } else {
		fprintf(stdout,"%1d ", (j / 100) % 10);
	    }
	}
	fprintf(stdout,"\n");
    }
    /* 2nd line */
    fprintf(stdout,"                     ");
    for (j = 0; j < arg_np; j++) {
	if (j < 10) {
	    fprintf(stdout,"  ");
	} else {
	    fprintf(stdout,"%1d ", (j / 10) % 10);
	}
    }
    fprintf(stdout,"\n");

    /* 3rd line */
    /*              1234 1234 1234567890 */
    fprintf(stdout,"rank psid %10s ", "nodename");
    for (j = 0; j < arg_np; j++)
	fprintf(stdout,"%1d ", j % 10);
    fprintf(stdout,"\n");

    memset(used_con_types, 0, sizeof(used_con_types));
    /* map */
    for (j = 0; j < arg_np; j++) {
	fprintf(stdout,"%4d %4d %10s ", j, map_psid[j], map_nodename[j]);
	for (k = 0;k < arg_np; k++) {
	    if (!arg_type) {
		if (conrecv[j][k])
		    fprintf(stdout,"%1d ", conrecv[j][k]);
		else
		    fprintf(stdout,". ");
	    } else {
		unsigned ctype = con_type[j][k];
		if (ctype == PSCOM_CON_TYPE_NONE) {
		    fprintf(stdout,"? ");
		} else {
		    fprintf(stdout, "%c ", pscom_con_type_str(ctype)[0]);
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
	    const char *state = pscom_con_type_str(j);
	    fprintf(stdout,"  %c=%s", state[0], state);
	}
	fprintf(stdout,"\n");
    }

    fflush(stdout);
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
    int i,j,k;
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
    fflush(stdout);
    free(checked);
    free(tmp);
    free(tmphost);
    free(tmp2);
    free(tmphost2);
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
    pscom_err_t rc = pscom_connect(con, node, port);

    if (rc) {
	printf("Connect to rank %d from rank %d failed : %s\n",
	       rank, myrank, pscom_err_str(rc));
	pscom_close_connection(con);
	con = NULL;
    }
    map_conn[rank] = con;
    map_node[rank] = node;
    map_port[rank] = port;
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


void send_info_to_master()
{
    test_xheader_t msg;

    /* Connect to master (rank 0) */
    connect_to_rank(0, PSE_getMasterNode(), PSE_getMasterPort());

    /* Send info to master */
    msg.type = MSG_INFO_TO_MASTER;
    msg.rank = myrank;
    msg.node = pscom_get_nodeid();
    msg.port = pscom_get_portno(pscom_socket);
    msg.psid = PSC_getMyID();

    gethostname(msg.hostname, HOSTNAME_SIZE);
    msg.hostname[HOSTNAME_SIZE - 1] = 0;

    pscom_send(map_conn[0], &msg, sizeof(msg), NULL, 0);
}

void send_info_to_slave(int about, int to)
{
    test_xheader_t msg;

    /* Send info to slave */
    msg.type = MSG_INFO_TO_SLAVE;
    msg.rank = about;
    msg.node = map_node[about];
    msg.port = map_port[about];

    pscom_send(map_conn[to], &msg, sizeof(msg), NULL, 0);
}

void send_info_slave_to_slave(int to)
{
    test_xheader_t msg;

    msg.type = MSG_INFO_SLAVE_TO_SLAVE;
    msg.rank = myrank;

    pscom_send(map_conn[to], &msg, sizeof(msg), NULL, 0);
}

void send_test_request(int to, int from)
{
    test_xheader_t msg;

    msg.type = MSG_TEST_REQUEST;
    msg.from = from;
    msg.to = to;

    pscom_send(map_conn[from], &msg, sizeof(msg), NULL, 0);
}

void send_test(int to)
{
    test_xheader_t msg;

    msg.type = MSG_TEST;
    msg.from = myrank;
    msg.to = to;

    pscom_send(map_conn[to], &msg, sizeof(msg), NULL, 0);
}

void send_test_response(int from, int to)
{
    test_xheader_t msg;

    msg.type = MSG_TEST_RESPONSE;
    msg.from = from;
    msg.to = to;
    msg.con_type = map_conn[from] ? map_conn[from]->type : PSCOM_CON_TYPE_NONE;

    pscom_send(map_conn[0], &msg, sizeof(msg), NULL, 0);
}

void send_exit(int to)
{
    test_xheader_t msg;

    msg.type = MSG_EXIT;

    pscom_send(map_conn[to], &msg, sizeof(msg), NULL, 0);
}


void run(int argc,char **argv,int np)
{
//    PSP_PortH_t rawporth;
    int i,j,k,end;
    FILE *out;
    struct itimerval timer;

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

    /* Initialize Myrinet */
    if (pscom_init(PSCOM_VERSION)) {
	perror("pscom_init() failed!");
	exit(-1);
    }

    pscom_socket = pscom_open_socket(0, 0);

    char name[10];
    sprintf(name, "rank%04u", myrank);
    pscom_socket_set_name(pscom_socket, name);

    if (pscom_listen(pscom_socket, arg_port)) {
	perror("Cant bind port!");
	exit(-1);
    }

    init_conns(np);

    if (myrank == 0) {
	/* Master node: Set parameter from rank 0 */
	PSE_spawnTasks(np-1, pscom_get_nodeid(), pscom_get_portno(pscom_socket), argc, argv);
    }

    /* Init output */
    out = stdout;
    if (myrank ==  0) {
	timer.it_interval.tv_sec=0;
	timer.it_interval.tv_usec=1500*1000;
	timer.it_value.tv_sec=0;
	timer.it_value.tv_usec=1500*1000;
	if (arg_map){
	    signal(SIGALRM,time_handler_old);
	}else{
	    signal(SIGALRM,time_handler);
	}
	setitimer(ITIMER_REAL,&timer,0);
    }

    send_info_to_master();

    end = np * np * arg_cnt;
//    for (i=0;(i<end)||(rank>0);i++){

    pscom_request_t *req = pscom_request_create(sizeof(test_xheader_t), 0);
    test_xheader_t *head;
    while (end) {
	req->data_len = 0;
	req->xheader_len = sizeof(*head);
	req->connection = NULL;
	req->socket = pscom_socket;

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
	    send_test_response(head->from, head->to);
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
	    PSE_finalize();
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

    PSE_finalize();
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
	{ "rlnofile", '\0', POPT_ARG_INT | POPT_ARGFLAG_ONEDASH,
	  &arg_rlimit_nofile, 0, "set RLIMIT_NOFILE (soft and hard)", "num"},
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

    if (arg_np <= 0) {
	fprintf(stderr, "missing arg -np\n");
	exit(1);
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
