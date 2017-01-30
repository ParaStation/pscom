/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psport4_pp.c: PingPong over psport4
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

#include "psport4.h"

int arg_verbose=0;
int arg_client=0;
int arg_sport=0;
int arg_server=0;
int arg_loops=1000;
#define MAX_XHEADER 100
int arg_xheader=10;
int arg_maxmsize = 1024 * 1024;

void usage(poptContext optCon, int exitcode, char *error, char *addl)
{
    poptPrintUsage(optCon, stderr, 0);
    if (error) fprintf(stderr, "%s: %s\n", error, addl);
    exit(exitcode);
}

void parse_opt(int argc, char **argv)
{
    int c;            /* used for argument parsing */
    poptContext optCon;   /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
	{ "verbose"  , 'v', POPT_ARG_INT, &arg_verbose , 0,
	  "be more verbose", "level" },
	{ "server" , 's', POPT_ARGFLAG_OR, &arg_server, 0,
	  "run as server", "" },
	{ "client" , 'c', POPT_ARG_INT, &arg_client, 0,
	  "run as client and connect", "server" },
	{ "sport" , 'p', POPT_ARG_INT, &arg_sport, 0,
	  "connect to port", "port" },
	{ "loops"  , 'l', POPT_ARG_INT, &arg_loops , 0,
	  "pp loops", "count" },

	{ "maxsize"  , 0, POPT_ARG_INT, &arg_maxmsize , 0,
	  "maximal messagesize", "size" },
	{ "xheader"  , 0, POPT_ARG_INT, &arg_xheader , 0,
	  "xheader size", "size" },

/*	{ "flag" , 'f', POPT_ARGFLAG_OR, &arg_flag, 0,
	  "flag description", "" },*/
	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };

    optCon = poptGetContext(NULL, argc,(const char **) argv, optionsTable, 0);

    if (argc < 1) {
	poptPrintUsage(optCon, stderr, 0);
	exit(1);
    }

    /* Now do options processing, get portname */
    while ((c = poptGetNextOpt(optCon)) >= 0) {

    }

    if (c < -1) {
	/* an error occurred during option processing */
	fprintf(stderr, "%s: %s\n",
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
		poptStrerror(c));
	poptPrintHelp(optCon, stderr, 0);
	exit(1);
    }

    poptFreeContext(optCon);
}


static
char *dumpstr(void *buf, int size)
{
    static char *ret=NULL;
    char *tmp;
    int s;
    char *b;
    if (ret) free(ret);
    ret = (char *)malloc(size * 5 + 4);
    tmp = ret;
    s = size; b = (char *)buf;
    for (; s ; s--, b++){
	    tmp += sprintf(tmp, "<%02x>", (unsigned char)*b);
    }
    *tmp++ = '\'';
    s = size; b = (char *)buf;
    for (; s ; s--, b++){
	    *tmp++ = (char)(((*b >= 32) && (*b < 127)) ? *b: '.');
    }
    *tmp++ = '\'';
    *tmp++ = 0;
    return ret;
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
void run_pp_server(PSP_PortH_t porth)
{
    void *buf = malloc(arg_maxmsize);
    PSP_RequestH_t req;
    struct {
	PSP_Header_t head_psp;
	char xhead[MAX_XHEADER];
    } header;

    req = PSP_IReceive(porth, buf, arg_maxmsize,
		       &header.head_psp, MAX_XHEADER, NULL, 0);
    PSP_Wait(porth, req);
    req = PSP_ISend(porth, buf, header.head_psp.datalen,
		    &header.head_psp, header.head_psp.xheaderlen,
		    header.head_psp.addr.from, 0);
    PSP_Wait(porth, req);
    PSP_StopListen(porth);
    while (1) {
	req = PSP_IReceive(porth, buf, arg_maxmsize,
			   &header.head_psp, MAX_XHEADER, NULL, 0);
	PSP_Wait(porth, req);
	req = PSP_ISend(porth, buf, header.head_psp.datalen,
			&header.head_psp, header.head_psp.xheaderlen,
			header.head_psp.addr.from, 0);
	PSP_Wait(porth, req);
    }
    free(buf);
}

static
void run_pp_server_verbose(PSP_PortH_t porth)
{
    void *buf = malloc(arg_maxmsize);
    PSP_RequestH_t req;
    int i;
    struct {
	PSP_Header_t head_psp;
	char xhead[MAX_XHEADER];
    } header;

    for (i = 0; i < MAX_XHEADER; i++) {
	header.xhead[i] = (char)(i + 0xe1);
    }
    req = PSP_IReceive(porth, buf, arg_maxmsize,
		       &header.head_psp, MAX_XHEADER, NULL, 0);
    PSP_Wait(porth, req);
    printf("Receive %d xheader :%s\n", header.head_psp.xheaderlen,
	   dumpstr(header.xhead, header.head_psp.xheaderlen));
    printf("        %d data :%s\n", header.head_psp.datalen,
	   dumpstr(buf, MIN(header.head_psp.datalen, 16)));
    req = PSP_ISend(porth, buf, header.head_psp.datalen,
		    &header.head_psp, header.head_psp.xheaderlen,
		    header.head_psp.addr.from, 0);
    PSP_Wait(porth, req);
    PSP_StopListen(porth);
    while (1) {
	req = PSP_IReceive(porth, buf, arg_maxmsize,
			   &header.head_psp, MAX_XHEADER, NULL, 0);
	PSP_Wait(porth, req);
	printf("Receive %d xheader :%s\n", header.head_psp.xheaderlen,
	       dumpstr(header.xhead, header.head_psp.xheaderlen));
	printf("        %d data :%s\n", header.head_psp.datalen,
	       dumpstr(buf, MIN(header.head_psp.datalen, 16)));
	req = PSP_ISend(porth, buf, header.head_psp.datalen,
			&header.head_psp, header.head_psp.xheaderlen,
			header.head_psp.addr.from, 0);
	PSP_Wait(porth, req);
    }
    free(buf);
}

static
int run_pp_c(PSP_PortH_t porth, int conid, int msize, int xsize, int loops)
{
    int cnt;
    void *sbuf = malloc(msize);
    void *rbuf = malloc(msize);
    PSP_RequestH_t rreq;
    struct {
	PSP_Header_t head_psp;
	char xhead[xsize];
    } sheader, rheader;

    memset(sbuf, 42, msize);
    memset(rbuf, 42, msize);
    if (arg_verbose)
	for (cnt = 0; cnt < xsize; cnt++)
	    sheader.xhead[cnt] = (char)(cnt + 1);

    for (cnt = 0; cnt < loops; cnt++) {
	PSP_ISend(porth, sbuf, msize,
		  &sheader.head_psp, xsize, conid, 0);

//	printf("SEND %d data :%s\n", msize,
//	       dumpstr(sbuf, MIN(msize, 16)));
	rreq = PSP_IReceive(porth, rbuf, msize,
			    &rheader.head_psp, xsize, NULL, 0);

	PSP_Wait(porth, rreq);
    }

    free(sbuf);
    free(rbuf);
    return 0;
}

void
do_pp_client(PSP_PortH_t porth, int conid)
{
    unsigned long t1, t2;
    double time;
    double throuput;
    unsigned int msgsize;
    double ms;
    int res;

    if (arg_xheader > MAX_XHEADER)
	arg_xheader = MAX_XHEADER;
    printf("Xheader : %d bytes\n", arg_xheader);
    printf("%5s %8s %6s %6s\n", "msize", "loops", "time", "throughput");
    for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
//	for (ms = 1.4142135; ms < IB_MTU_PAYLOAD - 1; ms = ms +1) {
	msgsize = (unsigned int)(ms + 0.5);

	/* warmup, for sync */
	run_pp_c(porth, conid, 2, 2, 2);
	t1 = getusec();
	res = run_pp_c(porth, conid, msgsize,
		       arg_xheader, arg_loops);
	t2 = getusec();
	time = (double)(t2 - t1) / (arg_loops * 2);
	throuput = msgsize / time;
	if (res == 0) {
	    printf("%5d %8d %6.2f %6.2f\n", msgsize, arg_loops, time, throuput);
	    fflush(stdout);
	} else {
	    printf("Error in communication...\n");
	}
    }

    return;
}



int main(int argc, char **argv)
{
    PSP_PortH_t porth;
    parse_opt(argc, argv);

    if ((!arg_server && !arg_client) ||
	(arg_server && arg_client)) {
	printf("run as server or client? (-s or -c)\n");
	exit(1);
    }
    if (arg_client && !arg_sport) {
	printf("server port? (-p sport)\n");
	exit(1);
    }

    if (PSP_Init() != PSP_OK) goto err_psp_init;


    if (arg_server) {
	porth = PSP_OpenPort(arg_sport ? arg_sport : PSP_ANYPORT);
	if (!porth) goto err_psp_open_port;

	printf("Call client with:\n");
	printf("%s -c %d -p %d --loops %d -v %d\n",
	       argv[0],
	       PSP_GetNodeID(),
	       PSP_GetPortNo(porth),
	       arg_loops,
	       arg_verbose);
	if (arg_verbose)
	    run_pp_server_verbose(porth);
	else
	    run_pp_server(porth);
    } else {
	int conid;
	porth = PSP_OpenPort(PSP_ANYPORT);
	if (!porth) goto err_psp_open_port;
	conid = PSP_Connect(porth, arg_client, arg_sport);
	if (conid < 0) goto err_psp_connect;
	do_pp_client(porth, conid);
    }

    return 0;
    /* --- */
 err_psp_init:
    printf("PSP_Init() failed!\n");
    exit(1);
    /* --- */
 err_psp_open_port:
    printf("PSP_OpenPort() failed!\n");
    exit(1);
    /* --- */
 err_psp_connect:
    printf("PSP_Connect() failed!\n");
    exit(1);
}
