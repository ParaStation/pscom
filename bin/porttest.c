/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <netinet/in.h>
#include <unistd.h>

#include "psport4.h"
#include "dump.c"

#include <popt.h>
#include "ps_perf.h"
//#include <asm/msr.h>


#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))


int arg_verbose = 0;
int arg_recvport = 0;

int arg_sendport = 0;
int arg_sendhost = INADDR_LOOPBACK;//0x7f000001;

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
	{ "recvport"  , 'r', POPT_ARG_INT, &arg_recvport , 0,
	  "port to listen on", "port" },
	{ "sendport"  , 's', POPT_ARG_INT, &arg_sendport , 0,
	  "port to send to", "port" },
	{ "sendhost"  , 'n', POPT_ARG_INT, &arg_sendhost , 0,
	  "host to send to (default localhost)", "node" },
	{ "verbose"  , 'v', POPT_ARG_INT, &arg_verbose , 0,
	  "be more verbose", "level" },
/*	{ "flag" , 'f', POPT_ARGFLAG_OR, &arg_flag, 0,
	  "flag description", "" },*/
	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };

    optCon = poptGetContext(NULL, argc,(const char **) argv, optionsTable, 0);

    if (argc < 2) {
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
char *inetstr( int addr )
{
    static char ret[16];
    sprintf( ret, "%u.%u.%u.%u",
	     (addr >> 24) & 0xff, (addr >> 16) & 0xff,
	     (addr >>  8) & 0xff, (addr >>  0) & 0xff);
    return ret;
}

static
void do_receive()
{
#define RECVBUFLEN 0x3000000
    PSP_PortH_t ph;
    char *recvbuf = (char *) malloc(RECVBUFLEN);
    PSP_RequestH_t rh;
    struct {
	PSP_Header_t phead;
	char xhead[26];
    } head;

    PSP_Init();

    ph = PSP_OpenPort( arg_recvport );

    if (!ph) goto err_openport;

    while (1){
	rh = PSP_IReceive( ph, recvbuf, RECVBUFLEN, &head.phead, sizeof( head.xhead ),
			   PSP_RecvAny, 0 );

	PSP_Wait( ph, rh );
	dump( recvbuf, 0, MIN( 30, head.phead.datalen ), 0, 16, "datalen" );
	dump( head.xhead, 0, MIN( 30, head.phead.xheaderlen ), 0, 16, "xhead" );
	if(0){
	    int i;
	    for (i=0;i<500;i++){
		usleep(2000);
		PSP_Wait( ph, rh );
	    }
	}
	if(0){
	    sleep(2);
	    printf("1st\n");
	    PSP_Wait( ph, rh );
	    printf("2nd\n");
	    sleep(2);
	}
	if(1){
	    unsigned long long t1,t2;
	    printf("calc start\n");
	    GET_CPU_CYCLES_LL( t1 );
	    do{
		GET_CPU_CYCLES_LL( t2 );
	    }while ( t1 + 15/*sec*/ * 800000000LL/*Hz*/ > t2 );
	    printf("calc stop\n");
	}


    }

    return;

 err_openport:
    perror("PSP_OpenPort");
    exit(1);
}

static
void do_sending()
{
#define SENDBUFLEN 0
    PSP_PortH_t ph;
    char *sendbuf = (char *) malloc(SENDBUFLEN + 1);
    PSP_RequestH_t rh;
    struct {
	PSP_Header_t phead;
	char xhead[22];
    } head;
    int dest;
    int i;

    PSP_Init();

    ph = PSP_OpenPort( arg_sendport + 1 );
    if (!ph) goto err_openport;

    if ( arg_sendhost == INADDR_LOOPBACK )
	arg_sendhost = PSP_GetNodeID();

    printf(" Connect to %s\n", inetstr( arg_sendhost ));
    dest = PSP_Connect( ph, arg_sendhost, arg_sendport );
    if ( dest < 0 ) goto err_connect;

    printf("Connect with id %d\n", dest );



    strncpy( sendbuf, "Hello Port!", SENDBUFLEN);
    strncpy( head.xhead, "XHeader is here", sizeof(head.xhead));

    for ( i=0 ;i < 3; i++){
	rh = PSP_ISend( ph, sendbuf,
			SENDBUFLEN,
//		    strlen( sendbuf ),
			&head.phead,
			sizeof( head.xhead ), dest, 0 );
	PSP_Wait( ph, rh );
	printf("Send %d done\n",i);
	//usleep(5000000);
    }
    printf("Byee\n");

    free(sendbuf);

    return;

 err_connect:
    perror("PSP_Connect");
    exit(1);
 err_openport:
    perror("PSP_OpenPort");
    exit(1);
}


void sighand(int sig)
{
    printf("############ Recv Sig %d ###########\n",sig);

}

int main(int argc, char **argv)
{
//    int i;
//    for(i=0;i<_NSIG;i++) signal(i,sighand);
    printf("Node ID: 0x%08x (%d) \n", PSP_GetNodeID(), PSP_GetNodeID());

    parse_opt(argc,argv);

    if   (arg_sendport) do_sending();
    else if (arg_recvport) do_receive();


    return 0;
}


/*
 * Local Variables:
 *  compile-command: "make porttest"
 * End:
 *
 */
