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
 * p4stat: Statistic information about the p4 module
 *
 * 2002-05-17 Jens Hauke <hauke@par-tec.com>
 */

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

#include "p4io.h"

#include <popt.h>

char *dumpstr( void *buf, int size )
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
	tmp += sprintf( tmp, "<%02x>", (unsigned char)*b );
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

int arg_verbose=0;
int arg_dumpsockets=0;
int arg_dumpnet=0;

void usage(poptContext optCon, int exitcode, char *error, char *addl)
{
    poptPrintUsage(optCon, stderr, 0);
    if (error) fprintf(stderr, "%s: %s", error, addl);
    exit(exitcode);
}

void parse_opt(int argc, char **argv)
{
    int c;            /* used for argument parsing */
    poptContext optCon;   /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
	{ "verbose"  , 'v', POPT_ARG_INT, &arg_verbose , 0,
	  "be more verbose", "level" },
	{ "sock" , 's', POPT_ARGFLAG_OR, &arg_dumpsockets, 0,
	  "dump all sockets", "" },
	{ "net" , 'n', POPT_ARGFLAG_OR, &arg_dumpnet, 0,
	  "dump all network ci's", "" },
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




int sock=-1;

static
void open_sock(void)
{
    sock = socket( PF_P4S , 0 ,0 );

    if ( sock < 0 ) goto err_socket;

    return;
 err_socket:
    perror("open_sock(): socket");
    exit(1);
}

static
void dump_p4_addr( p4_addr_t *addr )
{
    printf( "%s", dumpstr( addr, sizeof( *addr)));
}

static
void dump_socket( p4_dumpsock_t *sock )
{
    printf(" Addr: ");
    dump_p4_addr( &sock->addr );
    printf(" last_idx %d", sock->last_idx);
    printf(" refs %d\n", sock->RefCnt);
}

static
void dump_ci_headline( void )
{
    /*      123456 1234567 123456 1234567 1234567 1234567 1234567 123 123 1234 */
    printf("SSeqNo SWindow RSeqNo RWindow lusridx lnetidx rnetidx snq rnq refs\n");
}

static
void dump_ci( p4_dumpci_t *ci )
{
    printf("%6u %7u %6u %7u ", ci->SSeqNo, ci->SWindow, ci->RSeqNo, ci->RWindow );
    printf("%7d %7d %7d ", ci->list_usr_idx, ci->list_net_idx, ci->rem_net_idx);
    printf("%3d %3d %4d\n", ci->SFragQN, ci->RFragQN, ci->RefCnt);
    if (arg_verbose <= 1) return;

    dump_p4_addr( &ci->sap4.sp4_port );

    switch ( ci->sap4.sp4_ra.type ){
    case P4REMADDR_LOCAL:
	printf(" LOCAL\n");
	break;
    case P4REMADDR_ETHER:
	printf(" ETH: %02x:%02x:%02x:%02x:%02x:%02x %s\n",
	       ci->sap4.sp4_ra.tec.ether.addr.mac[0],
	       ci->sap4.sp4_ra.tec.ether.addr.mac[1],
	       ci->sap4.sp4_ra.tec.ether.addr.mac[2],
	       ci->sap4.sp4_ra.tec.ether.addr.mac[3],
	       ci->sap4.sp4_ra.tec.ether.addr.mac[4],
	       ci->sap4.sp4_ra.tec.ether.addr.mac[5],
	       ci->sap4.sp4_ra.tec.ether.devname);
	break;
    case P4REMADDR_MYRI:
	printf(" MYRI: ID %d\n",ci->sap4.sp4_ra.tec.myri.nodeid);
	break;
    case 4711:
	printf(" Wow\n");
	break;
    default:
	printf(" TYP %d: %s\n",ci->sap4.sp4_ra.type,
	       dumpstr( &ci->sap4.sp4_ra.tec, sizeof(ci->sap4.sp4_ra.tec))
	       );
    }
}

static
void dump_sockets( void )
{
    int sno = 0;
    int ret;
    int i, j;
    while (1){
	p4_io_dumpsock_t ds;
	ds.in.sockno = sno;

	ret = ioctl( sock, P4_DUMPSOCK, &ds );
	if (ret) break;

	printf("Socket #%d :",sno);

	dump_socket( &ds.sock );
	sno++;
    }
    if ( arg_verbose > 0 ){
	printf("Sock usr_idx ");
	dump_ci_headline();
	for ( j = 0; j < sno ; j++ ){
	    for ( i = 0; i < P4_N_CON_USR; i++ ){
		p4_io_dumpusrci_t uci;
		uci.in.sockno = j;
		uci.in.ci_usr_idx = i;
		ret = ioctl( sock, P4_DUMPUSRCI, &uci );
		if ( !ret ){
		    printf("%4u %7d ", j, i);
		    dump_ci( &uci.ci );
		}
	    }
//	    printf("\n");
	}
    }
}

static
void dump_net( void )
{
    int ret;
    int i;

    printf("net_idx      ");
    dump_ci_headline();

    for (i = 0; i < P4_N_CON_NET ; i++ ){
	p4_io_dumpnetci_t nci;
	nci.in.ci_net_idx = i;
	ret = ioctl( sock, P4_DUMPNETCI, &nci );
	if ( !ret ){
	    printf("%7d      ", i);
	    dump_ci( &nci.ci );
	}
    }
}



int main(int argc, char **argv)
{
    parse_opt(argc,argv);

    open_sock();

    if ( arg_dumpsockets ) dump_sockets();
    if ( arg_dumpnet ) dump_net();


    return 0;
}


/*
 * Local Variables:
 *  compile-command: "make p4stat"
 * End:
 *
 */
