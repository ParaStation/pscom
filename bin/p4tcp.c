/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
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
#include <arpa/inet.h>

#include "psockt.h"

#include <popt.h>

int arg_verbose=0;
int arg_add=0;
int arg_del=0;
int arg_list=1;
const char *arg_ipfrom = NULL;
const char *arg_ipto = NULL;

void parse_opt(int argc, char **argv)
{
    int c;            /* used for argument parsing */
    const char *s;
    poptContext optCon;   /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
	{ "verbose"  , 'v', 0, &arg_verbose , 0,
	  "be more verbose", "level" },
	{ "add" , 'a', POPT_ARGFLAG_OR, &arg_add, 0,
	  "add ip range", "" },
	{ "del" , 'd', POPT_ARGFLAG_OR, &arg_del, 0,
	  "delete ip range", "" },
	{ "list" , 'l', POPT_ARGFLAG_OR, &arg_list, 0,
	  "list all ip ranges", "" },
	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };

    optCon = poptGetContext(NULL, argc,(const char **) argv, optionsTable, 0);

    poptSetOtherOptionHelp(optCon, "[{-a|-d} ip_from [ip_to]]");

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
    arg_ipfrom = poptGetArg(optCon);
    arg_ipto = poptGetArg(optCon);

    arg_ipto = arg_ipto ? arg_ipto : arg_ipfrom;

    if ((arg_add || arg_del) && !arg_ipfrom) {
	/* an error occurred during option processing */
	fprintf(stderr, "Missing option\n");
	poptPrintHelp(optCon, stderr, 0);
	exit(1);
    }

    if ((s = poptGetArg(optCon))) {
	/* an error occurred during option processing */
	fprintf(stderr, "%s: %s\n",
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),s);
	poptPrintHelp(optCon, stderr, 0);
	exit(1);
    }

    poptFreeContext(optCon);
}

void error_no_module(void)
{
    fprintf(stderr, "Error: communication with TCP bypass failed.\n"
	    "(Module p4tcp not loaded?)\n");
    exit(1);
}


int sock=-1;

static
void open_sock(void)
{
    sock = socket(PF_TINET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) goto err_socket;
    }

    return;
 err_socket:
    perror("socket(PF_INET, SOCK_STREAM,0): failed");
    exit(1);
}

#define IP_SPLIT(addr)								\
    (((uint32_t)(addr)) >> 24) & 0xff, (((uint32_t)(addr)) >> 16) & 0xff,	\
    (((uint32_t)(addr)) >>  8) & 0xff, (((uint32_t)(addr)) >>  0) & 0xff

void print_range(p4tcp_ip_range_t *range)
{
	if (range->sin_from.s_addr != range->sin_to.s_addr) {
	    printf("%u.%u.%u.%u\t-\t%u.%u.%u.%u\n",
		   IP_SPLIT(ntohl(range->sin_from.s_addr)),
		   IP_SPLIT(ntohl(range->sin_to.s_addr)));
	} else {
	    printf("%u.%u.%u.%u\n",
		   IP_SPLIT(ntohl(range->sin_from.s_addr)));
	}

}

void check_module(void)
{
    p4tcp_ip_range_get_t r;
    int rc;
    r.index = 0;
    rc = ioctl(sock, P4TCP_GET_IP_RANGE, &r);

    if (!rc) return; /* OK */
    if (errno == ENOENT) return;/* OK */

    error_no_module();
}

void do_list(void)
{
    int rc = 0;
    int idx;

    for (idx = 0;; idx++) {
	p4tcp_ip_range_get_t r;
	r.index = idx;
	rc = ioctl(sock, P4TCP_GET_IP_RANGE, &r);

	if (rc) break;
	print_range(&r.range);
    }

    if (idx == 0) {
	if (errno == ENOENT) {
	    printf("list empty\n");
	} else {
	    perror("error ioctl(sock, P4TCP_GET_IP_RANGE, &r) ");
	}
    }
}

/* return 0 on success. 1 on error */
int get_ip(const char *ipstr, struct in_addr *ip)
{
    return (inet_aton(ipstr, ip) == 0);
}

void do_adddel(int add)
{
    int rc;
    p4tcp_ip_range_t range;
    if (get_ip(arg_ipfrom, &range.sin_from)) goto err_from;
    if (get_ip(arg_ipto, &range.sin_to)) goto err_to;

    rc = ioctl(sock,
	       add ? P4TCP_ADD_IP_RANGE : P4TCP_DEL_IP_RANGE,
	       &range);

    if (!rc) {
	/* no error */
	if (arg_verbose) {
	    printf("%s ", add ? "Add" : "Del");
	    print_range(&range);
	}
    } else {
	printf("%s ", add ? "Add" : "Del");
	print_range(&range);
	perror("failed");
	exit(1);
    }
    return;
    /* --- */
 err_from:
    fprintf(stderr, "Cant parse IP \"%s\"!\n", arg_ipfrom);
    exit(1);
    /* --- */
 err_to:
    fprintf(stderr, "Cant parse IP \"%s\"!\n", arg_ipto);
    exit(1);
}

int main(int argc, char **argv)
{
    parse_opt(argc,argv);

    open_sock();
    check_module();

    if (arg_add) {
	do_adddel(1);
    } else if (arg_del) {
	do_adddel(0);
    } else {
	do_list();
    }

    return 0;
}
