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
 * short ping pong
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <inttypes.h>
#include <popt.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include "p4sockets.h"
#include "p4io.h"

#include "dump.c"

int arg_verbose = 0;
int arg_serverport = 1001;
int arg_servernode = INADDR_LOOPBACK;//0x7f000001;
int arg_clientport = 1002;

int arg_cnt = 10;
int arg_size = 10;

int arg_ppserver = 0;




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
	{ "server"  , 's', POPT_ARGFLAG_OR, &arg_ppserver , 0,
	  "run as server", "" },
	{ "serverport"  , 'p', POPT_ARG_INT, &arg_serverport , 0,
	  "server port to listen on", "port" },
	{ "servernode"  , 'n', POPT_ARG_INT, &arg_servernode , 0,
	  "host of the server(IP as integer)", "node" },
	{ "clientport"  , 'c', POPT_ARG_INT, &arg_clientport , 0,
	  "client use port", "port" },
	{ "cnt"  , 0, POPT_ARG_INT, &arg_cnt , 0,
	  "No of packets for pp", "count" },
	{ "size"  , 0, POPT_ARG_INT, &arg_size , 0,
	  "Size of packets for pp", "size" },
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


#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))



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
	*tmp++ = ((*b >= 32) && (*b < 127)) ? *b: '.';
    }
    *tmp++ = '\'';
    *tmp++ = 0;
    return ret;
}



static inline
unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_usec+tv.tv_sec*1000000);
}



static
int bind_port(int sock, int portno)
{
    struct sockaddr_p4 sp4;
    int ret;

    memset(&sp4, 0, sizeof(sp4));

    sp4.sp4_family = PF_P4S;
    snprintf(&sp4.sp4_port[0], sizeof(sp4.sp4_port), "pp_%04x", portno);

    if (arg_verbose) {
	printf("bind address: %s\n",
	       dumpstr(&sp4.sp4_port, sizeof(sp4.sp4_port)));
    }
    ret = bind(sock, (struct sockaddr*)&sp4, sizeof(sp4));
    return ret;
}

#define PSP_PORTIDMAGIC  (*(uint32_t *)"test")

static int connect_port(int sock, int host, int portno)
{
    struct sockaddr_p4 sa_p4;
    int ret;
//      struct{
//	uint32_t	magic;
//	uint32_t	portno;
//      }id;

//      id.magic = PSP_PORTIDMAGIC;
//      id.portno = htons(portno);
//      memcpy( &sa_p4.sp4_port, &id, sizeof(sa_p4.sp4_port));

    sa_p4.sp4_family = PF_P4S;
    snprintf(&sa_p4.sp4_port[0], sizeof(sa_p4.sp4_port), "pp_%04x", portno);
//    sa_p4.sp4_ra.type = P4REMADDR_ETHER;
//    sa_p4.sp4_ra.tec.ether.addr.ipaddr = htonl(nodeid);
//    sa_p4.sp4_ra.tec.ether.devname[0] = 0; /* Use IP address */
    sa_p4.sp4_ra.type = P4REMADDR_PSID;
    sa_p4.sp4_ra.tec.psid.psid = host;
    ret = connect(sock, (struct sockaddr*)&sa_p4, sizeof(sa_p4));
    return ret;
}

//  static int connect_port(int sock, int host, int portno)
//  {
//      struct sockaddr_p4 sp4;
//      int ret;

//      memset(&sp4, 0, sizeof(sp4));

//      sp4.sp4_family = PF_P4S;
//      snprintf(&sp4.sp4_port[0], sizeof(sp4.sp4_port), "pp_%04x", portno);

//      sp4.sp4_ra.type = P4REMADDR_ETHER;
//      sp4.sp4_ra.tec.ether.addr.ipaddr = htonl(host);
//      sp4.sp4_ra.tec.ether.devname[0] = 0; /* Use IP address */

//      ret = connect(sock, (struct sockaddr*)&sp4, sizeof(sp4));
//      return ret;
//  }


/**********************************************************************/
int PSP_GetNodeID(void)
/**********************************************************************/
{
    /* Ask the socket layer */
    int fd;
    int ret;
    fd = socket(PF_P4S , 0, 0);
    if (fd < 0) goto err_socket;

    ret = ioctl(fd, P4_GETNODEID);
    if (ret < 0) goto err_ioctl;

    close(fd);

    if (ret == P4_NODE_ID_UNDEF) {
	/* Unknown id. Use first ip address as id */

	struct hostent *mhost;
	char myname[256];

	/* Lookup hostname */
	gethostname(myname, sizeof(myname));

	/* Get list of IP-addresses */
	mhost = gethostbyname(myname);

	if ( !mhost ) goto err_nohostent;

	/*
	  while (*mhost->h_addr_list) {
	  printf( " -Addr: %08x\n",
	  ((struct in_addr *) *mhost->h_addr_list)->s_addr);
	  mhost->h_addr_list++;
	  }
	*/

	ret = ntohl(*(int *)*mhost->h_addr_list);
    }

    return ret;
 err_socket:
    fprintf(stderr, "%s() : socket(PF_P4S , 0, 0) : %s\n", __func__, strerror(errno));
    exit(1);
 err_ioctl:
    fprintf(stderr, "%s() : ioctl(fd, P4_GETNODEID) : %s\n", __func__, strerror(errno));
    exit(1);
 err_nohostent:
    fprintf(stderr, "%s() : gethostbyname() failed : %s\n", __func__, strerror(errno));
    exit(1);
}


static inline
int sock_send(int sock, uint16_t DestNode, char *buf, int len)
{
#if 0
    struct msghdr hdr;
    struct iovec iov;

    hdr.msg_name = &DestNode;
    hdr.msg_namelen = sizeof(DestNode);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    iov.iov_base = buf;
    iov.iov_len = len;

    len = sendmsg(sock, &hdr, 0);
    if (len < 0) { perror("sendmsg");}
    return len;
#else
    struct p4s_io_send_s s;
    s.DestNode = DestNode;
    s.Flags = 0;
    s.iov.iov_base = buf;
    s.iov.iov_len = len;

    len = ioctl(sock, P4S_IO_SEND, &s);
    if (len < 0) { perror("sendmsg");}
    return len;
#endif
}

static inline
int sock_recv(int sock, uint16_t *src, char *buf, int len)
{
//#define RECV_FLAGS MSG_DONTWAIT
#define RECV_FLAGS 0
#if 0
    struct msghdr hdr;
    struct iovec iov;

    hdr.msg_name = src;
    hdr.msg_namelen = sizeof(*src);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    iov.iov_base = buf;
    iov.iov_len = len;

    /* len = recvmsg(sock, &hdr, MSG_NOSIGNAL | MSG_DONTWAIT);*/
    do {
	len = recvmsg(sock, &hdr, RECV_FLAGS);
    } while ((len < 0) && (errno == EAGAIN));
    if (arg_verbose > 0) {
	printf("Recv %d bytes from %d\n",len , *src);
	if ((arg_verbose > 1) && (len > 0)) {
	    printf(":%s:\n", dumpstr(buf, MIN(len ,32)));
	}
    }
    if (len < 0) {
	perror("recvmsg");
    }
    return len;
#else
    struct p4s_io_recv_s r;
    r.Flags = RECV_FLAGS;
    r.iov.iov_base = buf;
    r.iov.iov_len = len;

    do {
	len = ioctl(sock, P4S_IO_RECV, &r);
    } while ((len < 0) && (errno == EAGAIN));
    *src = r.SrcNode;
    if (len < 0) {
	perror("recvmsg");
    }
    return len;
#endif
}


#define SERVER_BUFLEN 123456


static
void run_recv()
{
    int sock;
    int ret;
    char *buf;

    printf("Start server on port %d. My PSID: %d\n",
	   arg_serverport, PSP_GetNodeID());
    sock = socket(PF_P4S , 0, 0);
    if (!sock) goto err_socket;

    ret = bind_port(sock, arg_serverport);
    if (ret) goto err_bind;

    buf = (char*)malloc(SERVER_BUFLEN);
    if (!buf) goto err_malloc;

    while (1) {
	uint16_t src;
	int len;
	len = sock_recv(sock, &src, buf, SERVER_BUFLEN);
	if (arg_verbose > 0) {
	    printf("Recv %d bytes from %d\n",len ,src);
	    if ((arg_verbose > 1) && (len > 0)) {
		if (arg_verbose > 2) {
		    dump(buf, 0, len, 0, 16, "recv");
		} else {
		    printf(":%s:\n", dumpstr(buf, MIN(len,32)));
		}
	    }
	}
    }

    return;
 err_socket:
    perror("socket()");
    exit(1);
 err_bind:
    perror("bind()");
    exit(1);
 err_malloc:
    perror("malloc()");
    exit(1);
}


static
void run_send()
{
    int sock;
    int ret;
    int conid;
    char *buf;
    int i;

    printf("Start client from port %d to port %d\n",
	   arg_clientport, arg_serverport);

    sock = socket( PF_P4S , 0, 0 );
    if (!sock) goto err_socket;

    ret = bind_port(sock, arg_clientport);
    if (ret) goto err_bind;

    buf = (char*)malloc(arg_size);
    if (!buf) goto err_malloc;

    for (i = 0; i < arg_size; i++) {
	buf[i] = (char)i;
    }
    for (i = 0; i < arg_size; i++) {
	buf[i] = (char)((i & ~3) >> (8*(3-(i & 3))));
    }
//    memset(buf, 0x42, arg_size);

    conid = connect_port(sock, arg_servernode, arg_serverport);
    if (conid < 0) goto err_connect;


    if (arg_verbose > 0) {
	printf("Connect to %08x:%d with id %d\n",
	       arg_servernode, arg_serverport, conid);
	printf("Send %d bytes\n",arg_size);

	if ((arg_verbose > 1) && (arg_size > 0)) {
	    if (arg_verbose > 2) {
		dump(buf, 0, arg_size, 0, 16, "send");
	    } else {
		printf(":%s:\n", dumpstr(buf, MIN(arg_size,32)));
	    }
	}
    }

    {
	uint16_t dest = (uint16_t)conid;
	int len;
	int offset = 0;

	while (offset < arg_size) {
	    len = sock_send(sock, dest, buf + offset, arg_size - offset);
	    if (len < 0) {
		perror("send");
	    } else {
		if (arg_verbose > 1) {
		    printf("Send bytes %d - %d.\n",
			   offset, offset + len - 1);
		}
		offset += len;
	    }
	}
    }
//    sleep(10);
    free(buf);
    return;
 err_socket:
    perror("socket()");
    exit(1);
 err_bind:
    perror("bind()");
    exit(1);
 err_malloc:
    perror("malloc()");
    exit(1);
 err_connect:
    perror("connect()");
    exit(1);
}



void sig_quit(int sig)
{
    printf("recv SIGQUIT\n");
}





int main(int argc, char **argv)
{
    parse_opt(argc, argv);

    signal(SIGQUIT,sig_quit);
//    if (arg_size > SERVER_BUFLEN) arg_size = SERVER_BUFLEN;

    if (arg_ppserver) {
	run_recv();
    } else {
	run_send();
    }
    return 0;
}
