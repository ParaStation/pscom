/*
 * ParaStation
 *
 * Copyright (C) 2006-2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "psport_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define INET_ADDR_SPLIT(addr) ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >>  8) & 0xff, (addr) & 0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"


/* Take a service name, and a service type, and return a port number.  If the
   service name is not found, it tries it as a decimal number.  The number
   returned is byte ordered for the network. */
int PSP_atoport(const char *service, const char *proto)
{
	long int lport;
	struct servent *serv;
	char *errpos = NULL;

	if (!service) { service = "";}

	lport = strtol(service, &errpos, 0);
	if (errpos && *errpos == 0) {
		/* valid integer, or empty string */
		return htons(lport);
	}

	if (!proto) {errno = EINVAL; return -1;}

	/* Try to read it from /etc/services */
	serv = getservbyname(service, proto);

	if (serv != NULL) {
		return serv->s_port;
	} else {
		errno = EINVAL; return -1;
	}
}

int PSP_atoaddr(const char *address, struct in_addr *addr)
{
	struct hostent *mhost;

	if (!addr) {errno = EINVAL; return -1;}

	if (!address) {
		addr->s_addr = INADDR_LOOPBACK;
		return 0;
	}

	/* First try it as aaa.bbb.ccc.ddd. */
	if (inet_aton(address, addr)) {
		/* ok */
		return 0;
	}


	/* Get list of IP-addresses */
	mhost = gethostbyname(address);
	/* printf("host %s\n", address);*/
	if (!mhost) goto err;
	if (!mhost->h_addr_list) goto err;

	addr->s_addr = *(in_addr_t *)*mhost->h_addr_list;

	return 0;
	/* --- */
 err:
	errno = EINVAL; return -1;
}

int PSP_ascii_to_sockaddr_in(const char *host, const char *port,
			     const char *protocol,
			     struct sockaddr_in *addr)
{
	int ret = 0;
	int aint;

	addr->sin_family = PF_INET;

	addr->sin_port = aint = PSP_atoport(port, protocol);
	if (aint < 0) ret = -1;

	aint = PSP_atoaddr(host, &addr->sin_addr);
	if (aint < 0) ret = -1;

	return ret;
}


const char *
PSP_local_name(PSP_PortH_t porth)
{
	static char local_name[sizeof("xxx.xxx.xxx.xxx:xxxxx") + 10];

	uint32_t node_id = PSP_GetNodeID();
	unsigned int port = PSP_GetPortNo(porth);

	snprintf(local_name, sizeof(local_name), INET_ADDR_FORMAT ":%u",
		 INET_ADDR_SPLIT(node_id),
		 port);
	return local_name;
}


int
PSP_Connect_name(PSP_PortH_t porth, const char *name)
{
	char *lname = strdup(name);
	char *host;
	char *port = NULL;
	int ret = -1;
	struct sockaddr_in sock;
	if (!lname) goto err_no_mem;

	host = strtok_r(lname, ":", &port);
	if (!host) goto err_no_host;
	if (!port) goto err_no_port;

	if (PSP_ascii_to_sockaddr_in(host, port, "tcp", &sock) < 0) goto err_to_sock;


	ret = PSP_Connect(porth, (int)ntohl(sock.sin_addr.s_addr), (int)ntohs(sock.sin_port));

 err_no_mem:
 err_no_host:
 err_no_port:
 err_to_sock:
	free(lname); host = NULL; port = NULL;

	return ret;
}
