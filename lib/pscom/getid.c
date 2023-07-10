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
/**
 * getid: getid functions with usage of env PSP_NETWORK.
 *   PSP_NETWORK is a space and or , sepparerted list of network IPs
 *   or hostnames inside the networks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>

static char vcid2[] __attribute__((unused)) = "$Id$";

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static in_addr_t psp_hostip(char *name)
{
    struct hostent *mhost;
    in_addr_t ret = 0;

    /* Get list of IP-addresses */
    mhost = gethostbyname(name);

    if (!mhost) { goto err_nohostent; }
    if (!mhost->h_addr_list) { goto err_empty; }

    while (*mhost->h_addr_list) {
        ret = *(unsigned *)*mhost->h_addr_list;
        if (ret != htonl(INADDR_LOOPBACK)) { /* Dont allow localhost */
            break;
        }
        mhost->h_addr_list++;
    }
err_nohostent:
err_empty:
    return ret;
}

static in_addr_t psp_getid_byname(void)
{
    char myname[256];
    static in_addr_t id = 0;

    if (!id) {
        /* Lookup hostname */
        if (gethostname(myname, sizeof(myname)) < 0) { goto err_gethostname; }

        id = psp_hostip(myname);
        if (!id) { goto err_nohostent; }
    }
    return id;
    /* --- */
err_gethostname:
    fprintf(stderr, "%s(): gethostname() failed : %s\n", __FUNCTION__,
            strerror(errno));
    return 0;
    /* --- */
err_nohostent:
    fprintf(stderr, "%s(): Cant get IP of node %s : %s\n", __FUNCTION__, myname,
            strerror(errno));
    return 0;
}

struct nw_dev_list_s {
    in_addr_t ip;
    in_addr_t mask;
};

static struct nw_dev_list_s *psp_get_dev_list(void)
{
    const unsigned int list_n = 64;
    int cnt                   = 0;
    struct ifconf ifc;
    int sfd                   = -1;
    struct nw_dev_list_s *ret = NULL;
    unsigned int i;

#define IFREQCNT  (list_n - 1)
#define IFREQSIZE ((unsigned)sizeof(struct ifreq) * IFREQCNT)
    ifc.ifc_ifcu.ifcu_req = malloc(IFREQSIZE);
    ifc.ifc_len           = IFREQSIZE;

    ret = malloc(sizeof(ret[0]) * list_n);

    sfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (!ifc.ifc_ifcu.ifcu_req || !ret || (sfd < 0)) { goto error; }

    if (ioctl(sfd, SIOCGIFCONF, &ifc) < 0) { goto error; }

    for (i = 0; i < MIN(IFREQCNT, ifc.ifc_len / sizeof(struct ifreq)); i++) {
        struct ifreq *req = &ifc.ifc_ifcu.ifcu_req[i];

        /* Up ? */
        if (ioctl(sfd, SIOCGIFFLAGS, req) < 0) { continue; }
        if (!(req->ifr_ifru.ifru_flags & IFF_UP)) { continue; }

        /* Get IP */
        if (ioctl(sfd, SIOCGIFADDR, req) < 0) { continue; }
        ret[cnt].ip =
            ((struct sockaddr_in *)&req->ifr_ifru.ifru_addr)->sin_addr.s_addr;

        /* Get Netmask */
        if (ioctl(sfd, SIOCGIFNETMASK, req) < 0) { continue; }
        ret[cnt].mask =
            ((struct sockaddr_in *)&req->ifr_ifru.ifru_netmask)->sin_addr.s_addr;
        cnt++;
    }

    ret[cnt].ip = 0;
out:
    if (ifc.ifc_ifcu.ifcu_req) { free(ifc.ifc_ifcu.ifcu_req); }
    if (sfd >= 0) { close(sfd); }
    return ret;
    /* --- */
error:
    if (ret) { free(ret); }
    ret = NULL;
    goto out;
}

static in_addr_t *psp_get_nw_list(char *str)
{
    const unsigned list_n = 64;
    in_addr_t *ret        = malloc(sizeof(in_addr_t) * list_n);
    char *tmp             = strdup(str);
    char *otmp            = tmp;
    unsigned cnt          = 0;

    if (!ret || !tmp) { goto error; }

    while ((cnt < list_n - 1) && str) {
        char *s;
        s = strsep(&str, " ,");
        if (s && (strlen(s) > 0)) {
            in_addr_t ip;
            ip = psp_hostip(s);
            if (ip) {
                ret[cnt] = ip;
                cnt++;
            }
        }
    }

    ret[cnt] = 0;
    if (otmp) { free(otmp); }
    return ret;
    /* --- */
error:
    if (ret) { free(ret); }
    if (otmp) { free(otmp); }
    return NULL;
}


static in_addr_t psp_getid_bynetwork(char *psp_network)
{
    in_addr_t *nw_list                = NULL;
    struct nw_dev_list_s *nw_dev_list = NULL;
    in_addr_t ret                     = (in_addr_t)0;
    in_addr_t *nw;
    struct nw_dev_list_s *dev;

    nw_list = psp_get_nw_list(psp_network);
    if (!nw_list || !nw_list[0]) { goto out; }
    nw_dev_list = psp_get_dev_list();
    if (!nw_dev_list) { goto out; }

    for (nw = nw_list; *nw; nw++) {
        for (dev = nw_dev_list; dev->ip; dev++) {
            if ((dev->ip & dev->mask) == (*nw & dev->mask)) {
                ret = dev->ip;
                goto nw_out;
            }
        }
    }
nw_out:
out:
    if (nw_list) { free(nw_list); }
    if (nw_dev_list) { free(nw_dev_list); }

    if (!ret) {
        return psp_getid_byname();
    } else {
        return ret;
    }
}


static uint32_t psp_getid(void)
{
#ifndef STAND_ALONE
    char *psp_network = pscom.env.network;
#else
    char *psp_network = getenv("PSP_NETWORK");
#endif
    if (!psp_network || psp_network[0] == 0) {
        /* use gethostbyname(gethostname) */
        return ntohl(psp_getid_byname());
    } else {
        return ntohl(psp_getid_bynetwork(psp_network));
    }
}


#ifdef STAND_ALONE
int main(int argc, char **argv)
{

    in_addr_t myid;
    struct in_addr addr;

    myid = psp_getid();

    addr.s_addr = htonl(myid);
    printf("My id is: 0x%08x %s\n", (int)myid, inet_ntoa(addr));

    return 0;
}
#endif

/* clang-format off
 *
 * Local Variables:
 *  compile-command: "gcc getid.c -DSTAND_ALONE -Wall -W -Wno-unused -O2 -o * getid"
 * End:
 *
 * clang-format on
 */
