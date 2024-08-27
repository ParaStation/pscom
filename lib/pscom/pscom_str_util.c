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

#include "pscom_str_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "pscom.h"
#include "pscom_debug.h"
#include "pscom_priv.h"


/* Take a service name, and a service type, and return a port number.  If the
   service name is not found, it tries it as a decimal number.  The number
   returned is byte ordered for the network. */
PSCOM_API_EXPORT
int pscom_atoport(const char *service, const char *proto)
{
    long int lport;
    struct servent *serv;
    char *errpos = NULL;

    if (!service) { service = ""; }

    lport = strtol(service, &errpos, 0);
    if (errpos && *errpos == 0) {
        /* valid integer, or empty string */
        return htons((uint16_t)lport);
    }

    if (!proto) {
        errno = EINVAL;
        return -1;
    }

    /* Try to read it from /etc/services */
    serv = getservbyname(service, proto);

    if (serv != NULL) {
        return serv->s_port;
    } else {
        errno = EINVAL;
        return -1;
    }
}


PSCOM_API_EXPORT
int pscom_atoaddr(const char *address, struct in_addr *addr)
{
    struct hostent *mhost;

    if (!addr) {
        errno = EINVAL;
        return -1;
    }

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
    if (!mhost) { goto err; }
    if (!mhost->h_addr_list) { goto err; }

    addr->s_addr = *(in_addr_t *)*mhost->h_addr_list;

    return 0;
    /* --- */
err:
    errno = EINVAL;
    return -1;
}


PSCOM_API_EXPORT
int pscom_ascii_to_sockaddr_in(const char *host, const char *port,
                               const char *protocol, struct sockaddr_in *addr)
{
    int res;
    int portno;
    struct in_addr inaddr;

    if (!host || !port || !protocol) { goto err; }

    portno = pscom_atoport(port, protocol);
    if (portno < 0) { goto err; }

    res = pscom_atoaddr(host, &inaddr);
    if (res < 0) { goto err; }

    if (addr) {
        addr->sin_family = PF_INET;
        addr->sin_port   = (short)portno;
        addr->sin_addr   = inaddr;
    }

    return 0;
    /* error code */
err:
    return -1;
}


PSCOM_API_EXPORT
const char *pscom_socket_ondemand_str(int nodeid, int portno, const char name[8])
{
    static char socket_str[sizeof("xxx.xxx.xxx.xxx:xxxxx@01234567____")];

    if (portno < 0 || portno > 65535) { goto err_invalid_port; }

    if (!name[0]) {
        snprintf(socket_str, sizeof(socket_str), INET_ADDR_FORMAT ":%u",
                 INET_ADDR_SPLIT(nodeid), portno);
    } else {
        snprintf(socket_str, sizeof(socket_str), INET_ADDR_FORMAT ":%u@%1.8s",
                 INET_ADDR_SPLIT(nodeid), portno, name);
    }
    return socket_str;
    /* error code */
err_invalid_port:
    errno = EINVAL;
    return NULL;
}


PSCOM_API_EXPORT
const char *pscom_socket_str(int nodeid, int portno)
{
    char name[8] = "";
    return pscom_socket_ondemand_str(nodeid, portno, name);
}


PSCOM_API_EXPORT
int pscom_parse_socket_ondemand_str(const char *socket_str, int *nodeid,
                                    int *portno, char (*name)[8])
{
    char *lname = NULL;
    char *host;
    char *port    = NULL;
    char *nametok = NULL;
    int ret       = 0;
    struct sockaddr_in sock;

    if (!socket_str) { goto err_arg; }

    lname = strdup(socket_str);
    if (!lname) { goto err_no_mem; }

    host = strtok_r(lname, ":", &port);
    if (!host) { goto err_no_host; }
    if (!port) { goto err_no_port; }
    strtok_r(port, "@", &nametok);

    if (pscom_ascii_to_sockaddr_in(host, port, "tcp", &sock) < 0) {
        goto err_to_sock;
    }

    if (nodeid) { *nodeid = (int)ntohl(sock.sin_addr.s_addr); }
    if (portno) { *portno = (int)ntohs(sock.sin_port); }
    if (name) {
        memset(name, 0, sizeof(*name));
        if (nametok) { strncpy(*name, nametok, sizeof(*name)); }
    }

    if (0) { /* error code */
    err_arg:
    err_no_host:
    err_no_port:
        errno = EINVAL;
    err_no_mem:
    err_to_sock:
        ret = -1;
    }

    if (lname) { free(lname); }
    return ret;
}


PSCOM_API_EXPORT
int pscom_parse_socket_str(const char *socket_str, int *nodeid, int *portno)
{
    char name[8];
    int rc = pscom_parse_socket_ondemand_str(socket_str, nodeid, portno, &name);
    if (!rc && name[0]) {
        // No error. But the name is not empty.
        errno = EINVAL;
        rc    = -1;
    }
    return rc;
}


PSCOM_API_EXPORT
pscom_err_t pscom_connect_socket_str(pscom_connection_t *connection,
                                     const char *socket_str)
{
    int nodeid;
    int portno;
    char name[8];
    int res;

    res = pscom_parse_socket_ondemand_str(socket_str, &nodeid, &portno, &name);
    if (res) { goto err_parse; }

    if (!name[0]) {
        return pscom_connect(connection, nodeid, portno);
    } else {
        return pscom_connect_ondemand(connection, nodeid, portno, name);
    }
    /* error code */
err_parse:
    if (socket_str) {
        DPRINT(D_ERR, "CONNECT (%s) failed : %s", socket_str,
               pscom_err_str(res));
    } else {
        DPRINT(D_ERR, "CONNECT (<null>) failed : %s", pscom_err_str(res));
    }
    return res;
}


PSCOM_API_EXPORT
const char *pscom_listen_socket_str(pscom_socket_t *socket)
{
    return pscom_socket_str(pscom_get_nodeid(), socket->listen_portno);
}


PSCOM_API_EXPORT
const char *pscom_listen_socket_ondemand_str(pscom_socket_t *socket)
{
    return pscom_socket_ondemand_str(pscom_get_nodeid(), socket->listen_portno,
                                     socket->local_con_info.name);
}


PSCOM_PLUGIN_API_EXPORT
const char *pscom_inetstr(int addr)
{
    static char ret[sizeof("xxx.xxx.xxx.xxx_____")];
    snprintf(ret, sizeof(ret), INET_ADDR_FORMAT, INET_ADDR_SPLIT(addr));
    return ret;
}


PSCOM_API_EXPORT
const char *pscom_con_state_str(pscom_con_state_t state)
{
    switch (state) {
    case PSCOM_CON_STATE_NO_RW: return "norw";
    case PSCOM_CON_STATE_R: return "ro";
    case PSCOM_CON_STATE_W: return "wo";
    case PSCOM_CON_STATE_RW: return "open";
    case PSCOM_CON_STATE_CLOSED: return "closed";
    case PSCOM_CON_STATE_CONNECTING: return "connecting";
    case PSCOM_CON_STATE_ACCEPTING: return "accepting";
    case PSCOM_CON_STATE_CLOSE_WAIT: return "close_wait";
    case PSCOM_CON_STATE_CLOSING: return "closing";
    case PSCOM_CON_STATE_SUSPENDING: return "suspending";
    case PSCOM_CON_STATE_SUSPEND_SENT: return "susp_sent";
    case PSCOM_CON_STATE_SUSPEND_RECEIVED: return "susp_recv";
    case PSCOM_CON_STATE_SUSPENDED: return "suspended";
    case PSCOM_CON_STATE_CONNECTING_ONDEMAND: return "con_ondemand";
    case PSCOM_CON_STATE_ACCEPTING_ONDEMAND: return "acc_ondemand";
    }

    {
        static char buf[sizeof("state0xXXXXXXXX_____")];
        snprintf(buf, sizeof(buf), "state0x%x", state);
        return buf;
    }
}


PSCOM_API_EXPORT
const char *pscom_con_type_str(pscom_con_type_t type)
{
    switch (type) {
    case PSCOM_CON_TYPE_NONE: return "none";
    case PSCOM_CON_TYPE_LOOP: return "loop";
    case PSCOM_CON_TYPE_TCP: return "tcp";
    case PSCOM_CON_TYPE_SHM: return "shm";
    case PSCOM_CON_TYPE_GM: return "gm";
    case PSCOM_CON_TYPE_MVAPI: return "mvapi";
    case PSCOM_CON_TYPE_PSM: return "psm";
    case PSCOM_CON_TYPE_OPENIB: return "openib";
    case PSCOM_CON_TYPE_OFED: return "ofed";
    case PSCOM_CON_TYPE_ELAN: return "elan";
    case PSCOM_CON_TYPE_CBC: return "cbc";
    case PSCOM_CON_TYPE_EXTOLL: return "extoll";
    case PSCOM_CON_TYPE_VELO: return "velo";
    case PSCOM_CON_TYPE_DAPL: return "dapl";
    case PSCOM_CON_TYPE_ONDEMAND: return "demand";
    case PSCOM_CON_TYPE_MXM: return "mxm";
    case PSCOM_CON_TYPE_SUSPENDED: return "susp";
    case PSCOM_CON_TYPE_UCP: return "ucp";
    case PSCOM_CON_TYPE_GW: return "gateway";
    case PSCOM_CON_TYPE_PORTALS: return "portals";
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    case PSCOM_CON_TYPE_P4S: return "p4s <deprecated>";
#pragma GCC diagnostic pop
    case PSCOM_CON_TYPE_COUNT: goto err_exit;
    }

err_exit:
    /* return unknown type for debugging purpose */
    {
        static char buf[sizeof("type0xXXXXXXXX______")];
        snprintf(buf, sizeof(buf), "type0x%x", type);
        return buf;
    }
}


PSCOM_API_EXPORT
const char *pscom_con_info_str(pscom_con_info_t *con_info)
{
    static char buf[sizeof("(xxx.xxx.xxx.xxx,pidxxx,0x_xblast_xblast__,"
                           "XXXXXXXXXXXXXXXX)_____")];
    snprintf(buf, sizeof(buf), "(" INET_ADDR_FORMAT ",%d,%p,%.8s)",
             INET_ADDR_SPLIT(con_info->node_id), con_info->pid, con_info->id,
             con_info->name);
    return buf;
}


PSCOM_API_EXPORT
const char *pscom_con_info_str2(pscom_con_info_t *con_info1,
                                pscom_con_info_t *con_info2)
{
    static char buf[sizeof("(xxx.xxx.xxx.xxx,pidxxx,0x_xblast_xblast__,"
                           "XXXXXXXXXXXXXXXX)_____ to "
                           "(xxx.xxx.xxx.xxx,pidxxx,0x_xblast_xblast__,"
                           "XXXXXXXXXXXXXXXX)_____")];
    snprintf(buf, sizeof(buf),
             "(" INET_ADDR_FORMAT ",%d,%p,%.8s) to (" INET_ADDR_FORMAT ",%d,%p,"
             "%.8s)",
             INET_ADDR_SPLIT(con_info1->node_id), con_info1->pid, con_info1->id,
             con_info1->name, INET_ADDR_SPLIT(con_info2->node_id),
             con_info2->pid, con_info2->id, con_info2->name);
    return buf;
}


PSCOM_API_EXPORT
const char *pscom_con_str(pscom_connection_t *connection)
{
    pscom_con_t *con = get_con(connection);
    pscom_con_info_t con_info;
    pscom_con_info(con, &con_info);

    return pscom_con_info_str2(&con_info, &con->pub.remote_con_info);
}


const char *pscom_con_str_reverse(pscom_connection_t *connection)
{
    pscom_con_t *con = get_con(connection);
    pscom_con_info_t con_info;
    pscom_con_info(con, &con_info);

    return pscom_con_info_str2(&con->pub.remote_con_info, &con_info);
}


PSCOM_API_EXPORT
const char *pscom_req_state_str(pscom_req_state_t state)
{
    static char buf[sizeof("sendrecvrmarrmaw(Pgpsdec)done_____")];
    const struct names {
        int flag;
        char *name;
    } n[] = {{PSCOM_REQ_STATE_SEND_REQUEST, "send"},
             {PSCOM_REQ_STATE_RECV_REQUEST, "recv"},

             {PSCOM_REQ_STATE_RMA_READ_REQUEST, "rmar"},
             {PSCOM_REQ_STATE_RMA_WRITE_REQUEST, "rmaw"},
             {PSCOM_REQ_STATE_RENDEZVOUS_REQUEST, "rdvu"},

             {~0, "("},
             {PSCOM_REQ_STATE_PASSIVE_SIDE, "P"},
             {PSCOM_REQ_STATE_GRECV_REQUEST, "g"},
             {PSCOM_REQ_STATE_POSTED, "p"},
             {PSCOM_REQ_STATE_IO_STARTED, "s"},
             {PSCOM_REQ_STATE_IO_DONE, "d"},
             {PSCOM_REQ_STATE_ERROR, "e"},
             {PSCOM_REQ_STATE_CANCELED, "c"},
             {PSCOM_REQ_STATE_TRUNCATED, "t"},
             {PSCOM_REQ_STATE_GRECV_MERGED, "m"},
             {~0, ")"},
             {PSCOM_REQ_STATE_DONE, "done"},
             {0, NULL}};
    int i;

    buf[0] = 0;

    for (i = 0; n[i].flag; i++) {
        if ((state & n[i].flag) || (n[i].flag == ~0)) {
            strcat(buf, n[i].name);
        }
    }

    return buf;
}


PSCOM_API_EXPORT
const char *pscom_err_str(pscom_err_t error)
{
    static char buf[100];
    switch (error) {
    case PSCOM_SUCCESS: return "success";
    case PSCOM_ERR_INVALID: return "Invalid argument";
    case PSCOM_ERR_ALREADY: return "Operation already in progress";
    case PSCOM_NOT_IMPLEMENTED: return "Function not implemented";
    case PSCOM_ERR_EOF: return "End of file";
    case PSCOM_ERR_IOERROR: return "IO Error";
    case PSCOM_ERR_UNSUPPORTED_VERSION: return "Unsupported version";
    case PSCOM_ERR_CONNECTION_REFUSED: return "Connection refused";
    case PSCOM_ERR_STDERROR: return strerror(errno);
    }

    snprintf(buf, sizeof(buf), "error %d", error);
    return buf;
}


PSCOM_API_EXPORT
const char *pscom_op_str(pscom_op_t operation)
{
    switch (operation) {
    case PSCOM_OP_READ: return "read";
    case PSCOM_OP_WRITE: return "write";
    case PSCOM_OP_CONNECT: return "connect";
    case PSCOM_OP_RW: return "rw";
    }

    {
        static char buf[sizeof("op%uxxxxx____")];
        snprintf(buf, sizeof(buf), "op%u", operation);
        return buf;
    }
}


PSCOM_API_EXPORT
const char *pscom_dumpstr(const void *buf, size_t size)
{
    static char *ret = NULL;
    char *tmp;
    size_t s;
    char *b;
    if (ret) { free(ret); }
    ret = (char *)malloc(size * 5 + 4);
    tmp = ret;
    s   = size;
    b   = (char *)buf;
    for (; s; s--, b++) { tmp += sprintf(tmp, "<%02x>", (unsigned char)*b); }
    *tmp++ = '\'';
    s      = size;
    b      = (char *)buf;
    for (; s; s--, b++) {
        /* *tmp++ = isprint(*b) ? *b: '.';*/
        *tmp++ = (char)(((*b >= 32) && (*b < 127)) ? *b : '.');
    }
    *tmp++ = '\'';
    *tmp++ = 0;
    return ret;
}
