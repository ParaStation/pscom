/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "pscom_priv.h"
#include "pscom_precon.h"
#include "pscom_precon_tcp.h"
#include "pscom_str_util.h"
#include "pscom_con.h"
#include "pscom_util.h"
#include "list.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_plugin.h"

pscom_env_table_entry_t pscom_env_table_precon_tcp[] = {
    {"SO_SNDBUF", "32768", "The SO_SNDBUF size of the precon/TCP connections.",
     &pscom.env.tcp_so_sndbuf, 0, PSCOM_ENV_PARSER_UINT},

    {"SO_RCVBUF", "32768", "The SO_RCVBUF size of the precon/TCP connections.",
     &pscom.env.tcp_so_rcvbuf, 0, PSCOM_ENV_PARSER_UINT},

    {"NODELAY", "1",
     "Enable/disable TCP_NODELAY for the precon/TCP connections.",
     &pscom.env.tcp_nodelay, 0, PSCOM_ENV_PARSER_INT},

    {"RECONNECT_TIMEOUT", "2000",
     "The reconnect timeout for the precon/TCP in milliseconds.",
     &pscom.env.precon_tcp_reconnect_timeout, 0, PSCOM_ENV_PARSER_UINT},

    {"CONNECT_STALLED_MAX", "6",
     "Declare after (PSP_CONNECT_STALLED * PSP_RECONNECT_TIMEOUT)[ms] "
     "without any received bytes the connect() as failed. Retry.",
     &pscom.env.precon_tcp_connect_stalled_max, 0, PSCOM_ENV_PARSER_UINT},

    {0},
};


// return true, if err indicate an temporary error and it make sense to retry
// later.
static int retry_on_error(int err)
{
    switch (err) {
    case ECONNREFUSED:
    case ECONNRESET:
    case ECONNABORTED:
    case ENETRESET:
    case ETIMEDOUT: return 1;
    }
    return 0;
}


/*
 * Helpers for sockets
 */
static int mtry_connect(int sockfd, const struct sockaddr *serv_addr,
                        socklen_t addrlen, void *debug_id)
{
    /* In the case the backlog (listen) is smaller than the number of
       processes, the connect could fail with ECONNREFUSED even though
       there is a linstening socket. mtry_connect() retry four times
       the connect after one second delay.
    */
    unsigned int i;
    int ret                = 0;
    struct sockaddr_in *sa = (struct sockaddr_in *)serv_addr;
    for (i = 0; i < pscom.env.retry; i++) {
        ret = connect(sockfd, serv_addr, addrlen);
        DPRINT(D_PRECON_TRACE, "precon(%p): connect(%d,\"%s:%u\") = %d (%s)",
               debug_id, sockfd, pscom_inetstr(ntohl(sa->sin_addr.s_addr)),
               ntohs(sa->sin_port), ret, ret ? strerror(errno) : "ok");
        if (ret >= 0) { break; }
        if (!retry_on_error(errno)) { break; }
        sleep(1);
        DPRINT(D_INFO, "Retry %d CONNECT to %s:%d", i + 1,
               pscom_inetstr(ntohl(sa->sin_addr.s_addr)), ntohs(sa->sin_port));
    }
    return ret;
}


static void configure_tcp(int fd)
{
    int ret;
    int val;

    if (pscom.env.tcp_so_sndbuf) {
        val = pscom.env.tcp_so_sndbuf;
        ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        DPRINT(D_DBG_V,
               "setsockopt(%d, SOL_SOCKET, SO_SNDBUF, [%d], %ld) = %d : %s", fd,
               val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");
    }
    if (pscom.env.tcp_so_rcvbuf) {
        val = pscom.env.tcp_so_rcvbuf;
        ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
        DPRINT(D_DBG_V,
               "setsockopt(%d, SOL_SOCKET, SO_RCVBUF, [%d], %ld) = %d : %s", fd,
               val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");
    }
    val = pscom.env.tcp_nodelay;
    ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
    DPRINT(D_DBG_V,
           "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY, [%d], %ld) = %d : %s", fd,
           val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");

    if (1) { // Set keep alive options.
        val = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
        DPRINT(ret ? D_DBG_V : D_TRACE,
               "setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE, [%d], %ld) = %d : %s",
               fd, val, (long)sizeof(val), ret,
               ret ? strerror(errno) : "Success");

        // Overwrite defaults from "/proc/sys/net/ipv4/tcp_keepalive*"

        val = 20; /* Number of keepalives before death */
        ret = setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
        DPRINT(ret ? D_DBG_V : D_TRACE,
               "setsockopt(%d, SOL_TCP, TCP_KEEPCNT, [%d], %ld) = %d : %s", fd,
               val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");

        val = 5; /* Start keeplives after this period */
        ret = setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
        DPRINT(ret ? D_DBG_V : D_TRACE,
               "setsockopt(%d, SOL_TCP, TCP_KEEPIDLE, [%d], %ld) = %d : %s", fd,
               val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");

        val = 4; /* Interval between keepalives */
        ret = setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
        DPRINT(ret ? D_DBG_V : D_TRACE,
               "setsockopt(%d, SOL_TCP, TCP_KEEPINTVL, [%d], %ld) = %d : %s",
               fd, val, (long)sizeof(val), ret,
               ret ? strerror(errno) : "Success");
    }
}


static void pscom_sockaddr_init(struct sockaddr_in *si, int nodeid, int portno)
{
    /* Setup si for TCP */
    si->sin_family      = PF_INET;
    si->sin_port        = htons((uint16_t)portno);
    si->sin_addr.s_addr = htonl(nodeid);
}


static int _pscom_connect_tcp(int nodeid, int portno, void *debug_id)
{
    struct sockaddr_in si;
    int rc;
    int optval;

    /* Open the socket */
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0) { goto err_socket; }

    /* Try a nonblocking connect. Ignoring fcntl errors and use blocking connect
     * in this case. */
    fcntl(fd, F_SETFL, O_NONBLOCK);

    /* Close on exec. Ignore errors. */
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    /* Enable keep alive. Ignore errors. */
    optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

    pscom_sockaddr_init(&si, nodeid, portno);

    /* Connect */
    rc = mtry_connect(fd, (struct sockaddr *)&si, sizeof(si), debug_id);
    if (rc < 0 && errno != EINPROGRESS) { goto err_connect; }

    return fd;
    /* --- */
err_connect:
    close(fd);
err_socket:
    return -1;
}


int pscom_precon_direct_connect_tcp(pscom_precon_t *precon, int nodeid,
                                    int portno)
{
    int fd;
    assert(precon->magic == MAGIC_PRECON);

    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pre_tcp->nodeid             = nodeid;
    pre_tcp->portno             = portno;
    pre_tcp->connect            = 1;

    fd = _pscom_connect_tcp(nodeid, portno, pre_tcp);
    if (fd >= 0) {
        pscom_precon_assign_fd_tcp(pre_tcp, fd);
        return 0;
    } else {
        return -1;
    }
}


void pscom_con_accept_tcp(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
    pscom_sock_t *sock = ufd_info->priv;
    int listen_fd      = pscom_listener_get_fd(&sock->listen);
    while (1) {
        pscom_precon_t *precon;
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        int fd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
        if (fd < 0) {
            return; // Ignore Errors.
        }

        /* Create a new precon */
        precon = pscom_precon_create(NULL);
        assert(precon);
        pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
        pre_tcp->sock = sock;
        DPRINT(D_PRECON_TRACE, "precon(%p): accept(%d,...) = %d", pre_tcp,
               listen_fd, fd);

        /* Save remote address */
        if (addr.sin_family == AF_INET) {
            pre_tcp->nodeid = ntohl(addr.sin_addr.s_addr);
            pre_tcp->portno = ntohs(addr.sin_port);
        }
        pscom_precon_assign_fd_tcp(pre_tcp, fd);

        /* Handshake with peer */
        pscom_precon_handshake_tcp(precon);
    }

    return;
}


static int pscom_precon_is_obsolete_backconnect_tcp(pscom_precon_tcp_t *pre_tcp)
{
    // A back connect is obsolete when it's associated
    // pscon_con_t con is not ONDEMAND anymore.
    // Probably, forward connect succeeded or finally failed.
    return (pre_tcp->back_connect && pre_tcp->con &&
            (pre_tcp->con->magic == MAGIC_CONNECTION) &&
            (pre_tcp->con->pub.type != PSCOM_CON_TYPE_ONDEMAND));
}


int pscom_precon_isconnected_tcp(pscom_precon_tcp_t *pre_tcp)
{
    return pre_tcp->ufd_info.fd != -1;
}


static void pscom_precon_connect_terminate_tcp(pscom_precon_tcp_t *pre_tcp)
{
    assert(pre_tcp->magic == MAGIC_PRECON);

    if (!pscom_precon_isconnected_tcp(pre_tcp)) { return; }

    close(pre_tcp->ufd_info.fd);
    ufd_del(&pscom.ufd, &pre_tcp->ufd_info);
    pre_tcp->ufd_info.fd = -1;
}


static void pscom_precon_terminate_backconnect_tcp(pscom_precon_tcp_t *pre_tcp)
{
    pscom_precon_connect_terminate_tcp(pre_tcp);
    DPRINT(D_DBG_V,
           "precon(%p): stopping obsolete back-connect on con:%p type:%6s "
           "state:%8s",
           pre_tcp, pre_tcp->con, pscom_con_type_str(pre_tcp->con->pub.type),
           pscom_con_state_str(pre_tcp->con->pub.state));
    pre_tcp->con = NULL; // do not touch the connected con anymore.

    pscom_precon_handle_receive_tcp(pre_tcp, PSCOM_INFO_FD_EOF, NULL, 0);
}


static void pscom_precon_reconnect_tcp(pscom_precon_tcp_t *pre_tcp)
{
    assert(pre_tcp->magic == MAGIC_PRECON);
    assert(pre_tcp->connect);

    pscom_precon_connect_terminate_tcp(pre_tcp);

    if (pscom_precon_is_obsolete_backconnect_tcp(pre_tcp)) {
        pscom_precon_terminate_backconnect_tcp(pre_tcp);
        goto out;
    }

    if (pre_tcp->reconnect_cnt < pscom.env.retry) {
        pre_tcp->reconnect_cnt++;
        DPRINT(D_DBG, "precon(%p):pscom_precon_reconnect_tcp count %u", pre_tcp,
               pre_tcp->reconnect_cnt);
        int fd = _pscom_connect_tcp(pre_tcp->nodeid, pre_tcp->portno, pre_tcp);
        if (fd < 0) { goto error; }

        pscom_precon_assign_fd_tcp(pre_tcp, fd);
    } else {
        errno = ECONNREFUSED;
        goto error;
    }

out:
    return;
    /* --- */
    int error_code;
error:
    /* precon connect failed. */
    error_code = errno;
    pscom_precon_handle_receive_tcp(pre_tcp, PSCOM_INFO_FD_ERROR, &error_code,
                                    sizeof(error_code));
    return;
}


/* Print statistic about this precon */
void pscom_precon_check_connect_tcp(pscom_precon_tcp_t *pre_tcp)
{
    unsigned long now = pscom_wtime_usec();
    if (!pre_tcp->connect) {
        // Not the connecting side of the precon.
        // The accepting side does nothing here.
    } else if (pscom_precon_is_obsolete_backconnect_tcp(pre_tcp)) {
        // pre is a backconnect and the forward connect succeeded or failed
        // finally.
        pscom_precon_terminate_backconnect_tcp(pre_tcp);
    } else if (now - pre_tcp->last_reconnect >
               pscom.env.precon_tcp_reconnect_timeout /* ms */ * 1000UL) {
        // reconnect timeout happened

        pre_tcp->last_reconnect = now;

        if (!pscom_precon_isconnected_tcp(pre_tcp)) {
            // reconnect after failure followed by the
            // precon_tcp_reconnect_timeout:
            pscom_precon_reconnect_tcp(pre_tcp);
        } else if ((pre_tcp->stat_recv == 0) && (pre_tcp->stat_send == 0)) {
            // precon stalled
            pre_tcp->stalled_cnt++;

            if (pre_tcp->stalled_cnt <
                pscom.env.precon_tcp_connect_stalled_max) {
                /* Wait */
                DPRINT(D_DBG, "precon(%p): connect(%s:%u) stalled %u/%u",
                       pre_tcp, pscom_inetstr(pre_tcp->nodeid), pre_tcp->portno,
                       pre_tcp->stalled_cnt,
                       pscom.env.precon_tcp_connect_stalled_max);
            } else {
                DPRINT(D_ERR,
                       "precon(%p): connect(%s:%u) stalled - reconnecting",
                       pre_tcp, pscom_inetstr(pre_tcp->nodeid),
                       pre_tcp->portno);

                /* ToDo:
                   If the peer is just busy, we should wait further, but if
                   this connection is broken we should reconnect. How to detect
                   that the remote missed the accept event? Here is a race: The
                   remote might have started already a handshake on this precon
                   while we terminate the connection and retry.
                */
                pre_tcp->stalled_cnt = 0;
                pscom_precon_reconnect_tcp(pre_tcp);
            }
        }
    }
}


void pscom_precon_recv_start_tcp(pscom_precon_t *precon)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    assert(pre_tcp->magic == MAGIC_PRECON);
    ufd_event_set(&pscom.ufd, &pre_tcp->ufd_info, POLLIN);
    pre_tcp->recv_done = 0;
}


void pscom_precon_recv_stop_tcp(pscom_precon_t *precon)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    assert(pre_tcp->magic == MAGIC_PRECON);
    if (pscom_precon_isconnected_tcp(pre_tcp)) {
        ufd_event_clr(&pscom.ufd, &pre_tcp->ufd_info, POLLIN);
    }
    pre_tcp->recv_done = 1;
}


void pscom_precon_send_tcp(pscom_precon_t *precon, unsigned type, void *data,
                           unsigned size)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    uint32_t ntype              = htonl(type);
    uint32_t nsize              = htonl(size);
    unsigned msg_size = size + (unsigned)(sizeof(ntype) + sizeof(nsize));
    char *msg;

    pscom_precon_info_dump(precon, "send", type, data, size);

    /* allocate msg_size bytes after existing pre->send */
    pre_tcp->send = realloc(pre_tcp->send, pre_tcp->send_len + msg_size);
    assert(pre_tcp->send);
    msg = pre_tcp->send + pre_tcp->send_len;
    pre_tcp->send_len += msg_size;

    /* append the message to pre->send */
    memcpy(msg, &ntype, sizeof(ntype));
    msg += sizeof(ntype);
    memcpy(msg, &nsize, sizeof(nsize));
    msg += sizeof(nsize);
    memcpy(msg, data, size);
    msg += size;

    /* Send */
    ufd_event_set(&pscom.ufd, &pre_tcp->ufd_info, POLLOUT);
}


static void pscom_precon_do_write_tcp(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)ufd_info->priv;
    pscom_precon_t *precon      = pre_tcp->precon;

    int len;
    assert(precon->magic == MAGIC_PRECON);

    if (pre_tcp->send_len) {
        len = (int)send(pre_tcp->ufd_info.fd, pre_tcp->send, pre_tcp->send_len,
                        MSG_NOSIGNAL);
    } else {
        len = 0;
    }

    // printf("write(%d, %p, %u) = %d(%s)\n", pre->ufd_info.fd,
    //       pre->send, pre->send_len, len, len < 0 ? strerror(errno) : "ok");

    if (len >= 0) {
        pre_tcp->stat_send += len;
        memmove(pre_tcp->send, pre_tcp->send + len, pre_tcp->send_len - len);
        pre_tcp->send_len -= len;
        if (!pre_tcp->send_len) {
            free(pre_tcp->send);
            pre_tcp->send = NULL;
            ufd_event_clr(&pscom.ufd, &pre_tcp->ufd_info, POLLOUT);
        }
    } else {
        if (pre_tcp->connect && retry_on_error(errno)) {
            /* Nonblocking connect() failed e.g. on ECONNREFUSED */
            pscom_precon_reconnect_tcp(pre_tcp);
            pre_tcp = NULL; // pscom_precon_reconnect_tcp() might close pre.
                            // Don't use pre afterwards.
        } else {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                /* Try again later */
                break;
            default: {
                /*
                 * Unexpected error. Stop writing. Print diagnostics.
                 * The cleanup will be done in do_read, which will
                 * (hopefully) also fail in read().
                 *
                 * NOTE: EPIPE is handled as a warning as this might occur in
                 *       back-connect situations and does not constitute an
                 * error.
                 */
                const int log_level = (errno == EPIPE) ? D_WARN : D_ERR;
                DPRINT(log_level, "precon(%p): write(%d, %p, %u) : %s", pre_tcp,
                       pre_tcp->ufd_info.fd, pre_tcp->send, pre_tcp->send_len,
                       strerror(errno));
                ufd_event_clr(&pscom.ufd, &pre_tcp->ufd_info, POLLOUT);
                close(pre_tcp->ufd_info.fd);
                pre_tcp->send_len = 0;
            }
            }
        }
    }

    if (pre_tcp) { pscom_precon_check_end_tcp(pre_tcp); }
}


static void pscom_precon_do_read_tcp(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)ufd_info->priv;
    assert(!pre_tcp->con || pre_tcp->con->magic == MAGIC_CONNECTION);

    if (pre_tcp->recv_done) {
        DPRINT(D_ERR, "pscom_precon_do_read: softassert(!pre->recv_done) "
                      "failed.");
        pscom_precon_recv_stop(pre_tcp->precon);
        return;
    }
    int len;
    uint32_t ntype;
    uint32_t nsize;
    const unsigned header_size = sizeof(ntype) + sizeof(nsize);
    int fd                     = pre_tcp->ufd_info.fd;

    /* Allocate bufferspace for the header. Be prepared for more data */
    if (!pre_tcp->recv) {
        pre_tcp->recv = malloc(header_size + 128);
        assert(pre_tcp->recv);
    }

    /* Read the header */
    if (pre_tcp->recv_len < header_size) {
        len = (int)read(fd, pre_tcp->recv + pre_tcp->recv_len,
                        header_size - pre_tcp->recv_len);
        // printf("read#1(%d, %p, %u) = %d(%s)\n", fd, pre->recv +
        // pre->recv_len,
        //        header_size - pre->recv_len, len, len < 0 ? strerror(errno) :
        //        "ok");
        if (len <= 0) { goto check_read_error; }
        pre_tcp->recv_len += len;
        pre_tcp->stat_recv += len;
    }

    /* Header complete? Read and process the data: */
    if (pre_tcp->recv_len >= header_size) {
        ntype = ntohl(*(uint32_t *)pre_tcp->recv);
        nsize = ntohl(*((uint32_t *)pre_tcp->recv + 1));

        unsigned msg_len = header_size + nsize;

        /* Allocate more for the data */
        pre_tcp->recv = realloc(pre_tcp->recv, msg_len);
        assert(pre_tcp->recv);

        /* Read the data */
        len = msg_len - pre_tcp->recv_len;
        if (len) {
            len = (int)read(fd, pre_tcp->recv + pre_tcp->recv_len, len);
            // printf("read#2(%d, %p, %u) = %d(%s)\n", fd, pre->recv +
            // pre->recv_len,
            //        msg_len - pre->recv_len, len, len < 0 ? strerror(errno) :
            //        "ok");
            if (len <= 0) { goto check_read_error; }
            pre_tcp->recv_len += len;
            pre_tcp->stat_recv += len;
        }

        /* Message complete? */
        if (pre_tcp->recv_len == msg_len) {
            /* Message complete. Handle the message. */
            void *msg = pre_tcp->recv;

            pre_tcp->recv     = NULL;
            pre_tcp->recv_len = 0;
            pscom_precon_handle_receive_tcp(pre_tcp, ntype, msg + header_size,
                                            nsize);
            /* Dont use pre hereafter, as handle_receive may free it! */

            pre_tcp = NULL;
            free(msg);
        }
    }
    return;
    /* --- */
check_read_error:
    if (len == 0) {
        /* receive EOF. Handle the pseudo message FD_EOF */
        ufd_event_clr(&pscom.ufd, &pre_tcp->ufd_info, POLLIN);
        pscom_precon_handle_receive_tcp(pre_tcp, PSCOM_INFO_FD_EOF, NULL, 0);
    } else if (errno == EAGAIN || errno == EINTR) {
        /* Try again later */
        return;
    } else if (retry_on_error(errno)) {
        DPRINT(D_DBG, "precon(%p): read(%d,...) : %s", pre_tcp, fd,
               strerror(errno));
        /* pscom_precon_reconnect_tcp(pre); */
        /* Terminate this connection. Reconnect after
         * pscom.env.precon_tcp_reconnect_timeout.*/
        pscom_precon_connect_terminate_tcp(pre_tcp);
    } else {
        /* Connection error. Handle the pseudo message FD_ERROR. */
        int error_code = errno;
        ufd_event_clr(&pscom.ufd, &pre_tcp->ufd_info, POLLIN);
        pscom_precon_handle_receive_tcp(pre_tcp, PSCOM_INFO_FD_ERROR,
                                        &error_code, sizeof(error_code));
    }
}


static void pscom_precon_send_PSCOM_INFO_VERSION_tcp(pscom_precon_tcp_t *pre_tcp)
{
    pscom_info_version_t ver;
    assert(pre_tcp->magic == MAGIC_PRECON);

    /* Send supported versions */
    ver.ver_from = VER_FROM;
    ver.ver_to   = VER_TO;
    pscom_precon_send(pre_tcp->precon, PSCOM_INFO_VERSION, &ver, sizeof(ver));
}


void pscom_precon_handshake_tcp(pscom_precon_t *precon)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    assert(pre_tcp->magic == MAGIC_PRECON);

    /* Enable receive */
    pscom_precon_recv_start(precon);

    // printf("%s:%u:%s CON_STATE:%s\n", __FILE__, __LINE__, __func__,
    //        pre->con ? pscom_con_state_str(pre->con->pub.state): "no
    //        connection");

    if (pre_tcp->con && (pre_tcp->con->pub.state & PSCOM_CON_STATE_CONNECTING)) {
        int on_demand = (pre_tcp->con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
        int type;
        if (on_demand) {
            type                    = PSCOM_INFO_CON_INFO_DEMAND;
            pre_tcp->con->pub.state = PSCOM_CON_STATE_CONNECTING_ONDEMAND;
        } else {
            type                    = PSCOM_INFO_CON_INFO;
            pre_tcp->con->pub.state = PSCOM_CON_STATE_CONNECTING;
        }
        pscom_precon_send_PSCOM_INFO_VERSION_tcp(pre_tcp);
        pscom_precon_send_PSCOM_INFO_CON_INFO_tcp(pre_tcp, type);
        plugin_connect_first(pre_tcp->con);
    }
}


void pscom_precon_handle_receive_tcp(pscom_precon_tcp_t *pre_tcp, uint32_t type,
                                     void *data, unsigned size)
{
    int err;
    pscom_con_t *con = pre_tcp->con;
    assert(pre_tcp->magic == MAGIC_PRECON);
    assert(!con || con->magic == MAGIC_CONNECTION);
    assert(!con || con->precon == pre_tcp->precon || pre_tcp->back_connect);

    pscom_precon_info_dump(pre_tcp->precon, "recv", type, data, size);

    switch (type) {
    case PSCOM_INFO_FD_EOF:
        pscom_precon_abort_plugin_tcp(pre_tcp);
        if (con) { pscom_con_setup_failed(con, PSCOM_ERR_EOF); }
        if (!pre_tcp->recv_done) { pscom_precon_terminate_tcp(pre_tcp); }
        break;
    case PSCOM_INFO_FD_ERROR:
        pscom_precon_abort_plugin_tcp(pre_tcp);
        err = data ? *(int *)data : 0;
        if (con && (!pre_tcp->back_connect || /* not a back connect */
                    (!retry_on_error(err)))   /* or a back connect and the error
                                                 is not due to a reverse
                                                 connection already triggered or
                                                 established by the peer. */
        ) {
            pscom_con_setup_failed(con, err == ECONNREFUSED
                                            ? PSCOM_ERR_CONNECTION_REFUSED
                                            : PSCOM_ERR_IOERROR);
        }
        pscom_precon_terminate_tcp(pre_tcp);
        break;
    case PSCOM_INFO_CON_INFO: {
        pscom_info_con_info_t *msg = data;
        if (size != sizeof(*msg)) { // old pscom version send CON_INFO before
                                    // VERSION.
            break;
        }

        pscom_sock_t *sock = pre_tcp->sock;

        if (!con) { // Accepting side of the connection
            con                            = pscom_con_create(sock);
            pre_tcp->con                   = con;
            con->precon                    = pre_tcp->precon;
            con->state.internal_connection = 1; // until the user get a handle
                                                // to con (via con->on_accept)
            con->pub.state                 = PSCOM_CON_STATE_ACCEPTING;
            con->pub.remote_con_info       = msg->con_info;
            pscom_precon_send_PSCOM_INFO_VERSION_tcp(pre_tcp);
            pscom_precon_send_PSCOM_INFO_CON_INFO_tcp(pre_tcp,
                                                      PSCOM_INFO_CON_INFO);
        } else {
            con->pub.remote_con_info = msg->con_info;
        }
        break;
    }
    case PSCOM_INFO_CON_INFO_DEMAND: {
        pscom_info_con_info_t *msg = data;
        assert(size >= sizeof(*msg));
        pscom_sock_t *sock = pre_tcp->sock;
        assert(!con);

        // Search for the existing matching connection
        con = pscom_ondemand_get_con(sock, msg->con_info.name);

        if (con) {
            /* Set con */
            assert(pre_tcp);
            pre_tcp->con = con;
            assert(con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
            assert(!con->precon);
            con->precon              = pre_tcp->precon;
            con->pub.remote_con_info = msg->con_info;
            con->pub.state           = PSCOM_CON_STATE_ACCEPTING_ONDEMAND;

            pscom_precon_send_PSCOM_INFO_VERSION_tcp(pre_tcp);
            pscom_precon_send_PSCOM_INFO_CON_INFO_tcp(pre_tcp,
                                                      PSCOM_INFO_CON_INFO);
        } else {
            /* No con found.
               Reject this connection! */
            DPRINT(D_WARN, "Reject %s : unknown on demand connection",
                   pscom_con_info_str(&msg->con_info));
            pscom_precon_terminate_tcp(pre_tcp);
        }
        break;
    }
    case PSCOM_INFO_VERSION: {
        pscom_info_version_t *ver = data;
        assert(size >= sizeof(*ver)); /* with space for the future */
        if ((VER_TO < ver->ver_from) || (ver->ver_to < VER_FROM)) {
            DPRINT(D_ERR,
                   "connection %s : Unsupported protocol version "
                   "(mine:[%04x..%04x] remote:[%04x..%04x])",
                   con ? pscom_con_str(&con->pub)
                       : pscom_precon_str_tcp(pre_tcp),
                   VER_FROM, VER_TO, ver->ver_from, ver->ver_to);
            errno = EPROTO;
            if (con) { pscom_con_setup_failed(con, PSCOM_ERR_STDERROR); }
            pscom_precon_terminate_tcp(pre_tcp);
        }
        break;
    }
    case PSCOM_INFO_BACK_CONNECT: {
        pscom_info_con_info_t *msg = data;
        pscom_con_info_t *con_info = &msg->con_info;
        assert(size >= sizeof(*msg));
        assert(!con);
        pscom_sock_t *sock = pre_tcp->sock;

        DPRINT(D_PRECON_TRACE, "precon(%p): recv backcon %.8s to %.8s", pre_tcp,
               con_info->name, sock->pub.local_con_info.name);
        // Search for an existing matching connection
        con = pscom_ondemand_find_con(sock, con_info->name);

        if (con && con->pub.type == PSCOM_CON_TYPE_ONDEMAND) {
            /* Trigger the back connect */
            DPRINT(D_DBG_V, "RACCEPT %s", pscom_con_str(&con->pub));
            con->write_start(con);
        } else {
            DPRINT(D_DBG_V, "RACCEPT from %s skipped",
                   pscom_con_info_str(con_info));
        }
        pscom_precon_send(pre_tcp->precon, PSCOM_INFO_BACK_ACK, NULL, 0);
        pscom_precon_recv_stop(pre_tcp->precon);
        break;
    }
    case PSCOM_INFO_BACK_ACK: {
        pscom_precon_recv_stop(pre_tcp->precon);
        break;
    }
    case PSCOM_INFO_ARCH_REQ: {
        assert(size == sizeof(int));
        assert(con);
        int arch               = *(int *)data;
        pscom_sock_t *sock     = get_sock(con->pub.socket);
        pscom_plugin_t *p      = NULL;
        pscom_precon_t *precon = pre_tcp->precon;

        if (_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(arch))) {
            p = pscom_plugin_by_archid(arch);
        }
        if (p && !p->con_init(con)) {
            precon->plugin = p;
            assert(con->precon);
            /* Use asynchronous handshake */
            p->con_handshake(con, type, data, size);
        } else {
            // Unknown or disabled arch or con_init fail. Try next arch.
            pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
        }
        break;
    }
    case PSCOM_INFO_ARCH_OK:
    case PSCOM_INFO_ARCH_STEP1:
    case PSCOM_INFO_ARCH_STEP2:
    case PSCOM_INFO_ARCH_STEP3:
    case PSCOM_INFO_ARCH_STEP4: {
        /* Handled by the current plugin. pre->plugin might be
         * null, in the case of an initialization error. */
        pscom_precon_t *precon = pre_tcp->precon;
        if (con) {
            if (precon->plugin) {
                precon->plugin->con_handshake(con, type, data, size);
                if (type == PSCOM_INFO_ARCH_OK) {
                    pscom_precon_recv_stop(precon);
                }
            } else {
                // Failed locally before. Handle OK like an ARCH_NEXT
                if (type == PSCOM_INFO_ARCH_OK) { plugin_connect_next(con); }
            }
        }
        break;
    }
    case PSCOM_INFO_ARCH_NEXT: {
        pscom_precon_abort_plugin_tcp(pre_tcp);
        plugin_connect_next(con);
        break;
    }
    case PSCOM_INFO_EOF: {
        pscom_precon_t *precon = pre_tcp->precon;
        if (precon->plugin && con) {
            precon->plugin->con_handshake(con, type, data, size);
        }
        precon->plugin = NULL;
    }
    default: /* ignore all unknown info messages */
        ;
    }
    pscom_precon_check_end_tcp(pre_tcp);
}


static void pscom_precon_print_stat_tcp(pscom_precon_tcp_t *pre_tcp)
{
    int fd                                = pre_tcp->ufd_info.fd;
    pscom_precon_provider_t *pre_provider = &pscom_precon_provider;
    char state[10]                        = "no fd";
    assert(pre_tcp->magic == MAGIC_PRECON);

    if (fd != -1) {
        struct pollfd *pollfd = ufd_get_pollfd(&pscom.ufd, &pre_tcp->ufd_info);
        if (pollfd) {
            state[0] = pollfd->events & POLLIN ? 'R' : '_';
            state[1] = pollfd->events & POLLOUT ? 'W' : '_';
            state[3] = 0;
        } else {
            strcpy(state, "no poll");
        }
    }
    DPRINT(D_PRECON_TRACE,
           "precon(%p): #%u send:%zu recv:%zu to_send:%u recv:%s active:%u "
           "state:%s\n",
           pre_tcp, pre_tcp->stat_poll_cnt, pre_tcp->stat_send,
           pre_tcp->stat_recv, pre_tcp->send_len,
           pre_tcp->recv_done ? "no" : "yes", pre_provider->precon_count,
           state);
}

/* Print statistic about this precon */
static int pscom_precon_do_read_poll_tcp(pscom_poll_t *poll)
{
    pscom_precon_tcp_t *pre_tcp = list_entry(poll, pscom_precon_tcp_t,
                                             poll_read);
    assert(pre_tcp->magic == MAGIC_PRECON);
    unsigned long now = pscom_wtime_usec();

    if (pscom.env.debug >= D_PRECON_TRACE) {
        if (now - pre_tcp->last_print_stat > 1500 /* ms */ * 1000) {
            pre_tcp->stat_poll_cnt++;

            pre_tcp->last_print_stat = now;
            pscom_precon_print_stat_tcp(pre_tcp);
        }
    }

    pscom_precon_check_connect_tcp(pre_tcp);

    return 0;
}


void pscom_precon_abort_plugin_tcp(pscom_precon_tcp_t *pre_tcp)
{
    pscom_con_t *con = pre_tcp->con;
    if (pre_tcp->precon->plugin && con) {
        DPRINT(D_PRECON_TRACE, "precon(%p):abort %s", pre_tcp,
               pre_tcp->precon->plugin->name);
        pre_tcp->precon->plugin->con_handshake(con, PSCOM_INFO_ARCH_NEXT, NULL,
                                               0);
    }
    pre_tcp->precon->plugin = NULL; // Do not use plugin anymore after
                                    // PSCOM_INFO_ARCH_NEXT
}


/* Send con_info. The type should be one of:
 *  - PSCOM_INFO_CON_INFO
 *  - PSCOM_INFO_CON_INFO_DEMAND
 *  - PSCOM_INFO_BACK_CONNECT
 */
void pscom_precon_send_PSCOM_INFO_CON_INFO_tcp(pscom_precon_tcp_t *pre_tcp,
                                               int type)
{
    pscom_info_con_info_t msg_con_info;
    assert(pre_tcp->magic == MAGIC_PRECON);
    assert(pre_tcp->con);
    assert(pre_tcp->con->magic == MAGIC_CONNECTION);

    /* Send connection information */
    pscom_con_info(pre_tcp->con, &msg_con_info.con_info);

    DPRINT(D_PRECON_TRACE, "precon(%p): con:%s", pre_tcp,
           pscom_con_str(&pre_tcp->con->pub));
    pscom_precon_send(pre_tcp->precon, type, &msg_con_info,
                      sizeof(msg_con_info));
}

void pscom_precon_terminate_tcp(pscom_precon_tcp_t *pre_tcp)
{
    assert(pre_tcp->magic == MAGIC_PRECON);
    DPRINT(D_DBG, "precon(%p): terminated", pre_tcp->precon);
    pscom_precon_recv_stop(pre_tcp->precon);
    // trow away the sendbuffer
    if (pre_tcp->send) {
        free(pre_tcp->send);
        pre_tcp->send = NULL;
    }
    if (pre_tcp->send_len) {
        // Dont send
        pre_tcp->send_len = 0;
        if (pre_tcp->ufd_info.fd != -1) {
            ufd_event_clr(&pscom.ufd, &pre_tcp->ufd_info, POLLOUT);
        }
    }
}

const char *pscom_precon_str_tcp(pscom_precon_tcp_t *pre_tcp)
{
    static char buf[sizeof("xxx.xxx.xxx.xxx:portxx_____     ")];
    snprintf(buf, sizeof(buf), INET_ADDR_FORMAT ":%u",
             INET_ADDR_SPLIT(pre_tcp->nodeid), pre_tcp->portno);
    return buf;
}


void pscom_precon_check_end_tcp(pscom_precon_tcp_t *pre_tcp)
{
    assert(pre_tcp->magic == MAGIC_PRECON);
    if ((pre_tcp->send_len == 0) && pre_tcp->recv_done) {
        if (!pre_tcp->back_connect) {
            pscom_plugin_t *p = pre_tcp->precon->plugin;

            if (pre_tcp->con) {
                pre_tcp->con->precon = NULL; // disallow precon usage in
                                             // handshake
            }

            if (p) { p->con_handshake(pre_tcp->con, PSCOM_INFO_EOF, NULL, 0); }
        }

        pscom_precon_print_stat_tcp(pre_tcp);

        pscom_precon_destroy(pre_tcp->precon);
        pre_tcp = NULL;
    }
}

/* assign ufd with tcp */
void pscom_precon_assign_fd_tcp(pscom_precon_tcp_t *pre_tcp, int con_fd)
{
    assert(pre_tcp->ufd_info.fd == -1);
    configure_tcp(con_fd);

    pre_tcp->ufd_info.fd        = con_fd;
    pre_tcp->ufd_info.can_read  = pscom_precon_do_read_tcp;
    pre_tcp->ufd_info.can_write = pscom_precon_do_write_tcp;
    pre_tcp->ufd_info.priv      = pre_tcp;

    ufd_add(&pscom.ufd, &pre_tcp->ufd_info);

    if (pre_tcp->send_len) {
        ufd_event_set(&pscom.ufd, &pre_tcp->ufd_info, POLLOUT);
    }
    if (!pre_tcp->recv_done) {
        ufd_event_set(&pscom.ufd, &pre_tcp->ufd_info, POLLIN);
    }
}

pscom_precon_t *pscom_precon_create_tcp(pscom_con_t *con)
{
    size_t precon_size = sizeof(pscom_precon_t) + sizeof(pscom_precon_tcp_t);
    pscom_precon_t *precon = malloc(precon_size);
    memset(precon, 0, precon_size);
    precon->magic = MAGIC_PRECON;

    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)precon->precon_data;
    pre_tcp->magic              = MAGIC_PRECON;
    pre_tcp->con                = con;
    pre_tcp->precon             = precon;
    pre_tcp->recv_done          = 1; // No recv
    pre_tcp->closefd_on_cleanup = 1; // Default: Close fd on cleanup. Only
                                     // PSCOM_CON_TYPE_TCP will overwrite this.
    pre_tcp->back_connect       = 0; // Not a back connect
    pre_tcp->connect            = 0;
    pre_tcp->stalled_cnt        = 0;

    pre_tcp->ufd_info.fd         = -1;
    pre_tcp->ufd_info.pollfd_idx = -1;

    pre_tcp->last_reconnect = pre_tcp->last_print_stat = pscom_wtime_usec();

    pscom_poll_init(&pre_tcp->poll_read);

    pscom_poll_start(&pre_tcp->poll_read, pscom_precon_do_read_poll_tcp,
                     &pscom.poll_read);

    pre_tcp->stat_send     = 0;
    pre_tcp->stat_recv     = 0;
    pre_tcp->stat_poll_cnt = 0;

    return precon;
}


void pscom_precon_cleanup_tcp(pscom_precon_t *precon)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)precon->precon_data;
    assert(pre_tcp->magic == MAGIC_PRECON);
    // clean up tcp
    int fd = pre_tcp->ufd_info.fd;
    if (fd != -1) {
        ufd_del(&pscom.ufd, &pre_tcp->ufd_info);
        pre_tcp->ufd_info.fd = -1;
    }

    pscom_poll_cleanup_init(&pre_tcp->poll_read);

    free(pre_tcp->send);
    pre_tcp->send     = NULL;
    pre_tcp->send_len = 0;
    free(pre_tcp->recv);
    pre_tcp->recv     = NULL;
    pre_tcp->recv_len = 0;

    if (pre_tcp->closefd_on_cleanup && fd != -1) {
        int rc = close(fd);
        if (!rc) {
            DPRINT(D_PRECON_TRACE, "precon(%p): close(%d)", pre_tcp, fd);
        } else {
            DPRINT(D_WARN, "precon(%p): close(%d) : %s", pre_tcp, fd,
                   strerror(errno));
        }
    } else {
        DPRINT(D_PRECON_TRACE, "precon(%p): done", pre_tcp);
    }
}


void pscom_precon_ondemand_backconnect_tcp(pscom_con_t *con)
{
    int nodeid = con->pub.remote_con_info.node_id;
    int portno = con->pub.remote_con_info.tcp.portno;
    int rc;

    pscom_precon_t *precon = pscom_precon_create(con);

    rc = pscom_precon_direct_connect_tcp(precon, nodeid, portno);
    if (rc >= 0) {
        /* Request a back connect. There are three reasons for
           a failing tcp_connect: 1.) Problems to connect,
           caused by network congestion or busy peer (e.g. tcp
           backlog to small). In this case the connection con
           should be terminated with an error. 2.) Peer is
           connecting to us at the same time and the listening
           tcp port is already closed. This is not an error
           and we must not terminate the connection con.
           3.) Peer has no receive request on this con and is
           not watching for POLLIN on the listening fd. This
           is currently unhandled and cause a connection error! */

        /* Send a rconnect request */
        pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
        DPRINT(D_PRECON_TRACE, "precon(%p): send backcon %.8s to %.8s", pre_tcp,
               con->pub.socket->local_con_info.name,
               con->pub.remote_con_info.name);
        pscom_precon_send_PSCOM_INFO_CON_INFO_tcp(pre_tcp,
                                                  PSCOM_INFO_BACK_CONNECT);

        pre_tcp->back_connect = 1; /* This is a back connect. */

        pscom_precon_recv_start(precon); // Wait for the
                                         // PSCOM_INFO_BACK_ACK
    } else {
        pscom_precon_destroy(precon);
    }
}


pscom_err_t pscom_precon_connect_tcp(pscom_con_t *con)
{
    pscom_sock_t *sock = get_sock(con->pub.socket);

    /* ToDo: Set connection state to "connecting". Suspend send and recieve
     * queues! */
    pscom_precon_t *precon = pscom_precon_create(con);
    con->precon            = precon;

    pscom_con_info_t *remote_con_info = &con->pub.remote_con_info;
    if (!remote_con_info->name[0]) {
        snprintf(remote_con_info->name, sizeof(remote_con_info->name), ":%u",
                 remote_con_info->tcp.portno);
    }

    if (list_empty(&con->next)) {
        list_add_tail(&con->next, &sock->connections);
    }

    if (pscom_precon_direct_connect_tcp(precon, remote_con_info->node_id,
                                        remote_con_info->tcp.portno) < 0) {
        goto err_connect;
    }

    con->pub.state = PSCOM_CON_STATE_CONNECTING;
    pscom_precon_handshake_tcp(precon);

    if (con->pub.state == PSCOM_CON_STATE_CLOSED) { goto err_connect; }

    return PSCOM_SUCCESS;
    /* --- */
// err_init_failed:
err_connect:
    if (errno != ENOPROTOOPT) {
        // if (errno == ENOPROTOOPT) _plugin_connect_next() already called
        // pscom_con_setup_failed().
        pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
    }
    return PSCOM_ERR_STDERROR;
}


int pscom_precon_guard_setup_tcp(pscom_precon_t *precon)
{
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    /* set cleanup to 0 such that fd will not be closed when precon tcp is
     * destroyed */
    pre_tcp->closefd_on_cleanup = 0;
    return pre_tcp->ufd_info.fd;
}


void pscom_precon_provider_init_tcp()
{
    pscom_env_table_register_and_parse("pscom PRECON", "PRECON_TCP_",
                                       pscom_env_table_precon_tcp);
}


pscom_err_t pscom_get_ep_info_from_socket_tcp(pscom_socket_t *socket,
                                              char **ep_str)
{
    /* error checking */
    if (!socket || !ep_str) { goto err_invalid_param; };

    /* [ip addr]:[port number]@[name], name is the socket name set by user. for
     * now this name is the local rank from process manager */
    size_t str_size  = sizeof("xxx.xxx.xxx.xxx:xxxxx@01234567____");
    char *ep_str_tcp = (char *)malloc(str_size);
    if (!ep_str_tcp) { goto err_malloc; }

    int portno = socket->listen_portno;
    int nodeid = socket->local_con_info.node_id;

    if (portno < 0 || portno > 65535) { goto err_invalid_param; }
    /* socket->local_con_info.name will be sent to the remote side */
    snprintf(ep_str_tcp, str_size, INET_ADDR_FORMAT ":%u@%1.8s",
             INET_ADDR_SPLIT(nodeid), portno, socket->local_con_info.name);
    *ep_str = ep_str_tcp;

    return PSCOM_SUCCESS;

    /* error code */
err_malloc:
    errno = ENOMEM;
    goto err_out;
err_invalid_param:
    errno = EINVAL;
err_out:
    return PSCOM_ERR_STDERROR;
}


pscom_err_t pscom_parse_ep_info_tcp(const char *ep_str,
                                    pscom_con_info_t *con_info)
{
    /* [ip addr]:[port number]@[name], name is the socket name set by user. for
     * now this name is rank */
    char lname[sizeof("xxx.xxx.xxx.xxx:xxxxx@01234567____")];
    char *host;
    char *port      = NULL;
    char *nametok   = NULL;
    pscom_err_t ret = PSCOM_SUCCESS;
    struct sockaddr_in sock;

    if (!ep_str) {
        /* NULL means loopback connection */
        con_info->node_id    = -1;
        con_info->tcp.portno = -1;
        memset(con_info->name, 0, sizeof(con_info->name));
        return ret;
    }

    strcpy(lname, ep_str);

    host = strtok_r(lname, ":", &port);
    if (!host) { goto err_no_host; }
    if (!port) { goto err_no_port; }
    strtok_r(port, "@", &nametok);

    if (pscom_ascii_to_sockaddr_in(host, port, "tcp", &sock) < 0) {
        goto err_to_sock;
    }

    con_info->node_id    = (int)ntohl(sock.sin_addr.s_addr);
    con_info->tcp.portno = (int)ntohs(sock.sin_port);

    memset(con_info->name, 0, sizeof(con_info->name));
    /* the parsed name should be socket->local_con_info.name from the remote
     * side, it will be used to find ondemand connection and determine who is
     * connecting/ back-connecting by comparing with the name in
     * socket->local_con_info.name */
    if (nametok) { strncpy(con_info->name, nametok, sizeof(con_info->name)); }

    return ret;

err_no_host:
err_no_port:
    errno = EINVAL;
err_to_sock:
    ret = PSCOM_ERR_STDERROR;
    return ret;
}


static int pscom_is_connect_loopback_tcp(pscom_socket_t *socket,
                                         pscom_connection_t *connection)
{
    int node_id = connection->remote_con_info.node_id;
    int portno  = connection->remote_con_info.tcp.portno;
    return ((node_id == -1) || (node_id == INADDR_LOOPBACK) ||
            (node_id == socket->local_con_info.node_id)) &&
           ((portno == -1) || (portno == socket->listen_portno));
}


pscom_precon_provider_t pscom_provider_tcp = {
    .precon_type             = PSCOM_PRECON_TYPE_TCP,
    .init                    = pscom_precon_provider_init_tcp,
    .send                    = pscom_precon_send_tcp,
    .create                  = pscom_precon_create_tcp,
    .cleanup                 = pscom_precon_cleanup_tcp,
    .recv_start              = pscom_precon_recv_start_tcp,
    .recv_stop               = pscom_precon_recv_stop_tcp,
    .connect                 = pscom_precon_connect_tcp,
    .guard_setup             = pscom_precon_guard_setup_tcp,
    .get_ep_info_from_socket = pscom_get_ep_info_from_socket_tcp,
    .parse_ep_info           = pscom_parse_ep_info_tcp,
    .is_connect_loopback     = pscom_is_connect_loopback_tcp,
};
