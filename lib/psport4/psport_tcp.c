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
 * psport_tcp.h: tcp communication
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "psport_priv.h"
#include "psport_tcp.h"
#include "psport_ufd.h"



static
char tmp_read_buf[128];

static
void PSP_do_read_tcp(ufd_t *ufd, int ufd_idx)
{
    PSP_Port_t *port = list_entry(ufd, PSP_Port_t, ufd);
    PSP_Connection_t *con = ufd->ufds_info[ufd_idx].priv;
    int len;
    PSP_Req_t *req = con->in.req;

    if (req) {
	/* tcp are configured non-blocking inside tcp_configure() */
	len = (int)readv(con->arch.tcp.con_fd,
			 req->u.req.iov, PSP_IOV_BUFFERS);
	if (len > 0) {
	    PSP_read_done(port, con, req, len);
	    return;
	}
    } else {
//	len = read(con->arch.tcp.con_fd,
//		   tmp_read_buf, sizeof(tmp_read_buf));
	len = (int)recv(con->arch.tcp.con_fd, tmp_read_buf,
			sizeof(tmp_read_buf), MSG_NOSIGNAL | MSG_DONTWAIT);
	if (len > 0) {
	    PSP_read_do(port, con, tmp_read_buf, len);
	    return;
	}
    }
    if (len == 0) {
	/* connection closed */
	goto err_con_closed;
    } else if ((errno != EINTR) && (errno != EAGAIN)) {
	goto err_con_broken;
    }

    return;
    /* --- */
    /* ToDo: */
 err_con_closed:
    PSP_con_terminate(port, con, PSP_TERMINATE_REASON_REMOTECLOSE);
    return;
    /* --- */
 err_con_broken:
    PSP_con_terminate(port, con, PSP_TERMINATE_REASON_READ_FAILED);
    return;
}

static
void _PSP_do_write_tcp(PSP_Port_t *port, PSP_Connection_t *con)
{
    PSP_Req_t *req = con->out.req;

    if (req) {
	int len;
//	len = writev(con->arch.tcp.con_fd,
//		     con->out.iov, con->out.count);
	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = req->u.req.iov;
	msg.msg_iovlen = PSP_IOV_BUFFERS;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;

	len = (int)sendmsg(con->arch.tcp.con_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);

	if (len > 0) {
	    PSP_write_done(port, con, req, len);
	} else if ((len < 0) &&
		   ((errno != EINTR) && (errno != EAGAIN)))
	    goto err_con_broken;
    }

    return;
    /* --- */
 err_con_broken:
    PSP_con_terminate(port, con, PSP_TERMINATE_REASON_WRITE_FAILED);
    return;
}

static
void PSP_do_write_tcp(ufd_t *ufd, int ufd_idx)
{
    PSP_Port_t *port = list_entry(ufd, PSP_Port_t, ufd);
    PSP_Connection_t *con = ufd->ufds_info[ufd_idx].priv;

    _PSP_do_write_tcp(port, con);

    return;
}

static
void PSP_set_write_tcp(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
    D_TR(printf("set Write %d tcp\n", start));
    if (start) {
	ufd_event_set(&port->ufd, con->arch.tcp.ufd_idx, POLLOUT);
	_PSP_do_write_tcp(port, con);
	/* Dont do anything after this line.
	   _PSP_do_write_tcp() can reenter PSP_set_write_tcp()! */
    } else
	ufd_event_clr(&port->ufd, con->arch.tcp.ufd_idx, POLLOUT);
}

static
void PSP_set_read_tcp(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
    D_TR(printf("set Read %d tcp\n", start));
    if (start)
	ufd_event_set(&port->ufd, con->arch.tcp.ufd_idx, POLLIN);
    else
	ufd_event_set(&port->ufd, con->arch.tcp.ufd_idx, POLLOUT);
}


static
void PSP_init_con_tcp(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    con->state = PSP_CON_STATE_OPEN_TCP;
    con->arch.tcp.con_fd = con_fd;

    ufd_add(&port->ufd, con_fd, PSP_do_read_tcp, PSP_do_write_tcp,
	    /* PSP_do_poll_tcp */NULL, &con->arch.tcp.ufd_idx, con);

    con->set_write = PSP_set_write_tcp;
    con->set_read = PSP_set_read_tcp;

}

void PSP_terminate_con_tcp(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.tcp.con_fd >= 0) {
	int con_fd = con->arch.tcp.con_fd;

	ufd_del(&port->ufd, con_fd);
	close(con_fd);

	con->arch.tcp.con_fd = -1;
    }
}

int PSP_connect_tcp(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_TCP;
    int ret;

    PSP_writeall(con_fd, &arch, sizeof(arch));
    ret = PSP_readall(con_fd, &arch, sizeof(arch));
    if ((ret != sizeof(arch)) || arch != PSP_ARCH_TCP)
	return 0;

    PSP_init_con_tcp(port, con, con_fd);

    return 1;
}

int PSP_accept_tcp(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_TCP;

    PSP_writeall(con_fd, &arch, sizeof(arch));

    PSP_init_con_tcp(port, con, con_fd);

    return 1;
}
