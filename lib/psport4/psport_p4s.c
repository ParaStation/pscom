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
 * psport_p4s.c: p4sock communication
 */

#ifdef P4S_IOC_MAGIC
static char info_p4sock[] __attribute__(( unused )) =
"$Info: with 32bit emulation on 64bit arch $";
#endif

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <assert.h>

#include "psport_priv.h"
#include "psport_p4s.h"

static
void p4s_register_conidx(PSP_Port_t *port, PSP_Connection_t *con, int p4s_idx)
{
    if ((p4s_idx < 0) || p4s_idx > 30000) {
	fprintf(stderr, "internal error in psport_p4s (idx %d):%d\n", p4s_idx, __LINE__);
	exit(1);
    }
    if (p4s_idx >= port->p4s_p4sconidx_cnt) {
	port->p4s_conidx = realloc(port->p4s_conidx,
				   sizeof(port->p4s_conidx[0]) * (p4s_idx + 1));
	memset(&port->p4s_conidx[port->p4s_p4sconidx_cnt], 0,
	       sizeof(port->p4s_conidx[0]) * (p4s_idx - port->p4s_p4sconidx_cnt));
	port->p4s_p4sconidx_cnt = (p4s_idx + 1);
    }
    port->p4s_conidx[p4s_idx] = con;
}

static
void p4s_unregister_conidx(PSP_Port_t *port, PSP_Connection_t *con)
{
    int conidx = con->arch.p4s.p4s_con;
    if ((conidx < 0) || conidx >= port->p4s_p4sconidx_cnt) {
	DPRINT(0, "%s: conidx %d out of range", __func__, conidx);
	return;
    }
    if (port->p4s_conidx[conidx] == con) {
	port->p4s_conidx[conidx] = NULL;
    } else {
	DPRINT(0, "%s: conidx %d not found", __func__, conidx);
    }
}

static
PSP_Connection_t *p4s_get_con(PSP_Port_t *port, int p4s_idx)
{
    if (((unsigned int)p4s_idx) >= (unsigned int)port->p4s_p4sconidx_cnt)
	return NULL;
    return port->p4s_conidx[p4s_idx];
}

static inline
int psp_recvmsg(int fd, struct iovec *iov, int iovlen, int flags, int *from)
{
    int ret;
    struct p4s_io_recv_iov_s rs;
    rs.Flags = (uint16_t)flags;
    rs.iov = iov;
    rs.iov_len = (uint16_t)iovlen;
    ret = ioctl(fd, P4S_IO_RECV_IOV, &rs);
    if ((ret >= 0) && from) {
	*from = rs.SrcNode;
    }

    return ret;
}

static inline
int psp_recv(int fd, char *buf, int len, int flags, int *from)
{
    int ret;
    struct p4s_io_recv_s rs;
    rs.Flags = (uint16_t)flags;
    rs.iov.iov_base = buf;
    rs.iov.iov_len = len;

//    perf_add(" p4s recvs");
    ret = ioctl(fd, P4S_IO_RECV, &rs);
//    perf_add(" p4s recve");

    if ((ret >= 0) && from) {
	*from = rs.SrcNode;
    }

    return ret;
}

static inline
int psp_sendmsg(int fd, int dest, struct iovec *iov, int iovlen, int flags)
{
    int ret;
    struct p4s_io_send_iov_s s;
    s.DestNode = (uint16_t)dest;
    s.Flags = (uint16_t)flags;
    s.iov = iov;
    s.iov_len = (uint16_t)iovlen;

//    perf_add(" p4s sends");
    ret = ioctl(fd, P4S_IO_SEND_IOV, &s);
//    perf_add(" p4s sende");
    return ret;
}

#define tmp_read_buf_p4s_size 128
static
char *tmp_read_buf_p4s = NULL;//[tmp_read_buf_p4s_size];

static int _p4s_do_read(PSP_Port_t *port, int flags)
{
    PSP_Connection_t *con = port->p4s_cur_recv;
    PSP_Req_t *req;

    if (con && ((req = con->in.req))) {
	int len = psp_recvmsg(port->p4s_fd, req->u.req.iov,
			      PSP_IOV_BUFFERS, flags, NULL);
	if (len > 0) {
	    PSP_read_done(port, con, req, len);
	    if (!con->in.req)
		port->p4s_cur_recv = NULL;
	    return 1;
	} else if (len == 0) {
	    /* connection closed */
	    goto err_con_closed;
	} else if ((errno != EINTR) && (errno != EAGAIN)) {
	    goto err_con_broken;
	}
    } else {
	/* Begin of new message */
	int from = 0;
	int len = psp_recv(port->p4s_fd, tmp_read_buf_p4s, tmp_read_buf_p4s_size,
			   flags, &from);
	if (len > 0) {
	    con = p4s_get_con(port, from);

	    if (con) {
		PSP_read_do(port, con, tmp_read_buf_p4s, len);
		if (con->in.req)
		    port->p4s_cur_recv = con;
		return 1;
	    } else {
		/* Just ignore ... */
		DPRINT(1, "p4s_do_read() Ignore %d bytes from %d", len, from);
	    }
	} else if (len == 0) {
	    /* connection closed */
	    con = p4s_get_con(port, from);
	    goto err_con_closed;
	} else if ((errno != EINTR) && (errno != EAGAIN)) {
	    con = NULL; /* Error from unknown connection */
	    goto err_con_broken;
	}
    }
    return 0; /* Nothing read */
    /* --- */
 err_con_closed:
    if (con) {
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_REMOTECLOSE);
    } else {
	DPRINT(0, "%s: ERROR ERROR ERROR ERROR ERROR ERROR ERROR", __func__);
	sleep(1);
    }
    return 0;
    /* --- */
 err_con_broken:
    if (con) {
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_READ_FAILED);
    } else {
	fprintf(stderr, "Internal error in unknown p4sock connection. Try to continue : %s\n",
		strerror(errno));
	sleep(1); /* Do not flood output in case of recursion */
    }
    return 0;
}

static
int _p4s_do_write(PSP_Port_t *port, PSP_Connection_t *con)
{
    PSP_Req_t *req = con->out.req;
    int p4s_idx = con->arch.p4s.p4s_con;
    int len;

    assert(req);

    /* ToDo: iovbuf always equal 2 ? */
    len = psp_sendmsg(port->p4s_fd, p4s_idx, req->u.req.iov, 2/* PSP_IOV_BUFFERS*/,
		      MSG_NOSIGNAL | MSG_DONTWAIT);

    if (len > 0) {
	PSP_write_done(port, con, req, len);
    }
    return len;
}

static void p4s_do_write(struct ufd_s *ufd, int ufd_idx)
{
    PSP_Port_t *port = list_entry(ufd, PSP_Port_t, ufd);

    struct list_head *pos, *next;

    list_for_each_safe(pos, next, &port->p4s_con_sendq) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.p4s.sendq);
	int len;

	len = _p4s_do_write(port, con);

	if (len <= 0) {
	    /* Move the blocking connection to the end of the list: */
	    list_del(&con->arch.p4s.sendq);
	    list_add_tail(&con->arch.p4s.sendq, &port->p4s_con_sendq);
	    break;
	}
    }
}

static void p4s_do_read(struct ufd_s *ufd, int ufd_idx)
{
    PSP_Port_t *port = list_entry(ufd, PSP_Port_t, ufd);
    _p4s_do_read(port, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static int p4s_do_poll(struct ufd_s *ufd, int ufd_idx, int timeout)
{
    PSP_Port_t *port = list_entry(ufd, PSP_Port_t, ufd);
    int nonblocking = (timeout >= 0);

    if (list_empty(&port->p4s_con_sendq)) {

	_p4s_do_read(port, nonblocking * (MSG_NOSIGNAL | MSG_DONTWAIT));

	return 1; /* handled */
    } else {

	p4s_do_write(ufd, ufd_idx); /* Non blocking send */

	if (_p4s_do_read(port, MSG_NOSIGNAL | MSG_DONTWAIT)) {
	    return 1; /* read something */
	}

	/* fallback to poll ?*/
	return nonblocking || list_empty(&port->p4s_con_sendq);
    }
}

static void p4s_set_write(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
    D_TR(printf("set Write %d p4s\n", start));

    if (start) {
	if (list_empty(&con->arch.p4s.sendq)) {
	    list_add_tail(&con->arch.p4s.sendq, &port->p4s_con_sendq);
	    ufd_event_set(&port->ufd, port->p4s_ufd_idx, POLLOUT);
	}
	_p4s_do_write(port, con); /* Try sending now! */
	/* Dont do anything after this line.
	   _p4s_do_write() can reenter p4s_set_write! */
    } else {
	if (!list_empty(&con->arch.p4s.sendq)) {
	    list_del_init(&con->arch.p4s.sendq);
	    if (list_empty(&port->p4s_con_sendq)) {
		ufd_event_clr(&port->ufd, port->p4s_ufd_idx, POLLOUT);
	    }
	}
    }
}


static
int p4s_node_id(void)
{
    static int initialized = 0;
    static int nodeid = P4_NODE_ID_UNDEF;
    int fd;
    int ret;

    if (initialized) goto out;

    /* Ask the socket layer */
    fd = socket(PF_P4S , 0, 0);
    if (fd < 0) goto out;

    bind(fd, NULL, 0); /* hack: init compat_ioctl */

    ret = ioctl(fd, P4_GETNODEID);
    if (ret < 0) goto out;

    close(fd);

    if (ret == P4_NODE_ID_UNDEF) {
	nodeid = PSP_GetNodeID();
    } else {
	nodeid = ret;
    }
 out:
    initialized = 1;
    return nodeid;
}

static
int p4s_available(void)
{
    return p4s_node_id() != P4_NODE_ID_UNDEF;
}

static
int p4s_open_port(PSP_Port_t *port)
{
    int i;
    int ret;
#if P4S_ADDRLEN != 8
#error P4S_ADDRLEN changed
#endif

    if (port->p4s_fd >= 0) goto err_fd_inuse;

    port->p4s_fd = socket(PF_P4S , 0, 0);
    if (port->p4s_fd < 0) goto err_nosocket;

    srandom(getpid());

    ret=0;
    for(i = 0; i < 300; i++) {
	struct sockaddr_p4 sp4;
	struct sockaddr *sa = (struct sockaddr *)&sp4;
	char buf[16];
	snprintf(buf, sizeof(buf),
		 "psp2%04u", (unsigned int)random());
	memcpy(&sp4.sp4_port, buf, 8);

	sp4.sp4_family = PF_P4S;
	sp4.sp4_ra.type = P4REMADDR_PSID;
	sp4.sp4_ra.tec.psid.psid = p4s_node_id();

	ret = bind(port->p4s_fd, sa, sizeof(sp4));

	memcpy(&port->p4s_sockaddr, &sp4, sizeof(port->p4s_sockaddr));
	if (!ret) {
	    break; /* Bind ok */
	}
	/* try another port */
    }

    if (ret) goto err_bind;

    return 0; /* OK */
    /* --- */
 err_fd_inuse:
 err_bind:
 err_nosocket:
    if (port->p4s_fd >= 0) {
	close(port->p4s_fd);
	port->p4s_fd = -1;
    }
    return -1;
}


void p4s_init(PSP_Port_t *port)
{
    port->p4s_fd = -1;
    port->p4s_users = 0;
    port->p4s_ufd_idx = -1;
/*    port->p4s_sockaddr;*/
    port->p4s_p4sconidx_cnt = 0;
    port->p4s_conidx = NULL;
    port->p4s_cur_recv = NULL;
    INIT_LIST_HEAD(&port->p4s_con_sendq);

    if (!tmp_read_buf_p4s)
	tmp_read_buf_p4s = malloc(tmp_read_buf_p4s_size);
}

/* increment the usecount of the p4sock fd.
   If this is the first user, open a port.
   return -1 on error */
static
int p4s_inc_usecnt(PSP_Port_t *port)
{
    if (port->p4s_fd < 0) {
	if (p4s_open_port(port) < 0) return -1; /* no fd */
	ufd_add(&port->ufd, port->p4s_fd,
		p4s_do_read, p4s_do_write, p4s_do_poll,
		&port->p4s_ufd_idx, NULL);
	ufd_event_set(&port->ufd, port->p4s_ufd_idx, POLLIN);
    }

    port->p4s_users++;

    return 0;
}

static
void p4s_dec_usecnt(PSP_Port_t *port)
{
    if (port->p4s_fd <= 0) return; /* nothing to do */

    port->p4s_users--;

    if (port->p4s_users <= 0) {
	ufd_del(&port->ufd, port->p4s_fd);
	close(port->p4s_fd);
	port->p4s_fd = -1;
	port->p4s_users = 0;
    }
}

int p4s_recv_ack(PSP_Port_t *port)
{
    int len;
    char ack = 0;
    struct iovec iov[1];
    int from;
    PSP_Connection_t *con;

    iov[0].iov_base = &ack;
    iov[0].iov_len = 1;

    while (1) {
	len = psp_recvmsg(port->p4s_fd, iov, 1, 0, &from);
	if (len < 0) {
	    if ((errno == EINTR) || (errno == EAGAIN))
		continue;
	    else
		return -1;
	}

	con = p4s_get_con(port, from);
	if (con) {
	    /* Data from different connection... */
	    PSP_read_do(port, con, &ack, len);
//	    DPRINT(1, "p4s_recv_ack() read %d byte from %d", len, from);
	} else {
	    /* Thats the new connection */
	    return from;
	}
    }
}

void p4s_send_ack(PSP_Port_t *port, int p4s_con)
{
    int len;
    char ack = 0;
    struct iovec iov[1];

    iov[0].iov_base = &ack;
    iov[0].iov_len = 1;

    while (1) {
	len = psp_sendmsg(port->p4s_fd, p4s_con, iov, 1, 0);
	if (len < 0) {
	    if ((errno == EINTR) || (errno == EAGAIN))
		continue;
	    else {
		DPRINT(1, "p4s_send_ack() failed");
		return;
	    }
	} else
	    break;
    };
}

typedef struct p4s_info_msg_s {
    struct sockaddr_p4 p4s_sockaddr;
} p4s_info_msg_t;

void PSP_init_con_p4s(PSP_Port_t *port, PSP_Connection_t *con,
		      int con_fd, int p4s_con)
{
    p4s_register_conidx(port, con, p4s_con);

    con->state = PSP_CON_STATE_OPEN_P4S;
    close(con_fd);

    con->arch.p4s.p4s_con = p4s_con;

    INIT_LIST_HEAD(&con->arch.p4s.sendq);

    con->set_write = p4s_set_write;
    /* ToDo: set_read and  */
//    con->set_read = xxx;
}

#define INET_ADDR_FORMAT "%u.%u.%u.%u"
#define INET_ADDR_SPLIT(addr) ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >>  8) & 0xff, (addr) & 0xff

void PSP_terminate_con_p4s(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.p4s.p4s_con != -1) {
	int ret;

	ret = ioctl(port->p4s_fd, P4_CLOSE_CON, (long)con->arch.p4s.p4s_con);
	if (ret) {
	    DPRINT(0, "Close connection to (%x,%d,%d): %s",
		   con->remote_con_info.node_id, con->remote_con_info.pid,
		   con->remote_con_info.con_idx, strerror(errno));
	}
	p4s_unregister_conidx(port, con);

	p4s_dec_usecnt(port);

	con->arch.p4s.p4s_con = -1;
    }
}

int PSP_connect_p4s(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_P4S;
    p4s_info_msg_t msg;
    int p4s_con;

    if ((!env_p4sock) || !p4s_available())
	return 0; /* Dont use p4sock */

    /* We want talk p4s */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 1 */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_P4S))
	goto err_remote;

    /* step 2 : recv my address */
    if (PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg))
	goto err_remote;

    if (p4s_inc_usecnt(port) < 0) goto err_local;

    p4s_con = connect(port->p4s_fd, (struct sockaddr *)&msg.p4s_sockaddr,
		      sizeof(msg.p4s_sockaddr));
    if (p4s_con < 0)
	goto err_local_connect;

    /* step 3: p4s initialized. Send final ACK. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* Send ACK over p4sock */
    p4s_send_ack(port, p4s_con);

    D_TR(printf("Send ACK for p4s %d\n", p4s_con));
    PSP_init_con_p4s(port, con, con_fd, p4s_con);

    return 1;
    /* --- */
 err_local_connect:
    p4s_dec_usecnt(port);
 err_local:
 err_remote:
    return 0;
}


int PSP_accept_p4s(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_P4S;
    p4s_info_msg_t msg;
    int p4s_con;

    if ((!env_p4sock) || !p4s_available() ||
	(p4s_inc_usecnt(port) < 0)) {
	arch = PSP_ARCH_ERROR;
	PSP_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use p4sock */
    }

    /* step 1:  Yes, we talk p4sock. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send my address. */
    memcpy(&msg.p4s_sockaddr, &port->p4s_sockaddr, sizeof(msg.p4s_sockaddr));
    PSP_writeall(con_fd, &msg, sizeof(msg));

    /* step 3: recv final ACK. */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_P4S)) goto err_remote;

    p4s_con = p4s_recv_ack(port);

    D_TR(printf("Recv ACK from p4s %d\n", p4s_con));
    /* At this time the p4s_con id is unknown */
    if (p4s_con >= 0) /* ToDo: Handle error */
	PSP_init_con_p4s(port, con, con_fd, p4s_con);

    return 1;
    /* --- */
 err_remote:
    p4s_dec_usecnt(port);
    return 0; /* shm failed */
    /* --- */
}
