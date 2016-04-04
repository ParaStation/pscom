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

#include "pscom_priv.h"
#include "pscom_precon.h"
#include "pscom_con.h"
#include "pscom_p4s.h"


static
void p4s_register_conidx(p4s_sock_t *sock, pscom_con_t *con, int p4s_idx)
{
	if ((p4s_idx < 0) || p4s_idx > 30000) {
		fprintf(stderr, "internal error in pscom_p4s.c (idx %d) : %d\n", p4s_idx, __LINE__);
		exit(1);
	}
	unsigned int old_cnt = sock->p4s_conidx_cnt;
	unsigned int new_cnt = (p4s_idx + 1);

	if (old_cnt < new_cnt) {
		sock->p4s_conidx = realloc(sock->p4s_conidx,
					   sizeof(sock->p4s_conidx[0]) * new_cnt);

		// clear from (old) port->p4s_p4sconidx_cnt to p4s_idx + 1
		memset(&sock->p4s_conidx[old_cnt], 0,
		       sizeof(sock->p4s_conidx[0]) * (new_cnt - old_cnt));

		sock->p4s_conidx_cnt = new_cnt;
	}
	sock->p4s_conidx[p4s_idx] = con;
}


static
void p4s_unregister_conidx(p4s_sock_t *sock, pscom_con_t *con)
{
	int conidx = con->arch.p4s.p4s_con;

	if ((conidx < 0) || conidx >= sock->p4s_conidx_cnt) {
		DPRINT(0, "%s: conidx %d out of range", __func__, conidx);
		return;
	}
	if (sock->p4s_conidx[conidx] == con) {
		sock->p4s_conidx[conidx] = NULL;
	} else {
		DPRINT(0, "%s: conidx %d not found", __func__, conidx);
	}
}


static
pscom_con_t *p4s_get_con(p4s_sock_t *sock, int p4s_idx)
{
	if (((unsigned int)p4s_idx) >= (unsigned int)sock->p4s_conidx_cnt)
		return NULL;
	return sock->p4s_conidx[p4s_idx];
}


static inline
int p4s_recvmsg(int fd, struct iovec *iov, int iovlen, int flags, int *from)
{
	int ret;
	struct p4s_io_recv_iov_s rs;
	rs.Flags = flags;
	rs.iov = iov;
	rs.iov_len = iovlen;

	ret = ioctl(fd, P4S_IO_RECV_IOV, &rs);

	if ((ret >= 0) && from) {
		*from = rs.SrcNode;
	}

	return ret;
}


static inline
int p4s_recv(int fd, char *buf, int len, int flags, int *from)
{
	int ret;
	struct p4s_io_recv_s rs;
	rs.Flags = flags;
	rs.iov.iov_base = buf;
	rs.iov.iov_len = len;

	ret = ioctl(fd, P4S_IO_RECV, &rs);

	if ((ret >= 0) && from) {
		*from = rs.SrcNode;
	}

	return ret;
}

static inline
int p4s_sendmsg(int fd, int dest, struct iovec *iov, int iovlen, int flags)
{
	int ret;
	struct p4s_io_send_iov_s s;
	s.DestNode = dest;
	s.Flags = flags;
	s.iov = iov;
	s.iov_len = iovlen;

	ret = ioctl(fd, P4S_IO_SEND_IOV, &s);

	return ret;
}


static inline
int p4s_send(int fd, int dest, void *buf, size_t len, int flags)
{
	struct iovec iov;
	iov.iov_base = buf;
	iov.iov_len = len;

	return p4s_sendmsg(fd, dest, &iov, 1, flags);
}


// return 1 if we made progress
static
int _p4s_do_read(p4s_sock_t *sock, int flags)
{
	pscom_con_t *con = sock->recv_cur_con;
	ssize_t rlen;

	if (con) {
		char *buf;
		size_t len;

		pscom_read_get_buf(con, &buf, &len);

		int testfrom = 0;
		rlen = p4s_recv(sock->ufd_info.fd, buf, len, flags, &testfrom);

		if (rlen >= 0) {
			assert(sock->recv_cur_con_idx == testfrom);

			pscom_read_done(con, buf, rlen);
			if (pscom_read_is_at_message_start(con)) {
				// end of message reached
				sock->recv_cur_con = NULL;
			}
		} else if ((errno != EINTR) && (errno != EAGAIN)) {
			// end of message reached
			sock->recv_cur_con = NULL;
			goto err_con_broken;
		} else { //errno == EAGAIN
			return 0;
		}
	} else {
		int from = 0;
#define tmp_read_buf_p4s_size 128
		char tmp_read_buf_p4s[tmp_read_buf_p4s_size];

		/* Begin of new message */
		rlen = p4s_recv(sock->ufd_info.fd, tmp_read_buf_p4s, tmp_read_buf_p4s_size,
				flags, &from);

		if (rlen >= 0) {
			con = p4s_get_con(sock, from);

			if (con) {
				pscom_read_done(con, tmp_read_buf_p4s, rlen);

				if (!pscom_read_is_at_message_start(con)) {
					// read more from same connection
					sock->recv_cur_con = con;
					sock->recv_cur_con_idx = from;
				}
			} else {
				/* ignore unknown data */
				DPRINT(1, "_p4s_do_read() Ignore %d bytes from %d", (int)rlen, from);
			}
		} else if ((errno != EINTR) && (errno != EAGAIN)) {
			con = NULL; /* Error from unknown connection */
			goto err_con_broken;
		} else { //errno == EAGAIN
			return 0;
		}
	}
	return 1;
	/* --- */
err_con_broken:
	if (con) {
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
	} else {
		fprintf(stderr, "Internal error in unknown p4sock connection. Try to continue : %s\n",
			strerror(errno));
		sleep(1); /* Do not flood output in case of recursion */
	}
	return 0;
}


// return 0 if we would block on that connection
static
int _p4s_do_write(p4s_sock_t *sock, pscom_con_t *con)
{
	struct iovec iov[2];
	int p4s_idx = con->arch.p4s.p4s_con;
	pscom_req_t *req;
	ssize_t rlen = -1;

	req = pscom_write_get_iov(con, iov);

	if (req) {
		rlen = p4s_sendmsg(sock->ufd_info.fd, p4s_idx, iov, 2, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (rlen >= 0) {
			pscom_write_done(con, req, rlen);
		} else if ((errno != EINTR) && (errno != EAGAIN)) {
			goto err_con_broken;
		} else {
			return 0;
		}
	}
	return 1;
	/* --- */
err_con_broken:
	pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
	return 1;
}


static
void p4s_do_write(struct ufd_s *ufd, ufd_funcinfo_t *ufd_info)
{
	p4s_sock_t *sock = (p4s_sock_t *) ufd_info->priv;

	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &sock->con_sendq) {
		pscom_con_t *con = list_entry(pos, pscom_con_t, arch.p4s.con_sendq_next);
		int ok;

		ok = _p4s_do_write(sock, con);

		if (!ok) {
			/* Move the blocking connection to the end of the list: */
			list_del(&con->arch.p4s.con_sendq_next);
			list_add_tail(&con->arch.p4s.con_sendq_next, &sock->con_sendq);
		}
		break;
	}
}


static
void p4s_do_read(struct ufd_s *ufd, ufd_funcinfo_t *ufd_info)
{
	p4s_sock_t *sock = (p4s_sock_t *) ufd_info->priv;

	_p4s_do_read(sock, MSG_NOSIGNAL | MSG_DONTWAIT);
}


static
int p4s_do_poll(struct ufd_s *ufd, ufd_funcinfo_t *ufd_info, int timeout)
{
	p4s_sock_t *sock = (p4s_sock_t *) ufd_info->priv;

	int nonblocking = (timeout >= 0);

	if (list_empty(&sock->con_sendq)) {
		_p4s_do_read(sock, nonblocking * (MSG_NOSIGNAL | MSG_DONTWAIT));
		return 1; /* handled */
	} else {
		p4s_do_write(ufd, ufd_info); /* Non blocking send */

		if (_p4s_do_read(sock, MSG_NOSIGNAL | MSG_DONTWAIT)) {
			return 1; /* read something */
		}
	}

	/* fallback to poll ?*/
	return nonblocking || list_empty(&sock->con_sendq);
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
		nodeid = pscom_get_nodeid();
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
int p4s_open_socket(p4s_sock_t *sock)
{
	int i;
	int ret;
	unsigned int port = getpid();
	int fd = sock->ufd_info.fd;

#if P4S_ADDRLEN != 8
#error P4S_ADDRLEN changed
#endif

	if (fd >= 0) goto err_fd_inuse;

	fd = socket(PF_P4S , 0, 0);
	if (fd < 0) goto err_nosocket;

	ret=0;
	for(i = 0; i < 300; i++) {
		struct sockaddr_p4 sp4;
		struct sockaddr *sa = (struct sockaddr *)&sp4;
		char buf[sizeof(sp4.sp4_port) + 1];

		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "p4s%05u", port);
		memcpy(&sp4.sp4_port, buf, sizeof(sp4.sp4_port));

		sp4.sp4_family = PF_P4S;
		sp4.sp4_ra.type = P4REMADDR_PSID;
		sp4.sp4_ra.tec.psid.psid = p4s_node_id();

		ret = bind(fd, sa, sizeof(sp4));

		memcpy(&sock->p4s_sockaddr, &sp4, sizeof(sock->p4s_sockaddr));
		if (!ret) {
			break; /* Bind ok */
		}
		/* try another port */
		port = (port + 1) % 100000;
	}

	if (ret) goto err_bind;

	sock->ufd_info.fd = fd;

	return 0; /* OK */
	/* --- */
err_bind:
	if (fd >= 0) close(fd);
err_nosocket:
err_fd_inuse:
	return -1;
}


/* increment the usecount of the p4sock fd.
   If this is the first user, open a port.
   return -1 on error */
static
int p4s_inc_usecnt(p4s_sock_t *sock)
{
	if (sock->ufd_info.fd < 0) {
		if (p4s_open_socket(sock) < 0) return -1; /* no fd */

		ufd_add(&pscom.ufd, &sock->ufd_info);
	}

	sock->users++;

	return 0;
}


static
void p4s_dec_usecnt(p4s_sock_t *sock)
{
	if (sock->ufd_info.fd < 0) return; /* nothing to do */

	sock->users--;

	if (sock->users <= 0) {
		ufd_del(&pscom.ufd, &sock->ufd_info);
		close(sock->ufd_info.fd);
		sock->ufd_info.fd = -1;
		sock->users = 0;
	}
}


// read one byte from a new connectino. return new connection index.
// this is a workaround for the missing accept call in p4sock
static
int p4s_recv_ack(p4s_sock_t *sock)
{
	int len;
	char ack = 0;
	int from;
	pscom_con_t *con;

	while (1) {
		len = p4s_recv(sock->ufd_info.fd, &ack, sizeof(ack), 0, &from);

		if (len < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			else
				return -1;
		}

		con = p4s_get_con(sock, from);
		if (con) {
			/* Data from different connection... */
			pscom_read_done(con, &ack, len);
		} else {
			/* Thats the new connection */
			return from;
		}
	}
}


// see p4s_recv_ack
static
void p4s_send_ack(p4s_sock_t *sock, int p4s_con)
{
	int len;
	char ack = 0;

	while (1) {
		len = p4s_send(sock->ufd_info.fd, p4s_con, &ack, sizeof(ack), 0);
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


static
void p4s_write_start(pscom_con_t *con)
{
	p4s_sock_t *sock = &get_sock(con->pub.socket)->p4s;
	D_TR(printf("write start p4s\n"));

	if (list_empty(&con->arch.p4s.con_sendq_next)) {
		list_add_tail(&con->arch.p4s.con_sendq_next, &sock->con_sendq);
		ufd_event_set(&pscom.ufd, &sock->ufd_info, POLLOUT);
	}

	_p4s_do_write(sock, con);
	/* Dont do anything after this line.
	   _p4s_do_write() can reenter p4s_write_start! */
}


static
void p4s_write_stop(pscom_con_t *con)
{
	if (!list_empty(&con->arch.p4s.con_sendq_next)) {
		p4s_sock_t *sock = &get_sock(con->pub.socket)->p4s;

		list_del_init(&con->arch.p4s.con_sendq_next);

		if (list_empty(&sock->con_sendq)) {
			ufd_event_clr(&pscom.ufd, &sock->ufd_info, POLLOUT);
		}
	}
}


static
void p4s_read_start(pscom_con_t *con)
{
	D_TR(printf("read start p4s (p4s.reading:%d)\n", con->arch.p4s.reading));
	if (!con->arch.p4s.reading) {
		p4s_sock_t *sock = &get_sock(con->pub.socket)->p4s;

		con->arch.p4s.reading = 1;
		if (!sock->readers) {
			ufd_event_set(&pscom.ufd, &sock->ufd_info, POLLIN);
		}
		sock->readers++;
	}
}


static
void p4s_read_stop(pscom_con_t *con)
{
	D_TR(printf("read stop p4s\n"));
	if (con->arch.p4s.reading) {
		p4s_sock_t *sock = &get_sock(con->pub.socket)->p4s;

		con->arch.p4s.reading = 0;
		sock->readers--;
		if (sock->readers <= 0) {
			ufd_event_clr(&pscom.ufd, &sock->ufd_info, POLLIN);
			sock->readers = 0; // should be useless
		}
	}
}


static
void p4s_close(pscom_con_t *con)
{
	if (con->arch.p4s.p4s_con != -1) {
		p4s_sock_t *sock = &get_sock(con->pub.socket)->p4s;
		int rc;

		rc = ioctl(sock->ufd_info.fd, P4_CLOSE_CON, (long)con->arch.p4s.p4s_con);
		if (rc) {
			DPRINT(0, "Close connection to %s : %s",
			       pscom_con_info_str(&con->pub.remote_con_info),
			       strerror(errno));
		}
		p4s_unregister_conidx(sock, con);

		p4s_dec_usecnt(sock);

		con->arch.p4s.p4s_con = -1;

		assert(list_empty(&con->arch.p4s.con_sendq_next));
		assert(!con->arch.p4s.reading);
	}
}


typedef struct p4s_info_msg_s {
	struct sockaddr_p4 p4s_sockaddr;
} p4s_info_msg_t;


static
void p4s_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_P4S;

	INIT_LIST_HEAD(&con->arch.p4s.con_sendq_next);

	con->write_start = p4s_write_start;
	con->write_stop = p4s_write_stop;
	con->read_start = p4s_read_start;
	con->read_stop = p4s_read_stop;
	con->close = p4s_close;

	con->arch.p4s.reading = 0;

	pscom_con_setup_ok(con);
}


static
void p4s_init(p4s_sock_t *sock)
{
	memset(sock, 0, sizeof(*sock));

	sock->ufd_info.fd = -1;
	sock->ufd_info.can_read = p4s_do_read;
	sock->ufd_info.can_write = p4s_do_write;
	sock->ufd_info.poll = p4s_do_poll;
	sock->ufd_info.priv = sock;
	sock->users = 0;
	sock->readers = 0;
	sock->p4s_conidx = NULL;
	sock->p4s_conidx_cnt = 0;
	INIT_LIST_HEAD(&sock->con_sendq);
	sock->recv_cur_con = NULL;
	sock->recv_cur_con_idx = -1;
}

/****************************************************************/
static
int pscom_p4s_open(p4s_sock_t *sock, pscom_con_t *con)
{
	con->arch.p4s.p4s_con = -1;

	if (!p4s_available()) return -1;
	if (p4s_inc_usecnt(sock) < 0) {
		DPRINT(2, "p4s_open_socket() : %s", strerror(errno));
		return -1;
	}

	return 0;
}


static
void pscom_p4s_cleanup(pscom_con_t *con)
{
	if (con->arch.p4s.p4s_con >= 0) {
		p4s_close(con);
	}
}


static
void pscom_p4s_get_info(p4s_sock_t *sock, p4s_info_msg_t *msg)
{
	memcpy(&msg->p4s_sockaddr, &sock->p4s_sockaddr, sizeof(msg->p4s_sockaddr));
}


static
void pscom_p4s_sock_init(pscom_sock_t *socket)
{
	p4s_init(&socket->p4s);
}


static
int pscom_p4s_con_init(pscom_con_t *con)
{
	return p4s_available() ? 0 : -1;
}


#define PSCOM_INFO_P4S_ADDR PSCOM_INFO_ARCH_STEP1


static
void pscom_p4s_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	p4s_sock_t *sock = &get_sock(con->pub.socket)->p4s;

	switch (type) {
	case PSCOM_INFO_ARCH_REQ:
		if (pscom_p4s_open(sock, con)) goto error_p4s_open;

		if (con->pub.state & PSCOM_CON_STATE_CONNECTING) {
			// Send my address
			p4s_info_msg_t msg;
			pscom_p4s_get_info(sock, &msg);
			pscom_precon_send(con->precon, PSCOM_INFO_P4S_ADDR, &msg, sizeof(msg));
		}
		break;
	case PSCOM_INFO_P4S_ADDR: {
		p4s_info_msg_t *msg = data;
		assert(sizeof(*msg) == size);

		// connect
		int p4s_con = connect(sock->ufd_info.fd, (struct sockaddr *)&msg->p4s_sockaddr,
				      sizeof(msg->p4s_sockaddr));
		if (p4s_con < 0) {
			DPRINT(2, "connect() failed : %s", strerror(errno));
			goto error_connect;
		}

		con->arch.p4s.p4s_con = p4s_con;
		p4s_register_conidx(sock, con, p4s_con);

		/* Send ACK over p4sock */
		p4s_send_ack(sock, p4s_con);

		pscom_precon_send(con->precon, PSCOM_INFO_ARCH_OK, NULL, 0);
		pscom_precon_close(con->precon);
		break; /* Next is INFO_EOF */
	}
	case PSCOM_INFO_ARCH_OK: {
		int p4s_con = p4s_recv_ack(sock);

		con->arch.p4s.p4s_con = p4s_con;
		p4s_register_conidx(sock, con, p4s_con);

		if (p4s_con < 0) {
			/* ToDo: Cleanup? */
			DPRINT(0, "__func__(): %s", strerror(errno));
		}

		break; /* Next is INFO_EOF */
	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Cleanup con */
		pscom_p4s_cleanup(con);
		break; /* Done (this one failed) */
	case PSCOM_INFO_EOF:
		p4s_init_con(con);
		break; /* Done (use this one) */
	}

	return;
	/* --- */
error_p4s_open:
error_connect:
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
}


pscom_plugin_t pscom_plugin_p4s = {
	.name		= "p4s",
	.arch_id	= PSCOM_ARCH_P4S,
	.priority	= PSCOM_P4S_PRIO,

	.init		= NULL,
	.destroy	= NULL,
	.sock_init	= pscom_p4s_sock_init,
	.sock_destroy	= NULL,
	.con_init	= pscom_p4s_con_init,
	.con_handshake	= pscom_p4s_handshake,
};
