/*
 * ParaStation
 *
 * Copyright (C) 2011 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#include "pscom_priv.h"
#include "pscom_precon.h"
#include "pscom_str_util.h"
#include "pscom_con.h"
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>


typedef struct {
	/* supported version range from sender,
	   overlap must be non empty. */
	uint32_t	ver_from;
	uint32_t	ver_to;
} pscom_info_version_t;

#define VER_FROM 0x0200
#define VER_TO   0x0200

static unsigned pscom_precon_count = 0;

static void pscom_precon_recv_stop(precon_t *pre);
static void pscom_precon_check_end(precon_t *pre);


static
const char *pscom_info_type_str(int type)
{
	switch (type) {
	case PSCOM_INFO_FD_EOF:		return "FD_EOF";
	case PSCOM_INFO_FD_ERROR:	return "FD_ERROR";
	case PSCOM_INFO_EOF:		return "EOF";
		//case PSCOM_INFO_ANSWER:		return "ANSWER";
	case PSCOM_INFO_CON_INFO:	return "CON_INFO";
	case PSCOM_INFO_CON_INFO_DEMAND:return "CON_INFO_DEMAND";
	case PSCOM_INFO_VERSION:	return "VERSION";
	case PSCOM_INFO_BACK_CONNECT:	return "BACK_CONNECT";
	case PSCOM_INFO_BACK_ACK:	return "BACK_ACK";
	case PSCOM_INFO_ARCH_REQ:	return "ARCH_REQ";
	case PSCOM_INFO_ARCH_OK:	return "ARCH_OK";
	case PSCOM_INFO_ARCH_NEXT:	return "ARCH_NEXT";
	case PSCOM_INFO_ARCH_STEP1:	return "ARCH_STEP1";
	case PSCOM_INFO_ARCH_STEP2:	return "ARCH_STEP2";
	case PSCOM_INFO_ARCH_STEP3:	return "ARCH_STEP3";
	case PSCOM_INFO_ARCH_STEP4:	return "ARCH_STEP4";
	default: {
		static char res[80];
		snprintf(res, sizeof(res), "#%d", type);
		return res;
	}
	}
}

static
void pscom_precon_info_dump(void *pre, char *op, int type, void *data, unsigned size)
{
	switch (type) {
	case PSCOM_INFO_FD_ERROR: {
		int noerr = 0;
		int *err = size == sizeof(int) && data ? data : &noerr;
		DPRINT(PRECON_LL, "precon(%p):%s: %s\t%d(%s)", pre, op,
		       pscom_info_type_str(type), *err, strerror(*err));
		break;
	}
	case PSCOM_INFO_ARCH_REQ: {
		pscom_info_arch_req_t *arch_req = data;
		DPRINT(PRECON_LL, "precon(%p):%s: %s\tarch_id:%u (%s)", pre, op,
		       pscom_info_type_str(type),
		       arch_req->arch_id,
		       pscom_con_type_str(PSCOM_ARCH2CON_TYPE(arch_req->arch_id)));
		break;
	}
	case PSCOM_INFO_BACK_CONNECT:
	case PSCOM_INFO_CON_INFO_DEMAND:
	case PSCOM_INFO_CON_INFO: {
		pscom_info_con_info_t *msg = data;
		DPRINT(PRECON_LL, "precon(%p):%s: %s\tcon_info:%s", pre, op,
		       pscom_info_type_str(type),
		       pscom_con_info_str(&msg->con_info));
		break;
	}
	case PSCOM_INFO_VERSION: {
		pscom_info_version_t *version = data;
		DPRINT(PRECON_LL, "precon(%p):%s: %s\tver_from:%04x ver_to:%04x", pre, op,
		       pscom_info_type_str(type),
		       version->ver_from, version->ver_to);
		break;
	}
	default:
		DPRINT(PRECON_LL, "precon(%p):%s: %s\t%p %u", pre, op,
		       pscom_info_type_str(type), data, size);
	}
}


static
void pscom_precon_print_stat(precon_t *pre)
{
	int fd = pre->ufd_info.fd;
	char state[10] = "no fd";
	assert(pre->magic == MAGIC_PRECON);

	if (fd != -1) {
		struct pollfd *pollfd = ufd_get_pollfd(&pscom.ufd, &pre->ufd_info);
		if (pollfd) {
			state[0] = pollfd->events & POLLIN ? 'R' : '_';
			state[1] = pollfd->events & POLLOUT ? 'W' : '_';
			state[3] = 0;
		} else {
			strcpy(state, "no poll");
		}
	}
	DPRINT(PRECON_LL, "precon(%p): #%u send:%zu recv:%zu to_send:%u recv:%s active:%u state:%s\n",
	       pre, pre->stat_poll_cnt, pre->stat_send, pre->stat_recv,
	       pre->send_len, pre->recv_done ? "no" : "yes", pscom_precon_count, state);
}


// return true, if err indicate an temporary error and it make sense to retry later.
static
int retry_on_error(int err)
{
	switch (err) {
	case ECONNREFUSED:
	case ECONNRESET:
	case ECONNABORTED:
	case ENETRESET:
	case ETIMEDOUT:
		return 1;
	}
	return 0;
}

/*
 * Helpers for sockets
 */
static
int mtry_connect(int sockfd, const struct sockaddr *serv_addr,
		 socklen_t addrlen, void *debug_id)
{
	/* In the case the backlog (listen) is smaller than the number of
	   processes, the connect could fail with ECONNREFUSED even though
	   there is a linstening socket. mtry_connect() retry four times
	   the connect after one second delay.
	*/
	unsigned int i;
	int ret = 0;
	struct sockaddr_in *sa = (struct sockaddr_in*)serv_addr;
	for (i = 0; i < pscom.env.retry; i++) {
		ret = connect(sockfd, serv_addr, addrlen);
		DPRINT(PRECON_LL, "precon(%p): connect(%d,\"%s:%u\") = %d (%s)",
		       debug_id, sockfd, pscom_inetstr(ntohl(sa->sin_addr.s_addr)),
		       ntohs(sa->sin_port), ret, ret ? strerror(errno) : "ok");
		if (ret >= 0) break;
		if (!retry_on_error(errno)) break;
		sleep(1);
		DPRINT(2, "Retry %d CONNECT to %s:%d",
		       i + 1,
		       pscom_inetstr(ntohl(sa->sin_addr.s_addr)),
		       ntohs(sa->sin_port));
	}
	return ret;
}


static
void tcp_configure(int fd)
{
	int ret;
	int val;

	if (pscom.env.so_sndbuf) {
		val = pscom.env.so_sndbuf;
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
		DPRINT(2, "setsockopt(%d, SOL_SOCKET, SO_SNDBUF, [%d], %ld) = %d : %s",
		       fd, val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");
	}
	if (pscom.env.so_rcvbuf) {
		val = pscom.env.so_rcvbuf;
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
		DPRINT(2, "setsockopt(%d, SOL_SOCKET, SO_RCVBUF, [%d], %ld) = %d : %s",
		       fd, val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");
	}
	val = pscom.env.tcp_nodelay;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	DPRINT(2, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY, [%d], %ld) = %d : %s",
	       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

	if (1) { // Set keep alive options.
		val = 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
		DPRINT(ret ? 2 : 5, "setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

		// Overwrite defaults from "/proc/sys/net/ipv4/tcp_keepalive*"

		val = 20; /* Number of keepalives before death */
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
		DPRINT(ret ? 2 : 5, "setsockopt(%d, SOL_TCP, TCP_KEEPCNT, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

		val = 5; /* Start keeplives after this period */
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
		DPRINT(ret ? 2 : 5, "setsockopt(%d, SOL_TCP, TCP_KEEPIDLE, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

		val = 4; /* Interval between keepalives */
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
		DPRINT(ret ? 2 : 5, "setsockopt(%d, SOL_TCP, TCP_KEEPINTVL, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");
	}

}


static
void pscom_sockaddr_init(struct sockaddr_in *si, int nodeid, int portno)
{
	/* Setup si for TCP */
	si->sin_family = PF_INET;
	si->sin_port = htons(portno);
	si->sin_addr.s_addr = htonl(nodeid);
}


static
int _pscom_tcp_connect(int nodeid, int portno, void *debug_id)
{
	struct sockaddr_in si;
	int rc;
	int optval;

	/* Open the socket */
	int fd = socket(PF_INET , SOCK_STREAM, 0);
	if (fd < 0) goto err_socket;

	/* Try a nonblocking connect. Ignoring fcntl errors and use blocking connect in this case. */
	fcntl(fd, F_SETFL, O_NONBLOCK);

	/* Close on exec. Ignore errors. */
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	/* Enable keep alive. Ignore errors. */
	optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

	pscom_sockaddr_init(&si, nodeid, portno);

	/* Connect */
	rc = mtry_connect(fd, (struct sockaddr*)&si, sizeof(si), debug_id);
	if (rc < 0 && errno != EINPROGRESS) goto err_connect;

	return fd;
	/* --- */
err_connect:
	close(fd);
err_socket:
	return -1;
}


static
void plugin_connect_next(pscom_con_t *con, int first)
{
	precon_t *pre = con->precon;
	pscom_sock_t *sock = get_sock(con->pub.socket);
	assert(pre->magic == MAGIC_PRECON);
	assert(con->magic == MAGIC_CONNECTION);
	assert(first ? !pre->plugin : 1); // if first, pre->plugin has to be NULL!

	do {
		pre->plugin = first ? pscom_plugin_first() : pscom_plugin_next(pre->plugin);
		first = 0;
	} while (pre->plugin &&
		 (!_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(pre->plugin->arch_id)) ||
		  pre->plugin->con_init(con)));

	if (!pre->plugin) {
		// error: No working plugin found
		errno = ENOPROTOOPT;
		pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
	} else {
		// Try this plugin:
		pscom_precon_send(pre, PSCOM_INFO_ARCH_REQ, &pre->plugin->arch_id, sizeof(pre->plugin->arch_id));
		pre->plugin->con_handshake(con, PSCOM_INFO_ARCH_REQ, &pre->plugin->arch_id, sizeof(pre->plugin->arch_id));
	}
}


static
unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec*1000000+tv.tv_usec;
}

/************************************************************************
 * pscom_precon functions
 */
static
const char *pscom_precon_str(precon_t *pre)
{
	static char buf[sizeof("xxx.xxx.xxx.xxx:portxx_____     ")];
	snprintf(buf, sizeof(buf), INET_ADDR_FORMAT":%u",
		 INET_ADDR_SPLIT(pre->nodeid), pre->portno);
	return buf;
}


static
void pscom_precon_terminate(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);

	DPRINT(1, "precon(%p): terminated", pre);
	pscom_precon_recv_stop(pre);
	// trow away the sendbuffer
	if (pre->send) {
		free(pre->send);
		pre->send = NULL;
	}
	if (pre->send_len) {
		// Dont send
		pre->send_len = 0;
		if (pre->ufd_info.fd != -1) {
			ufd_event_clr(&pscom.ufd, &pre->ufd_info, POLLOUT);
		}
	}
}


void pscom_precon_send_PSCOM_INFO_ARCH_NEXT(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	pre->plugin = NULL; // reject following STEPx and OK messages
	pscom_precon_send(pre, PSCOM_INFO_ARCH_NEXT, NULL, 0);
}


static
void pscom_precon_send_PSCOM_INFO_VERSION(precon_t *pre)
{
	pscom_info_version_t ver;
	assert(pre->magic == MAGIC_PRECON);

	/* Send supported versions */
	ver.ver_from = VER_FROM;
	ver.ver_to   = VER_TO;
	pscom_precon_send(pre, PSCOM_INFO_VERSION, &ver, sizeof(ver));
}


/* Send con_info. The type should be one of:
 *  - PSCOM_INFO_CON_INFO
 *  - PSCOM_INFO_CON_INFO_DEMAND
 *  - PSCOM_INFO_BACK_CONNECT
 */
void pscom_precon_send_PSCOM_INFO_CON_INFO(precon_t *pre, int type)
{
	pscom_info_con_info_t msg_con_info;
	assert(pre->magic == MAGIC_PRECON);
	assert(pre->con);
	assert(pre->con->magic == MAGIC_CONNECTION);

	/* Send connection information */
	pscom_con_info(pre->con, &msg_con_info.con_info);

	DPRINT(PRECON_LL, "precon(%p): con:%s", pre, pscom_con_str(&pre->con->pub));
	pscom_precon_send(pre, type, &msg_con_info, sizeof(msg_con_info));
}


static
void pscom_precon_abort_plugin(precon_t *pre)
{
	pscom_con_t *con = pre->con;
	if (pre->plugin && con) pre->plugin->con_handshake(con, PSCOM_INFO_ARCH_NEXT, NULL, 0);
	pre->plugin = NULL; // Do not use plugin anymore after PSCOM_INFO_ARCH_NEXT
}


static
void pscom_precon_handle_receive(precon_t *pre, uint32_t type, void *data, unsigned size)
{
	int err;
	pscom_con_t *con = pre->con;
	assert(pre->magic == MAGIC_PRECON);
	assert(!con || con->magic == MAGIC_CONNECTION);
	assert(!con || con->precon == pre || pre->back_connect);

	pscom_precon_info_dump(pre, "recv", type, data, size);

	switch (type) {
	case PSCOM_INFO_FD_EOF:
		pscom_precon_abort_plugin(pre);
		if (con) pscom_con_setup_failed(con, PSCOM_ERR_EOF);
		if (!pre->recv_done) pscom_precon_terminate(pre);
		break;
	case PSCOM_INFO_FD_ERROR:
		pscom_precon_abort_plugin(pre);
		err = data ? *(int*)data : 0;
		if (con && (
			    !pre->back_connect                              || /* not a back connect */
			    (!retry_on_error(err)))     /* or a back connect and the error is not due to a reverse
							   connection already triggered or established by the peer. */
		) {
			pscom_con_setup_failed(con, err == ECONNREFUSED ? PSCOM_ERR_CONNECTION_REFUSED : PSCOM_ERR_IOERROR);
		}
		pscom_precon_terminate(pre);
		break;
	case PSCOM_INFO_CON_INFO: {
		pscom_info_con_info_t *msg = data;
		if (size != sizeof(*msg)) { // old pscom version send CON_INFO before VERSION.
			break;
		}
		pscom_sock_t *sock = pre->sock;

		if (!con) { // Accepting side of the connection
			con = pscom_con_create(sock);
			pre->con = con;
			con->precon = pre;
			con->pub.state = PSCOM_CON_STATE_ACCEPTING;
			con->pub.remote_con_info = msg->con_info;
			pscom_precon_send_PSCOM_INFO_VERSION(pre);
			pscom_precon_send_PSCOM_INFO_CON_INFO(pre, PSCOM_INFO_CON_INFO);
		} else {
			con->pub.remote_con_info = msg->con_info;
		}
		break;
	}
	case PSCOM_INFO_CON_INFO_DEMAND: {
		pscom_info_con_info_t *msg = data;
		assert(size >= sizeof(*msg));
		pscom_sock_t *sock = pre->sock;
		assert(!con);

		// Search for the existing matching connection
		con = pscom_ondemand_get_con(sock, msg->con_info.name);

		if (con) {
			/* Set con */
			assert(pre);
			pre->con = con;
			assert(con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
			assert(!con->precon);
			con->precon = pre;
			con->pub.remote_con_info = msg->con_info;
			con->pub.state = PSCOM_CON_STATE_ACCEPTING_ONDEMAND;

			pscom_precon_send_PSCOM_INFO_VERSION(pre);
			pscom_precon_send_PSCOM_INFO_CON_INFO(pre, PSCOM_INFO_CON_INFO);
		} else {
			/* No con found.
			   Reject this connection! */
			DPRINT(1, "Reject %s : unknown on demand connection", pscom_con_info_str(&msg->con_info));
			pscom_precon_terminate(pre);
		}
		break;
	}
	case PSCOM_INFO_VERSION: {
		pscom_info_version_t *ver = data;
		assert(size >= sizeof(*ver)); /* with space for the future */
		if ((VER_TO < ver->ver_from) || (ver->ver_to < VER_FROM)) {
			DPRINT(0, "connection %s : Unsupported protocol version (mine:[%04x..%04x] remote:[%04x..%04x])",
			       con ? pscom_con_str(&con->pub) : pscom_precon_str(pre),
			       VER_FROM, VER_TO, ver->ver_from, ver->ver_to);
			errno = EPROTO;
			if (con) pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
			pscom_precon_terminate(pre);
		}
		break;
	}
	case PSCOM_INFO_BACK_CONNECT: {
		pscom_info_con_info_t *msg = data;
		pscom_con_info_t *con_info = &msg->con_info;
		assert(size >= sizeof(*msg));
		assert(!con);
		pscom_sock_t *sock = pre->sock;

		DPRINT(PRECON_LL, "precon(%p): recv backcon %.8s to %.8s",
		       pre, con_info->name, sock->pub.local_con_info.name);
		// Search for an existing matching connection
		con = pscom_ondemand_find_con(sock, con_info->name);

		if (con && con->pub.type == PSCOM_CON_TYPE_ONDEMAND) {
			/* Trigger the back connect */
			DPRINT(3, "RACCEPT %s", pscom_con_str(&con->pub));
			con->write_start(con);
		} else {
			DPRINT(3, "RACCEPT from %s skipped", pscom_con_info_str(con_info));
		}
		pscom_precon_send(pre, PSCOM_INFO_BACK_ACK, NULL, 0);
		pscom_precon_recv_stop(pre);
		break;
	}
	case PSCOM_INFO_BACK_ACK: {
		pscom_precon_recv_stop(pre);
		break;
	}
	case PSCOM_INFO_ARCH_REQ: {
		assert(size == sizeof(int));
		assert(con);
		int arch = *(int *)data;
		pscom_sock_t *sock = get_sock(con->pub.socket);
		pscom_plugin_t *p = NULL;

		if (_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(arch))) {
			p = pscom_plugin_by_archid(arch);
		}
		if (p && !p->con_init(con)) {
			pre->plugin = p;
			assert(con->precon);
			/* Use asynchronous handshake */
			p->con_handshake(con, type, data, size);
		} else {
			// Unknown or disabled arch or con_init fail. Try next arch.
			pscom_precon_send_PSCOM_INFO_ARCH_NEXT(pre);
		}
		break;
	}
	case PSCOM_INFO_ARCH_OK:
	case PSCOM_INFO_ARCH_STEP1:
	case PSCOM_INFO_ARCH_STEP2:
	case PSCOM_INFO_ARCH_STEP3:
	case PSCOM_INFO_ARCH_STEP4:
		/* Handled by the current plugin. pre->plugin might be
		 * null, in the case of an initialization error. */
		if (pre->plugin && con) {
			pre->plugin->con_handshake(con, type, data, size);
			if (type == PSCOM_INFO_ARCH_OK) {
				pscom_precon_close(pre);
			}
		}
		break;
	case PSCOM_INFO_ARCH_NEXT: {
		if (pre->plugin && con) pre->plugin->con_handshake(con, type, data, size);
		plugin_connect_next(con, 0);
		break;
	}
	case PSCOM_INFO_EOF: {
		if (pre->plugin && con) pre->plugin->con_handshake(con, type, data, size);
		pre->plugin = NULL;
	}
	default: /* ignore all unknown info messages */
		;
	}
	pscom_precon_check_end(pre);
}


void pscom_precon_destroy(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	int fd = pre->ufd_info.fd;

	if (fd != -1) {
		ufd_del(&pscom.ufd, &pre->ufd_info);
		pre->ufd_info.fd = -1;
	}

	pscom_precon_count--;
	list_del_init(&pre->poll_reader.next);

	free(pre->send); pre->send = NULL; pre->send_len = 0;
	free(pre->recv); pre->recv = NULL; pre->recv_len = 0;

	if (pre->closefd_on_cleanup && fd != -1) {
		int rc = close(fd);
		if (!rc) DPRINT(PRECON_LL, "precon(%p): close(%d)", pre, fd);
		else     DPRINT(1        , "precon(%p): close(%d) : %s", pre, fd, strerror(errno));
	} else           DPRINT(PRECON_LL, "precon(%p): done", pre);

	pre->magic = 0;
	free(pre);
}


static
int pscom_precon_isconnected(precon_t *pre) {
	return pre->ufd_info.fd != -1;
}


static
void pscom_precon_connect_terminate(precon_t *pre) {
	assert(pre->magic == MAGIC_PRECON);

	if (!pscom_precon_isconnected(pre)) return;

	close(pre->ufd_info.fd);
	ufd_del(&pscom.ufd, &pre->ufd_info);
	pre->ufd_info.fd = -1;
}


static
void pscom_precon_reconnect(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);

	pscom_precon_connect_terminate(pre);

	if (pre->back_connect && pre->con
	    && (pre->con->magic == MAGIC_CONNECTION)
	    && (pre->con->pub.type != PSCOM_CON_TYPE_ONDEMAND)) {
		// Back connect failed, but forward connect succeeded.
		DPRINT(2, "precon(%p): stopping obsolete back-connect on con:%p type:%6s state:%8s",
		       pre, pre->con,
		       pscom_con_type_str(pre->con->pub.type),
		       pscom_con_state_str(pre->con->pub.state));
		pre->con = NULL; // do not touch the connected con anymore.
		goto backconnect_obsolete;
	}

	if (pre->reconnect_cnt < pscom.env.retry) {
		pre->reconnect_cnt++;
		DPRINT(1, "precon(%p):pscom_precon_reconnect count %u",
		       pre, pre->reconnect_cnt);
		int fd = _pscom_tcp_connect(pre->nodeid, pre->portno, pre);
		if (fd < 0) goto error;

		pscom_precon_assign_fd(pre, fd);
	} else {
		errno = ECONNREFUSED;
		goto error;
	}

	return;
	/* --- */
	int error_code;
backconnect_obsolete:
	pscom_precon_handle_receive(pre, PSCOM_INFO_FD_EOF, NULL, 0);
	return;
error:
	/* precon connect failed. */
	error_code = errno;
	pscom_precon_handle_receive(pre, PSCOM_INFO_FD_ERROR, &error_code, sizeof(error_code));
	return;
}


static
void pscom_precon_check_end(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	if ((pre->send_len == 0) && pre->recv_done) {
		if (!pre->back_connect) {
			pscom_plugin_t *p = pre->plugin;

			if (pre->con) pre->con->precon = NULL; // disallow precon usage in handshake

			if (p) p->con_handshake(pre->con, PSCOM_INFO_EOF, NULL, 0);
		}

		pscom_precon_print_stat(pre);

		pscom_precon_destroy(pre); pre = NULL;
	}
}


static
void pscom_precon_do_write(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
	precon_t *pre = (precon_t *) ufd_info->priv;
	int len;
	assert(pre->magic == MAGIC_PRECON);

	if (pre->send_len) {
		len = (int)send(pre->ufd_info.fd, pre->send, pre->send_len, MSG_NOSIGNAL);
	} else {
		len = 0;
	}

	// printf("write(%d, %p, %u) = %d(%s)\n", pre->ufd_info.fd,
	//       pre->send, pre->send_len, len, len < 0 ? strerror(errno) : "ok");

	if (len >= 0) {
		pre->stat_send += len;
		memmove(pre->send, pre->send + len, pre->send_len - len);
		pre->send_len -= len;
		if (!pre->send_len) {
			free(pre->send);
			pre->send = NULL;
			ufd_event_clr(&pscom.ufd, &pre->ufd_info, POLLOUT);
		}
	} else {
		if (retry_on_error(errno)) {
			/* Nonblocking connect() failed e.g. on ECONNREFUSED */
			pscom_precon_reconnect(pre);
			pre = NULL; // pscom_precon_reconnect() might close pre. Don't use pre afterwards.
		} else {
			switch (errno) {
			case EAGAIN:
			case EINTR:
				/* Try again later */
				break;
			default:
				/* Unexpected error. Stop writing. Print diagnostics.
				   The cleanup will be done in do_read, which will
				   (hopefully) also fail in read(). */
				DPRINT(1, "precon(%p): write(%d, %p, %u) : %s",
				       pre, pre->ufd_info.fd, pre->send, pre->send_len, strerror(errno));
				ufd_event_clr(&pscom.ufd, &pre->ufd_info, POLLOUT);
				close(pre->ufd_info.fd);
				pre->send_len = 0;
			}
		}
	}

	if (pre) pscom_precon_check_end(pre);
}


static
void pscom_precon_do_read(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
	precon_t *pre = (precon_t *) ufd_info->priv;
	assert(pre->magic == MAGIC_PRECON);
	assert(!pre->con || pre->con->magic == MAGIC_CONNECTION);

	if (pre->recv_done) {
		DPRINT(1, "pscom_precon_do_read: softassert(!pre->recv_done) failed.");
		pscom_precon_recv_stop(pre);
		return;
	}
	int len;
	uint32_t ntype;
	uint32_t nsize;
	const unsigned header_size = sizeof(ntype) + sizeof(nsize);
	int fd = pre->ufd_info.fd;

	/* Allocate bufferspace for the header. Be prepared for more data */
	if (!pre->recv) {
		pre->recv = malloc(header_size + 128);
		assert(pre->recv);
	}

	/* Read the header */
	if (pre->recv_len < header_size) {
		len = (int)read(fd, pre->recv + pre->recv_len, header_size - pre->recv_len);
		// printf("read#1(%d, %p, %u) = %d(%s)\n", fd, pre->recv + pre->recv_len,
		//        header_size - pre->recv_len, len, len < 0 ? strerror(errno) : "ok");
		if (len <= 0) goto check_read_error;
		pre->recv_len += len;
		pre->stat_recv += len;
	}

	/* Header complete? Read and process the data: */
	if (pre->recv_len >= header_size) {
		ntype = ntohl(*(uint32_t *)pre->recv);
		nsize = ntohl(*((uint32_t *)pre->recv + 1));

		unsigned msg_len = header_size + nsize;

		/* Allocate more for the data */
		pre->recv = realloc(pre->recv, msg_len);
		assert(pre->recv);

		/* Read the data */
		len = msg_len - pre->recv_len;
		if (len) {
			len = (int)read(fd, pre->recv + pre->recv_len, len);
			// printf("read#2(%d, %p, %u) = %d(%s)\n", fd, pre->recv + pre->recv_len,
			//        msg_len - pre->recv_len, len, len < 0 ? strerror(errno) : "ok");
			if (len <= 0) goto check_read_error;
			pre->recv_len += len;
			pre->stat_recv += len;
		}

		/* Message complete? */
		if (pre->recv_len == msg_len) {
			/* Message complete. Handle the message. */
			void *msg = pre->recv;

			pre->recv = NULL;
			pre->recv_len = 0;
			pscom_precon_handle_receive(pre, ntype, msg + header_size, nsize);
			/* Dont use pre hereafter, as handle_receive may free it! */

			pre = NULL;
			free(msg);
		}
	}
	return;
	/* --- */
check_read_error:
	if (len == 0) {
		/* receive EOF. Handle the pseudo message FD_EOF */
		ufd_event_clr(&pscom.ufd, &pre->ufd_info, POLLIN);
		pscom_precon_handle_receive(pre, PSCOM_INFO_FD_EOF, NULL, 0);
	} else if (errno == EAGAIN || errno == EINTR) {
		/* Try again later */
		return;
	} else if (retry_on_error(errno)) {
		DPRINT(3, "precon(%p): read(%d,...) : %s", pre, fd, strerror(errno));
		/* pscom_precon_reconnect(pre); */
		/* Terminate this connection. Reconnect after pscom.env.precon_reconnect_timeout.*/
		pscom_precon_connect_terminate(pre);
	} else {
		/* Connection error. Handle the pseudo message FD_ERROR. */
		int error_code = errno;
		ufd_event_clr(&pscom.ufd, &pre->ufd_info, POLLIN);
		pscom_precon_handle_receive(pre, PSCOM_INFO_FD_ERROR, &error_code, sizeof(error_code));
	}
}


void pscom_precon_send(precon_t *pre, unsigned type, void *data, unsigned size)
{
	assert(pre->magic == MAGIC_PRECON);
	uint32_t ntype = htonl(type);
	uint32_t nsize = htonl(size);
	unsigned msg_size = size + (unsigned)(sizeof(ntype) + sizeof(nsize));
	char *msg;

	pscom_precon_info_dump(pre, "send", type, data, size);

	/* allocate msg_size bytes after existing pre->send */
	pre->send = realloc(pre->send, pre->send_len + msg_size);
	assert(pre->send);
	msg = pre->send + pre->send_len;
	pre->send_len += msg_size;

	/* append the message to pre->send */
	memcpy(msg, &ntype, sizeof(ntype)); msg += sizeof(ntype);
	memcpy(msg, &nsize, sizeof(nsize)); msg += sizeof(nsize);
	memcpy(msg, data, size); msg += size;

	/* Send */
	ufd_event_set(&pscom.ufd, &pre->ufd_info, POLLOUT);
}


void pscom_precon_close(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	pscom_precon_recv_stop(pre);
}


void pscom_precon_recv_start(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	ufd_event_set(&pscom.ufd, &pre->ufd_info, POLLIN);
	pre->recv_done = 0;
}


static
void pscom_precon_recv_stop(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	if (pscom_precon_isconnected(pre)) {
		ufd_event_clr(&pscom.ufd, &pre->ufd_info, POLLIN);
	}
	pre->recv_done = 1;
}


void pscom_precon_assign_fd(precon_t *pre, int con_fd)
{
	assert(pre->magic == MAGIC_PRECON);
	assert(pre->ufd_info.fd == -1);
	tcp_configure(con_fd);

	pre->ufd_info.fd = con_fd;
	pre->ufd_info.can_read = pscom_precon_do_read;
	pre->ufd_info.can_write = pscom_precon_do_write;
	pre->ufd_info.priv = pre;

	ufd_add(&pscom.ufd, &pre->ufd_info);

	if (pre->send_len) ufd_event_set(&pscom.ufd, &pre->ufd_info, POLLOUT);
	if (!pre->recv_done) ufd_event_set(&pscom.ufd, &pre->ufd_info, POLLIN);
}


int pscom_precon_tcp_connect(precon_t *pre, int nodeid, int portno)
{
	int fd;
	assert(pre->magic == MAGIC_PRECON);

	pre->nodeid = nodeid;
	pre->portno = portno;

	fd = _pscom_tcp_connect(nodeid, portno, pre);
	if (fd >= 0) {
		pscom_precon_assign_fd(pre, fd);
		return 0;
	} else {
		return -1;
	}
}


/* Print statistic about this precon */
static
int pscom_precon_do_read_poll(pscom_poll_reader_t *reader)
{
	precon_t *pre = list_entry(reader, precon_t, poll_reader);
	assert(pre->magic == MAGIC_PRECON);
	unsigned long now = getusec();

	if (pscom.env.debug >= PRECON_LL) {
		if (now - pre->last_print_stat > 1500 /* ms */ * 1000) {
			pre->stat_poll_cnt++;

			pre->last_print_stat = now;
			pscom_precon_print_stat(pre);
		}
	}

	if (now - pre->last_reconnect > pscom.env.precon_reconnect_timeout /* ms */ * 1000UL) {
		pre->last_reconnect = now;

		if (!pscom_precon_isconnected(pre) || (pre->stat_recv == 0)) {
			if (pscom_precon_isconnected(pre) && (pre->stat_recv == 0)) {
				/* ToDo:
				   If the peer is just busy, we should wait further, but if
				   this connection is broken we should reconnect. How to detect that
				   the remote missed the accept event? */
				DPRINT(3, "precon(%p): connection stalled", pre);
			} else {
				pscom_precon_reconnect(pre);
			}
		}
	}

	return 0;
}


precon_t *pscom_precon_create(pscom_con_t *con)
{
	precon_t *pre = malloc(sizeof(*pre));

	assert(pre);

	memset(pre, 0, sizeof(*pre));
	pre->magic = MAGIC_PRECON;

	pre->con = con;

	pre->recv_done = 1;	// No recv
	pre->closefd_on_cleanup = 1; // Default: Close fd on cleanup. Only PSCOM_CON_TYPE_TCP will overwrite this.
	pre->back_connect = 0;	// Not a back connect

	pre->ufd_info.fd = -1;
	pre->ufd_info.pollfd_idx = -1;

	pre->last_reconnect =
		pre->last_print_stat = getusec();

	pre->poll_reader.do_read = pscom_precon_do_read_poll;
	list_add_tail(&pre->poll_reader.next, &pscom.poll_reader);

	pre->stat_send = 0;
	pre->stat_recv = 0;
	pre->stat_poll_cnt = 0;

	pscom_precon_count++;

	return pre;
}


void pscom_precon_handshake(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);

	/* Enable receive */
	pscom_precon_recv_start(pre);

	// printf("%s:%u:%s CON_STATE:%s\n", __FILE__, __LINE__, __func__,
	//        pre->con ? pscom_con_state_str(pre->con->pub.state): "no connection");

	if (pre->con && (pre->con->pub.state & PSCOM_CON_STATE_CONNECTING)) {
		int on_demand = (pre->con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
		int type;
		if (on_demand) {
			type = PSCOM_INFO_CON_INFO_DEMAND;
			pre->con->pub.state = PSCOM_CON_STATE_CONNECTING_ONDEMAND;
		} else {
			type = PSCOM_INFO_CON_INFO;
			pre->con->pub.state = PSCOM_CON_STATE_CONNECTING;
		}
		pscom_precon_send_PSCOM_INFO_VERSION(pre);
		pscom_precon_send_PSCOM_INFO_CON_INFO(pre, type);
		plugin_connect_next(pre->con, 1);
	}
}


__attribute__((visibility("hidden")))
void pscom_con_accept(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
	pscom_sock_t *sock = ufd_info->priv;
	int listen_fd = pscom_listener_get_fd(&sock->listen);
	while (1) {
		precon_t *pre;
		struct sockaddr_in addr;
		socklen_t addrlen = sizeof(addr);

		int fd = accept(listen_fd, (struct sockaddr*)&addr, &addrlen);
		if (fd < 0) return; // Ignore Errors.

		/* Create a new precon */
		pre = pscom_precon_create(NULL);
		assert(pre);
		DPRINT(PRECON_LL, "precon(%p): accept(%d,...) = %d", pre, listen_fd, fd);

		pre->sock = sock;

		/* Save remote address */
		if (addr.sin_family == AF_INET) {
			pre->nodeid = ntohl(addr.sin_addr.s_addr);
			pre->portno = ntohs(addr.sin_port);
		}
		pscom_precon_assign_fd(pre, fd);

		/* Handshake with peer */
		pscom_precon_handshake(pre);
	}

	return;
}
