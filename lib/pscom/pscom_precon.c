/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
#include "pscom_priv.h"
#include "pscom_precon.h"
#include "pscom_str_util.h"
#include "pscom_con.h"
#include "pscom_util.h"
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

pscom_env_table_entry_t pscom_env_table_precon [] = {
	{"SO_SNDBUF", "32768",
	 "The SO_SNDBUF size of the precon/TCP connections.",
	 &pscom.env.so_sndbuf, 0, PSCOM_ENV_PARSER_UINT},

	{"SO_RCVBUF", "32768",
	 "The SO_RCVBUF size of the precon/TCP connections.",
	 &pscom.env.so_rcvbuf, 0, PSCOM_ENV_PARSER_UINT},

	{"TCP_NODELAY", "1",
	 "Enable/disable TCP_NODELAY for the precon/TCP connections.",
	 &pscom.env.tcp_nodelay, 0, PSCOM_ENV_PARSER_INT},

	{"RECONNECT_TIMEOUT", "2000",
	 "The reconnect timeout for the precon in milliseconds.",
	 &pscom.env.precon_reconnect_timeout, 0, PSCOM_ENV_PARSER_UINT},

	{"CONNECT_STALLED_MAX", "6",
	 "Declare after (PSP_CONNECT_STALLED * PSP_RECONNECT_TIMEOUT)[ms] "
	 "without any received bytes the connect() as failed. Retry.",
	 &pscom.env.precon_connect_stalled_max, 0, PSCOM_ENV_PARSER_UINT},

	{NULL},
};


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
void pscom_precon_info_dump(precon_t *pre, char *op, int type, void *data, unsigned size)
{
	const char *plugin_name = pre->plugin ? pre->plugin->name : "";

	switch (type) {
	case PSCOM_INFO_FD_ERROR: {
		int noerr = 0;
		int *err = size == sizeof(int) && data ? data : &noerr;
		DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\t%d(%s)", pre, op,
		       plugin_name, pscom_info_type_str(type), *err, strerror(*err));
		break;
	}
	case PSCOM_INFO_ARCH_REQ: {
		pscom_info_arch_req_t *arch_req = data;
		DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\tarch_id:%u (%s)", pre, op,
		       plugin_name, pscom_info_type_str(type),
		       arch_req->arch_id,
		       pscom_con_type_str(PSCOM_ARCH2CON_TYPE(arch_req->arch_id)));
		break;
	}
	case PSCOM_INFO_BACK_CONNECT:
	case PSCOM_INFO_CON_INFO_DEMAND:
	case PSCOM_INFO_CON_INFO: {
		pscom_info_con_info_t *msg = data;
		DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\tcon_info:%s", pre, op,
		       plugin_name, pscom_info_type_str(type),
		       pscom_con_info_str(&msg->con_info));
		break;
	}
	case PSCOM_INFO_VERSION: {
		pscom_info_version_t *version = data;
		DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\tver_from:%04x ver_to:%04x", pre, op,
		       plugin_name, pscom_info_type_str(type),
		       version->ver_from, version->ver_to);
		break;
	}
	default:
		DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\t%p %u", pre, op,
		       plugin_name, pscom_info_type_str(type), data, size);
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
	DPRINT(D_PRECON_TRACE, "precon(%p): #%u send:%zu recv:%zu to_send:%u recv:%s active:%u state:%s\n",
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
		DPRINT(D_PRECON_TRACE, "precon(%p): connect(%d,\"%s:%u\") = %d (%s)",
		       debug_id, sockfd, pscom_inetstr(ntohl(sa->sin_addr.s_addr)),
		       ntohs(sa->sin_port), ret, ret ? strerror(errno) : "ok");
		if (ret >= 0) break;
		if (!retry_on_error(errno)) break;
		sleep(1);
		DPRINT(D_INFO, "Retry %d CONNECT to %s:%d",
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
		DPRINT(D_DBG_V, "setsockopt(%d, SOL_SOCKET, SO_SNDBUF, [%d], %ld) = %d : %s",
		       fd, val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");
	}
	if (pscom.env.so_rcvbuf) {
		val = pscom.env.so_rcvbuf;
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
		DPRINT(D_DBG_V, "setsockopt(%d, SOL_SOCKET, SO_RCVBUF, [%d], %ld) = %d : %s",
		       fd, val, (long)sizeof(val), ret, ret ? strerror(errno) : "Success");
	}
	val = pscom.env.tcp_nodelay;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	DPRINT(D_DBG_V, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY, [%d], %ld) = %d : %s",
	       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

	if (1) { // Set keep alive options.
		val = 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
		DPRINT(ret ? D_DBG_V : D_TRACE, "setsockopt(%d, SOL_SOCKET, SO_KEEPALIVE, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

		// Overwrite defaults from "/proc/sys/net/ipv4/tcp_keepalive*"

		val = 20; /* Number of keepalives before death */
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &val, sizeof(val));
		DPRINT(ret ? D_DBG_V : D_TRACE, "setsockopt(%d, SOL_TCP, TCP_KEEPCNT, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

		val = 5; /* Start keeplives after this period */
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &val, sizeof(val));
		DPRINT(ret ? D_DBG_V : D_TRACE, "setsockopt(%d, SOL_TCP, TCP_KEEPIDLE, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");

		val = 4; /* Interval between keepalives */
		ret = setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &val, sizeof(val));
		DPRINT(ret ? D_DBG_V : D_TRACE, "setsockopt(%d, SOL_TCP, TCP_KEEPINTVL, [%d], %ld) = %d : %s",
		       fd, val, (long) sizeof(val), ret, ret ? strerror(errno) : "Success");
	}

}


static
void pscom_sockaddr_init(struct sockaddr_in *si, int nodeid, int portno)
{
	/* Setup si for TCP */
	si->sin_family = PF_INET;
	si->sin_port = htons((uint16_t)portno);
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


// Connecting or accepting peer?
static
int con_is_connecting_peer(pscom_con_t *con)
{
	return con && (
		(con->pub.state == PSCOM_CON_STATE_CONNECTING) ||
		(con->pub.state == PSCOM_CON_STATE_CONNECTING_ONDEMAND)
	);
}


static
void _plugin_connect_next(pscom_con_t *con, int first)
{
	precon_t *pre = con->precon;
	pscom_sock_t *sock = get_sock(con->pub.socket);
	assert(pre->magic == MAGIC_PRECON);
	assert(con->magic == MAGIC_CONNECTION);
	assert(first ? !pre->plugin : 1); // if first, pre->plugin has to be NULL!

	if (!con_is_connecting_peer(con)) return; // Nothing to do.

	do {
		pre->plugin = first ? pscom_plugin_first() : pscom_plugin_next(pre->_plugin_cur);
		pre->_plugin_cur = pre->plugin;
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
void plugin_connect_next(pscom_con_t *con)
{
	_plugin_connect_next(con, 0);
}


static
void plugin_connect_first(pscom_con_t *con)
{
	_plugin_connect_next(con, 1);
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

	DPRINT(D_DBG, "precon(%p): terminated", pre);
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


PSCOM_PLUGIN_API_EXPORT
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

	DPRINT(D_PRECON_TRACE, "precon(%p): con:%s", pre, pscom_con_str(&pre->con->pub));
	pscom_precon_send(pre, type, &msg_con_info, sizeof(msg_con_info));
}


static
void pscom_precon_abort_plugin(precon_t *pre)
{
	pscom_con_t *con = pre->con;
	if (pre->plugin && con) {
		DPRINT(D_PRECON_TRACE, "precon(%p):abort %s", pre, pre->plugin->name);
		pre->plugin->con_handshake(con, PSCOM_INFO_ARCH_NEXT, NULL, 0);
	}
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
			con->state.internal_connection = 1; // until the user get a handle to con (via con->on_accept)
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
			DPRINT(D_WARN, "Reject %s : unknown on demand connection", pscom_con_info_str(&msg->con_info));
			pscom_precon_terminate(pre);
		}
		break;
	}
	case PSCOM_INFO_VERSION: {
		pscom_info_version_t *ver = data;
		assert(size >= sizeof(*ver)); /* with space for the future */
		if ((VER_TO < ver->ver_from) || (ver->ver_to < VER_FROM)) {
			DPRINT(D_ERR, "connection %s : Unsupported protocol version (mine:[%04x..%04x] remote:[%04x..%04x])",
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

		DPRINT(D_PRECON_TRACE, "precon(%p): recv backcon %.8s to %.8s",
		       pre, con_info->name, sock->pub.local_con_info.name);
		// Search for an existing matching connection
		con = pscom_ondemand_find_con(sock, con_info->name);

		if (con && con->pub.type == PSCOM_CON_TYPE_ONDEMAND) {
			/* Trigger the back connect */
			DPRINT(D_DBG_V, "RACCEPT %s", pscom_con_str(&con->pub));
			con->write_start(con);
		} else {
			DPRINT(D_DBG_V, "RACCEPT from %s skipped", pscom_con_info_str(con_info));
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
		if (con) {
			if (pre->plugin) {
				pre->plugin->con_handshake(con, type, data, size);
				if (type == PSCOM_INFO_ARCH_OK) {
					pscom_precon_close(pre);
				}
			} else {
				// Failed locally before. Handle OK like an ARCH_NEXT
				if (type == PSCOM_INFO_ARCH_OK) {
					plugin_connect_next(con);
				}
			}
		}
		break;
	case PSCOM_INFO_ARCH_NEXT: {
		pscom_precon_abort_plugin(pre);
		plugin_connect_next(con);
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
	pscom_poll_cleanup_init(&pre->poll_read);

	free(pre->send); pre->send = NULL; pre->send_len = 0;
	free(pre->recv); pre->recv = NULL; pre->recv_len = 0;

	if (pre->closefd_on_cleanup && fd != -1) {
		int rc = close(fd);
		if (!rc) DPRINT(D_PRECON_TRACE, "precon(%p): close(%d)", pre, fd);
		else     DPRINT(D_WARN, "precon(%p): close(%d) : %s", pre, fd, strerror(errno));
	} else           DPRINT(D_PRECON_TRACE, "precon(%p): done", pre);

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
int pscom_precon_is_obsolete_backconnect(precon_t *pre) {
	// A back connect is obsolete when it's associated
	// pscon_con_t con is not ONDEMAND anymore.
	// Probably, forward connect succeeded or finally failed.
	return (pre->back_connect && pre->con
		&& (pre->con->magic == MAGIC_CONNECTION)
		&& (pre->con->pub.type != PSCOM_CON_TYPE_ONDEMAND));
}


static
void pscom_precon_terminate_backconnect(precon_t *pre) {
	pscom_precon_connect_terminate(pre);
	DPRINT(D_DBG_V, "precon(%p): stopping obsolete back-connect on con:%p type:%6s state:%8s",
	       pre, pre->con,
	       pscom_con_type_str(pre->con->pub.type),
	       pscom_con_state_str(pre->con->pub.state));
	pre->con = NULL; // do not touch the connected con anymore.

	pscom_precon_handle_receive(pre, PSCOM_INFO_FD_EOF, NULL, 0);
}


static
void pscom_precon_reconnect(precon_t *pre)
{
	assert(pre->magic == MAGIC_PRECON);
	assert(pre->connect);

	pscom_precon_connect_terminate(pre);

	if (pscom_precon_is_obsolete_backconnect(pre)) {
		pscom_precon_terminate_backconnect(pre);
		goto out;
	}

	if (pre->reconnect_cnt < pscom.env.retry) {
		pre->reconnect_cnt++;
		DPRINT(D_DBG, "precon(%p):pscom_precon_reconnect count %u",
		       pre, pre->reconnect_cnt);
		int fd = _pscom_tcp_connect(pre->nodeid, pre->portno, pre);
		if (fd < 0) goto error;

		pscom_precon_assign_fd(pre, fd);
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
		if (pre->connect && retry_on_error(errno)) {
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
				DPRINT(D_ERR, "precon(%p): write(%d, %p, %u) : %s",
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
		DPRINT(D_ERR, "pscom_precon_do_read: softassert(!pre->recv_done) failed.");
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
		DPRINT(D_DBG, "precon(%p): read(%d,...) : %s", pre, fd, strerror(errno));
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


PSCOM_PLUGIN_API_EXPORT
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
	pre->connect = 1;

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
int pscom_precon_do_read_poll(pscom_poll_t *poll)
{
	precon_t *pre = list_entry(poll, precon_t, poll_read);
	assert(pre->magic == MAGIC_PRECON);
	unsigned long now = pscom_wtime_usec();

	if (pscom.env.debug >= D_PRECON_TRACE) {
		if (now - pre->last_print_stat > 1500 /* ms */ * 1000) {
			pre->stat_poll_cnt++;

			pre->last_print_stat = now;
			pscom_precon_print_stat(pre);
		}
	}

	if (!pre->connect) {
		// Not the connecting side of the precon.
		// The accepting side does nothing here.
	} else if (pscom_precon_is_obsolete_backconnect(pre)) {
		// pre is a backconnect and the forward connect succeeded or failed finally.
		pscom_precon_terminate_backconnect(pre);
	} else if (now - pre->last_reconnect > pscom.env.precon_reconnect_timeout /* ms */ * 1000UL) {
		// reconnect timeout happened

		pre->last_reconnect = now;

		if (!pscom_precon_isconnected(pre)) {
			// reconnect after failure followed by the precon_reconnect_timeout:
			pscom_precon_reconnect(pre);
		} else if ((pre->stat_recv == 0) && (pre->stat_send == 0)) {
			// precon stalled
			pre->stalled_cnt++;

			if (pre->stalled_cnt < pscom.env.precon_connect_stalled_max) {
				/* Wait */
				DPRINT(D_DBG, "precon(%p): connect(%s:%u) stalled %u/%u",
				       pre, pscom_inetstr(pre->nodeid), pre->portno,
				       pre->stalled_cnt, pscom.env.precon_connect_stalled_max);
			} else {
				DPRINT(D_ERR, "precon(%p): connect(%s:%u) stalled - reconnecting",
				       pre, pscom_inetstr(pre->nodeid), pre->portno);

				/* ToDo:
				   If the peer is just busy, we should wait further, but if
				   this connection is broken we should reconnect. How to detect that
				   the remote missed the accept event? Here is a race: The remote might
				   have started already a handshake on this precon while we terminate
				   the connection and retry.
				*/
				pre->stalled_cnt = 0;
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
	pre->connect = 0;
	pre->stalled_cnt = 0;

	pre->ufd_info.fd = -1;
	pre->ufd_info.pollfd_idx = -1;

	pre->last_reconnect =
		pre->last_print_stat = pscom_wtime_usec();

	pscom_poll_init(&pre->poll_read);

	pscom_poll_start(&pre->poll_read, pscom_precon_do_read_poll, &pscom.poll_read);

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
		plugin_connect_first(pre->con);
	}
}


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
		DPRINT(D_PRECON_TRACE, "precon(%p): accept(%d,...) = %d", pre, listen_fd, fd);

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


void pscom_precon_init(void)
{
	pscom_env_table_register_and_parse("pscom PRECON", "PRECON_",
					   pscom_env_table_precon);
}
