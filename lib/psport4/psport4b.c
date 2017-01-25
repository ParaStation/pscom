/*
 * ParaStation
 *
 * Copyright (C) 2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

static char vcid[] = "$Id$";

#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <assert.h>

#include "psport4.h"
#include "psport_priv.h"

#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <netdb.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "list.h"
#include "getid.c"

#include "psport_ufd.h"
#include "perf.h"

LIST_HEAD(PSP_Ports);


/* Set Debuglevel */
#define ENV_DEBUG     "PSP_DEBUG"
/* Socket options */
#define ENV_SO_SNDBUF "PSP_SO_SNDBUF"
#define ENV_SO_RCVBUF "PSP_SO_RCVBUF"
#define ENV_TCP_NODELAY "PSP_TCP_NODELAY"
#define ENV_SHAREDMEM "PSP_SHAREDMEM"
#define ENV_P4SOCK "PSP_P4SOCK"
#define ENV_MVAPI "PSP_MVAPI"
#define ENV_OPENIB "PSP_OPENIB"
#define ENV_GM "PSP_GM"

/* Debugoutput on signal SIGQUIT (i386:3) (key: ^\) */
#define ENV_SIGQUIT "PSP_SIGQUIT"
#define ENV_READAHEAD "PSP_READAHEAD"
#define ENV_RETRY "PSP_RETRY"

int env_debug = 0;
static int env_so_sndbuf = 32768;
static int env_so_rcvbuf = 32768;
static int env_tcp_nodelay = 1;
int env_sharedmem = 1;
int env_p4sock = 1;
int env_mvapi = 1;
int env_openib = 1;
int env_gm = 1;
//static int env_nobgthread = 0;
static int env_sigquit = 0;
static int env_readahead = 100;
static int env_retry = 4;

static int GenReqs = 0;
static int GenReqsUsed = 0;

/*
 * Mem allocation functions
 */
static
void no_set_write(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
}

static
void no_set_read(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
}

static
PSP_Port_t *PSP_calloc_port(void)
{
    PSP_Port_t *port = malloc(sizeof(*port));
    int i;
    if (!port) return NULL;

    memset(port, 0, sizeof(*port));
    for (i = 0; i < PSP_MAX_CONNS; i++) {
	PSP_Connection_t *con = &port->con[i];
	INIT_LIST_HEAD(&con->sendq);
	INIT_LIST_HEAD(&con->recvq);
	INIT_LIST_HEAD(&con->genrecvq);
	con->set_write = no_set_write;
	con->set_read = no_set_read;
	con->con_idx = i;
	/* con->io is set to zero with memset above */
    }

    INIT_LIST_HEAD(&port->recvq_any);
    INIT_LIST_HEAD(&port->genrecvq_any);

    ufd_init(&port->ufd);
    INIT_LIST_HEAD(&port->shm_list);
    INIT_LIST_HEAD(&port->shm_list_send);

    p4s_init(port);

    INIT_LIST_HEAD(&port->dcb_list);

#ifdef ENABLE_MVAPI
    PSP_mvapi_init(port);
#endif
#ifdef ENABLE_OPENIB
    PSP_openib_init(port);
#endif
#ifdef ENABLE_GM
    PSP_gm_init(port);
#endif

    return port;
}



/*
 * Util
 */

static inline
int cb_match(PSP_RecvCallBack_t	*cb, void *cb_param, PSP_Header_Net_t *header, int from)
{
    return cb(header, from, cb_param);
}

static inline
int req_cb_match(PSP_Req_t *req, PSP_Header_Net_t *header, int from)
{
    return cb_match(req->u.req.cb, req->u.req.cb_param, header, from);
}

int PSP_writeall(int fd, const void *buf, int count) {
    int len;
    int c = count;

    while (c > 0) {
	len = (int)write(fd, buf, c);
	if (len < 0) {
	    if ((errno == EINTR) || (errno == EAGAIN))
		continue;
	    else
		return -1;
	}
	c -= len;
	buf = ((char*)buf) + len;
    }

    return count;
}

int PSP_readall(int fd, void *buf, int count) {
    int len;
    int c = count;

    while (c > 0) {
	len = (int)read(fd, buf, c);
	if (len <= 0) {
	    if (len < 0) {
		if ((errno == EINTR) || (errno == EAGAIN))
		    continue;
		else
		    return -1;
	    } else {
		return count - c;
	    }
	}
	c -= len;
	buf = ((char*)buf) + len;
    }

    return count;
}

static
char *inetstr(int addr)
{
    static char ret[16];
    sprintf( ret, "%u.%u.%u.%u",
	     (addr >> 24) & 0xff, (addr >> 16) & 0xff,
	     (addr >>  8) & 0xff, (addr >>  0) & 0xff);
    return ret;
}

#define INET_ADDR_SPLIT(addr) ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >>  8) & 0xff, (addr) & 0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"

static
char *con_state(int state)
{
    switch (state) {
    case PSP_CON_STATE_OPEN:		return "open";
    case PSP_CON_STATE_OPEN_LOOP:	return "loop";
    case PSP_CON_STATE_OPEN_GM:		return "gm";
    case PSP_CON_STATE_OPEN_MVAPI:	return "mvapi";
    case PSP_CON_STATE_OPEN_OPENIB:	return "openib";
    case PSP_CON_STATE_OPEN_P4S:	return "p4sock";
    case PSP_CON_STATE_OPEN_SHM:	return "shm";
    case PSP_CON_STATE_OPEN_TCP:	return "tcp";
    case PSP_CON_STATE_UNUSED:		return "unused";
    default:
	return "unknown";
    }
}


static
char *terminate_reason(int reason)
{
    switch (reason) {
    case PSP_TERMINATE_REASON_REMOTECLOSE:	return "close";
    case PSP_TERMINATE_REASON_WRITE_FAILED:	return "write failed";
    case PSP_TERMINATE_REASON_READ_FAILED:	return "read failed";
    default:
	return "unknown";
    }
}

inline
void PSP_sendrequest_done(PSP_Port_t *port, PSP_Connection_t *con, PSP_Req_t *req)
{
    D_TR(printf("PSP_sendrequest_done (state %p)\n", &req->u.req.state));

    assert(!(req->u.req.state & PSP_REQ_STATE_PROCESSED));

    req->u.req.state |= PSP_REQ_STATE_PROCESSED;
    list_del(&req->u.req.next);
//    free(req);
//    if (list_empty(&con->sendq))
//	con->set_write(port, con, 0);
}

static inline
void PSP_recvrequest_done(PSP_Port_t *port, PSP_Connection_t *con, PSP_Req_t *req)
{
    D_TR(printf("PSP_recvrequest_done (state %p)\n", &req->u.req.state));

    assert(!(req->u.req.state & PSP_REQ_STATE_PROCESSED));

    if (req->u.req.dcb) {
	/* Generated request (they use u.req.next) dont have a dcb! */
	/* Delay the dcp execution */
	list_add_tail(&req->u.req.next, &port->dcb_list);
    } else {
	req->u.req.state |= PSP_REQ_STATE_PROCESSED;
    }
}

#define PSP_NDCBS 10
static
void exec_dcb(PSP_Port_t *port)
{
    int ndcbs;
    int i;
    int more;
    struct {
	PSP_Req_t		*req;
    } dcbs[PSP_NDCBS];

 restart:
    more = 0;
    ndcbs = 0;
    if (list_empty(&port->dcb_list)) {
	/* unlock */
	return;
    }
//    perf_add("exec_dcb");
    while (!list_empty(&port->dcb_list)) {
	PSP_Req_t *req = list_entry(port->dcb_list.next, PSP_Req_t, u.req.next);
	list_del(&req->u.req.next);
	dcbs[ndcbs].req = req;
	ndcbs++;
	if (ndcbs == PSP_NDCBS) {
	    more = 1;
	    break;
	}
    }

    /* unlock */

    /* execute the done callbacks (without any lock) */
    for(i = 0; i < ndcbs; i++) {
	dcbs[i].req->u.req.dcb((PSP_Header_t *)dcbs[i].req,
			       dcbs[i].req->u.req.dcb_param);
	dcbs[i].req->u.req.state |= PSP_REQ_STATE_PROCESSED;
    }
    if (more) {
	/* There are more requests left */
	/* lock */
	goto restart;
    }
//    perf_add("exec_dcb done2");
}


static
int PSP_req_read(PSP_Req_t *req, void *buf, unsigned int len)
{
    len = PSP_MIN(req->u.req.iov_len, len);

    PSP_memcpy_to_iov(req->u.req.iov, buf, len);
    req->u.req.iov_len -= len;

//    if (!req->u.req.iov_len)
//	PSP_recvrequest_done(req);

    return len;
}

static unsigned int trash_size = 0;
static char *trash = NULL;


static inline
void PSP_req_init_iov(PSP_Req_t *req, unsigned int skip)
{
    unsigned int len = (unsigned)sizeof(req->nethead) + req->nethead.xheaderlen;
    req->u.req.iov[0].iov_base = &req->nethead;
    req->u.req.iov[0].iov_len = len;
    req->u.req.iov[1].iov_base = req->u.req.data;
    req->u.req.iov[1].iov_len = req->nethead.datalen;
    len += req->nethead.datalen;
    len += skip;
    if (skip) {
	if (trash_size < skip) {
	    trash = realloc(trash, skip);
	    trash_size = skip;
	}
    }
    req->u.req.iov[2].iov_base = trash;
    req->u.req.iov[2].iov_len = skip;
    req->u.req.iov_len = len;
}

static
void PSP_req_prepare_recv(PSP_Req_t *req, PSP_Header_Net_t *nh, uint32_t from)
{
    int len_diff;

    req->addr.from = from;

    len_diff =
	nh->xheaderlen + nh->datalen -
	req->nethead.xheaderlen - req->nethead.datalen;

    if (len_diff) {
	/* Adjust header */
	req->nethead.xheaderlen = PSP_MIN(req->nethead.xheaderlen, nh->xheaderlen);
	req->nethead.datalen = PSP_MIN(req->nethead.datalen, nh->datalen);
	len_diff =
	    nh->xheaderlen + nh->datalen -
	    req->nethead.xheaderlen - req->nethead.datalen;
	/* len_diff Always > 0! */
    }
    PSP_req_init_iov(req, len_diff);
}

/*
 * Request queueing
 */

static inline
PSP_Req_t *genreq_get_from_con_queue(PSP_Port_t *port, PSP_Connection_t *con,
				     PSP_RecvCallBack_t	*cb, void *cb_param,
				     int from, int dequeue)
{
    struct list_head *head = &con->genrecvq;
    struct list_head *pos;

    list_for_each(pos, head) {
	PSP_Req_t *genreq = list_entry(pos, PSP_Req_t, u.req.next);

	if (cb_match(cb, cb_param, &genreq->nethead, from)) {
	    if (dequeue) {
		list_del(&genreq->u.req.next);
		list_del(&genreq->u.req.gen_next_any);
	    }
	    return genreq;
	}
    }
    return NULL;
}

static inline
PSP_Req_t *genreq_get_from_any_queue(PSP_Port_t *port,
				     PSP_RecvCallBack_t	*cb, void *cb_param,
				     int from, int dequeue)
{
    struct list_head *head = &port->genrecvq_any;
    struct list_head *pos;

    list_for_each(pos, head) {
	PSP_Req_t *genreq = list_entry(pos, PSP_Req_t, u.req.gen_next_any);

	if (cb_match(cb, cb_param, &genreq->nethead, from)) {
	    if (dequeue) {
		list_del(&genreq->u.req.next);
		list_del(&genreq->u.req.gen_next_any);
	    }
	    return genreq;
	}
    }
    return NULL;
}

/* find generated request and dequeue it. */
static inline
PSP_Req_t *genreq_get(PSP_Port_t *port, PSP_Req_t *req)
{
    int from = req->addr.from;
    PSP_RecvCallBack_t *cb = req->u.req.cb;
    void *cb_param = req->u.req.cb_param;

    if (from != PSP_AnySender) {
	PSP_Connection_t *con = &port->con[from % PSP_MAX_CONNS];

	return genreq_get_from_con_queue(port, con, cb, cb_param, from, 1);
    } else {
	return genreq_get_from_any_queue(port, cb, cb_param, from, 1);
    }
}

static inline
PSP_Req_t *genreq_probe(PSP_Port_t *port,
			PSP_RecvCallBack_t *cb, void *cb_param, int sender)
{
    if (sender != PSP_AnySender) {
	PSP_Connection_t *con = &port->con[sender % PSP_MAX_CONNS];

	return genreq_get_from_con_queue(port, con, cb, cb_param, sender, 0);
    } else {
	return genreq_get_from_any_queue(port, cb, cb_param, sender, 0);
    }
}


static
void genreq_enq(PSP_Port_t *port, PSP_Connection_t *con, PSP_Req_t *genreq)
{
    list_add_tail(&genreq->u.req.next, &con->genrecvq);
    list_add_tail(&genreq->u.req.gen_next_any, &port->genrecvq_any);
}


static
void PSP_genreq_merge(PSP_Port_t *port, PSP_Req_t *req, PSP_Req_t *genreq)
{
    PSP_Connection_t *con = &port->con[genreq->addr.from % PSP_MAX_CONNS];
    unsigned int len;

    PSP_req_prepare_recv(req, &genreq->nethead, genreq->addr.from);

    len = genreq->nethead.xheaderlen + genreq->nethead.datalen +
	(unsigned)sizeof(genreq->nethead) -
	(unsigned)PSP_iovec_len(genreq->u.req.iov, PSP_IOV_BUFFERS);

    PSP_req_read(req, &genreq->nethead, len);

    if (con->in.req == genreq) {
	assert(!(genreq->u.req.state & PSP_REQ_STATE_PROCESSED));
	con->in.req = req;
    } else {
	assert(genreq->u.req.state & PSP_REQ_STATE_PROCESSED);
	PSP_recvrequest_done(port, con, req);
    }

    GenReqsUsed++;
    free(genreq);
}

static
void PSP_enq_recv_req(PSP_Port_t *port, PSP_Req_t *req)
{
    if ((req->addr.from != (uint32_t)PSP_AnySender) && list_empty(&port->recvq_any)) {
	PSP_Connection_t *con = &port->con[req->addr.from % PSP_MAX_CONNS];

	list_add_tail(&req->u.req.next, &con->recvq);
	con->set_read(port, con, 1);
    } else {
	list_add_tail(&req->u.req.next, &port->recvq_any);
	/* ToDo: call con->set_read(port, con, 1) for
	   every connection */
    }
}

static
void PSP_recvq_check_any(PSP_Port_t *port)
{
    struct list_head *pos, *next;

    list_for_each_safe(pos, next, &port->recvq_any) {
	PSP_Req_t *req = list_entry(pos, PSP_Req_t, u.req.next);
	if (req->addr.from != (uint32_t)PSP_AnySender) {
	    list_del(&req->u.req.next);
	    PSP_enq_recv_req(port, req);// ToDo: bug!!!??? mueste nur list_add_tail(req, con->resvq) sonst deadlock!
	} else {
	    break;
	}
    }
}

static
PSP_Req_t *PSP_get_posted_recv_req(PSP_Port_t *port, PSP_Connection_t *con,
				   PSP_Header_Net_t *header, uint32_t from)
{
    struct list_head *pos;

    list_for_each(pos, &con->recvq) {
	PSP_Req_t *req = list_entry(pos, PSP_Req_t, u.req.next);
	if (req_cb_match(req, header, from)) {
	    list_del(&req->u.req.next);
	    return req;
	}
    }

    list_for_each(pos, &port->recvq_any) {
	PSP_Req_t *req = list_entry(pos, PSP_Req_t, u.req.next);
	if (((req->addr.from == from) ||
	     (req->addr.from == (uint32_t)PSP_AnySender)) &&
	    req_cb_match(req, header, from)) {
	    list_del(&req->u.req.next);
	    PSP_recvq_check_any(port);
	    return req;
	}
    }
    return NULL;
}

static
PSP_Req_t *PSP_generate_recv_req(PSP_Port_t *port, PSP_Connection_t *con,
				 PSP_Header_Net_t *nh, uint32_t from)
{
    PSP_Req_t *req;
//    PSP_Header_t *header;

    GenReqs++;

    /* freed inside PSP_genreq_merge() */
    req = malloc(sizeof(*req) + nh->xheaderlen + nh->datalen);

    D_TR(printf("PSP_generate request (state %p)\n", &req->u.req.state));

//    req->header = header;
    req->u.req.data = ((char *)req->nethead.xheader) + nh->xheaderlen;
    req->nethead.datalen = nh->datalen;
    req->nethead.xheaderlen = nh->xheaderlen;

    req->u.req.cb = PSP_RecvAny;
    req->u.req.cb_param = NULL;
    req->u.req.dcb = NULL;
    req->u.req.dcb_param = NULL;
    req->u.req.state = PSP_REQ_STATE_GENERATED;

    genreq_enq(port, con, req);

    return req;
}



static
void PSP_handle_recv_req(PSP_Port_t *port, PSP_Req_t *req)
{
    PSP_Req_t *genreq = genreq_get(port, req);

    if (!genreq) {
	PSP_enq_recv_req(port, req);
    } else {
	PSP_genreq_merge(port, req, genreq);
	exec_dcb(port);
    }
}


void PSP_update_sendq(PSP_Port_t *port, PSP_Connection_t *con)
{
    PSP_Req_t *req = con->out.req;
    if (req) {
	if (!req->u.req.iov_len) {
	    PSP_sendrequest_done(port, con, con->out.req);

	    if (list_empty(&con->sendq)) {
		con->out.req = NULL;
		con->set_write(port, con, 0);
		/* Dont do anything after this line.
		   con->set_write() can reenter PSP_update_sendq()! */
	    } else {
		con->out.req = list_entry(con->sendq.next, PSP_Req_t, u.req.next);
	    }
	}
    } else if (!list_empty(&con->sendq)) {
	con->out.req = list_entry(con->sendq.next, PSP_Req_t, u.req.next);
	con->set_write(port, con, 1);
	/* Dont do anything after this line.
	   con->set_write() can reenter PSP_update_sendq()! */
    }
}

void PSP_update_recvq(PSP_Port_t *port, PSP_Connection_t *con)
{
    PSP_Req_t *req = con->in.req;
    if (req && (!req->u.req.iov_len)) {
	PSP_recvrequest_done(port, con, req);
	con->in.req = NULL;
	/* ToDo: Stop receiving  con->set_read(port, con, 0); ?*/
    }
}


static
void PSP_enq_send_req(PSP_Port_t *port, PSP_Req_t *req)
{
    PSP_Connection_t *con = &port->con[req->addr.to % PSP_MAX_CONNS];

    list_add_tail(&req->u.req.next, &con->sendq);
    PSP_update_sendq(port, con);
}


void PSP_write_done(PSP_Port_t *port, PSP_Connection_t *con,
		    PSP_Req_t *req, unsigned int len)
{
    D_TR(printf("PSP_write_done(port, con, len=%u)\n", len));

    PSP_forward_iov(req->u.req.iov, len);
    req->u.req.iov_len -= len;
    PSP_update_sendq(port, con);
}


void PSP_read_done(PSP_Port_t *port, PSP_Connection_t *con,
		   PSP_Req_t *req, unsigned int len)
{
    D_TR(printf("PSP_read_done(port, con, len=%u)\n", len));

    PSP_forward_iov(req->u.req.iov, len);
    req->u.req.iov_len -= len;
    PSP_update_recvq(port, con);
}


static
PSP_Req_t *PSP_get_recv_req(PSP_Port_t *port, PSP_Connection_t *con,
			    PSP_Header_Net_t *nh)
{
    PSP_Req_t *req;
    uint32_t from = con->con_idx;

    req = PSP_get_posted_recv_req(port, con, nh, from);

    if (req) {
	PSP_req_prepare_recv(req, nh, from);

	return req;
    } else {
	req = PSP_generate_recv_req(port, con, nh, from);

	PSP_req_prepare_recv(req, nh, from);

	return req;
    }
}


static
int PSP_is_header_complete(PSP_Header_Net_t *nh, unsigned int len)
{
    return (len >= sizeof(*nh)) && (len >= nh->xheaderlen + sizeof(*nh));
}


void PSP_read_do(PSP_Port_t *port, PSP_Connection_t *con, void *buf, unsigned int len)
{
    unsigned int ret;
    PSP_Req_t *req = con->in.req;

    D_TR(printf("PSP_read_do(port, con, buf=%p, len=%u)\n", buf, len));

    if (req) {
	unsigned int _len;

	_len = PSP_req_read(req, buf, len);
	len -= _len;
	buf += _len;

	PSP_update_recvq(port, con);

	assert(!con->in.unreadlen);

	if (!len) return;

	assert(!con->in.req);
    }

    if (con->in.unreadlen) {
	PSP_Req_t *req = NULL;

	con->in.unreadbuf = realloc(con->in.unreadbuf, con->in.unreadlen + len);
	memcpy(((char *)con->in.unreadbuf) + con->in.unreadlen, buf, len);
	con->in.unreadlen += len;

	buf = con->in.unreadbuf;
	len = con->in.unreadlen;

	/* ToDo: this while loop and the one in the else part is the same */
	while (PSP_is_header_complete((PSP_Header_Net_t *)buf , len)) {
	    req = PSP_get_recv_req(port, con, (PSP_Header_Net_t *)buf);

	    ret = PSP_req_read(req, buf, len);
	    len -= ret;
	    buf += ret;

	    if (!req->u.req.iov_len) {
		PSP_recvrequest_done(port, con, req);
		req = NULL;
	    }
	}
	con->in.req = req;

	con->in.unreadlen = len;

	if (len) {
	    memmove(con->in.unreadbuf, buf, len);
	}
    } else {
	PSP_Req_t *req = NULL;

	while (PSP_is_header_complete((PSP_Header_Net_t *)buf , len)) {
	    req = PSP_get_recv_req(port, con, (PSP_Header_Net_t *)buf);

	    ret = PSP_req_read(req, buf, len);
	    len -= ret;
	    buf += ret;

	    if (!req->u.req.iov_len) {
		PSP_recvrequest_done(port, con, req);
		req = NULL;
	    }
	}
	con->in.req = req;

	con->in.unreadlen = len;

	if (len) {
	    con->in.unreadbuf = realloc(con->in.unreadbuf, len);
	    memcpy(con->in.unreadbuf, buf, len);
	}
    }
}

/*
 * connect
 */

static
PSP_Connection_t *PSP_con(PSP_Port_t *port, int con_idx)
{
    if ((unsigned int)con_idx < PSP_MAX_CONNS)
	return &port->con[con_idx];
    else
	/* illegal and/or negative con_idx */
	return NULL;
}

static
PSP_Connection_t *PSP_con_open(PSP_Port_t *port)
{
    int con_idx;
    /* Find a free conn */
    for(con_idx = 0; con_idx < PSP_MAX_CONNS ;con_idx++) {
	PSP_Connection_t *con = PSP_con(port, con_idx);
	if (con->state == PSP_CON_STATE_UNUSED) {
	    con->state = PSP_CON_STATE_OPEN;

	    return con;
	}
    }
    return NULL;
}


static
void _PSP_requests_disrupt(PSP_Port_t *port, struct list_head *q)
{
    struct list_head *pos, *next;

    if (list_empty(q)) return;

    list_for_each_safe(pos, next, q) {
	PSP_Req_t *req = list_entry(pos, PSP_Req_t, u.req.next);

	DPRINT(2, "%s: dequeue %p, state is %x",
	       __func__, req, req->u.req.state);
	req->u.req.state |= PSP_REQ_STATE_ERROR;
	if (req->u.req.dcb) {
	    /* Generated request (they use u.req.next) dont have a dcb! */
	    /* Delay the dcp execution */
	    list_add_tail(&req->u.req.next, &port->dcb_list);
	} else {
	    req->u.req.state |= PSP_REQ_STATE_PROCESSED;
	    list_del(&req->u.req.next);
	}
    }
}

static
void _PSP_con_terminate(PSP_Port_t *port, PSP_Connection_t *con)
{
    con->state = PSP_CON_STATE_UNUSED;
    con->set_write = no_set_write;
    con->set_read = no_set_read;

    _PSP_requests_disrupt(port, &con->sendq);
    _PSP_requests_disrupt(port, &con->recvq);
    _PSP_requests_disrupt(port, &con->genrecvq);

    /* @todo If this is a port's last connection, also disrupt any-requests */
}

void PSP_con_terminate(PSP_Port_t *port, PSP_Connection_t *con, int reason)
{
    /* never terminate loopback */
    if ((con->state == PSP_CON_STATE_OPEN_LOOP)||
	(con->state == PSP_CON_STATE_UNUSED)) return;

    DPRINT(1, "Connection %d (%s) : %s : %s",
	   con->con_idx, con_state(con->state), terminate_reason(reason),
	   reason != PSP_TERMINATE_REASON_LOCALCLOSE ? strerror(errno) : "");

    switch (con->state) {
    case PSP_CON_STATE_OPEN_LOOP: /* Do nothing */
	break;
    case PSP_CON_STATE_OPEN_TCP:
	PSP_terminate_con_tcp(port, con);
	break;
    case PSP_CON_STATE_OPEN_SHM:
	PSP_terminate_con_shm(port, con);
	break;
    case PSP_CON_STATE_OPEN_P4S:
	PSP_terminate_con_p4s(port, con);
	break;
#ifdef ENABLE_GM
    case PSP_CON_STATE_OPEN_GM:
	PSP_terminate_con_gm(port, con);
	break;
#endif
#ifdef ENABLE_MVAPI
    case PSP_CON_STATE_OPEN_MVAPI:
	PSP_terminate_con_mvapi(port, con);
	break;
#endif
#ifdef ENABLE_OPENIB
    case PSP_CON_STATE_OPEN_OPENIB:
	PSP_terminate_con_openib(port, con);
	break;
#endif
    default:
	DPRINT(0, "PSP_con_terminate() with state %s on con %d",
	       con_state(con->state), con->con_idx);
    }

    /* ToDo: call a user callback handler? */
    _PSP_con_terminate(port, con);
}

static
int mtry_connect(int sockfd, const struct sockaddr *serv_addr,
		 socklen_t addrlen)
{
/* In the case the backlog (listen) is smaller than the number of
   processes, the connect could fail with ECONNREFUSED even though
   there is a linstening socket. mtry_connect() retry four times
   the connect after one second delay.
*/
    int i;
    int ret = 0;
    struct sockaddr_in *sa = (struct sockaddr_in*)serv_addr;
    for (i = 0; i < env_retry; i++) {
	ret = connect(sockfd, serv_addr, addrlen);
	if (ret >= 0) break;
	if (errno != ECONNREFUSED) break;
	sleep(1);
	DPRINT(2, "Retry %d CONNECT to %s:%d",
	       i + 1,
	       inetstr(ntohl(sa->sin_addr.s_addr)),
	       ntohs(sa->sin_port));
    }
    return ret;
}

static
void tcp_configure(int fd)
{
    int ret;
    int val;

    if (env_so_sndbuf) {
	errno = 0;
	val = env_so_sndbuf;
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
	DPRINT(2, "setsockopt(%d, SOL_SOCKET, SO_SNDBUF, [%d], %ld) = %d : %s",
	       fd, val, (long)sizeof(val), ret, strerror(errno));
    }
    if (env_so_rcvbuf) {
	errno = 0;
	val = env_so_rcvbuf;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
	DPRINT(2, "setsockopt(%d, SOL_SOCKET, SO_RCVBUF, [%d], %ld) = %d : %s",
	       fd, val, (long)sizeof(val), ret, strerror(errno));
    }
    errno = 0;
    val = env_tcp_nodelay;
    ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
    DPRINT(2, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY, [%d], %ld) = %d : %s",
	   fd, val, (long) sizeof(val), ret, strerror(errno));

    ret = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (ret == -1) {
	DPRINT(1, "tcp_configure(): fcntl(%d, F_SETFL, O_NONBLOCK) failed : %s",
	       fd, strerror(errno));
    }
}

static
void PSP_ConInfo(PSP_Port_t *port, PSP_Connection_t *con, PSP_ConInfo_t *con_info)
{
    con_info->node_id = PSP_GetNodeID();
    con_info->pid = getpid();
    con_info->con_idx = con->con_idx;
}

static
void PSP_setup_connection(PSP_Port_t *port, PSP_Connection_t *con)
{
    /* ToDo: disable read, if no "any" and no "node specific" request
       is enqueued */
    con->set_read(port, con, 1);

    if (!list_empty(&con->sendq)) {
	con->set_write(port, con, 1);
    }
}

static
int PSP_Connect_tcp(PSP_PortH_t porth, struct sockaddr *sa, socklen_t addrlen)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Connection_t *con;
    int con_fd;
    int initialized = 0;
    PSP_ConInfo_t con_info;

    /* Open connection */

    con = PSP_con_open(port);
    if (!con) goto err_nofreecon;

    /* Open the socket */
    con_fd = socket(PF_INET , SOCK_STREAM, 0);
    if (con_fd < 0) goto err_socket;

    /* Connect */
    if (mtry_connect(con_fd, sa, addrlen) < 0) goto err_connect;

    tcp_configure(con_fd);

    /* exchange connection information */
    PSP_ConInfo(port, con, &con_info);

    PSP_writeall(con_fd, &con_info, sizeof(PSP_ConInfo_t));
    PSP_readall(con_fd, &con->remote_con_info, sizeof(PSP_ConInfo_t));

    /* Search for "best" connections */
    initialized = initialized || PSP_connect_shm(port, con, con_fd);
#ifdef ENABLE_MVAPI
    initialized = initialized || PSP_connect_mvapi(port, con, con_fd);
#endif
#ifdef ENABLE_OPENIB
    initialized = initialized || PSP_connect_openib(port, con, con_fd);
#endif
#ifdef ENABLE_GM
    initialized = initialized || PSP_connect_gm(port, con, con_fd);
#endif
    initialized = initialized || PSP_connect_p4s(port, con, con_fd);
    initialized = initialized || PSP_connect_tcp(port, con, con_fd);

    if (!initialized)
	goto err_init_failed;

    DPRINT(1, "CONNECT ("INET_ADDR_FORMAT",%d,%d) to ("INET_ADDR_FORMAT",%d,%d) via %s",
	   INET_ADDR_SPLIT(con_info.node_id), con_info.pid, con_info.con_idx,
	   INET_ADDR_SPLIT(con->remote_con_info.node_id),
	   con->remote_con_info.pid, con->remote_con_info.con_idx,
	   con_state(con->state));

    PSP_setup_connection(port, con);

    return con->con_idx;
    /* --- */
 err_init_failed:
    DPRINT(1, "CONNECT ("INET_ADDR_FORMAT",%d,%d) to ("INET_ADDR_FORMAT",%d,%d) FAILED",
	   INET_ADDR_SPLIT(con_info.node_id), con_info.pid, con_info.con_idx,
	   INET_ADDR_SPLIT(con->remote_con_info.node_id),
	   con->remote_con_info.pid, con->remote_con_info.con_idx);
    close(con_fd);
 err_connect:
 err_socket:
    _PSP_con_terminate(port, con);
    DPRINT(1, "CONNECT failed : %s", strerror(errno));
    return -1;
    /* --- */
 err_nofreecon:
    DPRINT(1, "CONNECT failed (no free connections)");
    errno = ENOMEM;
    return -1;
}

static
void PSP_Accept(ufd_t *ufd, int ufd_idx)
{
    PSP_Port_t *port = list_entry(ufd, PSP_Port_t, ufd);
    PSP_Connection_t *con;
    int con_fd;
    PSP_ConInfo_t con_info;

    /* Open connection */

    con = PSP_con_open(port);
    if (!con) goto err_nofreecon;

    /* Open the socket */
    con_fd = accept(port->listen_fd, NULL, NULL);
    if (con_fd < 0) goto err_accept;

    tcp_configure(con_fd);

    /* exchange connection information */
    PSP_ConInfo(port, con, &con_info);

    PSP_readall(con_fd, &con->remote_con_info, sizeof(PSP_ConInfo_t));
    PSP_writeall(con_fd, &con_info, sizeof(PSP_ConInfo_t));

    while (1) {
	int arch;

	if (PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch))
	    goto err_init_failed;

	switch (arch) {
	case PSP_ARCH_TCP:
	    if (PSP_accept_tcp(port, con, con_fd)) goto out;
	    break;
	case PSP_ARCH_SHM:
	    if (PSP_accept_shm(port, con, con_fd)) goto out;
	    break;
#ifdef ENABLE_MVAPI
	case PSP_ARCH_MVAPI:
	    if (PSP_accept_mvapi(port, con, con_fd)) goto out;
	    break;
#endif
#ifdef ENABLE_OPENIB
	case PSP_ARCH_OPENIB:
	    if (PSP_accept_openib(port, con, con_fd)) goto out;
	    break;
#endif
#ifdef ENABLE_GM
	case PSP_ARCH_GM:
	    if (PSP_accept_gm(port, con, con_fd)) goto out;
	    break;
#endif
	case PSP_ARCH_P4S:
	    if (PSP_accept_p4s(port, con, con_fd)) goto out;
	    break;
	default:
	    arch = PSP_ARCH_ERROR;
	    PSP_writeall(con_fd, &arch, sizeof(arch));
	}
    }
 out:
    DPRINT(1, "ACCEPT  ("INET_ADDR_FORMAT",%d,%d) to ("INET_ADDR_FORMAT",%d,%d) via %s",
	   INET_ADDR_SPLIT(con->remote_con_info.node_id),
	   con->remote_con_info.pid, con->remote_con_info.con_idx,
	   INET_ADDR_SPLIT(con_info.node_id), con_info.pid, con_info.con_idx,
	   con_state(con->state));

    PSP_setup_connection(port, con);
    return;
    /* --- */
 err_init_failed:
    close(con_fd);
 err_accept:
    _PSP_con_terminate(port, con);
    DPRINT(1, "ACCEPT failed : %s", strerror(errno));
    return;
    /* --- */
 err_nofreecon:
    DPRINT(1, "ACCEPT failed (no free connections)");
    return;
}


static void
intgetenv(int *val, char *name)
{
    char *aval;

    aval = getenv(name);
    if (aval) {
	*val = atoi(aval);
	DPRINT(1, "set %s = %d", name, *val);
    } else {
	DPRINT(2, "default %s = %d", name, *val);
    }
}

static
void init_env(void)
{
    intgetenv(&env_debug, ENV_DEBUG);
    DPRINT(1,"# Version(PS4B): %s", vcid);
    intgetenv(&env_so_sndbuf, ENV_SO_SNDBUF);
    intgetenv(&env_so_rcvbuf, ENV_SO_RCVBUF);
    intgetenv(&env_tcp_nodelay, ENV_TCP_NODELAY);
    intgetenv(&env_sharedmem, ENV_SHAREDMEM);
    intgetenv(&env_p4sock, ENV_P4SOCK);
#ifdef ENABLE_MVAPI
    intgetenv(&env_mvapi, ENV_MVAPI);
#endif
#ifdef ENABLE_OPENIB
    intgetenv(&env_openib, ENV_OPENIB);
#endif
#ifdef ENABLE_GM
    intgetenv(&env_gm, ENV_GM);
#endif
//    intgetenv(&env_nobgthread, ENV_NOBGTHREAD);
    intgetenv(&env_sigquit, ENV_SIGQUIT);
    intgetenv(&env_readahead, ENV_READAHEAD);
    intgetenv(&env_retry, ENV_RETRY);
    env_readahead = PSP_MAX(env_readahead, (int)sizeof(PSP_Header_Net_t));
}


static
void print_request_queue(struct list_head *q)
{
    struct list_head *pos;
    int pid = getpid();
    int i = 1;

    list_for_each(pos, q) {
	PSP_Req_t *req = list_entry(pos, PSP_Req_t, u.req.next);
	_DPRINT("  %3d Req addr %3d (state %p %08x) head %d buf %d", pid, i,
		req->addr.from, &req->u.req.state, req->u.req.state,
		req->nethead.xheaderlen, req->nethead.datalen);
	i++;
    }
}


void PSP_info(void)
{
    int pid = getpid();
    int i;
    struct list_head *pos;

    list_for_each(pos, &PSP_Ports) {
	PSP_Port_t *port = list_entry(pos, PSP_Port_t, next_port);
	_DPRINT(" ----- listen_fd %d on port %d", pid, port->listen_fd, port->portno);
	_DPRINT(" GenReq:%d (%d)", pid, GenReqs - GenReqsUsed, GenReqs);

	for (i = 0; i < PSP_MAX_CONNS; i++) {
	    PSP_Connection_t *con = &port->con[i];
	    if (con->state != PSP_CON_STATE_UNUSED) {
		PSP_ConInfo_t con_info;
		PSP_ConInfo(port, con, &con_info);
		_DPRINT(" %4d %5s ("INET_ADDR_FORMAT",%d,%d) to ("INET_ADDR_FORMAT",%d,%d)",
			pid, i, con_state(con->state),
			INET_ADDR_SPLIT(con_info.node_id), con_info.pid, con_info.con_idx,
			INET_ADDR_SPLIT(con->remote_con_info.node_id),
			con->remote_con_info.pid, con->remote_con_info.con_idx);
		if (env_debug > 1) {
		    if (!list_empty(&con->sendq)) {
			_DPRINT(" Sendq:", pid);
			print_request_queue(&con->sendq);
		    }
		    if ((!list_empty(&con->recvq)) || con->in.unreadlen) {
			_DPRINT(" Recvq: (unread %d)", pid, con->in.unreadlen);
			print_request_queue(&con->recvq);
		    }
		    if (!list_empty(&con->genrecvq)) {
			_DPRINT(" GenReqq:", pid);
			print_request_queue(&con->genrecvq);
		    }
		}
	    }
	}
	if ((env_debug > 1) && (!list_empty(&port->recvq_any))) {
	    _DPRINT(" Recvq any:", pid);
	    print_request_queue(&port->recvq_any);
	}
    }
}

static
void PSP_sigquit(int sig)
{
    int pid = getpid();
    _DPRINT(" +++++++++ SIGQUIT START ++++ ", pid);
    PSP_info();
    _DPRINT(" +++++++++ SIGQUIT END ++++++ ", pid);
}


/*
 * poport4 API implementation
 */


void PSP_StopListen(PSP_PortH_t porth)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;

    if (port->listen_fd < 0) return;

    ufd_del(&port->ufd, port->listen_fd);

    close(port->listen_fd);
    port->listen_fd = -1;
}

int PSP_Connect(PSP_PortH_t porth, int nodeid, int portno)
{
    struct sockaddr_in si;

    /* Initial connection via TCP */
    si.sin_family = PF_INET;
    si.sin_port = htons(portno);
    si.sin_addr.s_addr = htonl(nodeid);

    return PSP_Connect_tcp(porth, (struct sockaddr *)&si, sizeof(si));
}

int PSP_RecvAny(PSP_Header_Net_t* header, int from, void *param)
{
    return 1;
}

int PSP_RecvFrom(PSP_Header_Net_t* header, int from, void *param)
{
    PSP_RecvFrom_Param_t *p = (PSP_RecvFrom_Param_t *)param;
    return from == p->from;
}

PSP_RequestH_t PSP_IReceiveCBFrom(PSP_PortH_t porth,
				  void *buf, unsigned buflen,
				  PSP_Header_t *header, unsigned xheaderlen,
				  PSP_RecvCallBack_t *cb, void *cb_param,
				  PSP_DoneCallback_t *dcb, void *dcb_param,
				  int sender)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Req_t *req = (PSP_Req_t *)header;

    D_TR(printf("PSP_IRecv from %d    (state %p) x %d head %u buf %u\n",
		sender, &req->u.req.state, (int)sizeof(PSP_Header_Net_t), xheaderlen, buflen));

//    perf_add("IRECV");

    if (!cb) cb = PSP_RecvAny;

    req->u.req.data = buf;
    req->u.req.cb = cb;
    req->u.req.cb_param = cb_param;
    req->u.req.dcb = dcb;
    req->u.req.dcb_param = dcb_param;
    req->u.req.state = PSP_REQ_STATE_RECV;

    req->addr.from = sender;

    req->nethead.xheaderlen = xheaderlen;
    req->nethead.datalen = buflen;

    /* Warning PSP_handle_recv_req() can call exec_dcb! */
    PSP_handle_recv_req(port, req);

    return (PSP_RequestH_t)req;
}


static
int PSP_do_sendrecv(PSP_Port_t *port, int timeout)
{

//    sleep(3);
    if (!list_empty(&port->shm_list)) {
	/* look inside sharemem regions */
	if (PSP_do_sendrecv_shm(port))
	    return 1;
	/* switch to polling mode */
	timeout = 0;
    }
#ifdef ENABLE_MVAPI
    if (!list_empty(&port->mvapi_list)) {
	if (PSP_do_sendrecv_mvapi(port))
	    return 1;
	/* switch to polling mode */
	timeout = 0;
    }
#endif
#ifdef ENABLE_OPENIB
    if (!list_empty(&port->openib_list)) {
	if (PSP_do_sendrecv_openib(port))
	    return 1;
	/* switch to polling mode */
	timeout = 0;
    }
#endif
#ifdef ENABLE_GM
    if (!list_empty(&port->gm_list)) {
	if (PSP_do_sendrecv_gm(port))
	    return 1;
	/* switch to polling mode */
	timeout = 0;
    }
#endif

    return ufd_poll(&port->ufd, timeout);
}

PSP_RequestH_t PSP_ISend(PSP_PortH_t porth,
			 void *buf, unsigned buflen,
			 PSP_Header_t *header, unsigned xheaderlen,
			 int dest, int flags)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Req_t *req = (PSP_Req_t *)header;

    D_TR(printf("PSP_Isend to %d      (state %p) x %d head %u buf %u\n",
		dest, &req->u.req.state, (int)sizeof(PSP_Header_Net_t), xheaderlen, buflen));

//    perf_add("ISEND");

    req->u.req.data = buf;
    req->u.req.flags = flags;
    req->u.req.state = PSP_REQ_STATE_SEND;

    req->addr.to = dest;

    req->nethead.xheaderlen = xheaderlen;
    req->nethead.datalen = buflen;

    PSP_req_init_iov(req, 0);

    PSP_enq_send_req(port, req); /* depending on connection, this
				    will send data! */

    exec_dcb(port); /* Loopback could enqueue one done callback! */

    return (PSP_RequestH_t)req;
}

PSP_Status_t PSP_Wait(PSP_PortH_t porth, PSP_RequestH_t request)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Req_t *req = (PSP_Req_t *)request;
    int timeout = 0;
    D_TR(printf("Enter Wait           (state %p)\n", &req->u.req.state));

//    perf_add("WAIT");

    while (!(req->u.req.state & PSP_REQ_STATE_PROCESSED)) {
	{ /* Magic for smp machines....*/
	    volatile int i;
	    for (i = 0; i < 3; i ++);
	}
	/* first loop just look nonblocking */
	PSP_do_sendrecv(port, timeout);
	timeout = -1;
	exec_dcb(port);
    }
    D_TR(printf("Leave Wait           (state %p)\n", &req->u.req.state));
//    perf_add("WAITdone");

    return (req->u.req.state & PSP_REQ_STATE_ERROR) ? PSP_CANCELED:PSP_SUCCESS;
}

PSP_Status_t PSP_Test(PSP_PortH_t porth, PSP_RequestH_t request)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Req_t *req = (PSP_Req_t *)request;

    PSP_do_sendrecv(port, 0);
    exec_dcb(port);

    if (req->u.req.state & PSP_REQ_STATE_PROCESSED) {
	return PSP_SUCCESS;
    } else {
	return PSP_NOT_COMPLETE;
    }
}

PSP_Status_t PSP_Cancel(PSP_PortH_t porth, PSP_RequestH_t request)
{
    static int cancelwarn = 0;
    if (!cancelwarn)
	fprintf(stderr, "PSP_Cancel() not implemented yet\n");
    cancelwarn = 1;
    return PSP_SUCCESS;
}

int PSP_IProbeFrom(PSP_PortH_t porth,
		   PSP_Header_t* header, unsigned xheaderlen,
		   PSP_RecvCallBack_t *cb, void* cb_param,
		   int sender)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Req_t *req;

    PSP_do_sendrecv(port, 0);
    exec_dcb(port);

    if (!cb) cb = PSP_RecvAny;

    req = genreq_probe(port, cb, cb_param, sender);
    if (req && header) {
	memcpy(PSP_HEADER_NET(header),
	       &req->nethead,
	       PSP_HEADER_NET_LEN +
	       PSP_MIN(xheaderlen, req->nethead.xheaderlen));
	header->addr.from = req->addr.from;
    }

    return (req != NULL);
}

int PSP_ProbeFrom(PSP_PortH_t porth,
		  PSP_Header_t* header, unsigned xheaderlen,
		  PSP_RecvCallBack_t *cb, void* cb_param,
		  int sender)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Req_t *req;

    if (!cb) cb = PSP_RecvAny;

    req = genreq_probe(port, cb, cb_param, sender);
    while (!req) {
	PSP_do_sendrecv(port, -1);
	exec_dcb(port);
	req = genreq_probe(port, cb, cb_param, sender);
    }

    if (header) {
	memcpy(PSP_HEADER_NET(header),
	       &req->nethead,
	       PSP_HEADER_NET_LEN +
	       PSP_MIN(xheaderlen, req->nethead.xheaderlen));
	header->addr.from = req->addr.from;
    }

    return 1;
}


int PSP_GetNodeID(void)
{
    static uint32_t id = 0;
    /*  p4s_node_id(void) expect the IP of this node! */

    if (!id) {
	id = psp_getid(); /* Use env PSP_NETWORK to get an IP */
    }
    return id;
}

int PSP_GetPortNo(PSP_PortH_t porth)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    return port->portno;
}

/* deprecated Interface */
unsigned int PSP_UsedHW(void)
{
    return 0x0000; /* Any */
}

char **PSP_HWList(void)
{
    static char *HWList[] = {
	"ethernet",
	"p4sock",
#ifdef ENABLE_MVAPI
	"mvapi",
#endif
#ifdef ENABLE_OPENIB
	"openib",
#endif
#ifdef ENABLE_GM
	"gm",
#endif
	NULL
    };

    return HWList;
}


int PSP_GetConnectionState(PSP_PortH_t porth, int dest, PSP_ConnectionState_t *cs)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    PSP_Connection_t *con = &port->con[(unsigned)dest % PSP_MAX_CONNS];

    if (cs) {
	PSP_ConInfo(port, con, &cs->local);
	memcpy(&cs->remote, &con->remote_con_info, sizeof(cs->remote));
    }
    return con->state;
}


const char *PSP_ConState_str(int state)
{
    return con_state(state);
}


static
void PSP_set_write_loop(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
    if (!start) return;

    while (start && (!list_empty(&con->sendq))) {
	PSP_Req_t *req = list_entry(con->sendq.next, PSP_Req_t, u.req.next);

	PSP_read_do(port, con, &req->nethead,
		    (unsigned)sizeof(req->nethead) + req->nethead.xheaderlen);
	PSP_read_do(port, con, req->u.req.data, req->nethead.datalen);

	req->u.req.iov_len = 0;

	PSP_update_sendq(port, con);
    }
}

static
void PSP_init_con_loopback(PSP_Port_t *port)
{
    PSP_Connection_t *con = &port->con[PSP_DEST_LOOPBACK % PSP_MAX_CONNS];
    con->state = PSP_CON_STATE_OPEN_LOOP;
    con->con_idx = PSP_DEST_LOOPBACK;

    PSP_ConInfo(port, con, &con->remote_con_info);

    con->set_write = PSP_set_write_loop;
}


PSP_PortH_t PSP_OpenPort(int portno)
{
    PSP_Port_t *port;
    struct sockaddr_in sa;
    unsigned int size;
    int idx;

    port = PSP_calloc_port();
    if (!port) goto err_alloc;

    port->listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (port->listen_fd < 0) goto err_socket;

    sa.sin_family = AF_INET;
    sa.sin_port = (portno == PSP_ANYPORT) ? 0 : htons(portno);
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(port->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	goto err_bind;

    size = sizeof(sa);
    if (getsockname(port->listen_fd, (struct sockaddr *)&sa, &size) < 0)
	goto err_getsockname;

    if (listen(port->listen_fd, 64) < 0)
	goto err_listen;

    port->portno = ntohs(sa.sin_port);

    idx = ufd_add(&port->ufd, port->listen_fd, PSP_Accept, NULL, NULL, NULL, NULL);
    ufd_event_set(&port->ufd, idx, POLLIN);

    PSP_init_con_loopback(port);

    list_add_tail(&port->next_port, &PSP_Ports);

    return (PSP_PortH_t)port;
    /* --- */
 err_listen:
 err_getsockname:
 err_bind:
    close(port->listen_fd);
    port->listen_fd = -1;
 err_socket:
    free(port);
 err_alloc:
    DPRINT(1, "PSP_OpenPort() failed : %s", strerror(errno));
    return NULL;
}

PSP_Err_t PSP_ClosePort(PSP_PortH_t porth)
{
    PSP_Port_t *port = (PSP_Port_t *)porth;
    int i;

    if (env_debug > 1)
	PSP_info();

    PSP_StopListen(porth);

    /* ToDo: Cleanup all requests!!! */

    for (i = 0; i < PSP_MAX_CONNS; i++) {
	if (port->con[i].state != PSP_CON_STATE_UNUSED) {
	    /* ToDo: Flush all buffers! */
	    PSP_con_terminate(port, &port->con[i], PSP_TERMINATE_REASON_LOCALCLOSE);
	}
    }

    list_del_init(&port->next_port);

    free(port);

    return 0;
}


PSP_Err_t PSP_Init(void)
{
    static int init=0;

    if (init) return 0;
    init = 1;

    init_env();

    if (env_sigquit)
	signal(SIGQUIT, PSP_sigquit);

    /*
      printf("sizeof(PSP_Request_t) = %d\n", (int)sizeof(PSP_Request_t));
      printf("sizeof(PSP_Req_t) = %d\n", (int)sizeof(PSP_Req_t));

      printf("dcb offset PSP_Request_s %ld\n", soffset(PSP_Request_T, dcb));
      printf("dcb offset PSP_Req_s     %ld\n", soffset(PSP_Req_s, u.req.dcb));
      printf("sizeof(PSP_Header_t) = %d\n", (int)sizeof(PSP_Header_t));
      printf("sizeof(PSP_Connection_t) = %d\n", (int)sizeof(PSP_Connection_t));
    */
    if (&(((PSP_Header_t *)NULL)->xheaderlen) != &((PSP_Req_t *)NULL)->nethead.xheaderlen) {
	fprintf(stderr, "Internal error in psport : xheaderlen position\n");
	exit(1);
    }
    return 0;
}
