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
/*
 * psport_priv.h: internel psport4 Header
 */

#ifndef _PSPORT_PRIV_H_
#define _PSPORT_PRIV_H_
#include "list.h"
#include "psport4.h"
#include "psport_types.h"

#include "psport_p4s.h"
#include "psport_shm.h"
#include "psport_tcp.h"

#include "psport_ufd.h"
#ifdef ENABLE_MVAPI
#include "psport_mvapi.h"
#endif
#ifdef ENABLE_OPENIB
#include "psport_openib.h"
#endif
#ifdef ENABLE_GM
#include "psport_gm.h"
#endif

#define PSP_MAX_CONNS 4096
#if PSP_MAX_CONNS >= PSP_DEST_LOOPBACK
#error PSP_MAX_CONNS to big
#endif

#define PSP_ARCH_ERROR 1
#define PSP_ARCH_LOOP  2
#define PSP_ARCH_TCP   3
#define PSP_ARCH_SHM   4
#define PSP_ARCH_P4S   5
#define PSP_ARCH_GM    6
#define PSP_ARCH_MVAPI 7
#define PSP_ARCH_OPENIB 8


#define PSP_TERMINATE_REASON_REMOTECLOSE 0
#define PSP_TERMINATE_REASON_LOCALCLOSE 0

#define PSP_TERMINATE_REASON_WRITE_FAILED 1
#define PSP_TERMINATE_REASON_READ_FAILED  2


struct PSP_Connection_s {
    int			state;
    struct list_head	sendq;
    struct list_head	recvq;
    struct list_head	genrecvq; /* list of generated receive requests */

    void (*set_write)(PSP_Port_t *port, PSP_Connection_t *con, int start);
    void (*set_read)(PSP_Port_t *port, PSP_Connection_t *con, int start);

    uint32_t	con_idx;
    struct {
	PSP_Req_t *req;
	void *unreadbuf;
	int unreadlen;
    } in;
    struct {
	PSP_Req_t *req;
    } out;

    union {
	PSP_ConnTCP_t	tcp;
	shm_info_t	shm;
	p4s_info_t	p4s;
#ifdef ENABLE_MVAPI
	psib_info_t	mvapi;
#endif
#ifdef ENABLE_OPENIB
	psoib_info_t	openib;
#endif
#ifdef ENABLE_GM
	psgm_info_t	gm;
#endif
    }			arch;
    PSP_ConInfo_t	remote_con_info;

    struct list_head	next_port;
};

struct PSP_Port_s {
    struct list_head next_port;

    struct list_head recvq_any;
    struct list_head genrecvq_any;

    int	 portno;
    int	 listen_fd;

    PSP_Connection_t con[PSP_MAX_CONNS];

    ufd_t	ufd;

    /* Shared Mem */
    struct list_head shm_list;
    struct list_head shm_list_send;

    /* Done callbacks */
    struct list_head dcb_list;

    /* P4sock */
    int		p4s_fd;
    int		p4s_users;
    int		p4s_ufd_idx;
    int		p4s_p4sconidx_cnt;
    PSP_Connection_t	**p4s_conidx;
    struct sockaddr_p4 p4s_sockaddr;
    PSP_Connection_t *p4s_cur_recv;
    struct list_head p4s_con_sendq;

#ifdef ENABLE_MVAPI
    /* MVapi */

    int mvapi_users;
    struct list_head mvapi_list;
    struct list_head mvapi_list_send;
#endif
#ifdef ENABLE_OPENIB
    /* OpenIB */

    int openib_users;
    struct list_head openib_list;
    struct list_head openib_list_send;
#endif
#ifdef ENABLE_GM
    /* GM */
    int			gm_users; /* gm user count */
    struct list_head	gm_list;
    struct list_head	gm_list_send; /* list head of connections with pending send requests */
#endif
};

/* compatibility request struct to old PSP_Request_t */
struct PSP_Req_s {
    union {
	PSP_Request_t	_old_req;
	struct {
	    struct list_head next;
	    int                 state;
	    int flags;
	    PSP_RecvCallBack_t	*cb;		/*< Callback to check message */
	    void		*cb_param;
	    PSP_DoneCallback_t	*dcb;
	    void		*dcb_param;
	    void		*data; /* Pointer do data */
#define PSP_IOV_BUFFERS	    3
	    struct iovec	iov[PSP_IOV_BUFFERS];
	    unsigned int	iov_len; /* Bytes in iov */
	    struct list_head gen_next_any;
	} req;
    } u;
    union{
	uint32_t	from;
	uint32_t	to;
	long		_align_long_; /* align xheaderlen (nethead) to long */
    } addr;
    PSP_Header_Net_t	nethead;
};

#define PSP_REQ_STATE_FREE		0
/* Recv request */
#define PSP_REQ_STATE_RECV		0x0001
/* Send request */
#define PSP_REQ_STATE_SEND		0x0002

#define PSP_REQ_STATE_GENERATED		0x0004

/* PROCESSED is set, if request is finished */
#define PSP_REQ_STATE_PROCESSED		0x8000

/* ERROR is set, if request finished due to an error, i.e. connection closed */
#define PSP_REQ_STATE_ERROR             0x4000

//#define PSP_REQ_STATE_MASK		0x00f0

/* Recv request states: */
//#define PSP_REQ_STATE_RECVPOSTED	0x0010
//#define PSP_REQ_STATE_RECVING		0x0020
//#define PSP_REQ_STATE_RECVCANCELED	0x0030
//#define PSP_REQ_STATE_RECVSHORTREAD     0x0040
//#define PSP_REQ_STATE_RECVOK		0x0050
//#define PSP_REQ_STATE_RECVGEN		0x0060
//#define PSP_REQ_STATE_RECVING2		0x0070

/* Send request states: */
//#define PSP_REQ_STATE_SENDPOSTED	0x0010
//#define PSP_REQ_STATE_SENDING		0x0020
//#define PSP_REQ_STATE_SENDOK		0x0040
//#define PSP_REQ_STATE_SENDNOTCON	0x0050

//#ifdef PSP_ENABLE_MAGICREQ
//#define PSP_MAGICREQ_MASK		0x7fff0000
//#define PSP_MAGICREQ_VALID		0x3e570000
//#else
//#define PSP_MAGICREQ_VALID		0x00000000
//#endif

#define PSP_MIN(a,b)      (((a)<(b))?(a):(b))
#define PSP_MAX(a,b)      (((a)>(b))?(a):(b))

extern int env_sharedmem;
extern int env_p4sock;
extern int env_mvapi;
extern int env_openib;
extern int env_gm;
extern int env_debug;

#define PSP_DPRINT_LEVEL 0

#define _DPRINT(fmt,pid,arg... ) do{			\
	fprintf(stderr, "<PSP%5d:"fmt">\n",pid ,##arg);	\
}while(0);

#define DPRINT(level,fmt,arg... ) do{				\
    if ((level)<=env_debug){					\
	fprintf(stderr, "<PSP%5d:"fmt">\n",getpid() ,##arg);	\
	fflush(stderr);						\
    }								\
}while(0);

int PSP_readall(int fd, void *buf, int count);
int PSP_writeall(int fd, const void *buf, int count);

void PSP_read_done(PSP_Port_t *port, PSP_Connection_t *con,
		   PSP_Req_t *req, unsigned int len);
void PSP_read_do(PSP_Port_t *port, PSP_Connection_t *con, void *buf, unsigned int len);

void PSP_write_done(PSP_Port_t *port, PSP_Connection_t *con,
		    PSP_Req_t *req, unsigned int len);
void PSP_update_sendq(PSP_Port_t *port, PSP_Connection_t *con);

void PSP_sendrequest_done(PSP_Port_t *port, PSP_Connection_t *con, PSP_Req_t *req);

/* reason should be one of PSP_TERMINATE_REASON_*.
   if reason != PSP_TERMINATE_REASON_REMOTECLOSE, errno must be set.
*/
void PSP_con_terminate(PSP_Port_t *port, PSP_Connection_t *con, int reason);

//#define D_TR(x) x
#define D_TR(x)

static inline
void PSP_memcpy_from_iov(char *data, struct iovec *iov, size_t len)
{
    while (len > 0) {
	if (iov->iov_len) {
	    size_t copy = PSP_MIN(len, iov->iov_len);
	    memcpy(data, iov->iov_base, copy);
	    len -= copy;
	    data += copy;
	    iov->iov_base += copy;
	    iov->iov_len -= copy;
	}
	iov++;
    }
}

/* iovlen : number of blocks in iov. return bytelen of iov */
static inline
size_t PSP_iovec_len(struct iovec *iov, size_t iovlen)
{
    size_t len = 0;
    while (iovlen) {
	len += iov->iov_len;
	iov++;
	iovlen--;
    }
    return len;
}

static inline
void PSP_memcpy_to_iov(struct iovec *iov, char *data, size_t len)
{
    while (len > 0) {
	if (iov->iov_len) {
	    size_t copy = PSP_MIN(len, iov->iov_len);
	    memcpy(iov->iov_base, data, copy);
	    len -= copy;
	    data += copy;
	    iov->iov_base += copy;
	    iov->iov_len -= copy;
	}
	iov++;
    }
}

static inline
void PSP_forward_iov(struct iovec *iov, size_t len)
{
    while (len > 0) {
	if (iov->iov_len) {
	    size_t copy = PSP_MIN(len, iov->iov_len);
	    len -= copy;
	    iov->iov_base += copy;
	    iov->iov_len -= copy;
	}
	iov++;
    }
}

static inline
void PSP_memcpy_from_iov_const(char *data, struct iovec *iov, size_t len)
{
    while (len > 0) {
	if (iov->iov_len) {
	    size_t copy = PSP_MIN(len, iov->iov_len);
	    memcpy(data, iov->iov_base, copy);
	    len -= copy;
	    data += copy;
	}
	iov++;
    }
}

/* Somewhere in the middle of the GCC 2.96 development cycle, we implemented
   a mechanism by which the user can annotate likely branch directions and
   expect the blocks to be reordered appropriately.  Define __builtin_expect
   to nothing for earlier compilers.  */
#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif

#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)


#endif /* _PSPORT_PRIV_H_ */
