/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2002 Jens Hauke <hauke@wtal.de>
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Authors:	Jens Hauke <hauke@par-tec.com>
 *		Jens Hauke <hauke@wtal.de> (2002-03-27)
 */

#ifndef  _P4PROT_H_
#define  _P4PROT_H_

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/uio.h>
#include <linux/spinlock.h>
#include "p4s_debug.h"
#include "p4io.h"
#include "p4sockets.h"
#include "p4linux.h"
#include "p4prot_pub.h"
#include "p4proc.h"


#define P4TYPE_SYN	0
#define P4TYPE_SYNACK	1
#define P4TYPE_DAT	2
#define P4TYPE_ACK	3
#define P4TYPE_CTRL	4

#define P4TYPESTRS {"SYN","SYNACK","DAT","ACK","CTRL"}

extern char *p4_typestrs[];

#define P4TYPESTR(t)				\
  ((unsigned int)(t) < 5 ?			\
   p4_typestrs[(unsigned int)(t)] : "???")



/* connection request */
typedef struct p4msg_syn_s {
    /* p4prot */
    uint16_t	cifrom;		/* sender ci_idx */
    p4_addr_t	destname;	/* remote search for this name and answer with ci_idx */
    p4_seqno_t	seqno;		/* Initial sequencenumber */
    p4_remaddr_t destsaddr;	/* destination server address */
    /* somtimes communicator dependent data */
/*    char abc[100];*/
} p4msg_syn_t;

/* connection response */
typedef struct p4msg_synack_s {
    /* p4prot */
    uint16_t	cito;		/* receiver ci_idx */
    uint16_t	cifrom;		/* sender ci_idx */
    p4_seqno_t	seqno;		/* Initial sequencenumber */
    p4_seqno_t	ackno;		/* seqno of SYN message */
    uint16_t	error;		/* errorcode if syn fails */
} p4msg_synack_t;


typedef struct p4msg_ack_s {
    uint16_t	cito;
    p4_seqno_t	ackno;
    p4_seqno_t	winsize;
    uint16_t	resend;
}p4msg_ack_t;

typedef struct p4msg_data_header_s {
    uint16_t	cito;
    p4_seqno_t	seqno;
    p4_seqno_t	ackno;
    p4_seqno_t	winno;
    uint16_t	len;
    uint16_t	flags;
} p4msg_data_header_t;

typedef struct p4msg_ctrl_s {
    uint16_t	type; /* One of P4TYPE_... e.g. P4TYPE_SYN */
    union {
	p4msg_syn_t	syn;
	p4msg_synack_t	synack;
	p4msg_ack_t	ack;
	p4msg_data_header_t dat;
    } t;
} p4msg_ctrl_t;

#define P4_CTRLMSGSIZE(name) (sizeof(p4msg_ctrl_t) -	\
       sizeof(((p4msg_ctrl_t*)0)->t) +			\
       sizeof(((p4msg_ctrl_t*)0)->t.name))

static inline int p4_seqcmp(p4_seqno_t a, p4_seqno_t b)
{
    return (int16_t)(a-b);
}

/* remote server information */
typedef struct p4_remserv_local_s {
}p4_remserv_local_t;

typedef struct p4_remserv_ether_s {
    union {
	uint8_t	 mac[IFHWADDRLEN];
	uint32_t ipaddr; /* should be: in_addr_t */
    }addr;
    struct net_device *netdev; /* netdev == NULL mean: Use ipaddr */
}p4_remserv_ether_t;

typedef struct p4_remserv_myri_s {
    uint32_t	nodeid;
}p4_remserv_myri_t;

typedef struct p4_remserv_s {
    union{
	p4_remserv_local_t local;
	p4_remserv_ether_t ether;
	p4_remserv_myri_t  myri;
    } tec;
}p4_remserv_t;


typedef struct p4_ci_send_s {
    /* Sendqueues */
    struct list_head SFragQ;

    /* Reliable part sending */
    p4_seqno_t	SSeqNo;  /* Next new packet get this SSeqNo */
    p4_seqno_t	SWindow; /* Send until (including) SWindow */
    p4_seqno_t  SAckNo;  /* Ack until (including) SAckNo */
    p4_seqno_t  SUntil;  /* Packets until (including) SUntil transmitted
			      at least one time. Or: Packets from
			      SUntil (excluded) wait for send */

    int		Sacks_waiting; /* true, if SFragQ include acked packets */

    atomic_t	sendcnt;	/* Retransmissioncnt of SYN */

    int		call_continue_send;
    p4_spinlock_t	SSeqLock; /* Lock SFragQ */
    struct semaphore	SendLock; /* Lock SeqNo. (not more than one message at time per ci) */
    struct timer_list resend_timer;
} p4_ci_send_t;


typedef struct p4_ci_recv_s {
    /* Reliable part receiving */
    p4_seqno_t	RSeqNo;
    p4_seqno_t	RWindow;
    atomic_t	Racks_waiting; /* true
				  , if acks should be send */
    int		Rresend; /* Next Ack with resend flag */

    /* Receivequeues */
    struct list_head RFragQ;
    struct list_head RFragQ_oo; /* Out of order */
    struct list_head NextCi;

    struct timer_list ack_timer;

    /* parameters for a delayed p4_ack (valid if call_p4 != 0) */
    int		call_p4;
    int		resend;
} p4_ci_recv_t;

#define CI_STATE_ESTAB		0
#define CI_STATE_CLOSED		1
#define CI_STATE_SYNSENT	2

#define CI_STATE_SBROKEN	3 /* resend failed multiple times */

#define CI_STATE_CLOSEING	4
#define CI_STATE_SBROKEN_CLOSEING	5 /* resend FIN failed multiple times */
//#define CI_STATE_CLOSEWAIT	5

#define CI_STATE_SET(ci, newstate) do {							\
    (ci)->state = (newstate);								\
    DP_CISTATE("%s(): %d ci %p -> State " #newstate"\n", __FUNCTION__, __LINE__, (ci));	\
} while (0)


/* connection info */
typedef struct p4_ci_s {
    struct p4_socket_s		*socket;
    struct p4_net_opts_s	*net_opts;

    atomic_t refcnt;  /* refcnt of this struct */

    p4_ci_send_t s; /* Send */
    p4_ci_recv_t r; /* Receive */

    int16_t	rem_net_idx;
    /* Data for the network module */
    p4_remserv_t rem_saddr;	/* remote socket address (depends on net_opts) */

    /* Protocolpart */
    int16_t	list_usr_idx; /* index inside socket->ci_list_usr[] */
    int16_t	list_net_idx; /* index inside p4_net.ci_list_net[] */
    p4_addr_t	rem_addr;	/* remote p4 address */

    int		state;
    /* private to p4ether/p4myri */
    atomic_t	dev_SendQsize;
    union {
	struct {
	    int		mtu; /* Used MTU */
	} eth;
    } u;
    unsigned int magic;
} p4_ci_t;

#define CI_MAGIC 0x4163ae21

#define P4_CONNBROKEN 1
// ToDo:
//void p4_send_usrctrl_cantsend(p4_ci_t *ci, int reason);
#define p4_send_usrctrl_cantsend(ci,reason)

/* Fragment flags */
typedef enum p4_fflags_e {
    P4_FFLAGS_LASTFRAG = 1
} p4_fflags_t;

/* Fragment info */
typedef struct p4_frag_s {
    struct list_head Next;
    atomic_t    refcnt;  /* refcnt of this struct */
    p4_seqno_t	SeqNo;
    uint16_t	fsize;
    int		Flags;
    int		foffset;
    void	(*destructor)(struct p4_frag_s *f);
//    void	*priv;
}p4_frag_t;

#define p4_frag_put(f) do {						\
    DP_HOLDPUT("put fragment %d %p\n", atomic_read(&(f)->refcnt) - 1, (f));\
    if (atomic_dec_and_test(&(f)->refcnt)) {				\
	(f)->destructor(f);						\
    }									\
} while (0);

#define p4_frag_put2(f,code) do {					\
    DP_HOLDPUT("put fragment %d %p\n", atomic_read(&(f)->refcnt) - 1, (f));\
    if (atomic_dec_and_test(&(f)->refcnt)) {				\
      code                                                              \
      (f)->destructor(f);						\
    }									\
} while (0);

#define p4_frag_hold(f) do {						\
    atomic_inc(&(f)->refcnt);						\
    DP_HOLDPUT("hold fragment %d %p\n", atomic_read(&(f)->refcnt), (f));	\
} while (0);

struct p4_ci_s;
struct p4_socket_s;

typedef struct p4_net_opts_s {
    int	MaxResend;	/* maximal retrys for resend */
    int	ResendTimeout;
//    int WaitWinTimeout; /* Timeout for probe winsize */
    int AckDelay;
    int MaxRecvQSize;	/* To calculate the window size */
    int MaxAcksPending;
    /* Network functions */
    /* reliable networks should return sf == NULL */
    int (*sendmsg)(p4_ci_t *ci, struct iovec *msg_iov, size_t *msgsize, p4_frag_t **sf);
    int (*recvmsg)(p4_ci_t *ci, struct iovec *msg_iov, p4_frag_t *rf, size_t fsize);

    /* Send one fragment */
    int (*net_send_frag)	(p4_ci_t *ci, p4_frag_t *sf);

    int  (*net_send_ctrl)	(p4_remserv_t *rs, p4msg_ctrl_t *msg, size_t msgsize);
    int  (*isequal)		(p4_ci_t *ci, p4_remaddr_t *ra, p4msg_syn_t *syn);
    /* set_rem_saddr is used in recv synack */
    void (*set_rem_saddr)	(p4_ci_t *ci, p4_remserv_t *rs);
    int  (*init_ci)		(p4_ci_t *ci, p4_remaddr_t *ra, int ralen);
    void (*cleanup_ci)		(p4_ci_t *ci);
    void (*getremaddr)		(p4_remaddr_t *ra, p4_remserv_t *rs);
} p4_net_opts_t;


int p4_init(void);
void p4_cleanup(void);
//struct p4_socket_s * p4_new_socket( void );
//void p4_free_socket( struct p4_socket_s * p4s);


//void p4_net_recv_syn(p4_net_opts_t *netopts, p4_remaddr_t *ra, p4msg_syn_t *syn);
//p4_ci_t *p4_net_recv_synack(p4msg_synack_t *synack);
/* Send ACK through net_send_ctrl interface */
void p4_send_ack(p4_ci_t *ci);

void p4_net_recv_ack(p4msg_ack_t *ack);
void p4_net_recv_ctrl(p4_net_opts_t *net_opts, p4_remserv_t *rs, p4msg_ctrl_t *msg);
void p4_net_receive(p4_frag_t *rf, p4msg_data_header_t *dat);
void p4_net_receive_noseq(uint16_t cito, p4_frag_t *rf);
void _p4_receive(p4_ci_t *ci, p4_frag_t *rf);

/* dont use _p4_ci_free directly. Use p4_ci_put! */
void _p4_ci_free(p4_ci_t *ci);
#define p4_ci_put(ci) do {						\
    DP_HOLDPUT("put  ci %d %p\n", atomic_read(&(ci)->refcnt), (ci));	\
    if (atomic_dec_and_test(&(ci)->refcnt)) {				\
	_p4_ci_free(ci);						\
    }									\
} while (0);

#define p4_ci_hold(ci) do {						\
    atomic_inc(&(ci)->refcnt);						\
    DP_HOLDPUT("hold ci %d %p\n", atomic_read(&(ci)->refcnt), (ci));	\
} while (0);

void p4_ci_init(p4_ci_t *ci);

void p4_ci_close_usr(p4_ci_t *ci);

void p4_lockcheck(char *pos);

#define _STRINGIFY(param) #param
#define INT2STR(param) _STRINGIFY(param)

/*
#define P4S_LOCKVAR unsigned long _flags
#define P4S_LOCK p4_lock( __FILE__ ":" INT2STR(__LINE__), &_flags)
#define P4S_LOCKCHK p4_lockcheck( __FILE__ ":" INT2STR(__LINE__))
#define P4S_UNLOCK p4_unlock(__FILE__ ":" INT2STR(__LINE__), &_flags)
*/



/* connction info list from network view */
typedef struct p4_ci_list_net_s{
    p4_ci_t	*(ci[P4_N_CON_NET]);
} p4_ci_list_net_t;

/* connction info list from network view */
typedef struct p4_ci_list_usr_s{
    p4_ci_t	*(ci[P4_N_CON_USR]);
} p4_ci_list_usr_t;


typedef struct p4_socket_s {
    struct list_head	next;		/* ptr to next socket */
    atomic_t refcnt;  /* refcnt of this struct */
//    rwlock_t lock;    /* Lock data in this struct (except next) */
    p4_addr_t		addr;		/* Address of this socket */
    uint16_t		last_idx;	/* last used ci_list_usr index */
    int			recvq_empty : 1;/* RecvQ empty if set. Unknown if unset */

    struct list_head receive_ci;	/* list of ci's with fragments */

    P4_WAITQ_HEADVAR(recv_waitq);	/* Waitq for receiving */
    P4_WAITQ_HEADVAR(send_waitq);	/* Waitq for sending */
#ifdef P4CALLBACKS
    void (*cb_data_ready)(struct p4_socket_s *socket, void *priv);
    void *cb_data_ready_priv;
    void (*cb_write_space)(struct p4_socket_s *socket, void *priv);
    void *cb_write_space_priv;
#endif
    p4_ci_list_usr_t	ci_list_usr;

    void (*cb_new_connection)(struct p4_socket_s *socket, int fromidx, void *priv);
    void *cb_new_connection_priv;
} p4_socket_t;

static inline
void p4_small_ack_received(p4_ci_t *ci, p4_seqno_t ackno, p4_seqno_t winno)
/* Ack wurde empfangen und soll spaeter einige sende puffer freigeben. */
{
//    ci->Sacks_waiting |= (ci->SAckNo != ackno);
    P4LOG(LOG_RXACK, ackno);
    P4LOG(LOG_RXWIN, winno);

    if (p4_seqcmp(ackno, ci->s.SAckNo) > 0) {
	if (!ci->s.Sacks_waiting) {
	    P4_WAITQ_WAKEUP(ci->socket->send_waitq);
#ifdef P4CALLBACKS
	    if (ci->socket->cb_write_space) ci->socket->cb_write_space(ci->socket, ci->socket->cb_write_space_priv);
#endif
	}
	ci->s.SAckNo = ackno;
	ci->s.Sacks_waiting = 1;
    }
    ci->s.SWindow = winno;
    atomic_set(&ci->s.sendcnt, 0);
}

static inline
void p4_full_ack_received(p4_ci_t *ci, p4_seqno_t ackno, p4_seqno_t winno, int resend)
/* Ack wurde empfangen und soll spaeter einige sende puffer freigeben. */
{
    p4_small_ack_received(ci, ackno, winno);
    if (!resend) {
	proc_recv_net_ack_cnt++;
    } else {
	ci->s.SUntil = ci->s.SAckNo; /* reset SUntil counter */
	proc_recv_net_nack_cnt++;
    }
}

static inline
void p4_small_ack_sent(p4_ci_t *ci)
/* piggyback Ack (without resend flag) sent */
{
    if (!ci->r.Rresend)
	atomic_set(&ci->r.Racks_waiting,0);
}

static inline
void p4_full_ack_sent(p4_ci_t *ci)
/* Ack wurde gesendet. */
{
    atomic_set(&ci->r.Racks_waiting,0);
    proc_send_net_ctrl_cnt++;
    if (!ci->r.Rresend) {
	proc_send_net_ack_cnt++;
    } else {
	proc_send_net_nack_cnt++;
    }
}


static inline
void _p4_socket_enq_receiveci(p4_ci_t *ci)
{
    P4_ASSERT(ci->state == CI_STATE_ESTAB);

    list_add_tail(&ci->r.NextCi, &ci->socket->receive_ci);
    p4_ci_hold(ci);
}

static inline
void _p4_socket_deq_receiveci(p4_ci_t *ci)
{
    list_del(&ci->r.NextCi);
    ci->r.NextCi.next = NULL; /* Mark ci as dequeued */
    p4_ci_put(ci);
}

static inline
long p4_receiveci_enqueued(p4_ci_t *ci)
{
    return (long)ci->r.NextCi.next;
}


typedef struct p4_net_s{
    int			last_idx;
//    p4_socket_t		*socket_list_head;	/* ptr to head of socket list */
    struct list_head	socket_list;
    p4_ci_list_net_t	ci_list_net;
//    rwlock_t		net_lock; /* Lock data in this struct */
//    rwlock_t		recv_lock;
    rwlock_t		netw_lock;
} p4_net_t;

extern p4_net_t p4_net;

extern uint32_t p4_node_id;
extern p4_net_opts_t *p4myri_opts_ptr;
extern p4_net_opts_t p4ether_opts;

#ifdef ENABLE_FRAGCNT
extern atomic_t _fragcnt;

#define FRAGCNT atomic_read(&_fragcnt)

#define FRAG_INC atomic_inc(&_fragcnt)
#define FRAG_DEC atomic_dec(&_fragcnt)
#else
#define FRAGCNT -1

#define FRAG_DEC
#define FRAG_INC
#endif



#ifdef CONFIG_SMP
#define P4_NUM_CPUS 2
// ToDo: Change 2 to smp_num_cpus
#else
#define P4_NUM_CPUS 1
#endif

/*
 * P4_NR_RUNNING should be:
 * "nr_running"   : vanilla 2.4.x kernels and suse/redhat up to 2.4.18 (?)
 *                  nr_running is: int nr_running
 * "nr_running()" : suse/redhat 2.4.19
 *                  nr_running is: unsigned long nr_running(void)
 * "1000"         : suse/redhat >= 2.4.20, all 2.2.x and 2.6.x
 *                  no EXPORT_SYMBOL(nr_running) (never poll)
 */
#ifndef P4_NR_RUNNING
#warning P4_NR_RUNNING is not set. assume P4_NR_RUNNING=1000
/*#define P4_NR_RUNNING nr_running*/
#define P4_NR_RUNNING 1000
#endif

#endif /* _P4PROT_H_ */
