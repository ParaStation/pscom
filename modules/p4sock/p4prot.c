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
/**
 * p4prot.c: protocol handling
 */

#include <linux/slab.h>
#include <asm/uaccess.h>
//#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/sched.h>

#include "p4s_debug.h"
#include "p4rel.h"
#include "p4prot.h"
#include "p4local.h"
#include "p4ether.h"
#include "p4dummy.h"
#include "p4proc.h"
#include "p4io_old.h"

/*
 * Constants
 */



/* Some macros */
#define _array_size( name )  ((sizeof(name))/sizeof(name[0]))


/*
 * Types
 */


#define p4_socket_hold(socket) atomic_inc(&socket->refcnt)
/* dont use _p4_socket_free directly. Use p4_socket_put! */
void _p4_socket_free(p4_socket_t *socket);
#define p4_socket_put(socket)			\
    if (atomic_dec_and_test(&socket->refcnt)) {	\
	_p4_socket_free(socket);		\
    }


/*
 * Static variables
 */


p4_net_t p4_net;

#ifdef ENABLE_FRAGCNT
atomic_t _fragcnt = ATOMIC_INIT(0);
#endif

struct list_head p4_pollfuncs = LIST_HEAD_INIT(p4_pollfuncs);

uint32_t p4_node_id = P4_NODE_ID_UNDEF;
p4_net_opts_t *p4myri_opts_ptr = NULL;

/* Reliable protocol. (included for better performance (static inline) */

#ifdef P4REL_AS_INCLUDE
#include "p4rel.c"
#endif

static char vcid[] __attribute__(( unused )) =
"$Id$";

/* get ci with idx idx. Call p4_ci_put() after usage of ci */
static inline
p4_ci_t *p4_net_get_ci_idx(unsigned int idx)
{
    p4_ci_t *ci;

    ci = p4_net.ci_list_net.ci[idx & (P4_N_CON_NET - 1)];
    if (ci) p4_ci_hold(ci);

    return ci;
}

/* socket unlocked */
/* get ci with idx idx. Call p4_ci_put() after usage of ci */
static inline
p4_ci_t *p4_socket_get_ci(p4_socket_t *socket,unsigned int idx)
{
    p4_ci_t *ci;

    ci = socket->ci_list_usr.ci[idx & (P4_N_CON_USR - 1)];
    p4_ci_hold(ci);

    return ci;
}

static inline
int p4_socket_used_ci(p4_socket_t *socket, unsigned int idx)
{
    return socket->ci_list_usr.ci[idx & (P4_N_CON_USR - 1)] != &p4_ci_dummy_usr;
}


/* Get sockno'th socket from socket list */
/* on success return you hold the socket. */
static
p4_socket_t *p4_dump_getsock(int sockno)
{
    p4_socket_t *res;
    int cnt;
    struct list_head *pos;

    READ_LOCK_ASSERT(&p4_net.netw_lock);

    cnt = 0;
    list_for_each(pos, &p4_net.socket_list) {
	res = list_entry(pos, p4_socket_t, next);
	if (cnt == sockno) {
	    p4_socket_hold(res);
	    goto found;
	}
	cnt++;
    }
    res = NULL;
 found:
    return res;
}

static int p4_dumpsock(int sockno, p4_dumpsock_t *dsock)
{
    p4_socket_t *sock;
    int ret;

    SYNC_RLOCK(&p4_net.netw_lock,{
	sock = p4_dump_getsock(sockno);
	if (sock) {
	    memcpy(&dsock->addr, &sock->addr, sizeof(*dsock));
	    dsock->last_idx = sock->last_idx;
	    dsock->RefCnt = atomic_read(&sock->refcnt) - 1;/* dont count myself */
	    p4_socket_put(sock);
	    ret = 0;
	} else {
	    ret = -ENXIO;
	}
    });

    return ret;
}

static int p4_dumpci(p4_ci_t *ci, p4_dumpci_t *dci)
{
    READ_LOCK_ASSERT(&p4_net.netw_lock);

    dci->SSeqNo		= ci->s.SSeqNo;
    dci->SWindow	= ci->s.SWindow;
    dci->RSeqNo		= ci->r.RSeqNo;
    dci->RWindow	= ci->r.RWindow;
    dci->list_usr_idx	= ci->list_usr_idx;
    dci->list_net_idx	= ci->list_net_idx;
    dci->sendcnt	= atomic_read(&ci->s.sendcnt);
    dci->rem_net_idx	= ci->rem_net_idx;

    dci->sap4.sp4_family = PF_P4S;
    memcpy(&dci->sap4.sp4_port, &ci->rem_addr, sizeof(dci->sap4.sp4_port));

    memset(&dci->sap4.sp4_ra, 0, sizeof( dci->sap4.sp4_ra ));
    if (ci->net_opts) ci->net_opts->getremaddr(&dci->sap4.sp4_ra, &ci->rem_saddr);

    {
	struct list_head *pos;
	if (SPIN_TRYLOCK(&ci->s.SSeqLock)) {
	    dci->SFragQN = 0;
	    list_for_each(pos, &ci->s.SFragQ){
		dci->SFragQN++;
	    }
	    SPIN_UNLOCK(&ci->s.SSeqLock);
	} else {
	    dci->SFragQN = -1;
	}

	dci->RFragQN = 0;
	list_for_each(pos, &ci->r.RFragQ) {
	    dci->RFragQN++;
	}
    }
    dci->RefCnt = atomic_read(&ci->refcnt) - 1; /* dont count myself */
    return 0;
}

static int p4_dumpusrci(p4_socket_t *socket, int sockno, unsigned int ci_usr_idx, p4_dumpci_t *dci)
{
    p4_socket_t *sock;
    p4_ci_t *ci = NULL;
    int ret;

    SYNC_RLOCK(&p4_net.netw_lock,{
	if (sockno == -1) { /* self */
	    sock = socket;
	    p4_socket_hold(sock);
	} else {
	    sock = p4_dump_getsock(sockno);
	}
	if (sock) {
	    ci = p4_socket_get_ci(sock, ci_usr_idx);
	    if (ci != &p4_ci_dummy_usr) {
		ret = p4_dumpci(ci, dci);
	    } else {
		ret = -ENXIO;
	    }
	    p4_ci_put(ci);
	    p4_socket_put(sock);
	} else {
	    ret = -ENXIO;
	}
    });

    return ret;
}

static int p4_dumpnetci(unsigned int ci_net_idx, p4_dumpci_t *dci)
{
    p4_ci_t *ci;
    int ret;

    SYNC_RLOCK(&p4_net.netw_lock,{
	ci = p4_net_get_ci_idx(ci_net_idx);
	if (ci) {
	    ret = p4_dumpci(ci, dci);
	    p4_ci_put(ci);
	} else {
	    ret = -ENXIO;
	}
    });

    return ret;
}

int p4_get_nodeid(void)
{
    DP_PROTRACE("%s() = %d\n", __func__, p4_node_id);
    return p4_node_id;
}

void p4_set_nodeid(uint32_t node_id)
{
    p4_node_id = node_id;
    DPRINT("P4PROT:%s(%d)\n", __func__, p4_node_id);
}


int p4_close_ci_idx(p4_socket_t *socket, int ci_idx)
{
    p4_ci_t *ci;
    int ret;
    if ((ci_idx < 0) || ci_idx >= P4_N_CON_USR){
	return -EINVAL;
    }

    SYNC_WLOCK(&p4_net.netw_lock,{
	ci = p4_socket_get_ci(socket, ci_idx);
	if (ci != &p4_ci_dummy_usr) {
	    p4_ci_close_usr(ci);
	    ret = 0;
	} else {
	    ret = -EBADFD;
	}
	p4_ci_put(ci);
    });
    DP_PROTRACE("%s(%p, %d) = %d\n", __func__,
		 socket, ci_idx, ret);
    return ret;
}


int p4_ioctl(p4_socket_t *socket, unsigned long cmd, unsigned long arg)
{
    int ret;

    switch (cmd) {
    case P4_DUMPSOCK_OLD:
    case P4_DUMPSOCK:{
	p4_io_dumpsock_t s;
	if (copy_from_user(&s, (void *)arg, sizeof(s))) goto error_fault;
	ret = p4_dumpsock(s.in.sockno, &s.sock);
	if (copy_to_user((void *)arg, &s, sizeof(s))) goto error_fault;
	break;
    }
    case P4_DUMPUSRCI_OLD:
    case P4_DUMPUSRCI:{
	p4_io_dumpusrci_t ioci;
	if (copy_from_user(&ioci, (void *)arg, sizeof(ioci))) goto error_fault;
	ret = p4_dumpusrci(socket, ioci.in.sockno, ioci.in.ci_usr_idx, &ioci.ci);
	if (copy_to_user((void *)arg, &ioci, sizeof(ioci))) goto error_fault;
	break;
    }
    case P4_DUMPNETCI_OLD:
    case P4_DUMPNETCI:{
	p4_io_dumpnetci_t ioci;
	if (copy_from_user(&ioci, (void *)arg, sizeof(ioci))) goto error_fault;
	ret = p4_dumpnetci(ioci.in.ci_net_idx, &ioci.ci);
	if (copy_to_user((void *)arg, &ioci, sizeof(ioci))) goto error_fault;
	break;
    }
    case P4_GETNODEID_OLD:
    case P4_GETNODEID:{
	return p4_get_nodeid();
    }
    case P4_CLOSE_CON_OLD:
    case P4_CLOSE_CON:{
	return p4_close_ci_idx(socket, arg);
    }
    default:
	ret = -EINVAL;
    }

    return ret;
    /* */
 error_fault:
    return -EFAULT;
}




/*
 * functions
 */



static
p4_ci_t *p4_ci_new(void)
{
    p4_ci_t *ci;

    ci = (p4_ci_t *)kmalloc(sizeof(*ci), GFP_ATOMIC);
    if (!ci) goto err_no_mem;

    memset( ci, 0, sizeof( *ci));

    proc_ci_counter++;

    DP_PROTRACE("%s() ci %p\n", __func__, ci);
    DP_REFCNT("(NEW) allocated ci %p : %d\n", ci, proc_ci_counter);

    return ci;
 err_no_mem:
    if (p4s_ratelimit())
	printk(KERN_ERR "P4s: %s(): kmalloc failed\n", __func__);
    return NULL;
}

/* return the index in ci_list_usr, or -1 on error */
/* On success the socket hold the ci and ci hold the socket */
static
int p4_socket_enq_ci_and_link(p4_socket_t *socket, p4_ci_t *ci)
{
    unsigned int i;
    int idx;
    static int begin_idx = 0;

    DP_PROTRACE("%s()\n", __func__);

    /* search a free idx */
    idx = -1;
    for (i = 0; i < P4_N_CON_USR; i++){
	int test_idx;
	test_idx = (i + begin_idx) % P4_N_CON_USR;

	if (!p4_socket_used_ci(socket, test_idx)) {
	    idx = test_idx;
	    begin_idx = idx + 1;
	    break;
	}
    };
    if (idx >= 0) {
	/* Free index found */
	/* Enqueue */
	p4_ci_hold(ci);
	socket->ci_list_usr.ci[idx] = ci;
	/* Link */
	p4_socket_hold(socket);
	ci->socket = socket;
	ci->list_usr_idx = idx;
    }

    return idx;
}

static
void p4_socket_deq_ci(p4_ci_t *ci)
{
    WRITE_LOCK_ASSERT(&p4_net.netw_lock);
    P4_ASSERT(ci->socket);

    if (ci->socket && (ci->list_usr_idx >= 0) &&
	ci->socket->ci_list_usr.ci[ci->list_usr_idx] == ci) {
	ci->socket->ci_list_usr.ci[ci->list_usr_idx] = &p4_ci_dummy_usr;
	p4_ci_put(ci);
    }
}

static
void p4_ci_unlink_socket(p4_ci_t *ci)
{
    DP_PROTRACE("%s()\n", __func__);

    /* Usualy this function is called from _p4_ci_free() with
       refcnt == 0 and no writelock. */
    if (atomic_read(&ci->refcnt)) {
	WRITE_LOCK_ASSERT(&p4_net.netw_lock);
    }

    if (!ci->socket) goto is_unlinked;

    P4_WAITQ_WAKEUP(ci->socket->recv_waitq);
#ifdef P4CALLBACKS
	    if (ci->socket->cb_data_ready) ci->socket->cb_data_ready(ci->socket, ci->socket->cb_data_ready_priv);
#endif
    p4_socket_put(ci->socket);
    ci->socket = NULL;

    return;
 is_unlinked:
//    DPRINT(KERN_DEBUG "P4:" __FUNCTION__ "() called twice!\n");
    return;
}



/* return the index in ci_list_net, or -1 on error */
/* On success the net hold the ci */
static
int p4_net_enq_ci(p4_net_t *net, p4_ci_t *ci)
{
    unsigned int i;
    int idx;
    static int begin_idx = 0;

    DP_PROTRACE("%s()\n", __func__);

    WRITE_LOCK_ASSERT(&p4_net.netw_lock);

    if (ci->list_net_idx >= 0) goto already_enqueued;
    /* search a free idx */
    idx = -1;
    for (i=0; i < P4_N_CON_NET; i++){
	unsigned int test_idx;
	test_idx = (i + begin_idx) % P4_N_CON_NET;
	if (!net->ci_list_net.ci[test_idx]){
	    idx = test_idx;
	    begin_idx = idx + 1;
	    break;
	}
    };
    if (idx >= 0) {
	/* Free index found */
	/* Enqueue */
	p4_ci_hold(ci);
	net->ci_list_net.ci[idx] = ci;
	net->last_idx = idx;
	/* Link */
	ci->list_net_idx = idx;
    }
    return idx;
 already_enqueued:
    return ci->list_net_idx;
}

/* after call ci are not valid unless you hold it */
static
void p4_net_deq_ci(p4_net_t *net, p4_ci_t *ci)
{
    DP_PROTRACE("%s()\n", __func__);

    WRITE_LOCK_ASSERT(&p4_net.netw_lock);

    if ((ci->list_net_idx < 0) ||
	(net->ci_list_net.ci[ci->list_net_idx] != ci)) goto already_dequeued;

    net->ci_list_net.ci[ci->list_net_idx] = NULL;
    ci->list_net_idx = -1;

    p4_ci_put(ci);
    return;

 already_dequeued:
    DPRINT(KERN_DEBUG "P4: %s() called twice!\n", __func__);
    return;
}

void p4_ci_init(p4_ci_t *ci)
{
    /* initialize ci  */
    atomic_set(&ci->refcnt, 1);
    ci->magic = CI_MAGIC;
    ci->socket = NULL;
    ci->list_usr_idx = -1;
    ci->list_net_idx = -1;
    ci->rem_net_idx  = -1;
    ci->net_opts = NULL;
    CI_STATE_SET(ci, CI_STATE_CLOSED);

    /* initialize reliable part of ci */
    p4_rel_init_ci(ci);
}


/* create initialized ci */
static
p4_ci_t *p4_ci_create(p4_net_opts_t *net_opts,
		      p4_remaddr_t *ra, int ralen, int *ret)
{
    p4_ci_t *ci;
    DP_PROTRACE("%s()\n", __func__);

    ci = p4_ci_new();
    if (!ci) goto err_nomem;

    p4_ci_init(ci);
    ci->net_opts = net_opts;

    *ret = net_opts->init_ci(ci, ra, ralen);
    if (*ret) goto err_initfailed;

    DP_PROTRACE("%s(): new ci with __RFraqQ %p\n", __func__, &ci->r.RFragQ);
    return ci;
 err_initfailed:
    p4_ci_put(ci); /* should free this ci */
 err_nomem:
    return NULL;
}

struct _p4_timer_s {
    struct timer_list timer;
    void (*function)(void *p1,void *p2);
    void *p1;
    void *p2;
};


static
void do_timed_call(unsigned long param)
{
    struct _p4_timer_s *t = (struct _p4_timer_s *)param;

    t->function(t->p1, t->p2);
    kfree(t);
    p4s_dec_usecount();
}

static
void p4_timedcall(unsigned long expires,
		  void (*function)(void *p1,void *p2),
		  void *p1,void *p2)
{
    struct _p4_timer_s *t;

    if (!p4s_inc_usecount()) {
	DPRINT(KERN_WARNING "p4_timedcall: try_module_get(THIS_MODULE) failed!\n");
	return;
    }

    t = (struct _p4_timer_s *)kmalloc(sizeof(*t), GFP_ATOMIC);
    if (!t) {
	DPRINT(KERN_WARNING "p4_timedcall out of mem.\n");
	p4s_dec_usecount();
	return; /* What should we do here? */
    }
    t->p1 = p1;
    t->p2 = p2;
    t->function = function;
    init_timer(&t->timer);
    t->timer.function = do_timed_call;
    t->timer.expires = expires;
    t->timer.data = (unsigned long)t;

    add_timer(&t->timer);
}

static
void p4_socket_deq_receiveci(p4_ci_t *ci)
{
    if (p4_receiveci_enqueued(ci)) {
	_p4_socket_deq_receiveci(ci);
    }
}

static
void p4_th_p4_net_deq_ci(void *p1,void *p2)
{
    p4_ci_t *ci = (p4_ci_t *)p1;
    int retry = 0;
    int sendq_empty = 0;

    if (SPIN_TRYLOCK(&ci->s.SSeqLock)) {
	p4_cleanup_sendq(ci);
	sendq_empty = list_empty(&ci->s.SFragQ);
	SPIN_UNLOCK(&ci->s.SSeqLock);
    }

    SYNC_WLOCK(&p4_net.netw_lock ,{
	/* ToDo: After  CI_STATE_SBROKEN -> CI_STATE_CLOSEING the sendq
	   is not empty, but nobody clear the queue!
	   (_p4_ci_free() do it, but thats to late for the next check. */
	atomic_inc(&ci->s.sendcnt);
	if (!sendq_empty && (ci->state == CI_STATE_CLOSEING) &&
	    /* Maybe give up ?*/(atomic_read(&ci->s.sendcnt) < 20)) {
	    retry = 1;
	} else {
	    DP_PROTRACE("net_deq_ci in state %d.\n", ci->state);
	    p4_net_deq_ci(&p4_net, ci);
	}
    });

    if (!retry) {
	if (del_timer_sync(&ci->r.ack_timer)) {
	    p4_ci_put(ci);
	}
	if (del_timer_sync(&ci->s.resend_timer)) {
	    p4_ci_put(ci);
	}
	p4_ci_put(ci);
    } else {
	/* Retry later. */
	p4_timedcall(jiffies + HZ / 2,
		     p4_th_p4_net_deq_ci, (void *)ci, NULL);
    }
}

static int p4_send_fin_ci(p4_ci_t *ci);

static
void p4_th_send_fin(void *p1,void *p2)
{
    p4_ci_t *ci = (p4_ci_t *)p1;
    int err;
    int retry = 1;
    int giveup = 0;
    /* Try to send a "null-message". */

    if (ci->state == CI_STATE_CLOSEING) {
	err = p4_send_fin_ci(ci);

	if (!err) {
	    retry = 0;
	} else {
	    atomic_inc(&ci->s.sendcnt);
	    /* Maybe give up ?*/
	    if (atomic_read(&ci->s.sendcnt) > 20) {
		retry = 0;
		giveup = 1;
	    }
	}
    } else {
	retry = 0;
    }

    if (retry) {
	/* retry later */
	p4_timedcall(jiffies + HZ / 10,
		     p4_th_send_fin, (void *)ci, NULL);
    } else {
	if (giveup) {
	    DP_PROTRACE("%s(): Cant send FIN - giving up.\n", __func__);
	    SYNC_WLOCK(&p4_net.netw_lock ,{
		CI_STATE_SET(ci, CI_STATE_SBROKEN_CLOSEING);
	    });
	};
	p4_ci_put(ci);
    }
}

static
void p4_send_fin(p4_ci_t *ci)
{
    atomic_set(&ci->s.sendcnt, 0);
    p4_ci_hold(ci);
    /* send fin */
    p4_timedcall(jiffies + 0,
		 p4_th_send_fin, (void *)ci, NULL);
}

void p4_ci_close_usr(p4_ci_t *ci)
{
    WRITE_LOCK_ASSERT(&p4_net.netw_lock);
    DP_PROTRACE("%s(): ci %p\n", __func__, ci);

    if ((ci->state != CI_STATE_CLOSEING) &&
	(ci->state != CI_STATE_SBROKEN_CLOSEING)){
	/* First call to p4_ci_close_usr */
	if (ci->state == CI_STATE_ESTAB) {
	    /* if state is ESTABLISHED, send one "NULL-message" */
	    CI_STATE_SET(ci, CI_STATE_CLOSEING);
	    p4_send_fin(ci);
	} else {
	    CI_STATE_SET(ci, CI_STATE_CLOSEING);
	}

	/* Disconnect from socket. */
	if (ci->socket) {
	    p4_socket_deq_ci(ci);
	    p4_socket_deq_receiveci(ci);
	    P4_WAITQ_WAKEUP(ci->socket->recv_waitq);
	    P4_WAITQ_WAKEUP(ci->socket->send_waitq);
#ifdef P4CALLBACKS
	    if (ci->socket->cb_data_ready) ci->socket->cb_data_ready(ci->socket, ci->socket->cb_data_ready_priv);
	    if (ci->socket->cb_write_space) ci->socket->cb_write_space(ci->socket, ci->socket->cb_write_space_priv);
#endif
	}

	/* Disconnect from network later. */
	if (ci->list_net_idx >= 0) {
	    p4_ci_hold(ci);
	    p4_timedcall(jiffies + 1,
			 p4_th_p4_net_deq_ci, (void *)ci, NULL);
	}
    }
}


void _p4_ci_free(p4_ci_t *ci)
{
    DP_PROTRACE("%s() ci %p\n", __func__, ci);

    P4_ASSERT(!timer_pending(&ci->s.resend_timer));
    P4_ASSERT(!timer_pending(&ci->r.ack_timer));
    P4_ASSERT(!p4_receiveci_enqueued(ci));
    P4_ASSERT(ci->magic == CI_MAGIC);
    ci->magic = 0;

    p4_ci_unlink_socket(ci);

    if (timer_pending(&ci->s.resend_timer) ||
	timer_pending(&ci->r.ack_timer) ||
	p4_receiveci_enqueued(ci)) {
	/* BUG!!! */
	printk(KERN_ERR "P4: %s(): timer_pending BUG!\n", __func__);
	return;
    }

    /* Free all Send Fragments */
    {
	struct list_head *pos, *n;
	list_for_each_safe(pos, n , &ci->s.SFragQ) {
	    p4_frag_t *sf;
	    sf = list_entry(pos, p4_frag_t, Next);
	    list_del(&sf->Next);
	    DP_PROTRACE("%s() free sfrags refcnt %d\n", __func__,
			atomic_read(&sf->refcnt));
	    p4_frag_put(sf);
	}
	DP_PROTRACE("%s() free sfrags done\n", __func__);
    }

    /* Free all Received Fragments */
    {
	struct list_head *pos, *n;

	list_for_each_safe(pos, n , &ci->r.RFragQ) {
	    p4_frag_t *rf;
	    rf = list_entry(pos, p4_frag_t, Next);
	    list_del(&rf->Next);
	    p4_frag_put(rf);
	}
	list_for_each_safe(pos, n , &ci->r.RFragQ_oo) {
	    p4_frag_t *rf;
	    rf = list_entry(pos, p4_frag_t, Next);
	    list_del(&rf->Next);
	    p4_frag_put(rf);
	}
	DP_PROTRACE("%s() free rfrags done\n", __func__);
    }

    /* Cleanup Network */
    /* ToDo: To late ? */
    if (ci->net_opts) ci->net_opts->cleanup_ci(ci);

    proc_ci_counter--;
    DP_REFCNT("(FREE) allocated ci: %d\n", proc_ci_counter);
    DP_REFCNT("fragcnt %d\n", FRAGCNT);

    kfree(ci);
}

static
void p4_net_enq_socket(p4_net_t *net, p4_socket_t *socket)
{
    DP_PROTRACE("%s()\n", __func__);

    WRITE_LOCK_ASSERT(&p4_net.netw_lock);
    p4_socket_hold(socket);
    list_add(&socket->next, &net->socket_list);
}

static
void p4_net_deq_socket(p4_net_t *net, p4_socket_t *socket)
{
    DP_PROTRACE("%s()\n", __func__);
    WRITE_LOCK_ASSERT(&p4_net.netw_lock);

    list_del(&socket->next);
    p4_socket_put(socket); /* release the socket */
}

/* call p4_socket_put() after usage of the returned socket */
static
p4_socket_t *p4_socket_find( p4_net_t *net, p4_addr_t *addr)
{
    p4_socket_t *res;
    struct list_head *pos;

    if (!addr) return NULL;

    DP_PROTRACE("%s() : search Addr %s\n", __func__, dumpstr(addr, sizeof(*addr)));

    list_for_each(pos, &net->socket_list) {
	res = list_entry(pos, p4_socket_t, next);
	if (!memcmp(res->addr, addr, sizeof(res->addr))) {
	    p4_socket_hold(res);
	    goto found;
	}
    }
    res = NULL;
 found:
    return res;
}



static
p4_socket_t *p4_socket_new( void )
{
    p4_socket_t *p4s;
    DP_PROTRACE("%s()\n", __func__);

    if (!p4s_inc_usecount()) return NULL;

    p4s = (p4_socket_t *)kmalloc( sizeof(*p4s), GFP_ATOMIC);
    if (! p4s) goto err_no_mem;

    memset( p4s, 0, sizeof(*p4s));

    proc_sock_alloc_cnt++;

    DP_REFCNT("(NEW) allocated p4_sockets: %d\n", proc_sock_alloc_cnt);

    return p4s;
 err_no_mem:
    if (p4s_ratelimit())
	printk(KERN_ERR "P4s: %s(): kmalloc failed\n", __func__);
    p4s_dec_usecount();
    return NULL;
}

void _p4_socket_free(p4_socket_t *socket)
{
    proc_sock_alloc_cnt--;

    DP_REFCNT("(FREE) allocated p4_sockets: %d\n", proc_sock_alloc_cnt);
    DP_REFCNT("fragcnt %d\n", FRAGCNT);
    kfree(socket);
    p4s_dec_usecount();
}


int p4_socket_bind(p4_socket_t *socket, p4_addr_t *addr)
{
    p4_socket_t *search;
    int ret = 0;

    DP_PROTRACE("%s()\n", __func__);
    SYNC_WLOCK(&p4_net.netw_lock,{
	search = p4_socket_find(&p4_net, addr);
	if (search) { /* err_already_bound */
	    p4_socket_put(search);
	    ret= -EADDRINUSE;
	} else {
	    memcpy(socket->addr, addr, sizeof(socket->addr));
	}
    });
    return ret;
}

static
void p4_send_syn(p4_ci_t *ci)
{
    p4msg_ctrl_t msg;
    p4msg_syn_t *syn = &msg.t.syn;
    p4_remserv_t rem_saddr;	/* remote server address */
    struct p4_net_opts_s	*net_opts;
    int state;
    DP_PROTRACE("%s()\n", __func__);

    SYNC_RLOCK(&p4_net.netw_lock,{
	syn->cifrom = ci->list_net_idx;
	memcpy(&syn->destname, &ci->rem_addr, sizeof(syn->destname));
	syn->seqno = ci->s.SSeqNo;
	msg.type = P4TYPE_SYN;
	net_opts = ci->net_opts;
	state = ci->state;
	rem_saddr = ci->rem_saddr;
    });

    if (state != CI_STATE_SYNSENT) goto err_state;
    if (!net_opts || !net_opts->getremaddr || !net_opts->net_send_ctrl)
	goto err_netopts;

    net_opts->getremaddr(&syn->destsaddr, &rem_saddr);
    net_opts->net_send_ctrl(&rem_saddr, &msg, P4_CTRLMSGSIZE(syn));
    proc_send_net_ctrl_cnt++;

    return;
 err_state:
 err_netopts:
    return;
}

static
void p4_send_synack(p4_ci_t *ci)
{
    p4msg_ctrl_t msg;
    p4msg_synack_t *synack = &msg.t.synack;
    struct p4_net_opts_s	*net_opts;
    p4_remserv_t rem_saddr;	/* remote server address */

    SYNC_RLOCK(&p4_net.netw_lock,{
	synack->cito = ci->rem_net_idx;
	synack->cifrom = ci->list_net_idx;
	if (list_empty(&ci->s.SFragQ)) {
	    synack->seqno = ci->s.SSeqNo;
	} else {
	    /* Seqno from first unacked data packet */
	    synack->seqno = list_entry(ci->s.SFragQ.next,
				       p4_frag_t, Next)->SeqNo;
	}
	synack->ackno = ci->r.RSeqNo;
	synack->error = 0;
	msg.type = P4TYPE_SYNACK;
	net_opts = ci->net_opts;
	rem_saddr = ci->rem_saddr;
    });

    if (!net_opts || !net_opts->net_send_ctrl) goto err_netopts;
    net_opts->net_send_ctrl(&rem_saddr, &msg, P4_CTRLMSGSIZE(synack));
    proc_send_net_ctrl_cnt++;

    return;
 err_netopts:
    return;
}

static
void p4_send_synnack(p4_net_opts_t *net_opts, p4_remserv_t *rs, p4msg_syn_t *syn)
{
//void p4_send_synack(p4_ci_t *ci)
//{
    p4msg_ctrl_t msg;
    p4msg_synack_t *synack = &msg.t.synack;

    synack->cito = syn->cifrom;
    synack->cifrom = 0;
    synack->seqno = 0;
    synack->ackno = syn->seqno;
    synack->error = ECONNREFUSED;
    msg.type = P4TYPE_SYNACK;

    if (!net_opts || !net_opts->net_send_ctrl) goto err_netopts;
    net_opts->net_send_ctrl(rs, &msg, P4_CTRLMSGSIZE(synack));
    proc_send_net_ctrl_cnt++;

    return;
 err_netopts:
    return;
}


/* Send ACK through net_send_ctrl interface */
void p4_send_ack(p4_ci_t *ci)
{
    p4msg_ctrl_t msg;
    p4msg_ack_t *ack = &msg.t.ack;

    DP_PROTRACE2("%s\n", __func__);

    ack->cito = ci->rem_net_idx;
    ack->ackno = ci->r.RSeqNo - 1;
    ack->winsize = ci->r.RWindow;
    ack->resend = ci->r.Rresend;

    msg.type = P4TYPE_ACK;

    if (!ci->net_opts->net_send_ctrl(&ci->rem_saddr, &msg, P4_CTRLMSGSIZE(ack))) {
	p4_full_ack_sent(ci);
    }
}


static
int p4_connect_wait(p4_socket_t *socket, p4_ci_t *ci)
{
    int ret = 0;
    unsigned long flags;
    int timeout;
    P4_WAITQ_VAR(wait);

    DP_PROTRACE("%s()\n", __func__);
    SYNC_WLOCK(&p4_net.netw_lock,{
	if (ci->state != CI_STATE_CLOSED) {
	    ret = -EFAULT;
	    SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_notclosed);
	}
	CI_STATE_SET(ci, CI_STATE_SYNSENT);
	atomic_set(&ci->s.sendcnt, 0);
    });

    current->state =TASK_INTERRUPTIBLE;
    P4_WAITQ_ADD(socket->recv_waitq, wait);

    while (1) {
	WRITE_LOCK_IRQSAVE(&p4_net.netw_lock, flags);
	if (ci->state != CI_STATE_SYNSENT) {
	    if (ci->state != CI_STATE_ESTAB)
		ret = -EFAULT;
	    goto out;
	}
	if (atomic_read(&ci->s.sendcnt) > ci->net_opts->MaxResend) {
	    ret = -ECONNREFUSED;
	    goto out;
	}
	if(signal_pending(current)){
	    ret = -ERESTARTSYS;
	    goto out;
	}
	atomic_inc(&ci->s.sendcnt);
	timeout = ci->net_opts ?
	    ci->net_opts->ResendTimeout : 0;
	WRITE_UNLOCK_IRQRESTORE(&p4_net.netw_lock, flags);

	p4_send_syn(ci);

	schedule_timeout(timeout);
	current->state = TASK_INTERRUPTIBLE;
    }

 out:
    WRITE_UNLOCK_IRQRESTORE(&p4_net.netw_lock, flags);
    P4_WAITQ_REMOVE(socket->recv_waitq, wait);
    current->state = TASK_RUNNING;
 err_notclosed:
    DP_PROTRACE("%s(): connect : %d\n", __func__, ret);
    return ret;
}


/**
 * @brief shutdown (emulate shutdown(SEND) from TCP) (never blocks)
 */
int p4_shutdown(p4_socket_t *socket, int destidx)
{
    p4_ci_t *ci;
    int ret;

    SYNC_RLOCK(&p4_net.netw_lock,{
	ci = p4_socket_get_ci(socket, destidx);
    });

    ret = p4_send_fin_ci(ci);

    p4_ci_put(ci);
    return ret;
}


static
int p4_send_fin_ci(p4_ci_t *ci)
{
    int ret;

    if (SPIN_TRYLOCK(&ci->s.SSeqLock)) {
	struct iovec msg_iov = {
	    .iov_base = NULL,
	    .iov_len = 0
	};
	size_t msgsize = 0;
	p4_frag_t *sf;
	P4_ASSERT(ci->net_opts && ci->net_opts->sendmsg);

	ret = ci->net_opts->sendmsg(ci, &msg_iov, &msgsize, &sf);
	if (!ret) {
	    ci->s.SSeqNo++;
	    if (sf) {
		p4_enq_for_resend(ci, sf);
		p4_frag_put(sf);
	    }
	    p4_cleanup_sendq(ci);
	}
	SPIN_UNLOCK(&ci->s.SSeqLock);
    } else {
	ret = -EAGAIN;
    }
    return ret;
}

/**
 * @brief Send msg
 */
int p4_sendmsg(p4_socket_t *socket, int destidx,
	       struct iovec *msg_iov, size_t msgsize, int flags)
{
    int (*sendmsg)(p4_ci_t *ci, struct iovec *msg_iov, size_t *msgsize, p4_frag_t **sf);
    p4_ci_t *ci;
    int cnt;
    int err = 0;
    p4_frag_t *sf;

    int in_sendwaitq = 0;
    P4_WAITQ_VAR(wait);
    size_t msgsize_bak = msgsize;

    P4LOG(LOG_SENDSTART, 0);

//    static int good=0;
    SYNC_RLOCK(&p4_net.netw_lock,{
	ci = p4_socket_get_ci(socket, destidx);
    });

    sendmsg = ci->net_opts->sendmsg;

    /* If multiple threads try to send at the same time,
       the second thread wait here. */
    down(&ci->s.SendLock);

    while (msgsize) {
	err = 0;
	for (cnt = 0; cnt < 2; cnt++) {
	    if (ci->state == CI_STATE_ESTAB) {
		err = sendmsg(ci, msg_iov, &msgsize, &sf);
	    } else {
		err = -EPIPE;
	    }

	    SPIN_LOCK(&ci->s.SSeqLock);
	    if (!err) {
		ci->s.SSeqNo++;
		if (sf) {
		    p4_enq_for_resend(ci, sf);
		    p4_frag_put(sf);
		}
		p4_cleanup_sendq(ci);
		proc_send_user_cnt++;
		SPIN_UNLOCK(&ci->s.SSeqLock);
		break;
	    }
	    p4_cleanup_sendq(ci);
	    SPIN_UNLOCK(&ci->s.SSeqLock);

	    if (err != -EAGAIN) break;
	};

	if (ci->s.call_continue_send) {
	    p4_continue_send(ci);
	}

	if (err) {
	    if ((err == -EAGAIN) && !(flags & MSG_DONTWAIT)) {
		if (signal_pending(current)) {
		    err = -EINTR;
		    goto out;
		}
		if (in_sendwaitq) {
/*		    if (p4s_ratelimit()) {
			DPRINT("schedule with msgsize %d (sqlen %d)\n",
			       msgsize, p4_sendqsize(ci));
			       }*/
		    schedule_timeout(HZ / 2);
		    current->state = TASK_INTERRUPTIBLE;
		} else {
		    in_sendwaitq = 1;
		    current->state = TASK_INTERRUPTIBLE;
		    P4_WAITQ_ADD(socket->send_waitq, wait);
		}
	    } else {
		goto out;
	    }
	}
    }
 out:
    if (in_sendwaitq) {
	current->state = TASK_RUNNING;
	P4_WAITQ_REMOVE(socket->send_waitq, wait);
    }

    up(&ci->s.SendLock);

    p4_ci_put(ci);
    P4LOG(LOG_SENDSTOP, 0);
    return (msgsize_bak > msgsize) ? msgsize_bak - msgsize : err;
}


void p4_poll_add(p4_pollfunc_t *pollfunc)
{
    list_add_tail(&pollfunc->next, &p4_pollfuncs);
}

void p4_poll_del(p4_pollfunc_t *pollfunc)
{
    list_del(&pollfunc->next);
}

static void p4_poll(void)
{
    struct list_head *pos;
    list_for_each(pos, &p4_pollfuncs) {
	p4_pollfunc_t *pf = list_entry(pos, p4_pollfunc_t, next);
	pf->func();
    }
}

static inline
void p4_check_urgent_acks(p4_ci_t *ci)
{
    if (atomic_read(&ci->r.Racks_waiting) >= ci->net_opts->MaxAcksPending) {
	p4_send_ack(ci);
    }
}

#define _P4_NR_RUNNING_STR(x) _STRINGIFY(x)
static char p4_nr_running_info[] __attribute__(( unused )) =
"$Info: P4_NR_RUNNING=" _P4_NR_RUNNING_STR(P4_NR_RUNNING) " $";

/**
 * @brief Recv msg
 * @param socket p4_socket
 * @param msg message to be receive (msg->msg_iov)
 * @param msgsize number of bytes to be receive (max)
 */
int p4_recvmsg(p4_socket_t *socket, struct iovec *msg_iov,uint16_t *msg_src,
	       size_t msgsize, int flags)
{
    int ret;
    unsigned long t1, t2;
    p4_ci_t *ci = NULL;
    p4_frag_t *rf;
    size_t len = 0;/* initialisation to remove gcc warnings */
    size_t msgsize_bak = msgsize;
    int in_recvwaitq = 0;
    int cnt = 0;
    int goout;

    P4_WAITQ_VAR(wait);
    P4LOG(LOG_RECVSTART, 0);

    t1 = jiffies;
    while (1) {
	rf = NULL;
	if (!socket->recvq_empty) SYNC_WLOCK(&p4_net.netw_lock,{
	    if (ci || !list_empty(&socket->receive_ci)) {
		if (!ci) {
		    ci = list_entry(socket->receive_ci.next, p4_ci_t, r.NextCi);
		    p4_ci_hold(ci);
		    if (msg_src) {
			*msg_src = ci->list_usr_idx;
		    }
		}

		if (!list_empty(&ci->r.RFragQ)) {
		    rf = list_entry(ci->r.RFragQ.next, p4_frag_t, Next);
		    P4LOG(LOG_RX__2, rf->SeqNo);
		    len = rf->fsize - rf->foffset;

		    if (msgsize >= len) {
			p4_seqno_t newwinsize;

			/* copy whole fragment */
			msgsize -= len;
			goout = !msgsize;

			if (rf->fsize) {
			    list_del(&rf->Next);
			} else {
			    goout = 1;
			    // DP_PROTRACE(__FUNCTION__ "() Receive EOF message.\n");
			    p4_frag_hold(rf); /* rf is still inside RFragQ */
			}
			DP_RELTRACE("%s Deq recv %u, flags %u\n", __func__,
				    rf->SeqNo, rf->Flags);

			/* Increase receive window */
			if (ci->net_opts->MaxRecvQSize) {
			    newwinsize = rf->SeqNo + ci->net_opts->MaxRecvQSize;
			    p4_setrwindow(ci, newwinsize);
			}

			if (rf->Flags & P4_FFLAGS_LASTFRAG) {
//  		        DPRINT(__FUNCTION__ "() P4_FFLAGS_LASTFRAG\n");
			    /* This is the last fragment of a message. */
			    if (list_empty(&ci->r.RFragQ)) {
				/* This was the last framgent in the receive queue */
				_p4_socket_deq_receiveci(ci);
//		            newwinsize = newwinsize - (P4MYRI_RECVWINSIZE - 1);
			    }
			    goout = goout || !(flags & MSG_WAITALL);
			}
		    } else {
			/* copy only part of fragment */
			len = msgsize;
			msgsize = 0;
			p4_frag_hold(rf); /* rf is still inside RFragQ */
			goout = 1;
		    }
		} else {
		    /* assert(rf == NULL); */
		    goout = (cnt && (!!(flags & MSG_DONTWAIT))) ||
			(ci->state != CI_STATE_ESTAB);
		    socket->recvq_empty = goout && proc_recvqcheck;
		    cnt = 1;
		}
	    } else {
		/* assert(ci == NULL && rf == NULL);*/
		goout =  cnt && !!(flags & MSG_DONTWAIT);
		socket->recvq_empty = goout && proc_recvqcheck;
		cnt = 1;
	    }
	}); else {
	    goout = cnt && !!(flags & MSG_DONTWAIT);
	    cnt = 1;
	}

	if (ci)
	    p4_check_urgent_acks(ci);

//	P4LOG(LOG_RX__3, 0);
	/*
	  ci = NULL : socket->receive_ci is empty.
	  rf = NULL : socket->receive_ci or ci->r.RFragQ is empty
	*/

	if (rf) {
	    /* this include ci != NULL */
	    ret = ci->net_opts->recvmsg(ci, msg_iov, rf, len);
	    rf->foffset += len;
	    p4_frag_put(rf);
	    if (ret) /* dont allow errors here. */
		goto err_recvmsg;
	    if (!goout) {
		continue; // goto start;
	    } else {
		break; // goto out;
	    }
	} else {
	    if (goout) {
		ret = msgsize_bak - msgsize ? msgsize_bak - msgsize : -EWOULDBLOCK;
		goto would_block;
	    }
	    p4_poll();
	}

	t2 = jiffies;

	if ((t2 - t1 < 2) && !list_empty(&p4_pollfuncs)) { /* Maximal 2/HZ sec polling */
	  if (((P4_NR_RUNNING <= P4_NUM_CPUS) && proc_polling) ||
	      (proc_polling > 1)) {
#ifdef __x86_64__
	      ndelay(500); /* ToDo: Why this performs better? */
#endif
#ifdef __powerpc64__
	      schedule();
#endif
	      continue; /* poll, if this is the only task on this CPU */
	  }
	}

	if (signal_pending(current)) {
	    DP_PROTRACE("%s(): ERESTARTSYS\n", __func__);
	    ret = msgsize_bak - msgsize ? msgsize_bak - msgsize : -EINTR;
	    goto signal;
	}
	if (in_recvwaitq) {
	    schedule();
//	    if (!schedule_timeout(30 * HZ)) {
//		DP_PROTRACE("Blocking schedule_timeout() ?\n");
//	    };
	    current->state = TASK_INTERRUPTIBLE;
	} else {
	    in_recvwaitq = 1;
	    current->state = TASK_INTERRUPTIBLE;
	    P4_WAITQ_ADD(socket->recv_waitq, wait);
	}
    } /* while (1) */

    ret = msgsize_bak - msgsize;
 would_block:
 signal:
 err_recvmsg:
    if (in_recvwaitq) {
	current->state =TASK_RUNNING;
	P4_WAITQ_REMOVE(socket->recv_waitq, wait);
    }

    if (ci) {
	p4_ci_put(ci);
    }
    P4LOG(LOG_RECVSTOP, 0);

    return ret;
}

unsigned int p4_socket_poll(struct file * file, p4_socket_t *socket, poll_table *wait)
{
    unsigned int mask = 0;

//#warning skip
//    mask |= POLLIN | POLLRDNORM;
//    goto skip;

    poll_wait(file, &socket->recv_waitq, wait);
    poll_wait(file, &socket->send_waitq, wait);

    if (!socket->recvq_empty) {
	SYNC_RLOCK(&p4_net.netw_lock,{
		if (!list_empty(&socket->receive_ci)) {
		    p4_ci_t *ci = list_entry(socket->receive_ci.next, p4_ci_t, r.NextCi);

		    if (!list_empty(&ci->r.RFragQ)) {
			mask |= POLLIN | POLLRDNORM;
		    } else {
			socket->recvq_empty = proc_recvqcheck;
		    }
		} else {
		    socket->recvq_empty = proc_recvqcheck;
		}
	    });
    }
// skip:
    if (1){
	mask |= POLLOUT | POLLWRNORM;
    }

    return mask;
}

static
int p4_routing(p4_remaddr_t *_ra, int _ralen,
	       p4_remaddr_t *ra, int *ralen, p4_net_opts_t **net_opts)
{
    if (_ralen < sizeof(_ra->type))
	goto err_inval;

    /* copy translated ra: */
    memcpy(ra, _ra, MIN(_ralen, sizeof(*ra)));
    *ralen = sizeof(*ra); /* all tec's are smaller or equal */

    switch (ra->type){
    case P4REMADDR_PSID:
	if (_ralen < sizeof(_ra->type) + sizeof(_ra->tec.psid))
	    goto err_inval;

	DP_PROTRACE("%s(): P4REMADDR_PSID.\n", __func__);
	if ((_ra->tec.psid.psid == p4_node_id) &&
	    (p4_node_id != P4_NODE_ID_UNDEF)) {
	    /* Local */
	    DP_PROTRACE("%s(): P4REMADDR_PSID %d -> LOCAL\n", __func__, _ra->tec.psid.psid);
	    ra->type = P4REMADDR_LOCAL;
	    *net_opts = &p4local_opts;
	} else if (_ra->tec.psid.psid < 4096) {
	    if (p4myri_opts_ptr) {
		/* Myrinet (or local). psid is myrinet nodeid. */
		DP_PROTRACE("%s(): P4REMADDR_PSID %d -> MYRI\n", __func__,
			    _ra->tec.psid.psid);
		if (!p4myri_opts_ptr) goto err_noproto;
		ra->type = P4REMADDR_MYRI;
		ra->tec.myri.nodeid = _ra->tec.psid.psid;
		*net_opts = p4myri_opts_ptr;
	    } else {
		/* No Myrinet available. Use ethernet with psid */
		/* Ethernet (or local). psid is ip address. */
		DP_PROTRACE("%s(): P4REMADDR_PSID %d -> ETHER(no Myrinet)\n",
			    __func__, _ra->tec.psid.psid);
		ra->type = P4REMADDR_ETHER;
		ra->tec.ether.addr.ipaddr = htonl(_ra->tec.psid.psid);
		ra->tec.ether.devname[0] = 0; /* Use IP address */
		*net_opts = &p4ether_opts;
	    }
	} else {
	    /* Ethernet (or local). psid is ip address. */
	    DP_PROTRACE("%s(): P4REMADDR_PSID %d -> ETHER\n", __func__, _ra->tec.psid.psid);
	    ra->type = P4REMADDR_ETHER;
	    ra->tec.ether.addr.ipaddr = htonl(_ra->tec.psid.psid);
	    ra->tec.ether.devname[0] = 0; /* Use IP address */
	    *net_opts = &p4ether_opts;
	}
	break;
    case P4REMADDR_LOCAL:
	/* local has no parameters */
	DP_PROTRACE("%s(): P4REMADDR_LOCAL\n", __func__);
	*net_opts = &p4local_opts;
	break;
    case P4REMADDR_ETHER:
	if (_ralen < sizeof(_ra->type) + sizeof(_ra->tec.ether))
	    goto err_inval;
	DP_PROTRACE("%s(): P4REMADDR_ETHER\n", __func__);
	*net_opts = &p4ether_opts;
	break;
    case P4REMADDR_MYRI:
	if (_ralen < sizeof(_ra->type) + sizeof(_ra->tec.myri))
	    goto err_inval;
	if (!p4myri_opts_ptr) goto err_noproto;
	DP_PROTRACE("%s(): P4REMADDR_MYRI\n", __func__);
	*net_opts = p4myri_opts_ptr;
	break;
    default:
	goto err_noproto;
    }

    return 0;
 err_inval:
    DP_PROTRACE("%s(): Invalid address.\n", __func__);
    return -EINVAL;
 err_noproto:
    DP_PROTRACE("%s(): Unknown Type %d\n", __func__, ra->type);
    return -EPROTONOSUPPORT;
}


int p4_socket_connect(p4_socket_t *socket, p4_addr_t *addr, p4_remaddr_t *_ra, int _ralen)
{
    p4_ci_t *ci;
    int ret;
    p4_net_opts_t *net_opts = NULL;
    p4_remaddr_t ra;
    int ralen = 0;
    int idx;
    int netidx;

    DP_PROTRACE("%s(): ENTER ralen %d\n", __func__, _ralen);
    p4_socket_hold(socket);

    ret = p4_routing(_ra, _ralen, &ra, &ralen, &net_opts);
    if (ret) goto err_unknown_remaddr;

    /* create a ci */
    ci = p4_ci_create(net_opts, &ra, ralen, &ret);
    if (!ci) goto err_ci_create;

    if (addr) memcpy(&ci->rem_addr, addr, sizeof(ci->rem_addr));

    SYNC_WLOCK(&p4_net.netw_lock,{
	idx = p4_socket_enq_ci_and_link(socket, ci);
	if (idx < 0) SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_noidx);

	DP_PROTRACE("Create ci, usr_idx: %d\n",idx);

	netidx = p4_net_enq_ci(&p4_net, ci);
    });

    if (netidx < 0) {
	ret = -EBUSY;
	DP_PROTRACE("No free netidx for ci %p\n", ci);
	goto err_nonetidx;
    };

    ret = p4_connect_wait(socket, ci);
    if (ret) goto err_connect_wait;

    p4_ci_put(ci); /* from p4_ci_create() */

    p4_socket_put(socket);
    return idx;
 err_connect_wait:
 err_nonetidx:
    SYNC_WLOCK(&p4_net.netw_lock,{
	p4_ci_close_usr(ci);
    });
 err_noidx:
    p4_ci_put(ci); /* from p4_ci_create() */
 err_ci_create:
 err_unknown_remaddr:
    if (p4s_ratelimit()) {
	if (ret == -ECONNREFUSED) {
	    DPRINT(KERN_DEBUG "P4s: %s(): Connection refused\n", __func__);
	} else {
	    DPRINT(KERN_DEBUG "P4s: %s(): ERROR = %d\n", __func__, ret);
	}
    }
    p4_socket_put(socket);
    return ret;
}

p4_socket_t *p4_socket_create(void)
{
    p4_socket_t *p4s;
    int i;
    DP_PROTRACE("%s()\n", __func__);

    p4s = p4_socket_new();
    if (!p4s) goto err_no_sock;

    for (i = 0; i < P4_N_CON_USR; i++) {
	p4s->ci_list_usr.ci[i] = &p4_ci_dummy_usr;
    }

//    p4s->lock = RW_LOCK_UNLOCKED;
    atomic_set(&p4s->refcnt,1);
    p4s->recvq_empty = 0;

    P4_WAITQ_INIT(p4s->recv_waitq);
    P4_WAITQ_INIT(p4s->send_waitq);

    INIT_LIST_HEAD(&p4s->receive_ci);

    SYNC_WLOCK(&p4_net.netw_lock,{
	p4_net_enq_socket(&p4_net, p4s);
    });

    p4s->cb_new_connection = NULL;

    return p4s;
 err_no_sock:
    return NULL;
}

void p4_socket_close(p4_socket_t *socket)
{
    int i;
    DP_PROTRACE("%s()\n", __func__);

    SYNC_WLOCK(&p4_net.netw_lock,{
	p4_net_deq_socket(&p4_net, socket);
	for (i = 0; i < P4_N_CON_USR; i++) {
	    p4_ci_t *ci;

	    if (!p4_socket_used_ci(socket, i))
		continue;

	    ci = p4_socket_get_ci(socket, i);
	    if (ci != &p4_ci_dummy_usr) {
		p4_ci_close_usr(ci);
	    }
	    p4_ci_put(ci);
	}
    });
    p4_socket_put(socket);
}

/* use p4_socket_put to release the result ci */
static
p4_ci_t *p4_socket_find_ci(p4_socket_t *socket, p4_net_opts_t *netopts,
			   p4_remaddr_t *ra, p4msg_syn_t *syn)
{
    p4_ci_t *ci;
    int i;
    DP_PROTRACE("%s()\n", __func__);

    for(i = 0; i < P4_N_CON_USR; i++) {
	if (!p4_socket_used_ci(socket, i))
	    continue;

	ci = p4_socket_get_ci(socket, i);
	if (ci != &p4_ci_dummy_usr) {
	    if ((ci->net_opts == netopts) &&
		(syn->cifrom == ci->rem_net_idx) &&
		(netopts->isequal(ci, ra, syn))){
		goto out;
	    }
	}
	p4_ci_put(ci);
    }
    ci = NULL;
 out:
    return ci;
}


static
void p4_notify_newconnection(p4_ci_t *ci)
{
    p4_socket_t *socket = ci->socket;
    int idx = ci->list_usr_idx;
    void (*cb)(struct p4_socket_s *socket, int fromidx, void *priv);

    cb = socket->cb_new_connection;
    if (cb) {
	cb(socket, idx, socket->cb_new_connection_priv);
    }
}


static
void p4_net_recv_syn(p4_net_opts_t *netopts, p4_remserv_t *rs, p4msg_syn_t *syn)
{
    p4_socket_t *socket;
    p4_ci_t *ci;
    int ret;
    int idx, netidx;
    int newcon = 0;
    p4_remaddr_t ra;

    netopts->getremaddr(&ra, rs);

    SYNC_WLOCK(&p4_net.netw_lock,{
	/* Search for a socket */
	socket = p4_socket_find(&p4_net, &syn->destname);
	if (!socket) SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_not_bound);

	/* Search for old connections */
	ci = p4_socket_find_ci(socket, netopts, &ra, syn);

	if (ci) {
	    DP_PROTRACE("%s(): found old CI %p\n", __func__, ci);
	} else {
	    /* No? Create new connection */
	    ci = p4_ci_create(netopts, &ra, sizeof(ra), &ret);
	    if (!ci) SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_ci_create);

	    idx = p4_socket_enq_ci_and_link(socket, ci);
	    if (idx < 0) {
		DP_PROTRACE("%s(): enq_ci_and_link failed for ci %p\n", __func__, ci);
		p4_ci_close_usr(ci);
		SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_socket_enq_);
	    }
	    newcon = 1;
	}

	/* connect to network (if necessary) */
	netidx = p4_net_enq_ci(&p4_net, ci);
	if (netidx < 0) {
	    DP_PROTRACE("%s(): net_enq_ci for ci %p\n", __func__, ci);
	    p4_ci_close_usr(ci);
	    SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_connect_network_);
	}

	/* assign infos from remote */
	ci->rem_net_idx = syn->cifrom;
	/* ci->rem_addr is unknown */
	ci->r.RSeqNo = syn->seqno;
	/* Initial window is 1 fragment */
	ci->r.RWindow = ci->r.RSeqNo;

	/* ESTAB is not correct here, if the syack is lost
	   and the user send data from this site. But the data
	   wont be acked from remote until we receive the next
	   syn and resend the synack. */
	CI_STATE_SET(ci, CI_STATE_ESTAB);
    });

    p4_send_synack(ci);

    if (newcon) {
	p4_notify_newconnection(ci);
    }

    p4_ci_put(ci);
    p4_socket_put(socket);

    return;
/*----*/
 err_connect_network_:
 err_socket_enq_:
    p4_ci_put(ci);
 err_ci_create:
    p4_socket_put(socket);
    return;
/*----*/
 err_not_bound:
    p4_send_synnack(netopts, rs, syn);
    return;
}

/* Return ci, if we accept this synack. You must release ci with p4_ci_put()*/
static
void p4_net_recv_synack(p4_net_opts_t *netopts, p4_remserv_t *rs,
			p4msg_synack_t *synack)
{
    p4_ci_t *ci;
    p4_socket_t *socket;
    unsigned long flags;

    WRITE_LOCK_IRQSAVE(&p4_net.netw_lock, flags);

    ci = p4_net_get_ci_idx(synack->cito);
    if (!ci) goto err_ci;

    /* check sequencenumber */
    if (ci->s.SSeqNo != synack->ackno)
	goto err_seqno;

    /* ToDo: Handle synack->error */
    if (synack->error)
	goto err_remote_error;

    ci->r.RSeqNo = synack->seqno;
    /* Initial window is 1 fragment */
    ci->r.RWindow = ci->r.RSeqNo;

    /* Last step: set remote idx */
    ci->rem_net_idx = synack->cifrom;

    if (ci->net_opts && ci->net_opts->set_rem_saddr)
	ci->net_opts->set_rem_saddr(ci, rs);

    if (ci->state == CI_STATE_SYNSENT) {
	CI_STATE_SET(ci, CI_STATE_ESTAB);
    }
    DP_PROTRACE("%s(): synack accepted\n", __func__);
 wakeup:
    socket = ci->socket;
    barrier();
    if (socket) {
	P4_WAITQ_WAKEUP(socket->recv_waitq);
#ifdef P4CALLBACKS
	if (ci->socket->cb_data_ready) ci->socket->cb_data_ready(ci->socket, ci->socket->cb_data_ready_priv);
#endif
    }

    WRITE_UNLOCK_IRQRESTORE(&p4_net.netw_lock, flags);
    p4_ci_put(ci);
    return;
    /* ----- */
 err_remote_error:
    DP_PROTRACE("%s(): synack rejected (synack error %d)\n", __func__, synack->error);
    if (ci->state == CI_STATE_SYNSENT) {
//	printk(KERN_INFO "received synnack\n");
//	atomic_set(&ci->s.sendcnt, 1 + ci->net_opts->MaxResend); /* Dont send more syncs! */
    }
    goto wakeup;
    /*
    WRITE_UNLOCK_IRQRESTORE(&p4_net.netw_lock, flags);
    p4_ci_put(ci);
    return;*/
    /* ----- */
 err_seqno:
    WRITE_UNLOCK_IRQRESTORE(&p4_net.netw_lock, flags);
    DP_PROTRACE("%s(): synack rejected (wrong seqno)\n", __func__);
    p4_ci_put(ci);
    return;
    /* ----- */
 err_ci:
    WRITE_UNLOCK_IRQRESTORE(&p4_net.netw_lock, flags);
    DP_PROTRACE("%s(): synack rejected (no ci)\n", __func__);
    return;
}

//    p4_net_recv_ctrl(&p4ether_opts, &rs, (p4msg_ctrl_t *)skb->data);

void p4_net_recv_ctrl(p4_net_opts_t *netopts, p4_remserv_t *rs, p4msg_ctrl_t *msg)
{
    switch (msg->type) {
    case P4TYPE_SYN: {
	DP_PROTRACE("%s() SYN\n", __func__);
	p4_net_recv_syn(netopts, rs, &msg->t.syn);
	break;
    }
    case P4TYPE_SYNACK:
	DP_PROTRACE("%s() SYNACK\n", __func__);
	p4_net_recv_synack(netopts, rs, &msg->t.synack);
	break;
    case P4TYPE_DAT:
	break;
    case P4TYPE_ACK:
	DP_PROTRACE2("%s() ACK\n", __func__);
	p4_net_recv_ack(&msg->t.ack);
	break;

    default:
	DP_PROTRACE("%s() ignore type %d\n", __func__, msg->type);
	break;
    }

    proc_recv_net_ctrl_cnt++;
}

void p4_net_recv_ack(p4msg_ack_t *ack)
{
    p4_ci_t *ci;
    DP_PROTRACE2("%s():%d  (cito: %4d, ack: %6d, win %6d)\n", __func__ ,__LINE__,
		 ack->cito, ack->ackno, ack->winsize);
    /* ToDo: Read lock ? */
    ci = p4_net_get_ci_idx(ack->cito);
    if (ci) {
	p4_full_ack_received(ci, ack->ackno, ack->winsize, ack->resend);
	p4_continue_send(ci);
	p4_ci_put(ci);
    }
}

/* ci must be writelocked! */
void _p4_receive(p4_ci_t *ci, p4_frag_t *rf)
{
    DP_PROTRACE2("%s():%d  (ci %p, Seq %6d)\n", __func__ ,__LINE__,
		 ci, rf->SeqNo);

    WRITE_LOCK_ASSERT(&p4_net.netw_lock);

    if (ci->state != CI_STATE_ESTAB) return;

    p4_frag_hold(rf);
    list_add_tail(&rf->Next, &ci->r.RFragQ);

    if (!p4_receiveci_enqueued(ci)) {
	_p4_socket_enq_receiveci(ci);
    }

    DP_PROTRACE2("%s(): Wakeup receive queue.\n", __func__);
    ci->socket->recvq_empty = 0;
    P4_WAITQ_WAKEUP(ci->socket->recv_waitq);
#ifdef P4CALLBACKS
    if (ci->socket->cb_data_ready) ci->socket->cb_data_ready(ci->socket, ci->socket->cb_data_ready_priv);
#endif
    P4LOG(LOG_RX___, rf->SeqNo);
    proc_recv_user_cnt++;
}


void p4_net_receive(p4_frag_t *rf, p4msg_data_header_t *dat)
{
    p4_ci_t *ci;

    DP_PROTRACE2("%s():%d  (cito %6d, Seq %6d)\n", __func__ ,__LINE__,
		 dat->cito, dat->seqno);

    rf->foffset = 0;
    rf->SeqNo = dat->seqno;
    rf->fsize = dat->len;
    rf->Flags = dat->flags;

    P4LOG(LOG_RXDAT, dat->seqno);

    SYNC_WLOCK(&p4_net.netw_lock,{
	ci = p4_net_get_ci_idx(dat->cito);

	if (!ci) SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_ci);

	p4rel_net_receive(ci, rf);
    });

    p4_small_ack_received(ci, dat->ackno, dat->winno);
    p4_continue_send(ci);

    p4_check_urgent_acks(ci);

    p4_ci_put(ci);

    return;
 err_ci:
    DP_PROTRACE2("%s(): No ci\n", __func__);
    /* Illegal or unbound destination */
    return;
}


/*
 * @brief Network received a fragment
 * @param cito connection info
 * @param f fragment received by the network
 */
void p4_net_receive_noseq(uint16_t cito, p4_frag_t *rf)
{
    p4_ci_t *ci;

    DP_PROTRACE2("%s():%d  (cito %6d)\n", __func__ ,__LINE__,
		 cito);

    SYNC_WLOCK(&p4_net.netw_lock,{
	ci = p4_net_get_ci_idx(cito);

	if ((!ci) || (!ci->socket)) SYNC_WLOCK_GOTO(&p4_net.netw_lock, err_con);

	_p4_receive(ci, rf);

	proc_recv_net_data_cnt++;
    });

    p4_ci_put(ci);
    return;
    /* ----- */
 err_con:
    if (!ci) {
	DP_PROTRACE("%s(): No ci\n", __func__);
	/* Illegal or unbound destination */
    } else {
	DP_PROTRACE("%s(): No socket\n", __func__);
	p4_ci_put(ci);
    }
    return;
}

void p4_setcb_new_connection(struct p4_socket_s *socket,
			     void (*new_connection)(struct p4_socket_s *socket,
						    int fromidx, void * priv),
			     void *priv)
{
    socket->cb_new_connection_priv = priv;
    socket->cb_new_connection = new_connection;
}

#ifdef P4CALLBACKS
void p4_setcb_data_ready(struct p4_socket_s *socket,
			 void (*data_ready)(struct p4_socket_s *socket, void * priv),
			 void * priv)
{
    socket->cb_data_ready_priv = priv;
    socket->cb_data_ready = data_ready;
}

void p4_setcb_write_space(struct p4_socket_s *socket,
			  void (*write_space)(struct p4_socket_s *socket, void * priv),
			  void *priv)
{
    socket->cb_write_space_priv = priv;
    socket->cb_write_space = write_space;
}

P4_EXPORT_SYMBOL(p4_setcb_data_ready);
P4_EXPORT_SYMBOL(p4_setcb_write_space);

#endif /* P4CALLBACKS */

static
int p4_net_init(void)
{
    int i;

    memset( &p4_net, 0, sizeof( p4_net ));

    p4_net.netw_lock = RW_LOCK_UNLOCKED;

    p4_net.last_idx = -1;
    INIT_LIST_HEAD(&p4_net.socket_list);

    for (i=0; i< P4_N_CON_NET; i++) {
	p4_net.ci_list_net.ci[i] = NULL;
    }
    return 0;
}

#ifdef DEBUG_TIMER
struct timer_list debug_timer;
static
void p4_do_debugtimer(unsigned long param)
{
    DPRINT(KERN_DEBUG "P4: ci:%d sock:%d  frag:%d nr_running:%d cpus:%d\n",
	   proc_ci_counter, proc_sock_alloc_cnt,
	   FRAGCNT,
	   (int)P4_NR_RUNNING,
	   P4_NUM_CPUS);
    debug_timer.expires = jiffies + 10 * HZ;
    add_timer(&debug_timer);
}
#endif

int p4_init(void)
{
    int ret;

    DPRINT(KERN_DEBUG "P4S: Version: " P4_VERSION " " __DATE__ " " __TIME__ "\n");
    p4dummy_init();

    ret = p4_net_init();
    if (ret) goto err_net_init;

    p4ether_init();

    p4_proc_init();

#ifdef DEBUG_TIMER
    init_timer(&debug_timer);
    debug_timer.function = p4_do_debugtimer;
    debug_timer.expires = jiffies + 1 * HZ;
    add_timer(&debug_timer);
#endif
    return 0;

 err_net_init:
    return ret;
}

void p4_cleanup(void)
{
#ifdef DEBUG_TIMER
    del_timer_sync(&debug_timer);
#endif
    p4_proc_cleanup();
    p4ether_cleanup();
    p4dummy_cleanup();
}



P4_EXPORT_SYMBOL(p4myri_opts_ptr);
P4_EXPORT_SYMBOL(p4_set_nodeid);
P4_EXPORT_SYMBOL(_p4_ci_free);
P4_EXPORT_SYMBOL(p4_poll_add);
P4_EXPORT_SYMBOL(p4_poll_del);
P4_EXPORT_SYMBOL(p4_net_receive);
P4_EXPORT_SYMBOL(p4_net_recv_ctrl);
P4_EXPORT_SYMBOL(p4_socket_close);
P4_EXPORT_SYMBOL(p4_shutdown);
P4_EXPORT_SYMBOL(p4_sendmsg);
P4_EXPORT_SYMBOL(p4_socket_bind);
P4_EXPORT_SYMBOL(p4_socket_create);
P4_EXPORT_SYMBOL(p4_recvmsg);
P4_EXPORT_SYMBOL(p4_socket_connect);
P4_EXPORT_SYMBOL(p4_socket_poll);
P4_EXPORT_SYMBOL(p4_setcb_new_connection);
