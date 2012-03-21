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
 * p4rel.c: reliable protocol
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include "p4s_debug.h"
#include "p4prot.h"
#include "p4rel.h"
#include "p4io.h"

#ifdef __KERNEL__
#define P4PRINTERR( fmt, arg... ) printk( KERN_ERR fmt ,##arg)
#else
#define P4PRINTERR( fmt, arg... ) fprintf( stderr, fmt ,##arg)
#endif

#ifndef __KERNEL__

/*
 * Debug functions
 */

void p4_dump_Next_queue( struct list_head *l,char *name )
{
    struct list_head *pos;
    struct list_head *next;
    p4_fi_t *f;
    int eee=100;
    int col=4;
    printf("NextQueue: %s\n",name);
    list_for_each_safe(pos, next, l){
	f = list_entry( pos, p4_fi_t, Next);
	printf(", %3ld(%2d(%s))", (long)f->priv, f->State,p4_fstat_str[f->State]);
	if (!(eee--)) goto error;
	if (!(--col)) {printf("\n");col=4;}
    }
    printf("\n");
    return;
 error:
    printf("error!\n");
}

void p4_dump_State_queue( struct list_head *l,char *name )
{
    struct list_head *pos;
    struct list_head *next;
    p4_fi_t *f;
    int eee=100;
    int col=4;
    printf("StatQueue: %s\n",name);
    list_for_each_safe(pos, next, l){
	f = list_entry( pos, p4_fi_t, NextState);
	printf(", %3ld(%2d(%s))", (long)f->priv, f->State, p4_fstat_str[f->State]);
	if (!(eee--)) goto error;
	if (!(--col)) {printf("\n");col=4;}
    }
    printf("\n");
    return;
 error:
    printf("error!\n");
}

void p4_dump_qentry( struct list_head *lh, char *desc)
{
    printf("%s %3ld(2%d(%s))\n", desc,
	   lh ? (long)list_entry( lh, p4_fi_t, Next )->priv: -1,
	   lh ? list_entry( lh, p4_fi_t, Next )->State: -1,
	   lh ?
	   p4_fstat_str[ list_entry( lh, p4_fi_t, Next )->State ]:
	   "NONE");
}

void p4_dump_queues( p4_ci_t *ci )
{
    p4_dump_Next_queue( &ci->FragQ,"FragQ");
/*    p4_dump_State_queue( &ci->WinOpenQ,"WinOpenQ");*/
    p4_dump_qentry( ci->WaitWinQ , "WaitWinQ" );
/*    p4_dump_qentry( ci->ToSendQ , "ToSendQ" );*/
    printf("NextSeqNo: %u SWin: %u\n", ci->SSeqNo, ci->SWindow );
}


#endif /* __KERNEL__*/


/*
 * Internal Events ( Send )
 */

static inline
p4_frag_t *p4_sf_get(p4_ci_t *ci, p4_seqno_t seq)
{
    p4_frag_t *ret = NULL;
    struct list_head *pos;

    SPIN_LOCK_ASSERT(&ci->s.SSeqLock);
    list_for_each(pos, &ci->s.SFragQ) {
	p4_frag_t *sf = list_entry(pos, p4_frag_t, Next);
	/* DP_RELTRACE(__FUNCTION__ "() Check Seq %d (search %d)\n",
	   sf->SeqNo, seq); */
	if (p4_seqcmp(sf->SeqNo , seq) == 0) {
	    /* DP_PROTRACE(__FUNCTION__ "():%d\n",__LINE__); */
	    p4_frag_hold(sf);
	    ret = sf;
	    goto out;
	}
    }
 out:
    return ret;
}

static void p4_set_resendtimeout(p4_ci_t *ci);


static inline
void p4_do_resend(p4_ci_t *ci)
{
    int set_resend_timeout = 1;
    int ret;
    /* mostly called from bottom half (softirq) */
    DP_RELTRACE("%s() seqfrom: %5d (sseq:%d ack:%d unti:%d) "
		"Enter in_interrupt:%d in_irq:%d in_softirq:%d\n",
		__func__,
		ci->s.SUntil + 1, ci->s.SSeqNo, ci->s.SAckNo, ci->s.SUntil,
		(int)in_interrupt(), (int)in_irq(), (int)in_softirq());

    if (ci->state != CI_STATE_ESTAB) {
	if (ci->state != CI_STATE_CLOSEING)
	    goto out;
    }

    if (SPIN_TRYLOCK(&ci->s.SSeqLock)) {
	p4_seqno_t seqfrom = ci->s.SUntil + 1;
	p4_cleanup_sendq(ci);
	while (1) {
	    p4_frag_t *sf = p4_sf_get(ci, seqfrom);
	    if (!sf) break;

	    DP_RELTRACE("%s() send seq: %5d ,Set SUntil %5d (try %d)\n", __func__,
			sf->SeqNo, ci->s.SUntil, atomic_read(&ci->s.sendcnt));

	    ret = ci->net_opts->net_send_frag(ci, sf);
	    p4_frag_put(sf);
	    if (ret) break;

	    if (p4_seqcmp(ci->s.SUntil, seqfrom) < 0) ci->s.SUntil = seqfrom;
	    seqfrom++;
	}
	set_resend_timeout = !list_empty(&ci->s.SFragQ);

	SPIN_UNLOCK(&ci->s.SSeqLock);
    } else {
	DP_RELTRACE("%s() SPIN_TRYLOCK(&ci->s.SSeqLock) failed\n", __func__);
	ci->s.call_continue_send = 1;
    }
    if (set_resend_timeout) p4_set_resendtimeout(ci);
    DP_RELTRACE("%s() exit\n", __func__);
 out:
    return;
}


/*
 * External Events ( Send )
 */


void p4_cleanup_sendq(p4_ci_t *ci)
{
    p4_frag_t *sf;

    SPIN_LOCK_ASSERT(&ci->s.SSeqLock);

    if (ci->s.Sacks_waiting) {
	ci->s.Sacks_waiting = 0;
	DP_PROTRACE2("%s():%d\n", __func__ ,__LINE__);
	while (!list_empty(&ci->s.SFragQ)) {
	    sf = list_entry(ci->s.SFragQ.next, p4_frag_t, Next);
	    if (p4_seqcmp(sf->SeqNo, ci->s.SAckNo) <= 0) {
		list_del(&sf->Next);
		p4_frag_put(sf);
	    } else {
		break;
	    }
	}
	if (p4_seqcmp(ci->s.SAckNo, ci->s.SUntil) > 0) {
	    ci->s.SUntil = ci->s.SAckNo; /* reset SUntil counter */
	}
    }
}

void p4_continue_send(p4_ci_t *ci)
{
    ci->s.call_continue_send = 0;
    /* Reading SUntil without the ci->s.SSeqLock is ok here! */
    if (p4_seqcmp(ci->s.SUntil + 1, ci->s.SSeqNo) < 0) {
	p4_do_resend(ci);
    }
}

static
void p4_timed_resend(unsigned long param)
{
    p4_ci_t *ci = (p4_ci_t *)param;

    if (ci->state != CI_STATE_ESTAB) {
	if (ci->state != CI_STATE_CLOSEING) {
	    DP_PROTRACE("resend: Connection %d-%d in state %d.\n",
			ci->list_usr_idx, ci->list_net_idx, ci->state);
	    goto out;
	}
    }

    atomic_inc(&ci->s.sendcnt);
    if (atomic_read(&ci->s.sendcnt) > ci->net_opts->MaxResend) {
	SYNC_WLOCK(&p4_net.netw_lock,{
	    if (ci->state == CI_STATE_ESTAB) {
		CI_STATE_SET(ci, CI_STATE_SBROKEN);
	    }
	    if (ci->state == CI_STATE_CLOSEING) {
		CI_STATE_SET(ci, CI_STATE_SBROKEN_CLOSEING);
	    }
	});
	printk(KERN_WARNING
	       "P4S: resend: Con %d-%d broken.(Missing HW flow control?)\n",
	       ci->list_usr_idx, ci->list_net_idx);
	DP_PROTRACE("resend: Connection %d-%d broken.\n",
		    ci->list_usr_idx, ci->list_net_idx);
	goto out;
    }

    /* Reset the SUntil without the ci->s.SSeqLock is ok here!(?) */
    ci->s.SUntil = ci->s.SAckNo; /* reset SUntil counter */
    p4_do_resend(ci);

    proc_timer_resend_cnt++;

    /* Probe next time with larger windowsize */
    ci->s.SWindow++;
 out:
    p4_ci_put(ci);
    return;
}

static
void p4_timed_send_ack(unsigned long param)
{
    p4_ci_t *ci = (p4_ci_t *)param;

    if (atomic_read(&ci->r.Racks_waiting)) {
	p4_send_ack(ci);
	proc_timer_ack_cnt++;
    }
    p4_ci_put(ci);
}

static
void p4_set_resendtimeout(p4_ci_t *ci)
{
    p4_ci_hold(ci);
    ci->s.resend_timer.data = (unsigned long)ci;
    ci->s.resend_timer.function = p4_timed_resend;

    if (mod_timer(&ci->s.resend_timer,
		  jiffies + ci->net_opts->ResendTimeout)) {
	p4_ci_put(ci);
    }
}


static
void p4_timed_continue_send(unsigned long param)
{
    p4_ci_t *ci = (p4_ci_t *)param;

    /* like p4_continue_send(), but force p4_set_resendtimeout();*/
    ci->s.call_continue_send = 0;
    /* Reading SUntil without the ci->s.SSeqLock is ok here! */
    if (p4_seqcmp(ci->s.SUntil + 1, ci->s.SSeqNo) < 0) {
	p4_do_resend(ci);
    } else {
	/* reschedule for resend */
	p4_set_resendtimeout(ci);
    }

    p4_ci_put(ci);
}


void p4_delayed_continue_send(p4_ci_t *ci)
{
    ci->s.call_continue_send = 0;
    /* Reading SUntil without the ci->s.SSeqLock is ok here! */
    if (p4_seqcmp(ci->s.SUntil + 1, ci->s.SSeqNo) < 0) {
	p4_ci_hold(ci);
	ci->s.resend_timer.data = (unsigned long)ci;
	// may replace p4_timed_resend:
	ci->s.resend_timer.function = p4_timed_continue_send; // Hope '=' is atomic!

	if (mod_timer(&ci->s.resend_timer, 0 /*now*/)) {
	    p4_ci_put(ci);
	}
    }
}



/*
 * @brief Send a fragment
 * @param f fragment to send
 * @param ci connection info
 */

void p4_enq_for_resend(p4_ci_t *ci, p4_frag_t *sf)
{
    DP_RELTRACE("%s\n", __func__);

    SPIN_LOCK_ASSERT(&ci->s.SSeqLock);
    /* Add to Sendq */
    P4LOG(LOG_SENDENQ, sf->SeqNo);

    list_add_tail(&sf->Next, &ci->s.SFragQ);
    p4_frag_hold(sf);
//    p4_cleanup_sendq(ci);
    p4_set_resendtimeout(ci);
}

static
void p4_delayed_send_ack(p4_ci_t *ci)
{
    atomic_inc(&ci->r.Racks_waiting);
    if (!timer_pending(&ci->r.ack_timer)) {
	p4_ci_hold(ci);
	ci->r.ack_timer.data = (unsigned long)ci;
	ci->r.ack_timer.function = p4_timed_send_ack;
	/* Maybe the timer function is also running and called add_timer.
	   So we use mod_timer here, to avoid double timer enqueue.*/
	if (mod_timer(&ci->r.ack_timer, jiffies +
		      ci->net_opts->AckDelay)) {
	    p4_ci_put(ci);
	}
    }
}

#if 0
void dump_ci_RFragQ_oo(p4_ci_t *ci)
{
    struct list_head *pos;
    int cnt = 8;
    list_for_each(pos, &ci->RFragQ_oo) {
	p4_rf_t *rf = list_entry(pos, p4_rf_t, Next);
	if (!(cnt--)) break;
	DPRINT("%d ",rf->SeqNo);
    }
}
#endif

/*
 * External Events ( Receive )
 */

/*
 * @brief Network received a fragment
 * @param ci connection info
 * @param f fragment received by the network
 */
void p4rel_net_receive(p4_ci_t *ci, p4_frag_t *rf)
{
    struct p4_socket_s *socket;

    WRITE_LOCK_ASSERT(&p4_net.netw_lock);

    socket = ci->socket;
    if (!socket) goto conn_closed;

    if (rf->SeqNo == ci->r.RSeqNo ){
	/* accept this packet, if Rwindow open */
	if (1 /*p4_seqcmp(rf->SeqNo, ci->RWindow) <= 0*/){
	    DP_RELTRACE("%s():Accept\n", __func__);
	    /* forward message one layer up */
	    ci->r.RSeqNo++;
	    _p4_receive(ci, rf);

	    /* Out of order packets? */
	    while (!list_empty(&ci->r.RFragQ_oo) &&
		   ((rf = list_entry(ci->r.RFragQ_oo.next, p4_frag_t, Next))->SeqNo
		    == ci->r.RSeqNo)) {
		list_del(&rf->Next);
		ci->r.RSeqNo++;
		_p4_receive(ci, rf);
		p4_frag_put(rf);
	    }
	    ci->r.Rresend = !list_empty(&ci->r.RFragQ_oo);

	    p4_delayed_send_ack(ci);
	}else{
	    DP_RELTRACE("%s():Accept, but closed window\n", __func__);
	    /* rwindow closed */
	    /* ToDo: Check if we can increase the window */
//	    if (net_opts) net_opts->net_send_ack(ci);
	}
    }else{
	if (p4_seqcmp(rf->SeqNo, ci->r.RSeqNo) < 0 ){
	    DP_RELTRACE("%s():Old Packet\n", __func__);
//	    DPRINT(__FUNCTION__ "():Old Packet Seqno %d expect %d\n",
//		   rf->SeqNo, ci->RSeqNo);
	    /* Old packet. Yust send ack back */
	    p4_delayed_send_ack(ci);
	}else{
	    struct list_head *pos;
	    DP_RELTRACE("%s():LostPacket Seqno %d expect %d\n", __func__,
			rf->SeqNo, ci->r.RSeqNo);
//	    DPRINT(__FUNCTION__ "():LostPacket Seqno %d expect %d\n",
//		   rf->SeqNo, ci->RSeqNo);
	    /* Lost packet detected. Ask for retransmission */

	    /* Enqueue (sorted) to RFragQ_oo */
	    pos = ci->r.RFragQ_oo.prev;
	    while (pos != &ci->r.RFragQ_oo) {
		p4_frag_t *lrf = list_entry(pos, p4_frag_t, Next);
		if (lrf->SeqNo == rf->SeqNo) {
		    goto go_double;
		}
		if (p4_seqcmp(lrf->SeqNo, rf->SeqNo) < 0) break;
		pos = pos->prev;
	    }
	    list_add(&rf->Next, pos);
	    p4_frag_hold(rf);

//	    dump_ci_RFragQ_oo(ci);
//	    DPRINT(" Enqueued %d\n", ci->RSeqNo);
	go_double:
	    ci->r.Rresend = 1;
	    p4_delayed_send_ack(ci);
	}
    }

    proc_recv_net_data_cnt++;
    return;
    /* ----- */
 conn_closed:
    p4_delayed_send_ack(ci);
    proc_recv_net_data_cnt++;
    return;
}

/*
 * @brief Set the receive window
 * @param ci connection info
 * @param win new window end
 */
void p4_setrwindow(p4_ci_t *ci, p4_seqno_t win)
{
    DP_RELTRACE("%s(cinetidx %d, %d (%d))\n", __func__,
		ci->list_net_idx, win, ci->r.RSeqNo);
    ci->r.RWindow = win;
    p4_delayed_send_ack(ci);
}

/*
 * Send/Receive Initialization
 */

/*
 * @brief Initialize a connection
 * @param ci connection info
 */
/* ci will be modified */
void p4_rel_init_ci(p4_ci_t *ci)
{
    /* init fragment queues */
    INIT_LIST_HEAD(&ci->s.SFragQ);
    INIT_LIST_HEAD(&ci->r.RFragQ);
    INIT_LIST_HEAD(&ci->r.RFragQ_oo);

    /* init timer */
    init_timer(&ci->s.resend_timer);
    init_timer(&ci->r.ack_timer);

    ci->s.SSeqLock = P4_SPIN_LOCK_UNLOCKED;
    init_MUTEX(&ci->s.SendLock);
    ci->r.call_p4 = 0;

    /* ToDo: Randomize the Sequencenumbers */
    ci->s.SSeqNo = 30000;
    ci->s.SWindow = 30100; /* ToDo: +100 */
    ci->s.SAckNo = ci->s.SSeqNo - 1;
    ci->s.SUntil = ci->s.SSeqNo - 1;
    ci->r.RSeqNo = 30000;
    ci->r.RWindow = 0;
}


P4_EXPORT_SYMBOL(p4_continue_send);
