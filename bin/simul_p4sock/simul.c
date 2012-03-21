#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <assert.h>

#include "list.h"


#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

#define DP_PROTO(fmt,args...) printf("# %6ld " fmt, current ,##args );

long current = 0;

struct timer_list {
    int enqueued;
    unsigned long expires;
    unsigned long data;
    void (*function)(unsigned long);
};


typedef struct conn_s {
    long SStart;
    long SSeqNo;
    long SAckNo;
    long SUntil;
    long SWindow;
    long SWindowHack;
    int Sacks_waiting;
    int dev_SendQsize;

    long RStart;
    long RSeqNo;
    long RWindow;
    long Racks_waiting;
    int Rresend;

    long _userwantsenduntil;
    long _userwantrecvuntil;

    struct timer_list _timerack;
    long _sendbusyuntil;
    long pipesize;
    struct conn_s *remote;
    char  *conname;
} conn_t;

typedef struct event_s {
    struct list_head next;
    long time;
    void (*func)(conn_t *conn, long param);
    conn_t *conn;
    long param;
    char *funcname;
} event_t;






struct list_head events = LIST_HEAD_INIT(events);

void _event_add(struct list_head *lh,
		long time, void (*func)(conn_t *conn, long param),
		conn_t *conn, long param, char *funcname)
{
    event_t *event;
    struct list_head *pos;
    event_t *te;

    event = (event_t *)malloc(sizeof(*event));

    time += current;
    event->time = time;
    event->func = func;
    event->conn = conn;
    event->param = param;
    event->funcname = funcname;

    list_for_each(pos, lh) {
	te = list_entry(pos, event_t, next);
	if (te->time > time) {
	    list_add_tail(&event->next, pos);
	    goto out;
	}
    }
    list_add_tail(&event->next, lh);
out:;
}
#define event_add(lh,time,func,conn,param) \
_event_add(lh,time,func,conn,param,#func);


void print_coninfo(conn_t *conn, char *desc)
{
    printf("%s%s %6ld | "
	   "%6ld %6ld %6ld %6ld %6ld %6d %6ld | "
	   "%6ld %6ld %6ld %6ld %6d\n",
	   conn->conname,
	   desc,
	   current,

	   conn->SStart,
	   conn->SSeqNo,
	   conn->SAckNo,
	   conn->SUntil,
	   conn->SWindow,
	   conn->Sacks_waiting,
	   conn->pipesize,

	   conn->remote->RStart,
	   conn->remote->RSeqNo,
	   conn->remote->RWindow,
	   conn->remote->Racks_waiting,
	   conn->remote->Rresend);
}


void events_execute(struct list_head *lh)
{
    while (!list_empty(lh)) {
	event_t *event = list_entry(lh->next, event_t, next);
	list_del(&event->next);

	current = event->time;
	DP_PROTO("EXEC %20s(%p , %6ld)\n", event->funcname, event->conn, event->param);
	if (event->conn) {
	    print_coninfo(event->conn,"execpre");
	}
	event->func(event->conn, event->param);
	if (event->conn) {
	    print_coninfo(event->conn,"execpost");
	}
	free(event);
    }
}

void events_print(void)
{
    struct list_head *pos;
    event_t *te;
    int i = 0;

    list_for_each(pos, &events) {
	te = list_entry(pos, event_t, next);
	i++;
	printf("#%3d %ld %s(%6ld)\n", i, te->time, te->funcname, te->param);
    }
}


int timer_pending(struct timer_list *timer)
{
    return timer->enqueued;
}

void exec_timer(conn_t *conn, long param)
{
    struct timer_list *timer = (struct timer_list *)param;
    timer->enqueued = 0;
    timer->function(timer->data);
}

void add_timer(struct timer_list *timer, char *desc)
{
    assert(!timer->enqueued);
    timer->enqueued = 1;
    _event_add(&events, timer->expires - current, exec_timer, NULL,
	       (long)timer,
	       desc ? desc : "exec_timer");
}



/* Polling send and receive times*/
#define select_sendtime  10
#define select_recvtime  10
/* RTT for one data packet */
/* Latency ethernet ~30, myrinet ~6 */
#define send_hrtt    30 /*  Latency */
/* ethernet 1.5kB / 10MB/s = ~146us */
#define send_busy    146 /* packetsize / bandwith + overhead */
/* RTT for one ack packet */
/* ethernet 60B / 10MB/s = ~6us */
#define send_ackbusy  6 /* packetsize / bandwith + overhead */
#define randombusyoffset 15.0

/* How long to delay an ack */
#define ackdelay     10 /* us */
#define maxackspend  30000
/* Sizes */
int maxpipesize = 10;
int maxsqsize = 10000;
#define maxsendqsize 60
#define maxrecvqsize 60

//#define SWINDOWHACK

#if 0
    p4_seqno_t	SSeqNo;  /* Next new packet get this SSeqNo */
    p4_seqno_t	SWindow; /* Send until (including) SWindow */
    p4_seqno_t  SAckNo;  /* Ack until (including) SAckNo */
    p4_seqno_t  SUntil;  /* Packets until (including) SUntil transmitted
			      at least one time. Or: Packets from
			      SUntil (excluded) wait for send */

    int		Sacks_waiting; /* true, if SFragQ include acked packets */

    atomic_t	sendcnt;	/* Retransmissioncnt of SYN */
#endif


conn_t con1 = {
    SStart:	0,
    SSeqNo:	0,
    SAckNo:	-1,
    SUntil:	-1,
    SWindow:	0,
    SWindowHack: 0,
    Sacks_waiting: 0,
    dev_SendQsize: 0,
    RStart:	0,
    RSeqNo:	0,
    RWindow:	0,
    Racks_waiting: 0,
    Rresend:	0,
    _userwantsenduntil : 0,
    _userwantrecvuntil : 0,
    _timerack : {0,0,0,0},
    _sendbusyuntil : 0,
    remote:	NULL,
    pipesize:	0,
    conname: "conn1"
};

conn_t con2 = {
    SStart:	0,
    SSeqNo:	0,
    SAckNo:	-1,
    SUntil:	-1,
    SWindow:	0,
    SWindowHack: 0,
    Sacks_waiting: 0,
    dev_SendQsize: 0,

    RStart:	0,
    RSeqNo:	0,
    RWindow:	0,
    Racks_waiting: 0,
    Rresend:	0,
    _userwantsenduntil : 0,
    _userwantrecvuntil : 0,
    _timerack : {0,0,0,0},
    _sendbusyuntil : 0,
    remote:	NULL,
    pipesize:	0,
    conname: "conn2"
};


int ackssend = 0;
int fragssend = 0;
typedef struct msg_s {
    void (*func)(conn_t *conn, long param);
    long param;

    /* after send: */
    void (*funcsend)(conn_t *conn, long param);
    long paramsend;
} msg_t;

void dev_queue_recv(conn_t *conn, long param)
{
    msg_t *dmsg = (msg_t *)param;

    dmsg->func(conn, dmsg->param);

    free(dmsg);
}


void dev_queue_xmit(conn_t *consrc, conn_t *condst, long busy, msg_t *msg)
{
    long dbusy;
    msg_t *dmsg;

    busy += (rand()*randombusyoffset*1.0)/ RAND_MAX;
    dbusy = consrc->_sendbusyuntil - current;
    dbusy = MAX(0, dbusy);
    dbusy += busy;
    assert(dbusy > 0);

    dmsg = (msg_t *)malloc(sizeof(*msg));
    memcpy(dmsg, msg, sizeof(*msg));
    event_add(&events, dbusy + send_hrtt, dev_queue_recv, condst, (long)dmsg);
    if (msg->funcsend) {
	event_add(&events, dbusy, msg->funcsend, consrc, msg->paramsend);
    }
    consrc->_sendbusyuntil = current + dbusy;
}

int sendqsize(conn_t *conn)
{
    return conn->SSeqNo - conn->SStart;
}

int recvqsize(conn_t *conn)
{
    return conn->RSeqNo - conn->RStart;
}


void user_recv(conn_t *conn, long param);
void user_send(conn_t *conn, long param);

void wakeuprecv(conn_t *conn)
{
    if (conn->_userwantrecvuntil) {
	event_add(&events, select_recvtime, user_recv, conn, conn->_userwantrecvuntil);
	conn->_userwantrecvuntil = 0;
    }
}

void wakeupsend(conn_t *conn)
{
    if (conn->_userwantsenduntil) {
	event_add(&events, select_sendtime, user_send, conn, conn->_userwantsenduntil);
	conn->_userwantsenduntil = 0;
    }
}

void sendfrag(conn_t *conn, long seqno);
void netsendack(conn_t *conn);

void continuesend(conn_t *conn)
{
    long lastseq = MIN(conn->SWindow, conn->SSeqNo - 1);

    while ((conn->SUntil + 1 <= lastseq) && (conn->dev_SendQsize < maxsqsize)) {
	conn->SUntil++;
	sendfrag(conn, conn->SUntil);
    }
}

void netrecvack(conn_t *conn, long param)
{
    long *ack = (long *)param;
    if (ack[0] > conn->SAckNo) {
	/* Ack some packets */
	conn->SAckNo = ack[0];
    }

    if (ack[2]) {
	/* Resend */
	conn->SUntil = conn->SAckNo;
    }

    DP_PROTO("RACK  %6ld win:%6ld resend:%ld \n",
	     ack[0], ack[1], ack[2]);
    print_coninfo(conn, "rack");

    /* Cleanup Sendq */
    if (conn->SAckNo > conn->SStart) {
	conn->SStart = conn->SAckNo;
    }
    /* Maybe use conn->SAckNo instead of conn->SStart */
    conn->SWindow = MIN(ack[1], conn->SStart + maxpipesize);
//    if (ack[1] > conn->SWindowHack)
    conn->SWindowHack = ack[1];

    if (conn->SUntil < conn->SWindow) {
	/* send more */
	continuesend(conn);
    }
    if (sendqsize(conn) < maxsendqsize) {
//    if (conn->SSeqNo <= conn->SWindow) {
	wakeupsend(conn);
    }
    free(ack);
}

void netsendack(conn_t *conn)
{
    msg_t msg;
    long *ack = (long *)malloc(sizeof(long *) * 3);

    ack[0] = conn->RSeqNo - 1;
    ack[1] = conn->RStart + maxrecvqsize;
    ack[2] = conn->Rresend;

    msg.func = netrecvack;
    msg.param = (long) ack;

    msg.funcsend = NULL;
    dev_queue_xmit(conn, conn->remote, send_ackbusy, &msg);

    ackssend++;
    DP_PROTO("SACK  %6ld win:%6ld resend:%ld \n",
	     ack[0], ack[1], ack[2]);
    print_coninfo(conn, "sack");

    conn->Racks_waiting = 0;
}

void timer_netsendack(unsigned long data)
{
    conn_t *conn = (conn_t *)data;
    if (conn->Racks_waiting) {
	netsendack(conn);
    }
}

void delayedack(conn_t *conn)
{
    conn->Racks_waiting++;

    if (timer_pending(&conn->_timerack)) {
	/* Ack already enqueued */
    } else {
	conn->Rresend = 0;
	conn->_timerack.expires = current + ackdelay;
	conn->_timerack.data = (long) conn;
	conn->_timerack.function = timer_netsendack;
	add_timer(&conn->_timerack,"timer_netsendack");
    }
}

void resendack(conn_t *conn)
{

}


void ack_received(conn_t *conn, long ackno)
{
}


void netrecvfrag(conn_t *conn, long param)
{
    long seqno = param;
    DP_PROTO("RECV %6ld\n", seqno);
    print_coninfo(conn, "rdat");
    conn->remote->pipesize--;

    if (seqno != conn->RSeqNo) {
	/* Dont accept this packet. */
	if (seqno < conn->RSeqNo) {
	    /* old packet */
	    delayedack(conn);
	} else {
	    /* lost packet */
	    resendack(conn);
	}
    } else {
	if (recvqsize(conn) >= maxrecvqsize) {
	    /* Recvq busy. Reject packet */
	    delayedack(conn);
	} else {
	    /* Accept packet */
	    conn->RSeqNo++;
	    delayedack(conn);
	    wakeuprecv(conn);
	    if (conn->Racks_waiting > maxackspend) {
		/* Send ack now */
		netsendack(conn);
	    }
#ifdef SWINDOWHACK
	    if (conn->SWindow < conn->SWindowHack) {
		conn->SWindow++;
		if (conn->SUntil < conn->SWindow) {
		    /* send more */
		    continuesend(conn);
		}
	    }
#endif
//	    ack_received(conn, rf->AckNo);
	}
    }
//    printf("%8ld Recv SeqNo %ld\n", current, param);
}

/* This should be the destructor of the send skb */
void netsenddone(conn_t *conn, long param)
{
    conn->dev_SendQsize--;
//    fprintf(stderr,"SQSize: %d\n", conn->SQSize);
    if (conn->dev_SendQsize < maxsqsize) {
	if (conn->SUntil < conn->SWindow) {
	    /* send more */
	    continuesend(conn);
	}
	if (sendqsize(conn) < maxsendqsize) {
//    if (conn->SSeqNo <= conn->SWindow) {
	    wakeupsend(conn);
	}
    }
}

void sendfrag(conn_t *conn, long seqno)
{
    msg_t msg;
    assert(seqno >= conn->SStart);
    assert(seqno < conn->SSeqNo);

    msg.func = netrecvfrag;
    msg.param = seqno;

    msg.funcsend = netsenddone;
    msg.paramsend = 0;

    dev_queue_xmit(conn, conn->remote, send_busy, &msg);
    conn->dev_SendQsize++;
    fragssend++;
    conn->pipesize++;

    DP_PROTO("SEND %6ld (busy until %ld)\n", seqno, conn->_sendbusyuntil);
    print_coninfo(conn, "sdat");
}


int sendenqfrag(conn_t *conn, long seqno)
{
    if (sendqsize(conn) >= maxsendqsize)
	return -1;
    /* OK enqueue */
    assert(seqno == conn->SSeqNo);
    conn->SSeqNo++;

    if (seqno <= conn->SWindow && (conn->dev_SendQsize < maxsqsize)) {
	sendfrag(conn, seqno);
	conn->SUntil = seqno;
    } else {
	events_print();
    }
    return 0;
}

long send(conn_t *conn, long param)
{
    long seq;
    assert(param >= conn->SSeqNo);
    for (seq = conn->SSeqNo; seq <= param; seq++) {
	if (sendenqfrag(conn, seq)) {
	    return seq - 1;
	}
    }
    return param;
}


long recv(conn_t *conn, long seqno)
{
    long newstart;

    newstart = MIN(conn->RSeqNo - 1, seqno);

    conn->RStart = newstart;
    /* ToDo : Send new windowsize as ack ?*/
    return newstart;
}



void user_send(conn_t *conn, long param)
{
    long until;

    until = send(conn, param);

    if (until < param) {
	if (0) {
	    /* poll for send */
	    event_add(&events, select_sendtime, user_send, conn, param);
	} else {
	    /* blocking send */
	    if (param > conn->_userwantsenduntil)
		conn->_userwantsenduntil = param;
	    /* save: */
//	    event_add(&events, select_sendtime * 1000, user_send, conn, param);
	}
    }
}

void user_recv(conn_t *conn, long param)
{
    long until;
    long from;

    from = conn->RStart;
    until = recv(conn, param);

    if (from < until)
	DP_PROTO("UREC %6ld  from %6ld\n", until, from +1);
    if (until < param) {
	if (0) {
	    /* poll for recv */
	    event_add(&events, select_recvtime, user_recv, conn, param);
	} else {
	    /* blocking recv */
	    if (param > conn->_userwantrecvuntil)
		conn->_userwantrecvuntil = param;
	    /* save: */
//	    event_add(&events, select_recvtime * 1000, user_recv, conn, param);
	}
    }
}



int main(int argc, char **argv)
{
    long t1;
    int ufrag = 0;
    /* Send Receive: */

    con1.remote = &con2;
    con2.remote = &con1;

//    for (maxpipesize = 30;maxpipesize <= 30; maxpipesize += 2) {
    if (1) {
	/* Send Receive: */
	t1 = -current;
	ufrag += 700;
	event_add(&events, 0, user_send, &con1, ufrag);
	event_add(&events, 0, user_send, &con2, ufrag);
	event_add(&events, 0, user_recv, &con1, ufrag);
	event_add(&events, 0, user_recv, &con2, ufrag);
	events_execute(&events);
	t1 += current;
	fprintf(stderr,"SendRecv time %ld (pipesize %d ackssend:%d fragssend:%d)\n",
		t1, maxpipesize, ackssend, fragssend);
	fprintf(stderr,"sqsize: %d\n",sendqsize(&con1));
    } else {
	/* Send only : */
	t1 = -current;
	event_add(&events, 0, user_send, &con1, 1000);
	event_add(&events, 0, user_recv, &con2, 1000);
	events_execute(&events);
	t1 += current;
	fprintf(stderr,"Send  time %ld (pipesize %d ackssend:%d fragssend:%d)\n",
		t1, maxpipesize, ackssend, fragssend);
    }

    return 0;
}


/*
 * Local Variables:
 *  compile-command: "gcc simul.c -g -Wall -W -Wno-unused -O2 -o simul && ( ./simul.gnu& sleep 10)"
 * End:
 *
 */
