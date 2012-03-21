/*
 * ParaStation
 *
 * Copyright (C) 2001-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2004-2006 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/*
   2006-04-06 Jens Hauke <hauke@par-tec.com>
   2005-03-03 Jens Hauke <hauke@par-tec.com>
   2003-11-17 Jens Hauke <hauke@par-tec.com> Changed implementation for p4sock.
   2001-06-08 Jens Hauke
*/

#include <linux/kernel.h>
// #include <linux/config.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <linux/poll.h>

#undef ALIGN

//#include "port_hash.h"
#include "p4linux.h"
#include "p4sockets.h"

#include "psockt.h"

static char vcid[] __attribute__(( unused )) =
"$Id$";

#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

#define IP_SPLIT(addr)								\
    (((uint32_t)(addr)) >> 24) & 0xff, (((uint32_t)(addr)) >> 16) & 0xff,	\
    (((uint32_t)(addr)) >>  8) & 0xff, (((uint32_t)(addr)) >>  0) & 0xff

#define PRINT_TRACE(fmt,param...) printk(KERN_INFO fmt,##param)
//#define PRINT_TRACE(fmt,param...)


//#define TINETLdeb(p) printk("<1>TINET LOCK "p"(%s:%d)\n",__FILE__,__LINE__)
#define TINETLdeb(p)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
/* this can not work with lustre !!! */
#define SK_MYPTR(sk) (sk)->sk_user_data
#define SK_MYPTR_ASSERT 1

#define p4_inet_sk(sk) inet_sk(sk)

#else

/* use space after protinfo.af_inet */
#define SK_MYPTR(sk) *((void **)((char *)(&(sk)->protinfo.af_inet) + sizeof((sk)->protinfo.af_inet)))

#define SK_MYPTR_ASSERT sk_myptr_assert()

static
int sk_myptr_assert(void)
{
	struct sock *sock = NULL;
	void *myptr = &SK_MYPTR(sock);
	void *endofprotinfo = ((char *)(&sock->protinfo)) + sizeof(sock->protinfo);
//      printk(KERN_INFO "p4tcp: my %p prot %p endofprot %p sizeofprot %d\n",
//	       myptr, &sock->protinfo, endofprotinfo, sizeof(sock->protinfo));
	if (endofprotinfo < myptr) {
		printk(KERN_ERR "p4tcp: assert \"SK_MYPTR(sock)\" failed!\n");
		return 0;
	}
	return 1;
}

#define p4_inet_sk(sk) sk

#endif

#ifndef unlikely
#define unlikely(_x) _x
#endif

static spinlock_t tinet_lock=SPIN_LOCK_UNLOCKED;

#define TINETLVAR	unsigned long _flags
/* tinet lock*/
#define TINETL   TINETLdeb("wl ");spin_lock_irqsave(&tinet_lock,_flags)
#define TINETUL  TINETLdeb("wul");spin_unlock_irqrestore(&tinet_lock,_flags)

#define TINET_IP2NETADDR(a,b,c,d) ((uint32_t)0x1000000*(d)+0x10000*(c)+0x100*(b)+(a))

static struct proto_ops tinet_proto_ops;
static struct proto_ops tinet_proto_ps_ops;

#define PEEK_BUF_SIZE	32

typedef struct p4sock_info_s {
	struct p4_socket_s *p4s;
	struct socket *tcp_sock;
	int rem_conidx;
	int state;
	char peek_buf[PEEK_BUF_SIZE];
	int peek_len;

	P4_WAITQ_HEADVAR(newcon_waitq);
} p4sock_info_t;

#define SOCK_STATE_UNCONNECTED  0 /* send and receive not allowed */
#define SOCK_STATE_CONNECTED    1 /* send and receive allowed */
#define SOCK_STATE_CONNECTED_PEEK    2 /* send and receive allowed and peek buffer holds data */
#define SOCK_STATE_EOF_RECEIVED 3 /* send allowed, receive not allowed (shutdown) */


typedef struct p4tcp_range_info_s {
	struct list_head next;
	p4tcp_ip_range_t iprange;
} p4tcp_range_info_t;


static
LIST_HEAD(p4tcp_range_head);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#define TINET_REGISTER_PROTO 1
#endif

#ifdef TINET_REGISTER_PROTO
static struct proto tinet_proto = {
	.name		= "TINET",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct sock),
};
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define sk_family family
#define sk_protocol protocol
#endif


static int tinet_is_addr_matching(struct socket *sock)
{
	struct list_head *pos;
	uint32_t check = ntohl(p4_inet_sk(sock->sk)->daddr);
	int ret = 0;
	TINETLVAR;

	TINETL;

	list_for_each(pos, &p4tcp_range_head) {
		p4tcp_ip_range_t *r = &list_entry(pos, p4tcp_range_info_t, next)->iprange;
		uint32_t f = ntohl(r->sin_from.s_addr);
		uint32_t t = ntohl(r->sin_to.s_addr);

		if ((f <= check) && (check <= t)) {
			ret = 1;
			goto out;
		}
	}
 out:
	TINETUL;
	return ret;
}

static
int _p4tcp_append_range(p4tcp_ip_range_t *iprange)
{
	p4tcp_range_info_t *n;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) {
		return -EAGAIN;
	} else {
		struct list_head *pos;
		uint32_t check = ntohl(iprange->sin_from.s_addr);
		n->iprange = *iprange;
		/* orderd add */
		list_for_each(pos, &p4tcp_range_head) {
			p4tcp_range_info_t *r = list_entry(pos, p4tcp_range_info_t, next);
			if (ntohl(r->iprange.sin_from.s_addr) > check) {
				list_add_tail(&n->next, pos);
				goto out;
			}
		}
		list_add_tail(&n->next, &p4tcp_range_head);
	out:
		return 0;
	}
}

static
int p4tcp_add_ip_range(p4tcp_ip_range_t *iprange)
{
	struct list_head *pos;
	int ret = 0;
	uint32_t lf, lt;
	p4tcp_range_info_t *l;

	TINETLVAR;

	if (ntohl(iprange->sin_from.s_addr) > ntohl(iprange->sin_to.s_addr))
		return -EINVAL;

	TINETL;

	ret = _p4tcp_append_range(iprange);
	if (ret) goto out; /* error.no mem ? */

	/* we have at least one entry! */
	l = list_entry(p4tcp_range_head.next, p4tcp_range_info_t, next);
	lf = ntohl(l->iprange.sin_from.s_addr);
	lt = ntohl(l->iprange.sin_to.s_addr);

	/* Cleanup the list (remove doubles) */
	for (pos = p4tcp_range_head.next->next; pos != &p4tcp_range_head; pos = pos->next) {
		/* loop starts on second entry */
		p4tcp_range_info_t *r = list_entry(pos, p4tcp_range_info_t, next);
		uint32_t rf = ntohl(r->iprange.sin_from.s_addr);
		uint32_t rt = ntohl(r->iprange.sin_to.s_addr);

		if ((lt >= rf) || (lt + 1 == rf /* uint32 wrap around */)) { /* overlap */
			if (lf < rf) {
				rf = lf;
				r->iprange.sin_from.s_addr = htonl(rf);
			}
			if (lt > rt) {
				rt = lt;
				r->iprange.sin_to.s_addr = htonl(rt);
			}
			list_del(&l->next);
			kfree(l);
		}
		l = r;
		lf = rf;
		lt = rt;
	}
 out:
	TINETUL;
	return ret;
}

static
int p4tcp_del_ip_range(p4tcp_ip_range_t *iprange)
{
	struct list_head *pos;
	struct list_head *tmp;
	uint32_t f = ntohl(iprange->sin_from.s_addr);
	uint32_t t = ntohl(iprange->sin_to.s_addr);
	int ret = 0;
	TINETLVAR;

	if (f > t)
		return -EINVAL;

	TINETL;

	list_for_each_safe(pos, tmp, &p4tcp_range_head) {
		p4tcp_range_info_t *r = list_entry(pos, p4tcp_range_info_t, next);
		uint32_t lf = ntohl(r->iprange.sin_from.s_addr);
		uint32_t lt = ntohl(r->iprange.sin_to.s_addr);

		if ((f <= lf) && (lt <= t)) { /* listentry inside range */
			list_del(&r->next);
			kfree(r);
			continue;
		}
		if ((lf < f) && (t < lt)) { /* listentry around range */
			p4tcp_ip_range_t nrange;
			nrange.sin_from.s_addr = htonl(t + 1);
			nrange.sin_to.s_addr = r->iprange.sin_to.s_addr;
			ret = _p4tcp_append_range(&nrange);
			/* we must go outof the for_each loop after _append_range!!! */
			if (!ret)
				r->iprange.sin_to.s_addr = htonl(f - 1);
			goto out;
		}
		if ((f <= lf) && (lf <= t)) { /* left overlap */
			r->iprange.sin_from.s_addr = htonl((lf = t + 1));
		}
		if ((lt <= t) && (f <= lt)) { /* right overlap */
			r->iprange.sin_to.s_addr = htonl((lt = f - 1));
		}
	}
 out:
	TINETUL;
	return ret;
}

static
int p4tcp_get_ip_range(int idx, p4tcp_ip_range_t *iprange)
{
	struct list_head *pos;
	int i = 0;
	int ret = 0;

	TINETLVAR;
	TINETL;

	list_for_each(pos, &p4tcp_range_head) {
		p4tcp_range_info_t *r = list_entry(pos, p4tcp_range_info_t, next);
		if (i == idx) {
			*iprange = r->iprange;
			goto out;
		}
		i++;
	}
	ret = -ENOENT;
 out:
	TINETUL;
	return ret;
}


/* wait for the rem_conidx or a signal */
static
int tinet_wait_for_newcon(p4sock_info_t *p4s_info)
{
	int err = EINTR;
	unsigned long msg_time;
	int msg_cnt = 0;

	P4_WAITQ_VAR(wait);

	if (p4s_info->rem_conidx >= 0) return 0;

	P4_WAITQ_ADD(p4s_info->newcon_waitq, wait);


	msg_time = jiffies + 10 * HZ;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);

		if (p4s_info->rem_conidx >= 0) {
			err = 0;
			break;
		}

		if (signal_pending(current)) {
			// Maybe use "err = sock_intr_errno(timeo);" ?
			err = -EINTR;
			break;
		}
		schedule_timeout(2 * HZ);
		if (msg_time <= jiffies) {
			struct sock *tcp_sk = p4s_info->tcp_sock->sk;
			msg_time = jiffies + (++msg_cnt) * 10 * HZ;

			printk(KERN_NOTICE "p4tcp: Error : TCP %u.%u.%u.%u:%u to %u.%u.%u.%u:%u : missing p4s accept?\n",
			       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->saddr)), ntohs(p4_inet_sk(tcp_sk)->sport),
			       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->daddr)), ntohs(p4_inet_sk(tcp_sk)->dport));
		}
	}

	set_current_state(TASK_RUNNING);
	P4_WAITQ_REMOVE(p4s_info->newcon_waitq, wait);

	return err;
}


static
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
int tinet_sendmsg_ps(struct socket *sock, struct msghdr *msg, int size,
		     struct scm_cookie *scm)
#else
int tinet_sendmsg_ps(struct kiocb *iocb, struct socket *sock,
		     struct msghdr *msg, size_t size)
#endif
{
	int ret=0;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	if (p4s_info->state != SOCK_STATE_UNCONNECTED) {
		if (unlikely(p4s_info->rem_conidx < 0)) {
			if (msg->msg_flags & MSG_DONTWAIT) {
				ret = -EWOULDBLOCK;
				goto out;
			}
			ret = tinet_wait_for_newcon(p4s_info);
			if (!ret && (p4s_info->rem_conidx < 0)) {
				ret = -EPIPE;
			}
			if (ret) goto out;
		}

		// PRINT_TRACE( "p4tcp: %p %p sendmsg_ps() SEND via PS\n",sock,sock->inode);
		ret = p4_sendmsg(p4s_info->p4s, p4s_info->rem_conidx,
				 msg->msg_iov, size, msg->msg_flags);
	} else {
		ret = -EPIPE; /* closed connection */
	}
out:
	return ret;
}


static inline
int tinet_read_p4sock(p4sock_info_t *p4s_info, struct iovec *iov, int size, int flags)
{
	int ret;

	ret = p4_recvmsg(p4s_info->p4s, iov, /*from */NULL, size, flags);
	if (ret > 0) {
		return ret;
	} else if (ret == 0) {
		/* remote connection closed or shutdown. */
		p4s_info->state = SOCK_STATE_EOF_RECEIVED;
	}
	return ret;
}


/* return size of peekbuf or err */
static inline
int tinet_fill_peek_buf(p4sock_info_t *p4s_info, int flags)
{
	mm_segment_t oldmm;
	struct iovec iov[1];
	int err;

	if (p4s_info->peek_len == PEEK_BUF_SIZE) return p4s_info->peek_len;

	iov[0].iov_base = p4s_info->peek_buf + p4s_info->peek_len;
	iov[0].iov_len = PEEK_BUF_SIZE - p4s_info->peek_len;

	oldmm = get_fs(); set_fs (KERNEL_DS);
	err = tinet_read_p4sock(p4s_info, iov, iov[0].iov_len, flags);
	set_fs(oldmm);

	if (err < 0) return err;

	p4s_info->peek_len += err;

	if (p4s_info->peek_len)
		p4s_info->state = SOCK_STATE_CONNECTED_PEEK;

	return p4s_info->peek_len;
}


static inline
int tinet_read_peek_buf(p4sock_info_t *p4s_info, struct iovec *iov, int size, int peek)
{
	int len = MIN(size, p4s_info->peek_len);
	int ret;

	ret = memcpy_toiovec(iov, p4s_info->peek_buf, len);
	if (ret) return ret;

	if (!peek) {
		p4s_info->peek_len -= len;
		if (!p4s_info->peek_len) {
			p4s_info->state = SOCK_STATE_CONNECTED;
		} else {
			memmove(p4s_info->peek_buf, p4s_info->peek_buf + len, p4s_info->peek_len);
		}
	}
	return len;
}


static
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
int tinet_recvmsg_ps(struct socket *sock, struct msghdr *msg, int size,
		     int flags, struct scm_cookie *scm)
#else
int tinet_recvmsg_ps(struct kiocb *iocb, struct socket *sock,
		     struct msghdr *msg, size_t size, int flags)
#endif
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);
	int err;

	// PRINT_TRACE( "p4tcp: %p %p recvmsg_ps() RECV via PS\n",sock,sock->inode);
	if (!(flags & MSG_PEEK)) {
		if (p4s_info->state == SOCK_STATE_CONNECTED) {

			return tinet_read_p4sock(p4s_info, msg->msg_iov, size, flags);

		} else if (p4s_info->state == SOCK_STATE_CONNECTED_PEEK) {

			if (size < 0) return -EINVAL;

			ret = tinet_read_peek_buf(p4s_info, msg->msg_iov, size, 0);
			if (ret < 0) return ret;

			size -= ret;
			if (size > 0) {
				/* read more */
				err = tinet_read_p4sock(p4s_info, msg->msg_iov, size, flags);
				if (err > 0) ret += err;
			}
		} else {
			return 0; /* closed connection */
		}
	} else {
		/* Peek message */
		if (size < 0) return -EINVAL;
		if ((p4s_info->state == SOCK_STATE_CONNECTED) ||
		    (p4s_info->state == SOCK_STATE_CONNECTED_PEEK)) {

			ret = tinet_fill_peek_buf(p4s_info, flags);
			if (ret >= 0) {
				ret = tinet_read_peek_buf(p4s_info, msg->msg_iov, size, 1);
			}
		} else {
			return 0; /* closed connection */
		}
	}

	return ret;
}


static
unsigned int
tinet_poll_ps(struct file * file, struct socket *sock,struct poll_table_struct *wait)
{
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);
	int ret;
	// PRINT_TRACE( "p4tcp: %p %p poll()\n",sock,sock->inode);

	if (p4s_info->state == SOCK_STATE_CONNECTED) {
		ret = p4_socket_poll(file, p4s_info->p4s, wait);
	} else if (p4s_info->state == SOCK_STATE_CONNECTED_PEEK) {
		/* peek buffer holds data. ToDo: check POLLOUT */
		ret = POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
	} else {
		/* closed connection or shutdown received*/
		ret = POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
	}
	// PRINT_TRACE( "p4tcp: %p %p poll()done\n",sock,sock->inode);
	return ret;
}


#ifdef P4CALLBACKS
void tinet_cb_data_ready(struct p4_socket_s *p4s, void *priv)
{
	struct sock *sk = priv;
	// PRINT_TRACE( "p4tcp: data_ready called\n");
	if (sk->data_ready) sk->data_ready(sk, 0);
	// p4_setcb_data_ready(p4s, NULL, NULL);
}

void tinet_cb_write_space(struct p4_socket_s *p4s, void *priv)
{
	struct sock *sk = priv;
	// PRINT_TRACE( "p4tcp: write_space called\n");
	if (sk->write_space) sk->write_space(sk);
	// p4_setcb_write_space(p4s, NULL, NULL);
}
#endif


static
void tinet_cb_newcon(struct p4_socket_s *socket, int fromidx, void *priv)
{
	p4sock_info_t *p4s_info = (p4sock_info_t *) priv;

	p4s_info->rem_conidx = fromidx;
	P4_WAITQ_WAKEUP(p4s_info->newcon_waitq);

#if 0
	{
		struct sock *tcp_sk = p4s_info->tcp_sock->sk;

		printk(KERN_DEBUG "p4tcp: Bypass TCP %u.%u.%u.%u:%u to %u.%u.%u.%u:%u (accept newcon on %d)\n",
		       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->saddr)), ntohs(p4_inet_sk(tcp_sk)->sport),
		       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->daddr)), ntohs(p4_inet_sk(tcp_sk)->dport),
		       fromidx);
	}
#endif
}


/* try handshake with other side. return 0 on success.
   On failure, this function leave the connection on TCP. */
static
int tinet_open_ps(struct socket *sock, int server)
{
	union {
		struct {
			char magic[2];
			uint16_t port;
			uint32_t ip;
		} s;
		p4_addr_t p4addr;
	} addr;

	unsigned long timeout;
	TINETLVAR;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);
	struct sock *tcp_sk = p4s_info->tcp_sock->sk;

	p4s_info->rem_conidx = -1;
	p4s_info->peek_len = 0;

	p4s_info->p4s = p4_socket_create();
	if (!p4s_info->p4s) goto err_create_failed;

	if (server) {
		p4_setcb_new_connection(p4s_info->p4s, tinet_cb_newcon, p4s_info);

		/* the p4addr is the ip/port pair from remote peer, which
		   is unique from this node. */
		addr.s.magic[0] = 'T';addr.s.magic[1] = 'P';
		addr.s.ip = p4_inet_sk(tcp_sk)->saddr;
		addr.s.port = p4_inet_sk(tcp_sk)->sport;

		p4_socket_bind(p4s_info->p4s, &addr.p4addr);
	} else {
		p4_remaddr_t p4remaddr;
		/* the p4addr is the ip/port pair from this peer, which
		   is unique on this node. */
		addr.s.magic[0] = 'T';addr.s.magic[1] = 'P';
		addr.s.ip = p4_inet_sk(tcp_sk)->daddr;
		addr.s.port = p4_inet_sk(tcp_sk)->dport;

		p4remaddr.type = P4REMADDR_ETHER;
		p4remaddr.tec.ether.addr.ipaddr = p4_inet_sk(tcp_sk)->daddr;
		p4remaddr.tec.ether.devname[0] = 0; /* Use IP address */

		if (p4_inet_sk(tcp_sk)->daddr == p4_inet_sk(tcp_sk)->saddr) {
			/* Ugly local connect workaround (delay the connect call)*/
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(1); /* sleep 1/HZ sec */
		}

		timeout = jiffies + 4 * HZ; /* Ugly timeout */

		while (1) {
			int ret = p4_socket_connect(p4s_info->p4s, &addr.p4addr, &p4remaddr, sizeof(p4remaddr));

			if (ret >= 0) {
				p4s_info->rem_conidx = ret;
				break; /* connection established */
			}

			/*
			  We have to wait some time. Other side calls tcp connect
			  before p4sock listen. ECONNREFUSED could be wrong!

			  if (ret == -ECONNREFUSED) {
			     goto err_connect_failed;
			  }
			*/

			if (jiffies > timeout)
				goto err_connect_failed;
			/* Maybe just a signal. retry until timeout after a short delay*/
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(1 + HZ / 10); /* sleep 0.1 sec */
		}
	}
	p4s_info->state = SOCK_STATE_CONNECTED;

	printk(KERN_INFO "p4tcp: Bypass TCP %u.%u.%u.%u:%u to %u.%u.%u.%u:%u (%s)\n",
	       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->saddr)), ntohs(p4_inet_sk(tcp_sk)->sport),
	       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->daddr)), ntohs(p4_inet_sk(tcp_sk)->dport),
	       server ? "connect" : "accept");
	TINETL;
#ifdef P4CALLBACKS
	p4_setcb_data_ready(p4s_info->p4s, tinet_cb_data_ready, sock->sk);
	p4_setcb_write_space(p4s_info->p4s, tinet_cb_write_space, sock->sk);
#endif
	sock->ops = &tinet_proto_ps_ops;

	TINETUL;

	return 0;
	/* --- */
 err_connect_failed:
	printk(KERN_NOTICE "p4tcp: Error : Connect via p4s to %u.%u.%u.%u:%u failed (fallback to TCP)!\n",
	       IP_SPLIT(ntohl(p4_inet_sk(tcp_sk)->daddr)), ntohs(p4_inet_sk(tcp_sk)->dport));
	p4_socket_close(p4s_info->p4s);
 err_create_failed:
	return -1;
}


static void tinet_unprepare_sock(struct socket *sock)
{
	if (sock->sk) {
		p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

		if (p4s_info) kfree(p4s_info);

		SK_MYPTR(sock->sk) = NULL;

		sock_put(sock->sk);//sk_free(sk);
	}
}


/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
static
int tinet_release(struct socket *sock)
{
	int ret = 0;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	if (p4s_info && p4s_info->tcp_sock) {
		ret = p4s_info->tcp_sock->ops->release(p4s_info->tcp_sock);
		p4s_info->tcp_sock = NULL;
	}

	tinet_unprepare_sock(sock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#endif
	return ret;
}

/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
static
int tinet_release_ps(struct socket *sock)
{
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	p4_socket_close(p4s_info->p4s);
	p4s_info->p4s = NULL;

	return tinet_release(sock);
}


static
int tinet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

//    PRINT_TRACE( "p4tcp: %p %p bind()\n",sock,sock->inode);
	ret = p4s_info->tcp_sock->ops->bind(p4s_info->tcp_sock, uaddr, addr_len);
//    PRINT_TRACE( "p4tcp: %p %p bind()done\n",sock,sock->inode);

	return ret;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
static
int tinet_stream_connect(struct socket *sock, struct sockaddr * uaddr,
			 int addr_len, int flags)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

//    PRINT_TRACE( "p4tcp: %p %p connect()\n",sock,sock->inode);
	ret = p4s_info->tcp_sock->ops->connect(p4s_info->tcp_sock, uaddr, addr_len, flags);
//    PRINT_TRACE( "p4tcp: %p %p connect()done\n",sock,sock->inode);

	if (!ret){
//	PRINT_TRACE( "p4tcp: make connection to %u.%u.%u.%u:%u from %u.%u.%u.%u:%u\n",
//		     IP_SPLIT(ntohl(sock->sk->daddr)), ntohs(sock->sk->dport),
//		     IP_SPLIT(ntohl(sock->sk->saddr)), ntohs(sock->sk->sport));
		if ((sock->type == SOCK_STREAM) && tinet_is_addr_matching(p4s_info->tcp_sock)){
			/* we cant call tinet_open_ps before tcp_sock->ops->connect(), because
			   we need p4_inet_sk(tcp_sk)->saddr and p4_inet_sk(tcp_sk)->sport! */
			tinet_open_ps(sock, 1);
		}
	}
	return ret;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static int tinet_prepare_sock(struct socket *sock, int protocol)
#else
static int tinet_prepare_sock(struct net *net, struct socket *sock, int protocol)
#endif
{
	struct sock *sk = NULL;
	p4sock_info_t *p4s_info = NULL;

	int err;

	/* assert */
	if (sock->sk) {
		printk(KERN_ERR "p4tcp: assert(!sock->sk) failed in tinet_prepare_sock\n");
	}
	sock->sk = NULL;


	err = -ENOBUFS;
	p4s_info = kmalloc(sizeof(*p4s_info), GFP_ATOMIC); /* Mabe change attributes */
	if (!p4s_info) goto err_out;

	err = -ENOBUFS;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	sk = sk_alloc(PF_INET, GFP_KERNEL, 1);
#else
#ifndef	TINET_REGISTER_PROTO
	sk = sk_alloc(PF_INET, GFP_KERNEL, 1, NULL);
#else /* TINET_REGISTER_PROTO ( >= 2.6.12 ) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	sk = sk_alloc(PF_P4S, GFP_KERNEL, &tinet_proto, 1);
#else
	sk = sk_alloc(net, PF_P4S, GFP_KERNEL, &tinet_proto);
#endif
#endif
#endif
	if (sk == NULL) goto err_out;

	sock_init_data(sock, sk);

	SK_MYPTR(sock->sk) = p4s_info;

//ToDo:	sk_set_owner(sk, sk->sk_prot->owner);

//        sk->sk_destruct    = inet_sock_destruct;
	sk->sk_family      = PF_TINET;
	sk->sk_protocol    = protocol;

	sock->ops = &tinet_proto_ops;
	p4s_info->tcp_sock = NULL;

	P4_WAITQ_INIT(p4s_info->newcon_waitq);

	return 0;
	/* --- */
 err_out:
	tinet_unprepare_sock(sock);
	if (p4s_info) kfree(p4s_info);
	if (sk) sock_put(sk);//sk_free(sk);

	return err;
}


/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */
static
int tinet_accept(struct socket *sock, struct socket *newsock, int flags)
{
	int err;
	struct socket *new_tcp_sock = NULL;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);
	p4sock_info_t *p4s_new_info;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	err = tinet_prepare_sock(newsock, sock->sk->sk_protocol);
	if (err) goto err_out;
#else
	// ToDo: check &init_net.
	err = tinet_prepare_sock(&init_net, newsock, sock->sk->sk_protocol);
	if (err) goto err_out;
#endif

	err = sock_create(PF_INET, sock->type, sock->sk->sk_protocol, &new_tcp_sock);
	if (err) goto err_out;

	new_tcp_sock->type = p4s_info->tcp_sock->type;
	new_tcp_sock->ops = p4s_info->tcp_sock->ops;

	err = p4s_info->tcp_sock->ops->accept(p4s_info->tcp_sock, new_tcp_sock, flags);

	if (err) goto err_out;

	p4s_new_info = SK_MYPTR(newsock->sk);
	p4s_new_info->tcp_sock = new_tcp_sock;

//	PRINT_TRACE( "p4tcp: get connection from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u\n",
//		     IP_SPLIT(ntohl(newsock->sk->daddr)), ntohs(newsock->sk->dport),
//		     IP_SPLIT(ntohl(newsock->sk->saddr)), ntohs(newsock->sk->sport));
	if ((sock->type == SOCK_STREAM) && tinet_is_addr_matching(new_tcp_sock)){
		tinet_open_ps(newsock, 0);
	}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#endif


	return 0;
	/* --- */
 err_out:
	if (new_tcp_sock) {
		sock_release(new_tcp_sock);
	}
	tinet_unprepare_sock(newsock);
	return err;
}


/*
 *	This does both peername and sockname.
 */
static
int tinet_getname(struct socket *sock, struct sockaddr *uaddr,
		  int *uaddr_len, int peer)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->getname(p4s_info->tcp_sock, uaddr, uaddr_len, peer);

	return ret;

}


static
unsigned int
tinet_poll(struct file * file, struct socket *sock,struct poll_table_struct *wait)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

//    PRINT_TRACE( "p4tcp: %p %p poll()\n",sock,sock->inode);
	ret = p4s_info->tcp_sock->ops->poll(file, p4s_info->tcp_sock, wait);
//    PRINT_TRACE( "p4tcp: %p %p poll()done\n",sock,sock->inode);
	return ret;
}


static
int tinet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
//    PRINT_TRACE( "p4tcp: %p %p ioctl()\n",sock,sock->inode);

	switch (cmd) {
	case P4TCP_ADD_IP_RANGE: {//  _IOW(P4TCP_IOC_MAGIC, 1, p4tcp_ip_range_t)
		p4tcp_ip_range_t iprange;
		if (copy_from_user(&iprange, (void*)arg, sizeof(iprange))) {
			ret = -EINVAL; break;
		}
		ret = p4tcp_add_ip_range(&iprange);
	}   break;
	case P4TCP_DEL_IP_RANGE: {//  _IOW(P4TCP_IOC_MAGIC, 2, p4tcp_ip_range_t)
		p4tcp_ip_range_t iprange;
		if (copy_from_user(&iprange, (void*)arg, sizeof(iprange))) {
			ret = -EINVAL; break;
		}
		ret = p4tcp_del_ip_range(&iprange);
	}	break;
	case P4TCP_GET_IP_RANGE: {//  _IOR(P4TCP_IOC_MAGIC, 3, p4tcp_get_ip_range_t)
		p4tcp_ip_range_get_t giprange;
		if (copy_from_user(&giprange, (void*)arg, sizeof(giprange))) {
			ret = -EINVAL; break;
		}
		ret = p4tcp_get_ip_range(giprange.index, &giprange.range);
		if (copy_to_user((void*)arg, &giprange, sizeof(giprange))) {
			ret = -EINVAL; break;
		}
	}   break;
	default: {
		p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

		ret = p4s_info->tcp_sock->ops->ioctl(p4s_info->tcp_sock, cmd, arg);
	}
	}
	return ret;
}

/*
 *	Move a socket into listening state.
 */
static
int tinet_listen(struct socket *sock, int backlog)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

//    PRINT_TRACE( "p4tcp: %p %p listen()\n",sock,sock->inode);
	ret = p4s_info->tcp_sock->ops->listen(p4s_info->tcp_sock, backlog);
//    PRINT_TRACE( "p4tcp: %p %p listen()done\n",sock,sock->inode);

	return ret;
}


static
int tinet_shutdown(struct socket *sock, int how)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->shutdown(p4s_info->tcp_sock, how);

	return ret;
}


static
int tinet_shutdown_ps(struct socket *sock, int how)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);
	int trycnt = 20;
//    PRINT_TRACE( "p4tcp: %p %p shutdown()\n",sock,sock->inode);
	do {
		if (p4s_info->rem_conidx >= 0) {
			ret = p4_shutdown(p4s_info->p4s, p4s_info->rem_conidx);
			if (ret == 0) break;
		} else {
			ret = -EPIPE;
			break;
		}
	} while (trycnt > 0);

	if (ret == 0) {
		ret = tinet_shutdown(sock, how);
	}
	return ret;
}


/*
 *	Set socket options on an inet socket.
 */
static
int tinet_setsockopt(struct socket *sock, int level, int optname,
		     char *optval, int optlen)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->setsockopt(p4s_info->tcp_sock, level,
						 optname, optval, optlen);
	return ret;
}

/*
 *	Get a socket option on an AF_INET socket.
 */
static
int tinet_getsockopt(struct socket *sock, int level, int optname,
		     char *optval, int *optlen)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->getsockopt(p4s_info->tcp_sock, level,
						 optname, optval, optlen);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static
int tinet_sendmsg(struct socket *sock, struct msghdr *msg, int size,
		  struct scm_cookie *scm)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->sendmsg(p4s_info->tcp_sock, msg, size, scm);

	return ret;
}

static
int tinet_recvmsg(struct socket *sock, struct msghdr *msg, int size,
		  int flags, struct scm_cookie *scm)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->recvmsg(p4s_info->tcp_sock, msg, size, flags, scm);

	return ret;
}

#else /*  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) */

static
int tinet_sendmsg(struct kiocb *iocb, struct socket *sock,
		  struct msghdr *msg, size_t size)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->sendmsg(iocb, p4s_info->tcp_sock, msg, size);

	return ret;
}

static
int tinet_recvmsg(struct kiocb *iocb, struct socket *sock,
		  struct msghdr *msg, size_t size, int flags)
{
	int ret;
	p4sock_info_t *p4s_info = SK_MYPTR(sock->sk);

	ret = p4s_info->tcp_sock->ops->recvmsg(iocb, p4s_info->tcp_sock, msg, size, flags);

	return ret;
}

#endif /*  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) */




/* proto_ops for proxy */
static struct proto_ops tinet_proto_ops = { /* inet_stream_ops */
	family:	   	PF_TINET,

//	sock_no_dup,
	release:	tinet_release,
	bind:	tinet_bind,
	connect:	tinet_stream_connect,
	socketpair:	sock_no_socketpair,
	accept:	tinet_accept,
	getname:	tinet_getname,
	poll:	tinet_poll,
	ioctl:	tinet_ioctl,
	listen:	tinet_listen,
	shutdown:	tinet_shutdown,
	setsockopt:	tinet_setsockopt,
	getsockopt:	tinet_getsockopt,
//	sock_no_fcntl,
	sendmsg:	tinet_sendmsg,
	recvmsg:	tinet_recvmsg,
	sendpage:	sock_no_sendpage
};

/* proto_ops for established connections via parastation */
static struct proto_ops tinet_proto_ps_ops = { /* inet_stream_ops */
	family:	PF_TINET,

//	tinet_dup_ps,
	release:	tinet_release_ps,
	bind:	tinet_bind,
	connect:	tinet_stream_connect,
	socketpair:	sock_no_socketpair,
	accept:	tinet_accept,
	getname:	tinet_getname,
	poll:	tinet_poll_ps,
	ioctl:	tinet_ioctl,
	listen:	tinet_listen,
	shutdown:	tinet_shutdown_ps,
	setsockopt:	tinet_setsockopt,
	getsockopt:	tinet_getsockopt,
//	sock_no_fcntl,
	sendmsg:	tinet_sendmsg_ps,
	recvmsg:	tinet_recvmsg_ps,
	sendpage:	sock_no_sendpage
};


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static int tinet_create(struct socket *sock, int protocol)
#else
static int tinet_create(struct net *net, struct socket *sock, int protocol)
#endif
{
	int err;
	p4sock_info_t *p4s_info = NULL;
	struct socket *tcp_sock = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	err = tinet_prepare_sock(sock, protocol);
#else
	err = tinet_prepare_sock(net, sock, protocol);
#endif
	if (err) goto err_out;


	/* Create the tcp socket */

	err = sock_create(PF_INET, sock->type, protocol, &tcp_sock);
	if (err) goto err_out;

	p4s_info = SK_MYPTR(sock->sk);
	p4s_info->tcp_sock = tcp_sock;


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#endif

	return 0;
	/* --- */
 err_out:
	tinet_unprepare_sock(sock);

	return err;
}





static struct net_proto_family tinet_family_ops =
{
	PF_TINET,
	tinet_create
};





static int tinet_proto_init(void)
{
	int ret;
	printk(KERN_INFO "p4tcp: Protocol init\n");

#ifdef TINET_REGISTER_PROTO
	ret = proto_register(&tinet_proto, 0);
	if (ret != 0) {
		printk(KERN_ERR
		       "p4tcp: proto_register(\"%s\") failed!\n", tinet_proto.name);
		return ret;
	}
#endif

//    inet_family_ops = net_families[ PF_INET ];
//    if (PF_INET == PF_TINET) {
//	sock_unregister(PF_INET);
//    }
	ret = sock_register(&tinet_family_ops);
	if (ret) {
		printk(KERN_ERR
		       "p4tcp: sock_register(&tinet_family_ops) failed. (PF_#%d already used?)\n",
		       PF_TINET);
#ifdef TINET_REGISTER_PROTO
		proto_unregister(&tinet_proto);
#endif
		return ret;
	}
	return ret;
}

static void tinet_proto_cleanup(void)
{
	printk(KERN_INFO "p4tcp: Protocol cleanup\n");
	sock_unregister( PF_TINET );
//    if (PF_INET == PF_TINET)
//	sock_register( &inet_family_ops );// Put original back;
#ifdef TINET_REGISTER_PROTO
	proto_unregister(&tinet_proto);
#endif
}


#ifdef MODULE
MODULE_AUTHOR("Jens Hauke <hauke@wtal.de>");
MODULE_DESCRIPTION("T in the INET socket layer");
#ifdef MODULE_LICENSE
MODULE_LICENSE("QPL");
#endif

int init_module(void)
{
	int ret = 0;
	TINETLVAR;

	if (! SK_MYPTR_ASSERT) return -EFAULT;

	TINETL;

	ret = tinet_proto_init();

	TINETUL;

	return ret;
}


void cleanup_module(void)
{
	TINETLVAR;
	TINETL;
	tinet_proto_cleanup();
	TINETUL;
}

#else /* !MODULE */

#error Please compile as module

#endif
